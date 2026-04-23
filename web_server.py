# -*- coding: utf-8 -*-
"""smtpsender Web Server - aiohttp"""
import asyncio
import json
import sys
import os
import re
import threading
import time
import logging
from pathlib import Path
from typing import Set, List, Optional, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from aiohttp import web
import aiohttp

from smtpsender.core.models import (
    SmtpAccount, SendTask, EvasionConfig, HiddenTextConfig,
    SpamWordConfig, TrackingConfig, SendResult
)
from smtpsender.core.template_engine import TemplateVarEngine
from smtpsender.core.proxy_manager import ApiProxyManager
from smtpsender.workers.sender_worker import SenderWorker
from smtpsender.workers.verify_worker import _SmtpVerifyWorker


# ------------------------------------------------------------
# 全局应用状态
# ------------------------------------------------------------

class AppState:
    """全局应用状态（线程安全）"""
    def __init__(self):
        self.lock = threading.RLock()
        self.state = 'idle'  # idle, running, paused
        self.worker: Optional[SenderWorker] = None
        self.verify_worker: Optional[_SmtpVerifyWorker] = None
        self.results: List[Dict[str, Any]] = []  # 存储发送结果，最多200条
        self.ws_clients: Set[web.WebSocketResponse] = set()
        self.proxy_manager = ApiProxyManager()
        self.done = 0
        self.total = 0
        self.success = 0
        self.failed = 0
        self.logs: List[Dict[str, Any]] = []
        
    def update_stats(self, done=None, total=None, success=None, failed=None):
        with self.lock:
            if done is not None:
                self.done = done
            if total is not None:
                self.total = total
            if success is not None:
                self.success = success
            if failed is not None:
                self.failed = failed
                
    def add_result(self, result: SendResult):
        with self.lock:
            # 将SendResult转换为字典（可序列化）
            result_dict = {
                'recipient': result.task.recipient,
                'success': result.success,
                'message': result.message,
                'elapsed_ms': result.elapsed_ms,
                'error_type': result.error_type,
                'proxy_used': result.proxy_used,
                'send_time': result.send_time,
                'smtp_used': result.smtp_used.username if result.smtp_used else None
            }
            self.results.insert(0, result_dict)
            if len(self.results) > 200:
                self.results = self.results[:200]
                
    def add_log(self, message: str, level: str = 'info'):
        with self.lock:
            log_entry = {
                'timestamp': time.time(),
                'message': message,
                'level': level
            }
            self.logs.insert(0, log_entry)
            if len(self.logs) > 100:
                self.logs = self.logs[:100]
                
    def set_state(self, new_state: str):
        with self.lock:
            self.state = new_state
            
    def set_worker(self, worker: SenderWorker):
        with self.lock:
            self.worker = worker
            
    def set_verify_worker(self, worker: _SmtpVerifyWorker):
        with self.lock:
            self.verify_worker = worker
            
    def clear_worker(self):
        with self.lock:
            self.worker = None
            
    def clear_verify_worker(self):
        with self.lock:
            self.verify_worker = None
            
    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                'state': self.state,
                'done': self.done,
                'total': self.total,
                'success': self.success,
                'failed': self.failed
            }
    
    def add_ws_client(self, ws: web.WebSocketResponse):
        with self.lock:
            self.ws_clients.add(ws)
            
    def remove_ws_client(self, ws: web.WebSocketResponse):
        with self.lock:
            self.ws_clients.discard(ws)
            
    async def broadcast(self, message: Dict[str, Any]):
        """向所有WebSocket客户端广播消息"""
        with self.lock:
            clients = list(self.ws_clients)
        data = json.dumps(message, ensure_ascii=False)
        for ws in clients:
            try:
                await ws.send_str(data)
            except Exception as e:
                logging.warning(f"WebSocket发送失败: {e}")
                self.remove_ws_client(ws)


app_state = AppState()


# ------------------------------------------------------------
# 解析辅助函数
# ------------------------------------------------------------

def parse_smtp_line(line: str) -> Optional[SmtpAccount]:
    """解析SMTP账号行：支持 user:pass@host:port 或 user|pass|host|port 格式"""
    line = line.strip()
    if not line:
        return None
        
    # 格式1: user:pass@host:port
    if '@' in line and ':' in line:
        # 先分割出 user:pass 和 host:port
        try:
            user_pass, host_port = line.split('@', 1)
            username, password = user_pass.split(':', 1)
            host, port_str = host_port.split(':', 1)
            port = int(port_str)
            return SmtpAccount(
                host=host,
                port=port,
                username=username.strip(),
                password=password.strip(),
                raw_line=line
            )
        except (ValueError, IndexError):
            pass
            
    # 格式2: user|pass|host|port
    if '|' in line:
        parts = line.split('|')
        if len(parts) >= 4:
            try:
                username, password, host, port_str = parts[:4]
                port = int(port_str)
                return SmtpAccount(
                    host=host.strip(),
                    port=port,
                    username=username.strip(),
                    password=password.strip(),
                    raw_line=line
                )
            except (ValueError, IndexError):
                pass
                
    # 尝试其他分隔符：空格或制表符分割
    parts = re.split(r'[\s\t]+', line)
    if len(parts) >= 4:
        try:
            username, password, host, port_str = parts[:4]
            port = int(port_str)
            return SmtpAccount(
                host=host.strip(),
                port=port,
                username=username.strip(),
                password=password.strip(),
                raw_line=line
            )
        except (ValueError, IndexError):
            pass
            
    logging.warning(f"无法解析SMTP行: {line}")
    return None


def parse_smtps(smtps_text: str) -> List[SmtpAccount]:
    """解析多行SMTP账号文本"""
    accounts = []
    seen = set()
    for line in smtps_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        account = parse_smtp_line(line)
        if account:
            key = f"{account.username}@{account.host}:{account.port}"
            if key not in seen:
                seen.add(key)
                accounts.append(account)
    return accounts


def parse_recipients(recipients_text: str) -> List[str]:
    """解析收件人列表，每行一个邮箱，去重"""
    emails = []
    seen = set()
    for line in recipients_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # 简单的邮箱格式检查
        if '@' in line and '.' in line:
            email = line.lower()
            if email not in seen:
                seen.add(email)
                emails.append(email)
        else:
            logging.warning(f"跳过无效邮箱格式: {line}")
    return emails


# ------------------------------------------------------------
# SenderWorker 回调包装器
# ------------------------------------------------------------

def create_sender_callbacks():
    """创建SenderWorker使用的回调函数"""
    async def on_log(message: str, level: str = 'info'):
        app_state.add_log(message, level)
        await app_state.broadcast({
            'type': 'log',
            'message': message,
            'level': level
        })
        
    async def on_progress(done: int, total: int, success: int, failed: int):
        app_state.update_stats(done=done, total=total, success=success, failed=failed)
        await app_state.broadcast({
            'type': 'progress',
            'done': done,
            'total': total,
            'success': success,
            'failed': failed
        })
        
    async def on_finished(total: int, success: int, failed: int, end_tag: str):
        app_state.update_stats(done=total, total=total, success=success, failed=failed)
        app_state.set_state('idle')
        await app_state.broadcast({
            'type': 'finished',
            'total': total,
            'success': success,
            'failed': failed,
            'end_tag': end_tag
        })
        app_state.clear_worker()
        
    async def on_batch_results(results: List[SendResult]):
        for result in results:
            app_state.add_result(result)
        await app_state.broadcast({
            'type': 'batch_results',
            'count': len(results)
        })
        
    async def on_batch_logs(logs: List[str]):
        for log in logs:
            app_state.add_log(log, 'info')
        await app_state.broadcast({
            'type': 'batch_logs',
            'count': len(logs)
        })
    
    # 由于回调在worker线程中调用，需要在线程中调度协程
    def make_async_wrapper(coro_func):
        def wrapper(*args, **kwargs):
            asyncio.run_coroutine_threadsafe(
                coro_func(*args, **kwargs),
                asyncio.get_event_loop()
            )
        return wrapper
    
    return {
        'log': make_async_wrapper(on_log),
        'progress': make_async_wrapper(on_progress),
        'finished': make_async_wrapper(on_finished),
        'batch_results': make_async_wrapper(on_batch_results),
        'batch_logs': make_async_wrapper(on_batch_logs)
    }


# ------------------------------------------------------------
# HTTP 路由处理器
# ------------------------------------------------------------

async def handle_status(request: web.Request):
    """GET /api/status"""
    return web.json_response(app_state.get_status())


async def handle_send(request: web.Request):
    """POST /api/send - 启动发送任务"""
    if app_state.state == 'running' or app_state.state == 'paused':
        return web.json_response(
            {'error': '已有任务正在运行，请先停止'}, status=400
        )
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({'error': '无效的JSON数据'}, status=400)
    
    # 必需字段验证
    required = ['smtps', 'recipients', 'subject', 'body']
    for field in required:
        if field not in data:
            return web.json_response(
                {'error': f'缺少必需字段: {field}'}, status=400
            )
    
    # 解析SMTP账号
    smtp_accounts = parse_smtps(data['smtps'])
    if not smtp_accounts:
        return web.json_response({'error': '没有有效的SMTP账号'}, status=400)
    
    # 解析收件人
    recipients = parse_recipients(data['recipients'])
    if not recipients:
        return web.json_response({'error': '没有有效的收件人邮箱'}, status=400)
    
    # 构建发送任务列表（简化：每个收件人一个任务，使用轮询SMTP账号）
    # 注意：实际实现需要更复杂的任务分配逻辑
    tasks = []
    for i, recipient in enumerate(recipients):
        account = smtp_accounts[i % len(smtp_accounts)]
        task = SendTask(
            account=account,
            recipient=recipient,
            subject=data['subject'],
            body_html=data['body'],
            body_format='html',
            bcc_mode=data.get('bcc_mode', False),
            comment_clean=True
        )
        tasks.append(task)
    
    # 构建配置
    evasion_cfg = EvasionConfig()
    hidden_cfg = HiddenTextConfig()
    spam_cfg = SpamWordConfig()
    template_engine = TemplateVarEngine()
    
    # 创建SenderWorker
    worker = SenderWorker(
        tasks=tasks,
        proxy_manager=app_state.proxy_manager,
        evasion_cfg=evasion_cfg,
        hidden_cfg=hidden_cfg,
        spam_cfg=spam_cfg,
        template_engine=template_engine,
        subject_template=data['subject'],
        body_template=data['body'],
        timeout=data.get('timeout', 30),
        retry=data.get('retry', 2),
        delay=data.get('delay', 0.5),
        threads=data.get('threads', 5),
        dry_run=data.get('dry_run', False),
        max_per_account=data.get('max_per_account', 100),
        callbacks=create_sender_callbacks(),
        progress_total=len(recipients)
    )
    
    # 更新状态并启动worker
    app_state.set_state('running')
    app_state.set_worker(worker)
    app_state.update_stats(done=0, total=len(recipients), success=0, failed=0)
    worker.start()
    
    return web.json_response({'success': True, 'message': '发送任务已启动'})


async def handle_stop(request: web.Request):
    """POST /api/stop - 停止发送"""
    with app_state.lock:
        if app_state.worker:
            app_state.worker.stop()
            app_state.set_state('idle')
            return web.json_response({'success': True, 'message': '正在停止任务'})
        else:
            return web.json_response(
                {'error': '没有正在运行的任务'}, status=400
            )


async def handle_pause(request: web.Request):
    """POST /api/pause - 暂停发送"""
    with app_state.lock:
        if app_state.worker and app_state.state == 'running':
            app_state.worker.pause()
            app_state.set_state('paused')
            return web.json_response({'success': True, 'message': '已暂停'})
        else:
            return web.json_response(
                {'error': '没有正在运行的任务'}, status=400
            )


async def handle_resume(request: web.Request):
    """POST /api/resume - 继续发送"""
    with app_state.lock:
        if app_state.worker and app_state.state == 'paused':
            app_state.worker.resume()
            app_state.set_state('running')
            return web.json_response({'success': True, 'message': '已继续'})
        else:
            return web.json_response(
                {'error': '任务未处于暂停状态'}, status=400
            )


async def handle_results(request: web.Request):
    """GET /api/results - 返回最新200条发送结果"""
    with app_state.lock:
        return web.json_response({'results': app_state.results})


async def handle_verify(request: web.Request):
    """POST /api/verify - 验证SMTP账号"""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({'error': '无效的JSON数据'}, status=400)
    
    if 'smtps' not in data:
        return web.json_response({'error': '缺少smtps字段'}, status=400)
    
    smtp_accounts = parse_smtps(data['smtps'])
    if not smtp_accounts:
        return web.json_response({'error': '没有有效的SMTP账号'}, status=400)
    
    # 创建验证回调
    def verification_callback(valid_lines: List[str], invalid_count: int, total: int):
        async def notify():
            await app_state.broadcast({
                'type': 'verify_result',
                'valid_count': len(valid_lines),
                'invalid_count': invalid_count,
                'total': total,
                'valid_lines': valid_lines
            })
            app_state.clear_verify_worker()
        
        asyncio.run_coroutine_threadsafe(
            notify(),
            asyncio.get_event_loop()
        )
    
    # 创建验证worker（注意：需要导入Signals类，这里简化处理）
    # 由于Signals可能不存在，我们暂时跳过验证worker的完整实现
    # 仅返回成功响应，实际验证需要更完整的实现
    return web.json_response({
        'success': True,
        'message': '验证功能需要完整实现Signals类',
        'parsed_count': len(smtp_accounts)
    })


async def websocket_handler(request: web.Request):
    """WebSocket连接处理器"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    app_state.add_ws_client(ws)
    app_state.add_log(f"WebSocket客户端连接，当前连接数: {len(app_state.ws_clients)}")
    
    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                # 客户端可以发送ping消息保持连接
                if msg.data == 'ping':
                    await ws.send_str('pong')
            elif msg.type == web.WSMsgType.ERROR:
                break
    except Exception as e:
        logging.warning(f"WebSocket错误: {e}")
    finally:
        app_state.remove_ws_client(ws)
        app_state.add_log(f"WebSocket客户端断开，剩余连接数: {len(app_state.ws_clients)}")
    
    return ws


async def handle_index(request: web.Request):
    """GET / - 返回前端页面"""
    # 检查static目录是否存在
    static_dir = Path(__file__).parent / 'static'
    index_file = static_dir / 'index.html'
    
    if index_file.exists():
        return web.FileResponse(str(index_file))
    else:
        # 如果没有前端文件，返回简单页面
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SMTP邮件群发控制台</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .panel { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }
                .status { background: #f5f5f5; padding: 10px; }
                .logs { height: 300px; overflow-y: auto; border: 1px solid #ccc; padding: 10px; font-family: monospace; }
                .form-group { margin-bottom: 10px; }
                label { display: inline-block; width: 150px; }
                input, textarea { width: 300px; }
                textarea { height: 100px; }
                button { padding: 5px 15px; margin-right: 10px; }
                .success { color: green; }
                .error { color: red; }
                .warning { color: orange; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SMTP邮件群发控制台</h1>
                
                <div class="panel">
                    <h2>状态</h2>
                    <div class="status">
                        状态: <span id="state">idle</span> |
                        进度: <span id="progress">0/0</span> |
                        成功: <span id="success">0</span> |
                        失败: <span id="failed">0</span>
                    </div>
                    <div>
                        <button onclick="startSend()">开始发送</button>
                        <button onclick="stopSend()">停止</button>
                        <button onclick="pauseSend()">暂停</button>
                        <button onclick="resumeSend()">继续</button>
                        <button onclick="verifyAccounts()">验证账号</button>
                    </div>
                </div>
                
                <div class="panel">
                    <h2>发送配置</h2>
                    <div class="form-group">
                        <label>SMTP账号:</label><br>
                        <textarea id="smtps" placeholder="user:pass@host:port&#10;每行一个账号"></textarea>
                    </div>
                    <div class="form-group">
                        <label>收件人:</label><br>
                        <textarea id="recipients" placeholder="email@example.com&#10;每行一个邮箱"></textarea>
                    </div>
                    <div class="form-group">
                        <label>主题:</label>
                        <input type="text" id="subject" value="测试邮件">
                    </div>
                    <div class="form-group">
                        <label>正文:</label><br>
                        <textarea id="body"><h1>测试邮件</h1><p>这是一封测试邮件。</p></textarea>
                    </div>
                    <div class="form-group">
                        <label>线程数:</label>
                        <input type="number" id="threads" value="5" min="1">
                    </div>
                    <div class="form-group">
                        <label>延迟(秒):</label>
                        <input type="number" id="delay" value="0.5" step="0.1">
                    </div>
                </div>
                
                <div class="panel">
                    <h2>日志</h2>
                    <div class="logs" id="logs"></div>
                </div>
                
                <div class="panel">
                    <h2>发送结果</h2>
                    <div id="results"></div>
                </div>
            </div>
            
            <script>
                let ws = null;
                
                function connectWebSocket() {
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    const wsUrl = `${protocol}//${window.location.host}/ws`;
                    ws = new WebSocket(wsUrl);
                    
                    ws.onopen = () => {
                        addLog('WebSocket已连接');
                    };
                    
                    ws.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        handleWebSocketMessage(data);
                    };
                    
                    ws.onclose = () => {
                        addLog('WebSocket断开，5秒后重连...');
                        setTimeout(connectWebSocket, 5000);
                    };
                    
                    ws.onerror = (error) => {
                        console.error('WebSocket错误:', error);
                    };
                }
                
                function handleWebSocketMessage(data) {
                    switch(data.type) {
                        case 'log':
                            addLog(data.message, data.level);
                            break;
                        case 'progress':
                            updateProgress(data.done, data.total, data.success, data.failed);
                            break;
                        case 'finished':
                            addLog(`任务完成: 成功${data.success}，失败${data.failed} (${data.end_tag})`);
                            updateProgress(data.total, data.total, data.success, data.failed);
                            break;
                    }
                }
                
                function addLog(message, level = 'info') {
                    const logsDiv = document.getElementById('logs');
                    const logEntry = document.createElement('div');
                    logEntry.className = level;
                    logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
                    logsDiv.appendChild(logEntry);
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                }
                
                function updateProgress(done, total, success, failed) {
                    document.getElementById('state').textContent = 'running';
                    document.getElementById('progress').textContent = `${done}/${total}`;
                    document.getElementById('success').textContent = success;
                    document.getElementById('failed').textContent = failed;
                }
                
                async function apiCall(endpoint, method='GET', data=null) {
                    const options = {
                        method,
                        headers: {'Content-Type': 'application/json'}
                    };
                    if (data) options.body = JSON.stringify(data);
                    
                    try {
                        const response = await fetch(`/api/${endpoint}`, options);
                        return await response.json();
                    } catch (error) {
                        addLog(`API调用失败: ${error}`, 'error');
                        return {error: error.toString()};
                    }
                }
                
                async function startSend() {
                    const data = {
                        smtps: document.getElementById('smtps').value,
                        recipients: document.getElementById('recipients').value,
                        subject: document.getElementById('subject').value,
                        body: document.getElementById('body').value,
                        threads: parseInt(document.getElementById('threads').value),
                        delay: parseFloat(document.getElementById('delay').value),
                        timeout: 30,
                        retry: 2,
                        max_per_account: 100,
                        dry_run: false,
                        bcc_mode: false
                    };
                    
                    const result = await apiCall('send', 'POST', data);
                    if (result.success) {
                        addLog('发送任务已启动');
                    } else {
                        addLog(`启动失败: ${result.error}`, 'error');
                    }
                }
                
                async function stopSend() {
                    const result = await apiCall('stop', 'POST');
                    if (result.success) {
                        addLog('正在停止任务...');
                    }
                }
                
                async function pauseSend() {
                    const result = await apiCall('pause', 'POST');
                    if (result.success) {
                        addLog('已暂停');
                    }
                }
                
                async function resumeSend() {
                    const result = await apiCall('resume', 'POST');
                    if (result.success) {
                        addLog('已继续');
                    }
                }
                
                async function verifyAccounts() {
                    const smtps = document.getElementById('smtps').value;
                    if (!smtps.trim()) {
                        addLog('请输入SMTP账号', 'warning');
                        return;
                    }
                    const result = await apiCall('verify', 'POST', {smtps});
                    addLog(`验证结果: ${result.message}`);
                }
                
                // 初始化
                connectWebSocket();
                // 加载状态
                async function loadStatus() {
                    const status = await apiCall('status');
                    if (!status.error) {
                        document.getElementById('state').textContent = status.state;
                        document.getElementById('progress').textContent = `${status.done}/${status.total}`;
                        document.getElementById('success').textContent = status.success;
                        document.getElementById('failed').textContent = status.failed;
                    }
                }
                loadStatus();
                setInterval(loadStatus, 5000);
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')


async def handle_static(request: web.Request):
    """GET /static/{filename} - 静态文件服务"""
    filename = request.match_info['filename']
    static_dir = Path(__file__).parent / 'static'
    file_path = static_dir / filename
    
    if not file_path.exists() or not file_path.is_file():
        return web.Response(status=404, text='文件未找到')
    
    # 简单的内容类型推断
    content_type = 'application/octet-stream'
    if filename.endswith('.html'):
        content_type = 'text/html'
    elif filename.endswith('.css'):
        content_type = 'text/css'
    elif filename.endswith('.js'):
        content_type = 'application/javascript'
    elif filename.endswith('.png'):
        content_type = 'image/png'
    elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
        content_type = 'image/jpeg'
    elif filename.endswith('.gif'):
        content_type = 'image/gif'
    
    return web.FileResponse(str(file_path), headers={'Content-Type': content_type})


# ------------------------------------------------------------
# 创建应用
# ------------------------------------------------------------

def create_app():
    app = web.Application()
    
    # REST API 路由
    app.router.add_get('/api/status', handle_status)
    app.router.add_post('/api/send', handle_send)
    app.router.add_post('/api/stop', handle_stop)
    app.router.add_post('/api/pause', handle_pause)
    app.router.add_post('/api/resume', handle_resume)
    app.router.add_get('/api/results', handle_results)
    app.router.add_post('/api/verify', handle_verify)
    
    # WebSocket
    app.router.add_get('/ws', websocket_handler)
    
    # 静态文件
    app.router.add_get('/static/{filename}', handle_static)
    
    # 首页
    app.router.add_get('/', handle_index)
    
    return app


# ------------------------------------------------------------
# 主程序入口
# ------------------------------------------------------------

if __name__ == '__main__':
    # 确保static目录存在
    static_dir = Path(__file__).parent / 'static'
    static_dir.mkdir(exist_ok=True)
    
    # 初始化日志
    logging.basicConfig(level=logging.INFO)
    
    app = create_app()
    web.run_app(app, host='0.0.0.0', port=8080)