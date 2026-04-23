# SMTP 群发工具 Web 控制台 v5.6.0

高性能 SMTP 邮件群发工具，模块化架构，Web 控制台，无 GUI 依赖。

## ✨ 特性

- **多线程并发发送** — 可配置线程数，ThreadPoolExecutor 调度
- **SMTP 持久连接池** — 复用认证连接，减少握手开销
- **四种伪装技术** — 线程劫持 / 混合编码 / 显示混淆 / 发件人伪装
- **21 种 HTML 隐藏文本注入** — 对抗垃圾邮件过滤器
- **敏感词 Unicode 形近字替换** — 52 个字符映射表
- **API 代理池** — SOCKS5 代理自动获取、健康检测、地域匹配
- **模板变量引擎** — `[%EMail]` `[%FName]` `[%IPV4]` 等动态变量
- **BCC 密送群发** — Envelope/Header From 分离
- **Web 控制台** — aiohttp + Vue3，实时 WebSocket 日志推送
- **Docker 一键部署** — 含健康检查

## 🏗️ 架构

```
smtpsender/
├── core/
│   ├── constants.py       # 敏感词表、形近字替换表、隐藏文本模板
│   ├── models.py          # 数据类：SmtpAccount, SendTask, ProxyEntry...
│   ├── utils.py           # 工具函数、SSL 缓存、HELO 生成器
│   ├── hidden_text.py     # HTML 注入引擎 + 敏感词替换引擎
│   ├── template_engine.py # 模板变量渲染引擎
│   ├── evasion.py         # 四种伪装技术引擎
│   ├── smtp_conn.py       # SMTP 连接层
│   ├── send_logic.py      # 核心发送逻辑、代理筛选
│   ├── smtp_pool.py       # SMTP 持久连接池
│   └── proxy_manager.py   # API 代理池管理器
├── workers/
│   ├── sender_worker.py   # 发送 Worker（threading，callback 模式）
│   └── verify_worker.py   # SMTP 账号验证 Worker
├── static/
│   └── index.html         # Vue3 CDN 深色主题控制台
├── tests/
│   └── smoke_test.py      # 冒烟测试（15/15 PASS）
├── web_server.py          # aiohttp Web 服务器
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 🚀 快速启动

### Docker（推荐）

```bash
git clone https://github.com/Tovarissh/smtpsender.git
cd smtpsender
docker-compose up -d
# 访问 http://localhost:8080
```

### 本地运行

```bash
pip install aiohttp PySocks
cd smtpsender
python3 web_server.py
# 访问 http://localhost:8080
```

## 📋 SMTP 格式

每行一个账号，支持两种格式：

```
user@example.com:password@smtp.example.com:587
user@example.com|password|smtp.example.com|465
```

## 🌐 API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 当前状态（idle/running/paused）|
| POST | `/api/send` | 启动发送任务 |
| POST | `/api/stop` | 停止发送 |
| POST | `/api/pause` | 暂停 |
| POST | `/api/resume` | 继续 |
| GET | `/api/results` | 发送结果（最新 200 条）|
| POST | `/api/verify` | 验证 SMTP 账号 |
| WS | `/ws` | 实时日志 & 进度推送 |

## 🧪 冒烟测试

```bash
cd /path/to/parent  # smtpsender 包的上级目录
python3 -m smtpsender.tests.smoke_test
# 期望输出: 15/15 PASS ✓ 全部通过
```

## 📦 依赖

- Python 3.9+
- `aiohttp >= 3.9.0`
- `PySocks >= 1.7.1`

## ⚠️ 免责声明

本工具仅供合法的邮件营销和系统测试使用。使用者须遵守当地法律法规及目标邮件服务商的服务条款。

## License

MIT
