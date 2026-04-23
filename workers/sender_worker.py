# -*- coding: utf-8 -*-
"""发送Worker：多线程并发发送、代理轮转、进度回调"""
from __future__ import annotations
import copy
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Callable, Dict, List, Optional, Tuple
from ..core.models import SmtpAccount, ProxyEntry, SendTask, SendResult, TrackingConfig

try:
    from email_tracker import TrackingDB, new_campaign
    HAS_TRACKER = True
except ImportError:
    HAS_TRACKER = False
    TrackingDB = None
    def new_campaign(*a, **kw): return ""

from ..core.send_logic import _send_one
from ..core.smtp_pool import _SmtpConnPool
from ..core.proxy_manager import ApiProxyManager


def _pick_bound_proxy(pool: List["ProxyEntry"]) -> "ProxyEntry":
    """任务级代理绑定辅助函数:从候选池中选出一个代理并绑定给本任务。

    隧道模式:优先选 tunnel_active 最低（最空闲）的端口。
    普通模式:按 RBL 干净 + 低延迟优先级选取。
    与 _send_one 内部的 _pick_best_proxy 逻辑相同，但作用域在任务级别。
    """
    has_tunnel = any(p.tunnel_idx >= 0 for p in pool)
    if has_tunnel:
        min_active = min(p.tunnel_active for p in pool)
        idle = [p for p in pool if p.tunnel_active == min_active]
        return random.choice(idle)
    # 普通模式分层选择
    tier1 = [p for p in pool if p.is_rbl_clean() and p.is_low_latency(5000)]
    if tier1:
        return random.choice(tier1)
    tier2 = [p for p in pool if p.is_rbl_clean()]
    if tier2:
        return random.choice(tier2)
    return random.choice(pool)


class SenderWorker(threading.Thread):
    """FIX: 全面修复竞态条件、优化退避策略、增强代理耗尽恢复机制。"""
    def __init__(
        self,
        tasks: List[SendTask],
        proxy_manager: ApiProxyManager,
        evasion_cfg: EvasionConfig,
        hidden_cfg: HiddenTextConfig,
        spam_cfg: SpamWordConfig,
        template_engine: TemplateVarEngine,
        subject_template: str,
        body_template: str,
        timeout: int,
        retry: int,
        delay: float,
        threads: int,
        dry_run: bool,
        max_per_account: int,
        callbacks: dict = None,
        comment_clean: bool = True,   # FIX-⑤: comment_clean 参数
        tracking_cfg: Optional["TrackingConfig"] = None,  # 跟踪配置
        progress_total: int = 0,  # 进度条总量（按收件人数；密送批成功按批内人数计）
    ):
        super().__init__()
        self.tasks = tasks
        self._progress_total = progress_total if progress_total > 0 else len(tasks)
        self.proxy_manager = proxy_manager
        self.evasion_cfg = evasion_cfg
        self.hidden_cfg = hidden_cfg
        self.spam_cfg = spam_cfg
        self.template_engine = template_engine
        self.subject_template = subject_template
        self.body_template = body_template
        self.timeout = timeout
        self.retry = retry
        self.delay = delay
        self.threads = threads
        self.dry_run = dry_run
        self.max_per_account = max_per_account
        self.callbacks = callbacks
        self.comment_clean = comment_clean   # FIX-⑤
        self._stop_flag = threading.Event()
        self._stop_event = threading.Event()  # for compatibility with quit/wait
        self.success = 0
        # ── 跟踪配置 ────────────────────────────────────────────────────────
        self.tracking_cfg: TrackingConfig = tracking_cfg or TrackingConfig()
        self._tracking_db: Optional[TrackingDB] = None
        self._tracking_campaign_id: str = ""
        if HAS_TRACKER and self.tracking_cfg.enabled:
            try:
                self._tracking_db = TrackingDB(self.tracking_cfg.db_path)
                name = (self.tracking_cfg.campaign_name
                        or f"发送-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                self._tracking_campaign_id = new_campaign(
                    self._tracking_db, name)
            except Exception as _te:
                self._cb('log', f"[跟踪] 初始化失败: {_te}", "warn")
        self.failed = 0
        # FIX: 为共享可变状态引入线程锁
        self._counter_lock = threading.Lock()
        self._usage_lock = threading.Lock()
        self._blacklist_lock = threading.Lock()
        # P1: 创建持久连接池，复用已认证连接减少握手开销
        self._conn_pool = _SmtpConnPool(
            max_per_key=max(2, threads // 2),  # 每账号保留连接数与并发线程数成比例
            max_idle_sec=50.0,
            max_emails_per_conn=80,
        )
        # v5.6 新增:暂停/继续支持
        self._pause_flag = threading.Event()
        self._pause_flag.set()  # 初始为非暂停状态（set=可继续）
        # v5.6 新增:SMTP账号级黑名单（永久移除集合）
        self._smtp_blacklisted_set: set = set()
        self._smtp_blacklist_lock = threading.Lock()
        # v5.6 新增:可用SMTP账号列表（故障转移使用，运行时动态移除被拉黑账号）
        self._available_smtps: List[SmtpAccount] = []
        self._avail_smtp_lock = threading.Lock()

    def _cb(self, name, *args):
        """调用注册的回调函数"""
        cb = (self.callbacks or {}).get(name)
        if cb:
            cb(*args)

    def stop(self):
        self._stop_flag.set()
        self._stop_event.set()
        self._pause_flag.set()  # 确保暂停时也能响应停止
        # P1: 停止任务时清空连接池，关闭所有持久连接
        self._conn_pool.clear()

    def quit(self):
        """兼容原Qt QThread quit方法"""
        self._stop_event.set()

    def wait(self, timeout: int = 5000):
        """兼容原Qt QThread wait方法"""
        self.join(timeout=timeout / 1000.0)

    def pause(self):
        """暂停发送（v5.6新增）。"""
        self._pause_flag.clear()

    def resume(self):
        """恢复发送（v5.6新增）。"""
        self._pause_flag.set()

    def is_paused(self) -> bool:
        return not self._pause_flag.is_set()

    def _get_next_smtp(self, exclude_keys: set) -> Optional[SmtpAccount]:
        """从可用列表中获取下一个未拉黑且未在exclude_keys中的SMTP账号（v5.6故障转移）。"""
        with self._avail_smtp_lock:
            candidates = [
                s for s in self._available_smtps
                if s.username not in self._smtp_blacklisted_set
                and s.username not in exclude_keys
            ]
        if not candidates:
            return None
        return random.choice(candidates)

    def _blacklist_smtp(self, acct: SmtpAccount) -> None:
        """永久拉黑SMTP账号:从可用列表移除并写入黑名单文件（v5.6新增）。"""
        key = acct.username
        with self._smtp_blacklist_lock:
            if key in self._smtp_blacklisted_set:
                return
            self._smtp_blacklisted_set.add(key)
        # 从可用列表移除
        with self._avail_smtp_lock:
            self._available_smtps = [
                s for s in self._available_smtps if s.username != key
            ]
        # 写入黑名单文件
        try:
            bl_dir = get_output_dir(MODULE_NAME)
            bl_file = bl_dir / "smtp_blacklist.txt"
            line = (f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    f" | BLACKLISTED | {acct.raw_line or acct.username}\n")
            with open(bl_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
        # 发出回调通知UI
        self._cb('smtp_blacklisted', acct.raw_line or acct.username)

    def run(self):
        total = len(self.tasks)
        done = 0
        account_usage: Dict[str, int] = {}

        # v5.6: 初始化可用SMTP列表（从所有任务中提取唯一账号）
        seen_keys: set = set()
        for t in self.tasks:
            k = t.account.username
            if k not in seen_keys:
                seen_keys.add(k)
                self._available_smtps.append(t.account)

        # v5.6: 收件人黑名单（从任务列表中提取，防重发）
        recipient_blacklist_set: set = set()
        try:
            bl_dir = get_output_dir(MODULE_NAME)
            rcpt_bl_file = bl_dir / "recipient_blacklist.txt"
            if rcpt_bl_file.exists():
                for line in rcpt_bl_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        recipient_blacklist_set.add(line.split("|")[0].strip())
        except Exception:
            pass

        # 代理耗尽等待参数
        PROXY_WAIT_MAX = 5
        PROXY_WAIT_SEC = 15
        # v5.6: 每个收件人最多尝试3个不同SMTP服务器
        MAX_SMTP_TRIES_PER_RECIPIENT = 3

        def _send_with_account(task: SendTask, acct: SmtpAccount) -> SendResult:
            """用指定SMTP账号发送一封邮件，返回SendResult。内部含代理重试逻辑。"""
            t0 = time.time()
            last_err = ""
            proxy_waits = 0
            smtp_domain = acct.host.lower()
            country_hint = _guess_smtp_country(smtp_domain)
            _full_pool = self.proxy_manager.get_alive_filtered(
                country=country_hint, require_clean=True, max_latency_ms=5000)
            if not _full_pool:
                raise ProxyExhaustedError("代理池无可用代理")
            _bound_proxy: Optional[ProxyEntry] = _pick_bound_proxy(_full_pool)

            task_copy = copy.copy(task)
            task_copy.account = acct

            for attempt in range(1, self.retry + 1):
                if self._stop_flag.is_set():
                    return None  # type: ignore

                # 暂停检测
                while not self._pause_flag.wait(timeout=0.5):
                    if self._stop_flag.is_set():
                        return None  # type: ignore

                if _bound_proxy is None or not _bound_proxy.alive:
                    _full_pool = self.proxy_manager.get_alive_filtered(
                        country=country_hint, require_clean=True, max_latency_ms=5000)
                    if not _full_pool:
                        proxy_waits += 1
                        if proxy_waits <= PROXY_WAIT_MAX:
                            jitter = random.uniform(0, 5)
                            self._stop_flag.wait(timeout=PROXY_WAIT_SEC + jitter)
                            if self._stop_flag.is_set():
                                return None  # type: ignore
                            continue
                        return SendResult(
                            task=task_copy, success=False,
                            message=f"代理池耗尽(已等待{proxy_waits}次)",
                            elapsed_ms=(time.time() - t0) * 1000,
                            error_type="retryable",
                            send_time=datetime.now().strftime("%H:%M:%S"),
                            smtp_used=acct)
                    _bound_proxy = _pick_bound_proxy(_full_pool)

                try:
                    msg, proxy_str = _send_one(
                        task_copy, [_bound_proxy], self.timeout, self.dry_run,
                        conn_pool=self._conn_pool)
                    elapsed = (time.time() - t0) * 1000
                    with self._usage_lock:
                        # BUG-2 FIX: 批量密送任务按实际收件人数计入配额
                        _sent_count = len(task_copy.bcc_recipients) if task_copy.bcc_recipients else 1
                        account_usage[acct.username] = account_usage.get(acct.username, 0) + _sent_count
                    _r_tid = task_copy.tracking_id
                    if (HAS_TRACKER and self.tracking_cfg.enabled and _r_tid
                            and self._tracking_db is not None):
                        try:
                            self._tracking_db.record_send(
                                _r_tid,
                                task_copy.campaign_id or self._tracking_campaign_id,
                                task_copy.recipient, task_copy.subject,
                                smtp_host=acct.host,
                                from_addr=acct.username)
                        except Exception:
                            pass
                    return SendResult(
                        task=task_copy, success=True, message=msg,
                        elapsed_ms=elapsed, proxy_used=proxy_str,
                        tracking_id=_r_tid,
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=acct)
                except (AuthFailedError, AccountDisabledError) as e:
                    # SMTP账号被拉黑，立即永久移除
                    self._blacklist_smtp(acct)
                    raise  # 向上抛出，让调用方知道此账号不可用
                except PortBlockedError as e:
                    return SendResult(
                        task=task_copy, success=False,
                        message=f"端口封锁: {e}",
                        elapsed_ms=(time.time() - t0) * 1000,
                        error_type="retryable",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=acct)
                except ProxyExhaustedError as e:
                    last_err = str(e)
                    return SendResult(
                        task=task_copy, success=False,
                        message=f"代理耗尽: {last_err}",
                        elapsed_ms=(time.time() - t0) * 1000,
                        error_type="retryable",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=acct)
                except PermanentError as e:
                    return SendResult(
                        task=task_copy, success=False,
                        message=str(e),
                        elapsed_ms=(time.time() - t0) * 1000,
                        error_type="permanent",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=acct)
                except ManualInterventionError as e:
                    return SendResult(
                        task=task_copy, success=False,
                        message=str(e),
                        elapsed_ms=(time.time() - t0) * 1000,
                        error_type="manual",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=acct)
                except RetryableError as e:
                    last_err = str(e)
                    if attempt < self.retry:
                        self._stop_flag.wait(timeout=2 + random.uniform(0, 3))
                        if self._stop_flag.is_set():
                            return None  # type: ignore
                        continue
                except Exception as e:
                    last_err = str(e)
                    if attempt < self.retry:
                        self._stop_flag.wait(timeout=2 + random.uniform(0, 3))
                        if self._stop_flag.is_set():
                            return None  # type: ignore
                        continue
            return SendResult(
                task=task_copy, success=False, message=last_err,
                elapsed_ms=(time.time() - t0) * 1000, error_type="retryable",
                send_time=datetime.now().strftime("%H:%M:%S"),
                smtp_used=acct)

        def process_task(task: SendTask) -> Optional[SendResult]:
            if self._stop_flag.is_set():
                return None

            # 暂停检测
            while not self._pause_flag.wait(timeout=0.5):
                if self._stop_flag.is_set():
                    return None

            # 收件人黑名单检测
            # BUG-3 FIX: 批量密送模式下，过滤掉 bcc_recipients 中所有黑名单地址
            if task.bcc_mode and task.bcc_recipients:
                clean_batch = [r for r in task.bcc_recipients
                               if r not in recipient_blacklist_set]
                if not clean_batch:
                    # 整批全部在黑名单，跳过
                    return SendResult(
                        task=task, success=False,
                        message="整批收件人均在黑名单中(跳过)",
                        error_type="permanent",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=task.account)
                if len(clean_batch) < len(task.bcc_recipients):
                    # 部分在黑名单，更新批次并记录日志
                    removed = len(task.bcc_recipients) - len(clean_batch)
                    task = copy.copy(task)
                    task.bcc_recipients = clean_batch
                    task.recipient = clean_batch[0]
            elif task.recipient in recipient_blacklist_set:
                return SendResult(
                    task=task, success=False,
                    message="收件人在黑名单中(跳过)",
                    error_type="permanent",
                    send_time=datetime.now().strftime("%H:%M:%S"),
                    smtp_used=task.account)

            # 账号用量检测
            acct_key = task.account.username
            with self._usage_lock:
                usage = account_usage.get(acct_key, 0)
                if usage >= self.max_per_account:
                    return SendResult(
                        task=task, success=False,
                        message=f"超出单账号上限({self.max_per_account})",
                        error_type="permanent",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=task.account)

            # 渲染模板
            task.body_html = self.template_engine.render(
                self.body_template, recipient=task.recipient)
            task.subject = self.template_engine.render(
                self.subject_template, recipient=task.recipient)
            task.comment_clean = self.comment_clean

            if self.spam_cfg.enabled:
                task.body_html = replace_spam_words_with_homoglyphs(
                    task.body_html, self.spam_cfg.rate)
                task.subject = replace_spam_words_with_homoglyphs(
                    task.subject, self.spam_cfg.rate)

            if self.hidden_cfg.enabled and self.hidden_cfg.texts:
                task.body_html = inject_hidden_text(
                    task.body_html, self.hidden_cfg.texts,
                    count=self.hidden_cfg.count, position=self.hidden_cfg.position)

            if (HAS_TRACKER and self.tracking_cfg.enabled
                    and task.body_format == "html"):
                _tid = generate_tracking_id()
                task.body_html = prepare_tracked_html(
                    task.body_html, _tid,
                    self.tracking_cfg.base_url,
                    track_clicks=self.tracking_cfg.track_clicks,
                    masq_domain=self.tracking_cfg.masq_domain)
                task.tracking_id = _tid
                task.campaign_id = self._tracking_campaign_id

            target_domain = task.recipient.split("@")[-1] if "@" in task.recipient else "example.com"
            task = EvasionEngine.apply(task, self.evasion_cfg, target_domain)

            # v5.6: 收件人级别SMTP故障转移
            # 策略:当前SMTP失败 → 换下一个可用SMTP重试 → 最多尝试3个不同SMTP
            tried_keys: set = set()  # 本收件人已尝试过的SMTP账号key
            last_result: Optional[SendResult] = None

            # 第一个账号:使用任务原始分配的账号
            first_acct = task.account
            if first_acct.username not in self._smtp_blacklisted_set:
                tried_keys.add(first_acct.username)
                try:
                    result = _send_with_account(task, first_acct)
                    if result is None:
                        return None
                    if result.success:
                        return result
                    last_result = result
                except (AuthFailedError, AccountDisabledError) as e:
                    # 账号已被_blacklist_smtp()处理，继续故障转移
                    last_result = SendResult(
                        task=task, success=False, message=str(e),
                        elapsed_ms=0, error_type="permanent",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=first_acct)

            # 故障转移:尝试其他可用SMTP账号（最多凑满3个不同账号）
            while len(tried_keys) < MAX_SMTP_TRIES_PER_RECIPIENT:
                if self._stop_flag.is_set():
                    return None
                next_acct = self._get_next_smtp(tried_keys)
                if next_acct is None:
                    break  # 没有更多可用SMTP
                tried_keys.add(next_acct.username)
                try:
                    result = _send_with_account(task, next_acct)
                    if result is None:
                        return None
                    if result.success:
                        return result
                    last_result = result
                except (AuthFailedError, AccountDisabledError) as e:
                    last_result = SendResult(
                        task=task, success=False, message=str(e),
                        elapsed_ms=0, error_type="permanent",
                        send_time=datetime.now().strftime("%H:%M:%S"),
                        smtp_used=next_acct)

            # 三个SMTP均失败 → 最终失败，加入收件人黑名单
            try:
                bl_dir = get_output_dir(MODULE_NAME)
                rcpt_bl_file = bl_dir / "recipient_blacklist.txt"
                with open(rcpt_bl_file, "a", encoding="utf-8") as f:
                    f.write(f"{task.recipient} | FINAL_FAILED | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | tried={','.join(tried_keys)}\n")
                recipient_blacklist_set.add(task.recipient)
            except Exception:
                pass

            if last_result is not None:
                last_result.error_type = last_result.error_type or "retryable"
                return last_result

            return SendResult(
                task=task, success=False, message="所有SMTP均失败",
                elapsed_ms=0, error_type="retryable",
                send_time=datetime.now().strftime("%H:%M:%S"),
                smtp_used=task.account)

        # ── 批量缓冲参数 ───
        BATCH_SIZE = max(20, self.threads // 2)
        BATCH_INTERVAL = 0.3
        result_buf: List[SendResult] = []
        log_buf: List[tuple] = []
        last_flush = time.time()
        buf_lock = threading.Lock()

        def flush_buf(force: bool = False) -> None:
            nonlocal last_flush, result_buf, log_buf, done
            with buf_lock:
                if not result_buf and not log_buf:
                    return
                now = time.time()
                if not force and len(result_buf) < BATCH_SIZE and (now - last_flush) < BATCH_INTERVAL:
                    return
                if result_buf:
                    batch = list(result_buf)
                    result_buf.clear()
                    self._cb('batch_results', batch)
                if log_buf:
                    logs = list(log_buf)
                    log_buf.clear()
                    self._cb('batch_logs', logs)
                self._cb('progress', done, self._progress_total, self.success, self.failed)
                last_flush = now

        def handle_result(f) -> None:
            nonlocal done
            if self._stop_flag.is_set():
                return
            try:
                r = f.result()
            except Exception:
                return
            if r is None:
                return

            expanded = expand_bcc_success_to_per_recipient(r)
            n_done = len(expanded) if (r.success and len(expanded) > 1) else 1

            with self._counter_lock:
                done += n_done
                if r.success:
                    self.success += len(expanded)
                else:
                    self.failed += 1

            if r.success:
                if r.task.bcc_mode and r.task.bcc_recipients:
                    self._cb('recipients_sent_ok', list(r.task.bcc_recipients))
                else:
                    self._cb('recipients_sent_ok', [r.task.recipient])

            log_msgs: List[Tuple[str, str]] = []
            result_rows: List[SendResult] = []
            for row in expanded:
                if row.success:
                    level, icon = "success", "✓"
                elif row.error_type == "permanent":
                    level, icon = "error", "✗"
                elif row.error_type == "manual":
                    level, icon = "warn", "⚠"
                else:
                    level, icon = "retry", "↺"
                smtp_acct = row.smtp_used or row.task.account
                proxy_info = f" [{row.proxy_used}]" if row.proxy_used else ""
                log_msg = (
                    f"{icon} [{smtp_acct.host}:{smtp_acct.port}]{proxy_info} "
                    f"→ {row.task.recipient} | {row.message} ({row.elapsed_ms:.0f}ms)")
                log_msgs.append((log_msg, level))
                result_rows.append(row)

            with buf_lock:
                result_buf.extend(result_rows)
                log_buf.extend(log_msgs)
            flush_buf()

        pool = ThreadPoolExecutor(max_workers=self.threads)
        pending_futures = []
        submitted = 0

        try:
            for task in self.tasks:
                if self._stop_flag.is_set():
                    break
                # 暂停检测（提交循环中也要响应暂停）
                while not self._pause_flag.wait(timeout=0.5):
                    if self._stop_flag.is_set():
                        break
                if self._stop_flag.is_set():
                    break
                f = pool.submit(process_task, task)
                f.add_done_callback(handle_result)
                pending_futures.append(f)
                submitted += 1

                if self.delay > 0:
                    self._stop_flag.wait(timeout=self.delay)

            for f in pending_futures:
                if self._stop_flag.is_set():
                    break
                f.result()
        except Exception as e:
            self._cb('log', f"Worker异常: {e}", "error")
        finally:
            pool.shutdown(wait=False)

        flush_buf(force=True)
        self._conn_pool.clear()
        end_tag = "stopped" if self._stop_flag.is_set() else "complete"
        self._cb('finished', self._progress_total, self.success, self.failed, end_tag)