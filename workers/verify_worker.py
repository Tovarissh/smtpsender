# -*- coding: utf-8 -*-
"""SMTP账号验证Worker：使用threading.Thread异步验证账号有效性"""
from __future__ import annotations
import smtplib
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from ..core.models import SmtpAccount
from ..core.smtp_conn import _build_smtp_server

import random


class _SmtpVerifyWorker(threading.Thread):
    """FIX-②: 在独立 thread 中执行 SMTP 账号批量验证，不阻塞 UI 主线程。
    完成后通过 callback 回调将结果投递回主线程，替代信号模式。
    """

    def __init__(self, smtps: List[SmtpAccount],
                 proxy_manager: "ApiProxyManager",
                 signals: "Signals",
                 callback: Optional[Callable[[List[str], int, int], None]] = None):
        super().__init__()
        self.smtps = smtps
        self.proxy_manager = proxy_manager
        self.signals = signals
        self.callback = callback

    def run(self) -> None:
        valid_lines: List[str] = []
        invalid_count = 0
        total = len(self.smtps)
        for idx, acct in enumerate(self.smtps):
            if idx % 5 == 0:
                self.signals.log.emit(f"验证进度: {idx}/{total}", "info")
            alive_proxies = self.proxy_manager.get_alive()
            if not alive_proxies:
                # 无可用代理，保留该账号
                valid_lines.append(acct.raw_line)
                continue
            proxy = random.choice(alive_proxies)
            enc_order = (
                # WARN-5 FIX: 与 _send_one 保持一致:465 只用 ssl，587 只用 starttls，其他端口明文优先
                ["ssl"] if acct.port == 465
                else ["starttls"] if acct.port == 587
                else ["plain", "starttls"]
            )
            verified = False
            auth_failed = False
            for enc in enc_order:
                server = None
                sock = None
                try:
                    sock = _make_proxy_socket(proxy, acct.host, acct.port, 15)
                    server = _build_smtp_server(acct, enc, sock, 15)
                    _try_login_with_fallback(server, acct.username, acct.password, enc)
                    try:
                        server.quit()
                    except Exception:
                        pass
                    verified = True
                    break
                except (AuthFailedError, AccountDisabledError):
                    _safe_close(server, sock)
                    auth_failed = True
                    break
                except smtplib.SMTPAuthenticationError:
                    _safe_close(server, sock)
                    auth_failed = True
                    break
                except Exception:
                    _safe_close(server, sock)
                    continue
            if verified:
                valid_lines.append(acct.raw_line)
            elif auth_failed:
                invalid_count += 1
                self.signals.log.emit(
                    f"<span style='color:red'>✗ {acct.username} — 认证失败，已剔除</span>",
                    "error")
            else:
                # 连接失败（可能是代理问题），保留账号
                valid_lines.append(acct.raw_line)
        # 通过回调返回结果
        if self.callback:
            self.callback(valid_lines, invalid_count, total)