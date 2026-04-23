# -*- coding: utf-8 -*-
"""SMTP持久连接池：复用连接减少据手开销"""
from __future__ import annotations
import smtplib
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from .models import SmtpAccount
from .smtp_conn import _build_smtp_server
from .send_logic import _safe_close

# ═══════════════════════════════════════════════════════════════════════════════
# P1: SMTP 持久连接池（握手速度最大优化）
# ═══════════════════════════════════════════════════════════════════════════════

class _SmtpConnPool:
    """SMTP 持久连接池:每个账号+加密方式维护若干已认证连接，发送时直接复用。

    原理:SMTP 握手（TCP+SSL+EHLO+AUTH）通常耗时 500ms–2s，批量发件时每封
    邮件都重建连接是最大的性能瓶颈。持久连接池在首次握手成功后保留连接，
    后续邮件直接调用 server.sendmail()，跳过全部握手阶段。

    线程安全:所有公开方法通过内部锁保护，可在多线程 ThreadPoolExecutor 中安全使用。

    池容量策略:
    - max_per_key:每个 (username|host:port|enc) 最多保留的连接数，默认 4
    - max_idle_sec:连接最长空闲时间，超时后自动丢弃，默认 50s
    - max_emails_per_conn:单条连接最多发送邮件数，防止触发服务器单连接限额，默认 80
    """

    def __init__(self,
                 max_per_key: int = 4,
                 max_idle_sec: float = 50.0,
                 max_emails_per_conn: int = 80):
        self._lock = threading.Lock()
        # key = "username|host:port|enc"
        # value = list of [server, sock, proxy_str, last_used_ts, emails_sent]
        self._pool: Dict[str, list] = {}
        self.max_per_key = max_per_key
        self.max_idle_sec = max_idle_sec
        self.max_emails_per_conn = max_emails_per_conn

    def _make_key(self, username: str, host: str, port: int, enc: str) -> str:
        return f"{username}|{host}:{port}|{enc}"

    def acquire(self, username: str, host: str, port: int, enc: str
                ) -> Optional[Tuple[smtplib.SMTP, Optional[object], str, int]]:
        """尝试取出一条可用的已认证连接。

        Returns:
            (server, sock, proxy_str, prior_emails_sent) 若有空闲连接；否则 None。
            prior_emails_sent 为该连接已累计发送封数，归还池时须传入 prior+本次封数。
        """
        key = self._make_key(username, host, port, enc)
        now = time.monotonic()
        with self._lock:
            entries = self._pool.get(key, [])
            # 从末尾取最近使用的连接（热端弹出）
            while entries:
                server, sock, proxy_str, last_ts, emails_sent = entries.pop()
                age = now - last_ts
                if age > self.max_idle_sec:
                    # 连接超时，关闭丢弃
                    _safe_close(server, sock)
                    continue
                if emails_sent >= self.max_emails_per_conn:
                    # 超过单连接邮件上限，关闭丢弃
                    _safe_close(server, sock)
                    continue
                # 快速探活:发一个 NOOP，确认连接仍存活
                try:
                    code, _ = server.noop()
                    if code == 250:
                        return server, sock, proxy_str, emails_sent
                    else:
                        _safe_close(server, sock)
                        continue
                except Exception:
                    _safe_close(server, sock)
                    continue
        return None

    def release(self, username: str, host: str, port: int, enc: str,
                server: smtplib.SMTP, sock: Optional[object],
                proxy_str: str, emails_sent: int = 1) -> None:
        """将用完的连接归还池中，供后续邮件复用。

        emails_sent: 该连接上的累计已发送封数（非增量）。新握手首次入池传 1；
        从 acquire 取出时传 prior+1，以便 max_emails_per_conn 正确生效。
        """
        key = self._make_key(username, host, port, enc)
        with self._lock:
            entries = self._pool.setdefault(key, [])
            if len(entries) < self.max_per_key:
                entries.append([server, sock, proxy_str,
                                 time.monotonic(), emails_sent])
            else:
                # 池已满，关闭多余连接
                _safe_close(server, sock)

    def invalidate(self, username: str, host: str, port: int, enc: str = "") -> None:
        """连接不可用时（断开/认证失效），清空该账号对应的所有连接。"""
        with self._lock:
            prefix = f"{username}|{host}:{port}|" if not enc else \
                     self._make_key(username, host, port, enc)
            keys_to_del = [k for k in self._pool
                           if (k == prefix or k.startswith(prefix))]
            for k in keys_to_del:
                for entry in self._pool.pop(k, []):
                    _safe_close(entry[0], entry[1])

    def clear(self) -> None:
        """关闭并清空池中所有连接（程序退出时调用）。"""
        with self._lock:
            for entries in self._pool.values():
                for entry in entries:
                    _safe_close(entry[0], entry[1])
            self._pool.clear()

    @property
    def stats(self) -> Dict[str, int]:
        """返回当前连接池统计:各 key 的空闲连接数。"""
        with self._lock:
            return {k: len(v) for k, v in self._pool.items() if v}

