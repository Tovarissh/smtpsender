# -*- coding: utf-8 -*-
"""SMTP连接层：代理socket建立、SMTP服务器构建、邮件发送执行"""
from __future__ import annotations
import re
import smtplib
import socket
import ssl
import time
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from typing import Any, Dict, List, Optional, Tuple
try:
    import socks
except ImportError:
    socks = None
try:
    from PyQt5.QtCore import QObject, pyqtSignal
except ImportError:
    QObject = object
    def pyqtSignal(*args, **kwargs):
        return property(lambda self: None)
from .models import SmtpAccount, ProxyEntry, SendTask, TrackingConfig
from .utils import _make_shared_ssl_ctx, _random_helo_domain, random_msgid, jitter_date, random_hex, _SHARED_SSL_CTX


class Signals(QObject):
    progress = pyqtSignal(int, int, int, int)
    result_row = pyqtSignal(object)          # 单条（保留兼容）
    batch_results = pyqtSignal(list)          # 批量结果
    batch_logs = pyqtSignal(list)             # 批量日志 [(msg, level), ...]
    log = pyqtSignal(str, str)
    finished = pyqtSignal(int, int, int, str)  # total_units, success, failed, end_tag
    recipients_sent_ok = pyqtSignal(list)     # 密送整批成功后的收件人列表，供 UI 从列表移除
    smtp_blacklisted = pyqtSignal(str)        # SMTP账号被拉黑通知 (raw_line)


class RetryableError(Exception):
    pass

class PermanentError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# SOCKS5 代理 SMTP 连接（含 HELO 修复）
# ═══════════════════════════════════════════════════════════════════════════════

def _make_proxy_socket(entry: ProxyEntry, target_host: str,
                       target_port: int, timeout: int) -> socket.socket:
    """FIX-v3: 细分代理层错误类型，区分代理本身问题 vs ISP 端口封锁 vs 目标不可达。

    异常分类:
    - socks.ProxyConnectionError(含 SOCKS5 auth failed) → 代理本身故障，应标记代理死亡
    - socket.timeout 通过代理连接目标 → 可能是 ISP 封端口，不应标记代理死亡
    - ConnectionRefused → 目标服务器拒绝，不是代理问题
    """
    ptype_map = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4,
                 "http": socks.HTTP, "https": socks.HTTP}
    ptype = ptype_map.get(entry.protocol.lower(), socks.SOCKS5)
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    sock.set_proxy(ptype, entry.host, entry.port,
                   username=entry.username or None,
                   password=entry.password or None, rdns=True)
    sock.settimeout(timeout)
    try:
        sock.connect((target_host, target_port))
    except socks.ProxyConnectionError as e:
        # 代理本身连接失败（含 SOCKS5 auth failed）— 代理有问题
        sock.close()
        raise RetryableError(f"\x00PROXY_DEAD\x00代理连接失败: {entry.host}:{entry.port} [{e}]")
    except socks.GeneralProxyError as e:
        sock.close()
        err_str = str(e).lower()
        if "timed out" in err_str:
            # 通过代理连接目标超时 — 可能是 ISP 封端口，不应标记代理死亡
            raise RetryableError(f"\x00PORT_TIMEOUT\x00代理出口超时: {target_host}:{target_port} via {entry.host}")
        elif "connection closed" in err_str:
            # 代理连接被关闭 — 可能是代理不稳定
            raise RetryableError(f"\x00PROXY_UNSTABLE\x00代理连接被关闭: {entry.host}:{entry.port}")
        else:
            raise RetryableError(f"\x00PROXY_DEAD\x00代理错误: {entry.host}:{entry.port} [{e}]")
    except socket.timeout:
        sock.close()
        raise RetryableError(f"\x00PORT_TIMEOUT\x00连接超时: {target_host}:{target_port} via {entry.host}")
    except ConnectionRefusedError:
        sock.close()
        raise RetryableError(f"\x00TARGET_REFUSED\x00目标拒绝连接: {target_host}:{target_port}")
    except OSError as e:
        sock.close()
        raise RetryableError(f"网络连接失败: {entry.host}:{entry.port} -> {target_host}:{target_port} [{e}]")
    return sock


def _attach_socket_to_smtp(server: smtplib.SMTP, sock: socket.socket) -> None:
    """FIX-⑨: 将裸 socket 挂载到 SMTP 对象，兼容 Python 3.8–3.13+ 各版本私有属性变化。"""
    server.sock = sock
    # Python 3.12+ 中 server.file 可能已移除，使用 hasattr 安全检查
    if hasattr(server, 'file') or True:   # 仍需赋值，供 getreply() 使用
        try:
            server.file = sock.makefile("rb")
        except AttributeError:
            pass
    server.helo_resp = None
    server._host = getattr(server, '_host', '')


def _build_smtp_server(acct: SmtpAccount, enc: str,
                       sock: socket.socket, timeout: int) -> smtplib.SMTP:
    """FIX-⑱: 重构三分支重复代码为公共流程，FIX-⑨ 安全封装私有属性访问。
    P2 OPT: 使用模块级共享 SSL Context，避免每次握手都重新创建 SSLContext 对象。

    公共流程: 挂载 socket → getreply → EHLO → (可选 STARTTLS/SSL 包装)
    """
    # P2: 使用预创建的共享 SSL Context（线程安全，只读）
    ctx = _SHARED_SSL_CTX

    sender_domain = ""
    if hasattr(acct, 'username') and '@' in (acct.username or ''):
        sender_domain = acct.username.split('@', 1)[1]
    helo_domain = _random_helo_domain(acct.host, sender_domain)
    server = smtplib.SMTP()
    server.timeout = timeout

    try:
        if enc == "ssl":
            # SSL 模式:先用 SSL 包装 socket，再挂载
            wrapped = ctx.wrap_socket(sock, server_hostname=acct.host)
            _attach_socket_to_smtp(server, wrapped)
            server._host = acct.host
        else:
            # STARTTLS / 明文:先挂载裸 socket
            _attach_socket_to_smtp(server, sock)
            server._host = acct.host

        # FIX-⑱: 公共流程 — getreply + EHLO
        code, msg = server.getreply()
        if code != 220:
            raise smtplib.SMTPConnectError(code, msg)
        ehlo_code, _ = server.ehlo(helo_domain)
        if ehlo_code >= 400:
            raise smtplib.SMTPHeloError(ehlo_code, _)

        # STARTTLS 升级（仅 starttls 模式）
        if enc == "starttls":
            if server.has_extn('starttls'):
                server.starttls(context=ctx)
                server.ehlo(helo_domain)
            # 服务器不支持 STARTTLS 时，继续使用明文连接

    except Exception:
        try:
            server.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        raise
    return server


def _do_send(server: smtplib.SMTP, task: SendTask) -> None:
    """FIX-v3: 邮件头构建深度优化 + TC-3.2 发件人伪装支持 + BCC 密送群发。
    1) MIME-Version 头（RFC 2045 强制要求）
    2) 纯文本备选部分，降低垃圾邮件评分
    3) Message-ID 使用发件人域名（或伪造域名）
    4) 去除 X-Mailer 头
    5) MAIL FROM 始终使用真实 SMTP 账号（确保 SPF PASS）
    6) TC-3.2: From 头支持伪造地址（与 MAIL FROM 分离）
    7) TC-3.2: 移除显式 Return-Path（由接收方 MTA 自动生成）
    8) 清理零宽字符和同形字的纯文本版本
    9) 可选 List-Unsubscribe 头（降低垃圾评分）
    10) BCC 密送群发:To: 填虚拟地址，RCPT TO 指向真实收件人，互不可见
    """
    t = task.account
    msg = MIMEMultipart("alternative")
    msg["MIME-Version"] = "1.0"
    msg["Subject"] = task.subject

    # ── TC-3.2: Envelope/Header From 分离 ──
    # 如果设置了伪造地址，From 头使用伪造地址;否则使用真实 SMTP 账号
    if task.spoof_from_addr:
        # TC-3.2 模式: From 头使用伪造地址
        from_addr = task.spoof_from_addr
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else t.host.replace("smtp.", "")
    else:
        # 标准模式: From 头使用真实 SMTP 账号
        from_addr = t.username
        from_domain = t.username.split("@")[-1] if "@" in t.username else t.host.replace("smtp.", "")

    if task.from_name:
        msg["From"] = formataddr((task.from_name, from_addr))
    else:
        msg["From"] = from_addr

    # ── BCC 密送群发:To: Header 与 RCPT TO 信封地址分离 ──────────────────────
    # BCC 原理:To: Header 仅影响邮件头显示，不影响实际投递路径（RCPT TO）
    # 每位真实收件人收到的邮件 To: 字段相同（虚拟地址），因此互相看不到彼此地址
    if task.bcc_mode:
        # BCC 模式:To: 填写虚拟展示地址，不泄露真实收件人
        display_to = task.display_to.strip() if task.display_to.strip() else "undisclosed-recipients:;"
        msg["To"] = display_to
        # 注意:故意不写 Bcc: Header（写了部分邮件客户端会展示该字段，保持隐蔽）
    else:
        # 标准模式:To: = 真实收件人（原有逻辑不变）
        msg["To"] = task.recipient

    # Message-ID 使用 From 头的域名（伪造或真实）
    msg["Message-ID"] = random_msgid(from_domain)
    msg["Date"] = jitter_date()

    # TC-3.2: 不再显式设置 Return-Path（由接收方 MTA 根据 MAIL FROM 自动生成）
    # 这样 Return-Path 会显示真实 SMTP 账号，与 SPF 对齐
    # 而 From 头可以是伪造地址，实现分离

    # List-Unsubscribe 头（降低垃圾评分，Gmail/Outlook 推荐）
    # 使用 From 头的域名保持一致性
    msg["List-Unsubscribe"] = f"<mailto:unsubscribe@{from_domain}?subject=unsubscribe>"
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    # 处理额外头（但跳过 X-Mailer）
    for k, v in task.extra_headers.items():
        if k.lower() == 'x-mailer':
            continue  # FIX: 跳过 X-Mailer
        if k in msg:
            del msg[k]
        msg[k] = v

    if task.body_format == "plain":
        # 纯文本模式:直接作为 text/plain 发送，不包装 HTML
        plain_body = task.body_html  # 此时 body_html 实际存储的是纯文本
        plain_body = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', plain_body)
        msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    else:
        # HTML 模式:multipart/alternative (plain + html)
        # FIX-④: 仅当 comment_clean=True 时清理注释（受 UI 开关控制）
        if task.comment_clean:
            body_clean = re.sub(r'<!--.*?-->', '', task.body_html, flags=re.DOTALL)
        else:
            body_clean = task.body_html
        # FIX-v2: 纯文本版本清理零宽字符和同形字，确保可读性
        plain_text = re.sub(r'<[^>]+>', '', body_clean).strip()
        plain_text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', plain_text)
        if plain_text:
            msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_clean, "html", "utf-8"))

    # ── 关键:RCPT TO 信封地址始终为真实收件人，不受 To: Header 影响 ──────────
    # MAIL FROM 始终使用真实 SMTP 账号（确保 SPF 对齐）
    # BCC 批量群发:server.sendmail(from, rcpt_list, msg) 中第二参数支持列表
    # 所有收件人在同一次 SMTP 会话中发送，To: Header 全部显示虚拟地址，互不可见
    if task.bcc_mode and task.bcc_recipients:
        # 批量密送模式：一次 SMTP DATA 投递整个批次
        rcpt_list = task.bcc_recipients
    else:
        rcpt_list = [task.recipient]
    server.sendmail(t.username, rcpt_list, msg.as_string())