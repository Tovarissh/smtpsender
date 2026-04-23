# -*- coding: utf-8 -*-
"""数据模型：错误分类、所有dataclass数据类"""
from __future__ import annotations
import copy
import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# 错误分类
# ═══════════════════════════════════════════════════════════════════════════════

class RetryableError(Exception):
    pass

class PermanentError(Exception):
    pass

class ManualInterventionError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# 数据类
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SmtpAccount:
    host: str
    port: int
    username: str
    password: str
    raw_line: str = ""
    send_count: int = 0
    blacklisted: bool = False

@dataclass
class ProxyEntry:
    host: str
    port: int
    username: str = ""
    password: str = ""
    protocol: str = "socks5"
    alive: bool = True
    last_test: float = 0.0
    # 预检测字段（从代理端 API 获取）
    country_code: str = ""     # ISO 3166-1 alpha-2 国家代码
    rbl_count: int = 0          # RBL 黑名单命中数
    latency_ms: float = 0.0     # TCP 延迟（毫秒）
    precheck_time: float = 0.0  # 上次检测时间戳
    # 上游隧道状态字段
    tunnel_idx: int = -1        # 隧道端口索引（用于 /proxy/{idx} 查询）
    tunnel_active: int = 0      # 当前活跃连接数

    def __str__(self):
        if self.username:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"

    def is_rbl_clean(self) -> bool:
        return self.rbl_count == 0

    def is_low_latency(self, threshold_ms: float = 5000) -> bool:
        return self.latency_ms > 0 and self.latency_ms <= threshold_ms

@dataclass
class ApiProxyConfig:
    url: str = ""
    username: str = ""
    password: str = ""
    protocol: str = "socks5"
    order: str = "random"
    fetch_count: int = 280000
    refresh_min: float = 10.0
    auto_remove_dead: bool = True
    pause_on_fail: bool = False
    enabled: bool = False
    # 上游隧道代理模式（对接 proxysmtp 本地 SOCKS5 端口池）
    tunnel_mode: bool = False
    tunnel_api_base: str = ""  # 自动推断，如 http://127.0.0.1:5100

@dataclass
class EvasionConfig:
    technique: str = "none"
    thread_sender_name: str = "HR Department"
    thread_topic: str = "Annual Benefits Enrollment"
    thread_prefix: str = "Re: "
    enc_b64_part: str = "Action Required: "
    enc_qp_part: str = "Review Pending Invoice"
    ambiguity_user: str = "admin"
    ambiguity_domain: str = ""
    ambiguity_label: str = "IT Support: Action Required"
    unicode_display_name: str = ""
    # TC-3.2: 发件人伪装 (Envelope/Header From 分离)
    spoof_from_address: str = ""   # 伪造的 From 地址，如 hr@gmail.com
    spoof_from_name: str = ""      # 伪造的显示名，如 HR Department

@dataclass
class HiddenTextConfig:
    enabled: bool = False
    count: int = 5
    position: str = "random"
    texts: List[str] = field(default_factory=list)

@dataclass
class SpamWordConfig:
    enabled: bool = False
    rate: float = 0.4

@dataclass
class SendTask:
    account: SmtpAccount
    recipient: str
    subject: str
    body_html: str
    from_name: str = ""
    body_format: str = "html"  # "html" 或 "plain"
    extra_headers: Dict[str, str] = field(default_factory=dict)
    # TC-3.2: 伪造的 From 地址（与 MAIL FROM 分离）
    spoof_from_addr: str = ""  # 如果设置，From 头使用此地址而非真实 SMTP 账号
    # ── BCC 密送群发字段 ──────────────────────────────────────────────────────
    bcc_mode: bool = False          # 是否启用密送模式
    display_to: str = ""            # To: Header 展示地址（虚拟/通用收件人，留空=undisclosed-recipients:;）
    bcc_group_id: str = ""          # 同批群发的 Message-ID 锚点（线程追踪，可选）
    bcc_recipients: List[str] = field(default_factory=list)  # BCC批量群发：本次RCPT TO的完整收件人列表（空=仅发recipient）
    # ── HTML 注释清理 ─────────────────────────────────────────────────────────
    comment_clean: bool = True      # FIX-④: 发送前是否清理 HTML 注释（对应 UI comment_clean_cb）
    # ── 跟踪字段 ─────────────────────────────────────────────────────────────
    tracking_id:  str = ""   # 本条邮件的唯一跟踪 ID（由 SenderWorker 在发送前填充）
    campaign_id:  str = ""   # 所属活动 ID

@dataclass
class TrackingConfig:
    """邮件跟踪配置
    INFO-2 说明:此类使用 @dataclass + @property 混合写法。
    @property 字段（base_url）不会出现在 __init__ 参数中，
    也不会被 dataclasses.asdict() 序列化。配置导出应直接读取 UI 字段。
    """
    enabled:        bool = False
    track_clicks:   bool = True          # 是否替换链接为跟踪跳转链接
    tracker_host:   str  = "127.0.0.1"  # 跟踪服务器本地监听地址
    tracker_port:   int  = 8899          # 跟踪服务器端口
    public_base_url: str = ""            # 对外地址（注入邮件的URL前缀，留空=同监听地址）
    masq_domain:    str  = ""            # URL 伪装域名（@-syntax），如 mail.google.com
                                         # 留空=不伪装;非空时自动升级为 https
    db_path:        str  = "tracker.db" # SQLite 数据库路径
    campaign_name:  str  = ""           # 活动名称（空则自动生成）

    @property
    def base_url(self) -> str:
        """注入邮件中的 URL 前缀（优先使用 public_base_url）"""
        if self.public_base_url:
            return self.public_base_url.rstrip("/")
        return f"http://{self.tracker_host}:{self.tracker_port}"

@dataclass
class SendResult:
    task: SendTask
    success: bool
    message: str
    elapsed_ms: float = 0.0
    error_type: str = ""
    proxy_used: str = ""
    tracking_id: str = ""   # 跟踪 ID（成功发送后填充）
    send_time: str = ""     # 发送时间 HH:MM:SS（v5.6 新增）
    smtp_used: Optional["SmtpAccount"] = None  # 实际成功的SMTP账号（v5.6 故障转移记录）


def expand_bcc_success_to_per_recipient(r: SendResult) -> List[SendResult]:
    """批量密送成功时拆成每人一条结果，便于结果表逐行展示。"""
    if not r.success:
        return [r]
    t = r.task
    if not (t.bcc_mode and t.bcc_recipients and len(t.bcc_recipients) > 1):
        return [r]
    out: List[SendResult] = []
    for email in t.bcc_recipients:
        nt = copy.copy(t)
        nt.recipient = email
        nt.bcc_recipients = [email]
        out.append(
            SendResult(
                task=nt,
                success=True,
                message=r.message,
                elapsed_ms=r.elapsed_ms,
                error_type="",
                proxy_used=r.proxy_used,
                tracking_id=r.tracking_id,
                send_time=r.send_time,
                smtp_used=r.smtp_used,
            )
        )
    return out