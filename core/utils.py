# -*- coding: utf-8 -*-
"""工具函数：随机生成器、SSL缓存、HELO域名生成器"""
from __future__ import annotations
import base64
import random
import re
import socket
import ssl
import string
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Dict, Optional

def get_output_dir(module: str) -> Path:
    p = Path("output") / module
    p.mkdir(parents=True, exist_ok=True)
    return p

def random_hex(n: int = 6) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))

def random_letnum(min_len: int = 2, max_len: int = 5) -> str:
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

def random_msgid(domain: str = "mail.internal") -> str:
    return f"<{random_hex(12)}.{random_hex(8)}@{domain}>"

def jitter_date(base: Optional[datetime] = None, spread_sec: int = 120) -> str:
    """FIX-⑧: 仅允许过去时间抜动，禁止产生未来时间戳被严格 MTA 拒绝。"""
    dt = base or datetime.now(timezone.utc)
    # FIX: 只向过去抜动（-spread_sec 到 0），不产生未来时间
    dt += timedelta(seconds=random.randint(-spread_sec, 0))
    return formatdate(dt.timestamp(), localtime=False, usegmt=True)

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff"]
HOMOGLYPHS = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
              "c": "\u0441", "x": "\u0445"}

def inject_zero_width(text: str, density: float = 0.15) -> str:
    out = []
    for ch in text:
        out.append(ch)
        if random.random() < density:
            out.append(random.choice(ZERO_WIDTH_CHARS))
    return "".join(out)

def apply_homoglyphs(text: str, rate: float = 0.2) -> str:
    out = []
    for ch in text:
        if ch.lower() in HOMOGLYPHS and random.random() < rate:
            out.append(HOMOGLYPHS[ch.lower()])
        else:
            out.append(ch)
    return "".join(out)

def encode_mixed_subject(part_b64: str, part_qp: str) -> str:
    b64 = base64.b64encode(part_b64.encode("utf-8")).decode("ascii")
    qp_chars = []
    for ch in part_qp.encode("utf-8"):
        if 33 <= ch <= 126 and ch != 61:
            qp_chars.append(chr(ch))
        else:
            qp_chars.append(f"={ch:02X}")
    qp = "".join(qp_chars)
    tag = random_hex(6)
    return f"=?UTF-8?B?{b64}?= =?UTF-8?Q?{qp}?= [{tag}]"

def make_thread_index() -> str:
    raw = struct.pack(">Q", int(time.time() * 1e7)) + os.urandom(14)
    return base64.b64encode(raw[:22]).decode("ascii")


# ═══════════════════════════════════════════════════════════════════════════════
# ── 握手加速:模块级缓存（P2/P3/P4）────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _make_shared_ssl_ctx() -> ssl.SSLContext:
    """创建共享的宽松 SSL Context（跳过证书校验，适用于批量发件场景）。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode   = ssl.CERT_NONE
    # 关闭重协商降低握手往返次数（TLS 1.3 自动处理，TLS 1.2 兼容）
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    return ctx

# P2: SSL Context 仅在模块首次加载时创建一次，全所有线程共享（只读，线程安全）
_SHARED_SSL_CTX: ssl.SSLContext = _make_shared_ssl_ctx()
SHARED_SSL_CTX = _SHARED_SSL_CTX  # 兼容导出

# P3: 加密方式成功记忆表 { "host:port" → "ssl"|"starttls"|"plain" }
# 第一次成功后写入，后续直接用记忆的方式，省去无效尝试的握手开销
_ENC_CACHE: Dict[str, str] = {}
_ENC_CACHE_LOCK = threading.Lock()

# P4: AUTH 方法成功记忆表 { "host:port:enc" → "LOGIN"|"PLAIN"|"CRAM-MD5" }
# 记住每个服务器+加密组合下能成功的 AUTH 方法，直接跳过无效方法的降级
_AUTH_METHOD_CACHE: Dict[str, str] = {}
_AUTH_CACHE_LOCK = threading.Lock()

# ═══════════════════════════════════════════════════════════════════════════════
# HELO 域名生成器（修复 HELO 泄露）
# ═══════════════════════════════════════════════════════════════════════════════

_HELO_DOMAINS = [
    "mail.outlook.com", "smtp.google.com", "mta.yahoo.com",
    "relay.icloud.com", "mx.zoho.com", "mail.protonmail.ch",
    "smtp.fastmail.com", "mta.gmx.net", "relay.aol.com",
    "mail.comcast.net", "smtp.att.net", "mta.verizon.net",
    "relay.charter.net", "mail.cox.net", "smtp.earthlink.net",
]

def _random_helo_domain(smtp_host: str = "", sender_domain: str = "") -> str:
    """生成 HELO 域名，优先使用发件人域名以提升 SPF 一致性。

    FIX-v2: EHLO 域名应与发件人域名一致，而非使用 SMTP 服务器域名。
    这样收件方验证 EHLO 域名时不会因为不匹配而降低信任评分。
    优先级: 发件人域名 > SMTP 服务器域名 > 随机域名
    """
    # 优先使用发件人域名
    if sender_domain:
        parts = sender_domain.split(".")
        if len(parts) >= 2:
            prefixes = ["mail", "smtp", "mta", "out", "mx"]
            return f"{random.choice(prefixes)}.{sender_domain}"
    # 其次使用 SMTP 服务器域名
    if smtp_host:
        parts = smtp_host.split(".")
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
            prefixes = ["mail", "smtp", "mta", "relay", "mx"]
            return f"{random.choice(prefixes)}.{base}"
    return random.choice(_HELO_DOMAINS)


# ═══════════════════════════════════════════════════════════════════════════════
# 模板变量引擎
# ═══════════════════════════════════════════════════════════════════════════════

FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly",
    "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth",
    "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
]


