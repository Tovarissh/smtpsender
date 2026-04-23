# -*- coding: utf-8 -*-
"""核心发送逻辑：登录验证、代理筛选、单封邮件发送"""
from __future__ import annotations
import smtplib
import socket
import ssl
import time
import threading
from typing import Any, Dict, List, Optional, Tuple
from .models import (
    SmtpAccount, ProxyEntry, SendTask, SendResult, TrackingConfig,
    RetryableError, PermanentError, ManualInterventionError
)
from .utils import _make_shared_ssl_ctx, SHARED_SSL_CTX, _ENC_CACHE, _ENC_CACHE_LOCK, _AUTH_METHOD_CACHE, _AUTH_CACHE_LOCK
from .smtp_conn import _make_proxy_socket, _build_smtp_server, _do_send

class ProxyExhaustedError(RetryableError):
    """代理池耗尽 — 可恢复，等待代理池刷新后重试。"""
    pass


class PortBlockedError(RetryableError):
    """端口被 ISP 封锁 — 代理出口无法连接目标端口（常见于端口 25）。"""
    pass


class AuthFailedError(PermanentError):
    """认证失败 — 账号密码错误，应拉黑该SMTP账号。"""
    pass


class AccountDisabledError(PermanentError):
    """账号被禁用 — 服务器明确拒绝，应拉黑该SMTP账号。"""
    pass


def _try_login_with_fallback(server: smtplib.SMTP, username: str, password: str,
                             enc: str, cache_key: str = "") -> None:
    """尝试多种认证方式登录，失败时自动降级。

    FIX-v2: 彻底修复双重 AUTH 问题。
    P4 OPT: 接受 cache_key 参数。首次成功后将方法写入 _AUTH_METHOD_CACHE，
            后续调用直接跳过无效方法，省去降级往返。

    根因: server.login() 内部遍历 [CRAM-MD5, PLAIN, LOGIN]，如果某个方法
    在服务器端成功(235)但 Python 端解析异常，login() 会抛出非
    SMTPAuthenticationError 的异常，导致进入降级逻辑又发一次 AUTH。
    修复: 在异常处理中通过 NOOP 探测服务器是否已处于已认证状态，
    如果已认证则直接返回，避免重复 AUTH。
    """
    # ── 预注入凭证，确保 auth_* 回调可用 ──
    server.user = username
    server.password = password

    # P4: 若有缓存的成功方法，优先直接尝试，减少往返次数
    if cache_key:
        with _AUTH_CACHE_LOCK:
            cached_method = _AUTH_METHOD_CACHE.get(cache_key)
        if cached_method:
            try:
                if cached_method == 'LOGIN':
                    server.auth('LOGIN', server.auth_login, initial_response_ok=False)
                elif cached_method == 'PLAIN':
                    server.auth('PLAIN', server.auth_plain, initial_response_ok=False)
                elif cached_method == 'CRAM-MD5':
                    server.auth('CRAM-MD5', server.auth_cram_md5, initial_response_ok=False)
                elif cached_method == 'standard':
                    server.login(username, password)
                return  # 缓存命中成功
            except smtplib.SMTPException as e:
                err_str = str(e)
                if '503' in err_str or 'already' in err_str.lower():
                    return
                # 缓存方法失败，清除缓存并走全量流程
                with _AUTH_CACHE_LOCK:
                    _AUTH_METHOD_CACHE.pop(cache_key, None)
            except Exception:
                with _AUTH_CACHE_LOCK:
                    _AUTH_METHOD_CACHE.pop(cache_key, None)

    # ── 第一步:尝试标准 login() ──
    try:
        server.login(username, password)
        # P4: 记录成功方法
        if cache_key:
            with _AUTH_CACHE_LOCK:
                _AUTH_METHOD_CACHE[cache_key] = 'standard'
        return  # 直接成功
    except smtplib.SMTPAuthenticationError as e:
        first_err = e  # 记录但不立即放弃，后续降级尝试
    except smtplib.SMTPNotSupportedError:
        first_err = None  # 服务器不支持默认方式
    except smtplib.SMTPException as e:
        # FIX-v2: login() 可能在内部已经完成了认证(235)但抛出了异常
        # 通过 NOOP 探测服务器是否已处于已认证状态
        try:
            code, _ = server.noop()
            if code == 250:
                return  # 服务器正常响应，假设已认证成功
        except Exception:
            pass
        first_err = e
    except Exception as e:
        # FIX-v2: 捕获所有异常，同样检查是否已认证
        try:
            code, _ = server.noop()
            if code == 250:
                return
        except Exception:
            pass
        first_err = e

    # ── 第二步:手动降级尝试各认证方式 ──
    # 检查服务器支持的认证方式
    supported = []
    if hasattr(server, 'esmtp_features'):
        auth_feature = server.esmtp_features.get('auth', '')
        if isinstance(auth_feature, str):
            supported = auth_feature.upper().split()

    # 按优先级排列认证方式
    auth_methods = []
    if 'LOGIN' in supported:
        auth_methods.append('LOGIN')
    if 'PLAIN' in supported:
        auth_methods.append('PLAIN')
    if 'CRAM-MD5' in supported:
        auth_methods.append('CRAM-MD5')
    if not auth_methods:
        auth_methods = ['LOGIN', 'PLAIN', 'CRAM-MD5']

    last_err = first_err
    for method in auth_methods:
        try:
            if method == 'LOGIN':
                server.auth('LOGIN', server.auth_login, initial_response_ok=False)
            elif method == 'PLAIN':
                server.auth('PLAIN', server.auth_plain, initial_response_ok=False)
            elif method == 'CRAM-MD5':
                server.auth('CRAM-MD5', server.auth_cram_md5, initial_response_ok=False)
            # P4: 降级成功后写入缓存，下次直接用该方法
            if cache_key:
                with _AUTH_CACHE_LOCK:
                    _AUTH_METHOD_CACHE[cache_key] = method
            return  # 成功
        except smtplib.SMTPAuthenticationError as e:
            last_err = e
            continue
        except smtplib.SMTPException as e:
            # FIX-v2: 捕获 503 Already authenticated
            err_str = str(e)
            if '503' in err_str or 'already' in err_str.lower():
                return  # 已经认证过了，不需要重复
            last_err = e
            continue
        except Exception as e:
            # FIX-v2: 检查是否已认证
            try:
                code, _ = server.noop()
                if code == 250:
                    return
            except Exception:
                pass
            last_err = e
            continue

    if last_err:
        raise AuthFailedError(f"认证失败 [{enc}]: {last_err}")
    raise AuthFailedError(f"认证失败 [{enc}]: 所有认证方式均失败")


# ── SMTP 服务器域名 → 国家代码映射表 ────────────────────────────────────────────
# 基于域名后缀（ccTLD）和已知 SMTP 服务商的地域策略
SMTP_COUNTRY_MAP = {
    # 国家顶级域名后缀
    ".za": "ZA",    # 南非
    ".tw": "TW",    # 中国台湾
    ".cn": "CN",    # 中国大陆
    ".jp": "JP",    # 日本
    ".kr": "KR",    # 韩国
    ".de": "DE",    # 德国
    ".fr": "FR",    # 法国
    ".uk": "GB",    # 英国
    ".it": "IT",    # 意大利
    ".es": "ES",    # 西班牙
    ".br": "BR",    # 巴西
    ".ru": "RU",    # 俄罗斯
    ".in": "IN",    # 印度
    ".au": "AU",    # 澳大利亚
    ".ca": "CA",    # 加拿大
    ".mx": "MX",    # 墨西哥
    ".nl": "NL",    # 荷兰
    ".se": "SE",    # 瑞典
    ".no": "NO",    # 挪威
    ".pl": "PL",    # 波兰
    ".pt": "PT",    # 葡萄牙
    ".ar": "AR",    # 阿根廷
    ".cl": "CL",    # 智利
    ".co": "CO",    # 哥伦比亚
    ".th": "TH",    # 泰国
    ".my": "MY",    # 马来西亚
    ".sg": "SG",    # 新加坡
    ".hk": "HK",    # 香港
    ".il": "IL",    # 以色列
    ".tr": "TR",    # 土耳其
    ".at": "AT",    # 奥地利
    ".ch": "CH",    # 瑞士
    ".be": "BE",    # 比利时
    ".cz": "CZ",    # 捷克
    ".fi": "FI",    # 芬兰
    ".dk": "DK",    # 丹麦
    ".ie": "IE",    # 爱尔兰
    ".nz": "NZ",    # 新西兰
    ".ph": "PH",    # 菲律宾
    ".ro": "RO",    # 罗马尼亚
    ".hu": "HU",    # 匈牙利
    ".ua": "UA",    # 乌克兰
    # 已知服务商域名
    "sina.com": "CN",
    "163.com": "CN",
    "126.com": "CN",
    "qq.com": "CN",
    "sohu.com": "CN",
    "aliyun.com": "CN",
    "tiscali.co.za": "ZA",
    "telkomsa.net": "ZA",
    "mweb.co.za": "ZA",
    "vodamail.co.za": "ZA",
    "seed.net.tw": "TW",
    "hinet.net": "TW",
    "sfr.fr": "FR",
    "orange.fr": "FR",
    "free.fr": "FR",
    "laposte.net": "FR",
    "mail.ru": "RU",
    "yandex.ru": "RU",
    "rambler.ru": "RU",
    "web.de": "DE",
    "gmx.de": "DE",
    "t-online.de": "DE",
}

# 高延迟代理阈值（毫秒）—— 超过此值的代理将被降级
LATENCY_THRESHOLD_MS = 5000


def _guess_smtp_country(smtp_host: str) -> str:
    """根据 SMTP 服务器域名推断其国家/地区要求。
    返回 ISO 3166-1 alpha-2 国家代码，或空字符串表示无特定要求。
    """
    host = smtp_host.lower().strip()
    # 先检查完整域名匹配
    for domain, cc in SMTP_COUNTRY_MAP.items():
        if not domain.startswith(".") and domain in host:
            return cc
    # 再检查 ccTLD 后缀
    for suffix, cc in SMTP_COUNTRY_MAP.items():
        if suffix.startswith(".") and host.endswith(suffix):
            return cc
    return ""


def _send_one(
    task: SendTask,
    proxy_pool: List[ProxyEntry],
    timeout: int,
    dry_run: bool,
    max_proxy_retry: int = 5,
    conn_pool: Optional["_SmtpConnPool"] = None,
) -> Tuple[str, str]:
    """FIX: 1) 每次尝试后安全关闭 server/sock，防止 FD 泄漏
           2) 代理死亡标记增加连续失败计数，避免单次超时就永久拉黑
       3) 更精确的异常分类，区分代理错误、服务器拒绝、网络超时
       4) 账号禁用关键词扩展，减少误判
    P1 OPT: 接受 conn_pool 参数，优先复用已认证连接跳过握手阶段。
    P3 OPT: 记忆成功的加密方式，下次直接用该方式跳过无效尝试。
    P4 OPT: 将 auth_cache_key 传给 _try_login_with_fallback，减少 AUTH 往返。
    """
    if dry_run:
        time.sleep(0.05)
        return "DRY-RUN", ""
    t = task.account

    # P3: 优先使用缓存的成功加密方式，无缓存时按端口默认顺序
    enc_cache_key = f"{t.host}:{t.port}"
    with _ENC_CACHE_LOCK:
        cached_enc = _ENC_CACHE.get(enc_cache_key)

    if cached_enc:
        # 缓存命中:该加密方式放首位，原顺序其余的作为 fallback
        default_order = (
            ["ssl"] if t.port == 465
            else ["starttls"] if t.port == 587
            else ["plain", "starttls"]
        )
        enc_order = [cached_enc] + [e for e in default_order if e != cached_enc]
    else:
        # FIX-v3: 基于实测数据优化端口-加密方式映射
        # 465: 隐式 SSL 优先（87.5% 成功率）
        # 587: STARTTLS 标准流程
        # 25/2525: 明文 AUTH 优先（实测大多数不支持 STARTTLS，明文成功率更高）
        enc_order = (
            ["ssl"] if t.port == 465
            else ["starttls"] if t.port == 587
            else ["plain", "starttls"]
        )

    alive = [p for p in proxy_pool if p.alive]
    if not alive:
        raise ProxyExhaustedError("代理池无可用代理")

    tried_proxies = set()
    last_conn_err = ""
    auth_failed_enc = set()
    proxy_fail_counts: Dict[int, int] = {}  # FIX: 代理连续失败计数
    port_timeout_count = 0  # FIX-v3: 端口超时计数（用于检测 ISP 封端口）
    ssl_handshake_failed = False  # FIX-v3: SSL 握手失败标记（服务器不支持）

    # P1: 先尝试从连接池取一条已认证的连接直接发送，成功则跳过整个握手阶段
    if conn_pool is not None:
        for enc in enc_order:
            pooled = conn_pool.acquire(t.username, t.host, t.port, enc)
            if pooled is None:
                continue
            server, sock, proxy_str, prior_sent = pooled
            try:
                _do_send(server, task)
                # 发送成功，将连接归还池中（累计发送数 = 池取出时的计数 + 本封）
                conn_pool.release(t.username, t.host, t.port, enc,
                                  server, sock, proxy_str,
                                  emails_sent=prior_sent + 1)
                return f"POOL-REUSE/{enc.upper()}", proxy_str
            except Exception:
                # 连接已断开或发送失败，丢弃该连接，走正常新建连接流程
                _safe_close(server, sock)
                conn_pool.invalidate(t.username, t.host, t.port, enc)
                break  # 跳出池尝试，走下方正常握手流程

    def _pick_best_proxy(candidates: List[ProxyEntry]) -> ProxyEntry:
        # WARN-7 FIX: 内部局部函数与模块级 _pick_bound_proxy 逻辑完全相同，直接调用模块级函数避免重复代码
        return _pick_bound_proxy(candidates)

    for attempt in range(max_proxy_retry):
        candidates = [p for p in alive if id(p) not in tried_proxies]
        if not candidates:
            candidates = [p for p in alive if p.alive]
            if not candidates:
                break
        entry = _pick_best_proxy(candidates)
        tried_proxies.add(id(entry))
        proxy_str = f"{entry.host}:{entry.port}"
        conn_failed_this_proxy = True  # 跟踪本轮代理是否有任何连接成功

        for enc in enc_order:
            if enc in auth_failed_enc:
                continue
            # FIX-v3: SSL 握手失败后不再重试同类型加密（服务器不支持）
            if enc == "ssl" and ssl_handshake_failed:
                continue
            server = None
            sock = None
            try:
                sock = _make_proxy_socket(entry, t.host, t.port, timeout)
                server = _build_smtp_server(t, enc, sock, timeout)
                # P4: 传入 cache_key，_try_login_with_fallback 内部会记忆成功的 AUTH 方法
                auth_cache_key = f"{t.host}:{t.port}:{enc}"
                _try_login_with_fallback(server, t.username, t.password, enc,
                                         cache_key=auth_cache_key)
                _do_send(server, task)
                # P3: 握手+发送全成功，记忆当前加密方式供后续直接使用
                with _ENC_CACHE_LOCK:
                    _ENC_CACHE[enc_cache_key] = enc
                # P1: 将已认证连接入池（不 quit，保持连接供下一封邮件复用）
                if conn_pool is not None:
                    conn_pool.release(t.username, t.host, t.port, enc,
                                      server, sock, proxy_str, emails_sent=1)
                else:
                    try:
                        server.quit()
                    except Exception:
                        pass
                return f"OK via {enc.upper()}", proxy_str
            except ManualInterventionError:
                _safe_close(server, sock)
                raise
            except AuthFailedError:
                _safe_close(server, sock)
                conn_failed_this_proxy = False  # 连接成功了，只是认证失败
                auth_failed_enc.add(enc)
                if len(auth_failed_enc) >= len(enc_order):
                    raise
                continue
            except AccountDisabledError:
                _safe_close(server, sock)
                raise
            except smtplib.SMTPAuthenticationError as e:
                _safe_close(server, sock)
                conn_failed_this_proxy = False
                auth_failed_enc.add(enc)
                if len(auth_failed_enc) >= len(enc_order):
                    raise AuthFailedError(f"认证失败 [{enc}]: {e}")
                continue
            except smtplib.SMTPNotSupportedError:
                _safe_close(server, sock)
                continue
            except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as e:
                _safe_close(server, sock)
                raise PermanentError(f"邮件被拒绝: {e}")
            except smtplib.SMTPDataError as e:
                _safe_close(server, sock)
                err_str = str(e).lower()
                if any(w in err_str for w in ["spam", "rejected", "policy", "content"]):
                    raise PermanentError(f"内容被拒绝: {e}")
                last_conn_err = str(e)
                continue
            except Exception as e:
                _safe_close(server, sock)
                err_str = str(e)
                err_lower = err_str.lower()

                # FIX-v3: 细分代理层错误类型
                if "\x00PORT_TIMEOUT\x00" in err_str:
                    # ISP 端口封锁/超时 — 不标记代理死亡
                    port_timeout_count += 1
                    conn_failed_this_proxy = False  # 不是代理的错
                    last_conn_err = err_str.replace("\x00PORT_TIMEOUT\x00", "")
                    # FIX-v3: 连续 3 次端口超时，判定为 ISP 封端口
                    if port_timeout_count >= 3 and t.port in (25, 2525):
                        raise PortBlockedError(
                            f"端口 {t.port} 疑似被代理出口 ISP 封锁"
                            f"（连续 {port_timeout_count} 次超时）"
                        )
                    break  # 超时后不再尝试其他加密方式，换代理
                elif "\x00PROXY_DEAD\x00" in err_str:
                    # 代理本身故障 — 应标记死亡
                    last_conn_err = err_str.replace("\x00PROXY_DEAD\x00", "")
                    break  # 换代理
                elif "\x00PROXY_UNSTABLE\x00" in err_str:
                    # 代理不稳定 — 记录但不立即标记死亡
                    last_conn_err = err_str.replace("\x00PROXY_UNSTABLE\x00", "")
                    break  # 换代理
                elif "\x00TARGET_REFUSED\x00" in err_str:
                    # 目标服务器拒绝 — 不是代理问题
                    conn_failed_this_proxy = False
                    last_conn_err = err_str.replace("\x00TARGET_REFUSED\x00", "")
                    break  # 目标拒绝了，换代理重试

                # FIX-v3: SSL 握手失败标记（后续不再尝试 SSL）
                if "ssl" in err_lower and any(w in err_lower for w in [
                    "handshake", "sslv3", "eof", "ssl_error",
                    "certificate", "wrong version",
                ]):
                    ssl_handshake_failed = True

                # 账号禁用关键词
                if any(w in err_lower for w in [
                    "disabled", "suspended", "blocked", "banned",
                    "deactivated", "locked", "closed", "terminated",
                    "too many login", "rate limit",
                ]):
                    raise AccountDisabledError(f"账号被禁用: {e}")
                last_conn_err = str(e)
                continue

        # FIX-v3: 代理死亡标记 — 只有代理本身故障才计入失败计数
        # PORT_TIMEOUT / TARGET_REFUSED 不计入（不是代理的错）
        if conn_failed_this_proxy and not auth_failed_enc:
            pid = id(entry)
            # 检查是否是 PROXY_DEAD 类型的错误
            is_proxy_fault = "\x00PROXY_DEAD\x00" in (last_conn_err or "")
            if is_proxy_fault:
                proxy_fail_counts[pid] = proxy_fail_counts.get(pid, 0) + 1
                if proxy_fail_counts[pid] >= 2:
                    entry.alive = False
            else:
                # 非代理故障（如端口超时、目标拒绝），不标记代理死亡
                proxy_fail_counts[pid] = proxy_fail_counts.get(pid, 0) + 1
                if proxy_fail_counts[pid] >= 3:  # 容忍度更高
                    entry.alive = False

    raise RetryableError(f"尝试 {len(tried_proxies)} 个代理均失败: {last_conn_err[:80]}")


def _safe_close(server: Optional[smtplib.SMTP], sock: Optional[socket.socket]) -> None:
    """FIX: 安全关闭 SMTP 服务器和底层 socket，防止任何异常泄漏。"""
    if server:
        try:
            server.close()
        except Exception:
            pass
    if sock:
        try:
            sock.close()
        except Exception:
            pass


