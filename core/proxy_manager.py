# -*- coding: utf-8 -*-
"""API代理池管理器：代理获取、健康检测、定时刷新"""
from __future__ import annotations
import random
import re
import socket
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from .models import ProxyEntry, ApiProxyConfig

import json
from concurrent.futures import ThreadPoolExecutor
import socks


class ApiProxyManager:
    def __init__(self):
        self.config = ApiProxyConfig()
        self.pool: List[ProxyEntry] = []
        self._lock = threading.Lock()
        self._refresh_timer: Optional[threading.Timer] = None
        self._running = False

    def fetch_proxies(self) -> int:
        cfg = self.config
        if not cfg.url:
            return 0
        try:
            req = urllib.request.Request(cfg.url)
            if cfg.username and cfg.password:
                import base64 as b64mod
                cred = b64mod.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
                req.add_header("Authorization", f"Basic {cred}")
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            # self.log_message.emit(f"API获取失败: {e}")
            if cfg.pause_on_fail:
                # self.status_changed.emit("状态:API加载失败，任务已暂停")
                pass
            return -1

        new_proxies: List[ProxyEntry] = []
        for idx, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if cfg.tunnel_mode:
                # 隧道模式:尊重上游返回的协议（socks5://host:port），不覆盖
                entry = self._parse_proxy_line(line, "socks5")
            else:
                entry = self._parse_proxy_line(line, cfg.protocol)
            if entry:
                if cfg.tunnel_mode:
                    entry.tunnel_idx = len(new_proxies)  # 赋予隧道索引
                new_proxies.append(entry)

        # 获取数量:0=不限制；>0 时只保留最多 fetch_count 条（与 UI「获取数量」一致）
        if cfg.fetch_count > 0 and len(new_proxies) > cfg.fetch_count:
            if cfg.order == "random":
                new_proxies = random.sample(new_proxies, cfg.fetch_count)
            else:
                new_proxies = new_proxies[: cfg.fetch_count]
        elif cfg.order == "random":
            random.shuffle(new_proxies)

        # 隧道模式:从 /proxy/{idx} 获取端口状态（活跃连接数）
        # 非隧道模式:从 /proxy/status 获取预检测信息
        if cfg.tunnel_mode:
            self._try_fetch_tunnel_status(new_proxies, cfg.url)
        else:
            self._try_fetch_precheck(new_proxies, cfg.url)

        with self._lock:
            # FIX: 新拉取的代理全部重置为 alive，清除旧的死亡标记
            for p in new_proxies:
                p.alive = True
            self.pool = new_proxies

        count = len(new_proxies)
        mode_label = "隧道模式" if cfg.tunnel_mode else "API模式"
        # self.log_message.emit(f"{mode_label}:拉取 {count} 条代理")
        # self.status_changed.emit(f"状态:已加载 {count} 条代理")
        return count

    def _parse_proxy_line(self, line: str, default_proto: str) -> Optional[ProxyEntry]:
        """FIX: 增强代理格式解析，支持更多常见格式，减少解析失败。"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # 带协议前缀的 URL 格式
        if "://" in line:
            try:
                parsed = urlparse(line)
                host = parsed.hostname or ""
                try:
                    port = parsed.port or 1080
                except ValueError:
                    port = 1080
                if not host:
                    return None
                return ProxyEntry(
                    host=host,
                    port=port,
                    username=parsed.username or "",
                    password=parsed.password or "",
                    protocol=parsed.scheme or default_proto)
            except Exception:
                return None

        # 支持 user:pass@host:port 格式
        if "@" in line:
            auth_part, _, addr_part = line.rpartition("@")
            parts = addr_part.split(":")
            if len(parts) >= 2:
                try:
                    host = parts[0]
                    port = int(parts[1])
                    auth_parts = auth_part.split(":", 1)
                    username = auth_parts[0] if len(auth_parts) > 0 else ""
                    password = auth_parts[1] if len(auth_parts) > 1 else ""
                    return ProxyEntry(host=host, port=port, username=username,
                                      password=password, protocol=default_proto)
                except (ValueError, IndexError):
                    pass

        # 纯 host:port 或 host:port:user:pass 格式
        parts = line.replace("\t", ":").replace(" ", ":").split(":")
        if len(parts) >= 2:
            try:
                host = parts[0]
                port = int(parts[1])
                username = parts[2] if len(parts) > 2 else ""
                password = parts[3] if len(parts) > 3 else ""
                return ProxyEntry(host=host, port=port, username=username,
                                  password=password, protocol=default_proto)
            except (ValueError, IndexError):
                return None
        return None

    def get_alive(self) -> List[ProxyEntry]:
        """FIX: 当所有代理都被标记死亡时，回退到全量池并重置状态，而非返回空列表。"""
        with self._lock:
            alive = [p for p in self.pool if p.alive]
            if alive:
                return alive
            # FIX: 所有代理都死亡，重置状态给它们第二次机会
            if self.pool:
                for p in self.pool:
                    p.alive = True
                return list(self.pool)
            return []

    def get_alive_filtered(self, country: str = "",
                           require_clean: bool = False,
                           max_latency_ms: float = 0) -> List[ProxyEntry]:
        """智能代理选择:按国家、RBL 状态、延迟过滤。
        如果过滤后无可用代理，逐步放宽条件（延迟→RBL→国家）。
        """
        alive = self.get_alive()
        if not alive:
            return alive

        # 第 1 层:全部条件
        filtered = alive
        if country:
            cc = country.upper()
            by_country = [p for p in filtered if p.country_code.upper() == cc]
            if by_country:
                filtered = by_country
        if require_clean:
            clean = [p for p in filtered if p.is_rbl_clean()]
            if clean:
                filtered = clean
        if max_latency_ms > 0:
            low_lat = [p for p in filtered if p.is_low_latency(max_latency_ms)]
            if low_lat:
                filtered = low_lat

        if filtered:
            return filtered

        # 第 2 层:放宽延迟限制
        filtered = alive
        if country:
            cc = country.upper()
            by_country = [p for p in filtered if p.country_code.upper() == cc]
            if by_country:
                filtered = by_country
        if require_clean:
            clean = [p for p in filtered if p.is_rbl_clean()]
            if clean:
                filtered = clean
        if filtered:
            return filtered

        # 第 3 层:放宽 RBL 限制
        filtered = alive
        if country:
            cc = country.upper()
            by_country = [p for p in filtered if p.country_code.upper() == cc]
            if by_country:
                filtered = by_country
        if filtered:
            return filtered

        # 全部放宽，返回所有存活代理
        return alive

    def _try_fetch_precheck(self, proxies: List[ProxyEntry], api_url: str) -> None:
        """尝试从代理端的 /proxy/status JSON API 获取预检测信息。"""
        try:
            # 从 proxies.txt URL 推断基础 URL
            parsed = urlparse(api_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            status_url = f"{base_url}/proxy/status"
            req = urllib.request.Request(status_url)
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))

            if not isinstance(data, list):
                return

            # 建立 IP → 检测信息的映射
            info_map = {}
            for item in data:
                ip = item.get("ip") or item.get("host", "")
                if ip:
                    info_map[ip] = item

            # 将检测信息写入代理对象
            enriched = 0
            for p in proxies:
                info = info_map.get(p.host)
                if info:
                    p.country_code = info.get("country", "") or info.get("country_code", "")
                    p.rbl_count = int(info.get("rbl_count", 0) or 0)
                    p.latency_ms = float(info.get("latency_ms", 0) or info.get("latency", 0) or 0)
                    p.precheck_time = float(info.get("last_check", 0) or info.get("precheck_time", 0) or 0)
                    enriched += 1

            if enriched > 0:
                # self.log_message.emit(f"预检测信息已加载: {enriched}/{len(proxies)} 条代理已匹配")
                pass
        except Exception:
            # 预检测信息获取失败不影响正常发送流程
            pass

    def _try_fetch_tunnel_status(self, proxies: List[ProxyEntry], api_url: str) -> None:
        """从上游隧道代理的 /proxy/{idx} API 批量获取端口活跃连接数。

        用于智能负载均衡:优先选择 active=0 的空闲端口。
        采用并发请求（最多 20 线程），超时 3 秒/请求，失败静默跳过。
        """
        try:
            parsed = urlparse(api_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 保存推断的 base_url 供后续使用
            self.config.tunnel_api_base = base_url

            # 采样查询前 min(50, len) 个端口的状态（避免端口数过多时阻塞）
            sample_size = min(50, len(proxies))
            sample_proxies = proxies[:sample_size]
            enriched = 0

            def _fetch_one(p: ProxyEntry) -> bool:
                if p.tunnel_idx < 0:
                    return False
                try:
                    status_url = f"{base_url}/proxy/{p.tunnel_idx}"
                    req = urllib.request.Request(status_url)
                    req.add_header("Accept", "application/json")
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    p.tunnel_active = int(data.get("active", 0))
                    return True
                except Exception:
                    return False

            with ThreadPoolExecutor(max_workers=min(20, sample_size)) as executor:
                results = list(executor.map(_fetch_one, sample_proxies))
                enriched = sum(1 for r in results if r)

            if enriched > 0:
                # self.log_message.emit(
                #     f"隧道状态已加载: {enriched}/{sample_size} 个端口已获取活跃连接数")
                pass
        except Exception as e:
            # 隧道状态获取失败不影响正常发送流程
            # self.log_message.emit(f"隧道状态获取失败(不影响发送): {e}")
            pass

    def test_proxy(self, entry: ProxyEntry, target_host: str = "smtp.gmail.com",
                    target_port: int = 465) -> bool:
        """FIX-⑬: 测试目标改为可配置，不再硬编码 Gmail。"""
        try:
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            ptype = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4,
                     "http": socks.HTTP}.get(entry.protocol.lower(), socks.SOCKS5)
            sock.set_proxy(ptype, entry.host, entry.port,
                           username=entry.username or None,
                           password=entry.password or None, rdns=True)
            sock.settimeout(10)
            sock.connect((target_host, target_port))
            sock.close()
            return True
        except Exception:
            return False

    def start_refresh(self, interval_min: float) -> None:
        self._running = True
        if interval_min <= 0:
            return
        seconds = interval_min * 60
        def refresh_task():
            if self._running:
                # 在新线程中执行代理获取，避免阻塞定时器线程
                threading.Thread(target=self.fetch_proxies, daemon=True).start()
                # 重新启动定时器
                if self._running:
                    self._refresh_timer = threading.Timer(seconds, refresh_task)
                    self._refresh_timer.daemon = True
                    self._refresh_timer.start()
        # 启动第一个定时器
        self._refresh_timer = threading.Timer(seconds, refresh_task)
        self._refresh_timer.daemon = True
        self._refresh_timer.start()

    def stop_refresh(self) -> None:
        self._running = False
        if self._refresh_timer:
            self._refresh_timer.cancel()
            self._refresh_timer = None