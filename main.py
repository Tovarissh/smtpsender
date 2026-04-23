# -*- coding: utf-8 -*-
"""
smtpsender 入口（无GUI模式）
用法：
  from smtpsender.core.models import SmtpAccount, SendTask
  from smtpsender.workers.sender_worker import SenderWorker
  from smtpsender.core.proxy_manager import ApiProxyManager
"""
from smtpsender.core.models import (
    SmtpAccount, ProxyEntry, SendTask, SendResult,
    EvasionConfig, HiddenTextConfig, SpamWordConfig, TrackingConfig
)
from smtpsender.core.template_engine import TemplateVarEngine
from smtpsender.core.evasion import EvasionEngine
from smtpsender.core.hidden_text import inject_hidden_text, replace_spam_words_with_homoglyphs
from smtpsender.core.proxy_manager import ApiProxyManager
from smtpsender.workers.sender_worker import SenderWorker
from smtpsender.workers.verify_worker import _SmtpVerifyWorker

VERSION = "5.6.0"

__all__ = [
    "SmtpAccount", "ProxyEntry", "SendTask", "SendResult",
    "EvasionConfig", "HiddenTextConfig", "SpamWordConfig", "TrackingConfig",
    "TemplateVarEngine", "EvasionEngine",
    "inject_hidden_text", "replace_spam_words_with_homoglyphs",
    "ApiProxyManager", "SenderWorker", "_SmtpVerifyWorker",
]
