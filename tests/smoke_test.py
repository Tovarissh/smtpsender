#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smtpsender 冒烟测试脚本
不依赖GUI，不需要真实SMTP，测试核心功能是否正常
运行方式: cd /tmp && python3 -m smtpsender.tests.smoke_test
"""
import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

RESULTS = []

def report(name, ok, msg=""):
    RESULTS.append((name, ok, msg))
    status = "PASS" if ok else "FAIL"
    suffix = f": {msg}" if msg else ""
    print(f"  [{'✓' if ok else '✗'}] {status} {name}{suffix}")

# ─── Test 1: 全模块 import ────────────────────────────────────────────────────
def test_imports():
    print("\n[1] 全模块 import")
    failed = []
    mods = [
        "smtpsender.core.constants",
        "smtpsender.core.models",
        "smtpsender.core.utils",
        "smtpsender.core.hidden_text",
        "smtpsender.core.template_engine",
        "smtpsender.core.evasion",
        "smtpsender.core.smtp_conn",
        "smtpsender.core.send_logic",
        "smtpsender.core.smtp_pool",
        "smtpsender.core.proxy_manager",
        "smtpsender.workers.sender_worker",
        "smtpsender.workers.verify_worker",
    ]
    import importlib
    for m in mods:
        try:
            importlib.import_module(m)
        except Exception as e:
            failed.append(f"{m}: {e}")
    if failed:
        report("全模块import", False, "; ".join(failed[:2]))
        return False
    report("全模块import", True, f"{len(mods)} 个模块")
    return True

# ─── Test 2: 常量加载 ──────────────────────────────────────────────────────────
def test_constants():
    print("\n[2] 常量加载")
    try:
        from smtpsender.core.constants import SPAM_WORDS, UNICODE_REPLACEMENTS, HIDDEN_TEMPLATES
        report("SPAM_WORDS", len(SPAM_WORDS) > 0, f"{len(SPAM_WORDS)} 条")
        report("UNICODE_REPLACEMENTS", len(UNICODE_REPLACEMENTS) > 0, f"{len(UNICODE_REPLACEMENTS)} 个")
        report("HIDDEN_TEMPLATES", len(HIDDEN_TEMPLATES) > 0, f"{len(HIDDEN_TEMPLATES)} 个")
        return True
    except Exception as e:
        report("常量加载", False, str(e))
        return False

# ─── Test 3: TemplateVarEngine ────────────────────────────────────────────────
def test_template_engine():
    print("\n[3] TemplateVarEngine 渲染")
    try:
        from smtpsender.core.template_engine import TemplateVarEngine
        engine = TemplateVarEngine()
        recipient = "test@example.com"
        # 使用正确的模板变量格式 [%EMail] [%FName]
        result = engine.render("[%EMail] [%FName] 你好", recipient)
        has_email = "test@example.com" in result
        no_placeholder = "[%EMail]" not in result
        report("render [%EMail]", has_email, result[:60])
        report("占位符已替换", no_placeholder, result[:60])
        return has_email
    except Exception as e:
        report("TemplateVarEngine", False, str(e))
        return False

# ─── Test 4: EvasionEngine ───────────────────────────────────────────────────
def test_evasion():
    print("\n[4] EvasionEngine 伪装")
    try:
        from smtpsender.core.evasion import EvasionEngine
        from smtpsender.core.models import SendTask, EvasionConfig, SmtpAccount
        acct = SmtpAccount(username="u@test.com", password="pass",
                           host="smtp.test.com", port=587)
        task = SendTask(
            account=acct,
            recipient="target@gmail.com",
            subject="Test Subject",
            body_html="<html><body>Hello</body></html>",
            body_format="html",
        )
        cfg = EvasionConfig(spoof_from_address='hr@gmail.com')
        result = EvasionEngine.apply(task, cfg, "gmail.com")
        report("EvasionEngine.apply 不抛异常", True)
        report("返回 SendTask", isinstance(result, SendTask))
        return True
    except Exception as e:
        report("EvasionEngine", False, str(e))
        return False

# ─── Test 5: inject_hidden_text ──────────────────────────────────────────────
def test_hidden_text():
    print("\n[5] HTML 隐藏文本注入")
    try:
        from smtpsender.core.hidden_text import inject_hidden_text
        from smtpsender.core.models import HiddenTextConfig
        html = "<html><body><p>正文内容</p></body></html>"
        cfg = HiddenTextConfig(enabled=True, texts=["hidden_token_xyz"], count=1)
        result = inject_hidden_text(html, cfg.texts, count=cfg.count)
        changed = result != html
        report("输出与原文不同", changed)
        report("长度增加", len(result) > len(html), f"原{len(html)}→新{len(result)}")
        return changed
    except Exception as e:
        report("inject_hidden_text", False, str(e))
        return False

# ─── Test 6: replace_spam_words_with_homoglyphs ───────────────────────────────
def test_spam_replace():
    print("\n[6] 敏感词 Unicode 替换")
    try:
        from smtpsender.core.hidden_text import replace_spam_words_with_homoglyphs
        from smtpsender.core.constants import SPAM_WORDS
        text = " ".join(SPAM_WORDS[:5]) + " 普通内容"
        result = replace_spam_words_with_homoglyphs(text, rate=1.0)
        changed = result != text
        report("替换后与原文不同", changed)
        return changed
    except Exception as e:
        report("replace_spam_words", False, str(e))
        return False

# ─── Test 7: SMTP行解析 ───────────────────────────────────────────────────────
def test_smtp_parse():
    print("\n[7] SMTP 行格式解析")
    try:
        import re
        def parse_smtp(line):
            m = re.match(r"^(.+?):(.+)@([^:@]+):?(\d+)?$", line.strip())
            if m:
                return {"user": m.group(1), "pass": m.group(2),
                        "host": m.group(3), "port": int(m.group(4) or 587)}
            parts = line.strip().split("|")
            if len(parts) >= 3:
                return {"user": parts[0], "pass": parts[1],
                        "host": parts[2], "port": int(parts[3]) if len(parts) > 3 else 587}
            return None

        r1 = parse_smtp("user@mail.com:mypass123@smtp.gmail.com:587")
        r2 = parse_smtp("user@mail.com|mypass123|smtp.163.com|465")
        report("格式1 user:pass@host:port", r1 is not None, str(r1))
        report("格式2 user|pass|host|port", r2 is not None and r2["port"] == 465, str(r2))
        return r1 is not None and r2 is not None
    except Exception as e:
        report("SMTP行解析", False, str(e))
        return False

# ─── Test 8: SenderWorker 可实例化 ───────────────────────────────────────────
def test_sender_worker():
    print("\n[8] SenderWorker 实例化")
    try:
        from smtpsender.workers.sender_worker import SenderWorker
        from smtpsender.core.models import (
            SmtpAccount, SendTask, EvasionConfig, HiddenTextConfig,
            SpamWordConfig, TrackingConfig
        )
        from smtpsender.core.template_engine import TemplateVarEngine
        from smtpsender.core.proxy_manager import ApiProxyManager

        acct = SmtpAccount(username="u@test.com", password="pass",
                           host="smtp.test.com", port=587)
        tasks = [SendTask(
            account=acct,
            recipient="a@b.com",
            subject="test",
            body_html="hello",
            body_format="plain",
        )]
        worker = SenderWorker(
            tasks=tasks,
            proxy_manager=ApiProxyManager(),
            evasion_cfg=EvasionConfig(),
            hidden_cfg=HiddenTextConfig(),
            spam_cfg=SpamWordConfig(),
            template_engine=TemplateVarEngine(),
            subject_template="test",
            body_template="hello",
            timeout=30,
            retry=1,
            delay=0,
            threads=1,
            dry_run=True,
            max_per_account=100,
            callbacks={},
        )
        report("SenderWorker 实例化成功", True)
        report("dry_run=True 生效", worker.dry_run is True)
        return True
    except Exception as e:
        report("SenderWorker", False, str(e))
        return False

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  smtpsender 冒烟测试")
    print("=" * 60)
    for t in [test_imports, test_constants, test_template_engine,
              test_evasion, test_hidden_text, test_spam_replace,
              test_smtp_parse, test_sender_worker]:
        try:
            t()
        except Exception as e:
            report(t.__name__, False, f"未捕获异常: {e}")

    print("\n" + "=" * 60)
    passed = sum(1 for r in RESULTS if r[1])
    total = len(RESULTS)
    all_pass = passed == total
    print(f"  总计: {passed}/{total} PASS {'✓ 全部通过' if all_pass else '✗ 有失败项'}")
    print("=" * 60)
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
