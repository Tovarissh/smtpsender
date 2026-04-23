#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 测试导入
try:
    from smtpsender.core.models import SmtpAccount, SendTask
    from smtpsender.core.template_engine import TemplateVarEngine
    from smtpsender.core.proxy_manager import ApiProxyManager
    from smtpsender.workers.sender_worker import SenderWorker
    print("导入成功")
except Exception as e:
    print(f"导入失败: {e}")
    import traceback
    traceback.print_exc()