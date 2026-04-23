# -*- coding: utf-8 -*-
"""模板变量引擎：{{变量名}}渲染、文件变量加载"""
from __future__ import annotations
import os
import random
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .utils import random_letnum

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


class TemplateVarEngine:
    BUILTIN_VARS = {"IPV4", "IPV6", "IPAddress", "Date", "Time",
                    "EMail", "FName", "LName"}
    # 防止超大 txt 拖垮内存或阻塞 UI
    MAX_VAR_FILE_BYTES = 12 * 1024 * 1024

    def __init__(self):
        self.file_vars: Dict[str, List[str]] = {}
        self.file_paths: Dict[str, str] = {}
        self._recipient_names: Dict[str, Tuple[str, str]] = {}
        self._lock = threading.RLock()

    def load_file_var(self, var_name: str, file_path: str) -> int:
        p = Path(file_path)
        if not p.is_file():
            return 0
        try:
            sz = p.stat().st_size
        except OSError:
            return 0
        if sz > self.MAX_VAR_FILE_BYTES:
            return 0
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, MemoryError, UnicodeError):
            return 0
        lines = [
            l.strip() for l in raw.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        with self._lock:
            self.file_vars[var_name] = lines
            self.file_paths[var_name] = file_path
        return len(lines)

    def _gen_ipv4(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _gen_ipv6(self) -> str:
        return ":".join(f"{random.randint(0, 0xffff):04x}" for _ in range(8))

    def _gen_ip_address(self) -> str:
        return self._gen_ipv4() if random.random() < 0.7 else self._gen_ipv6()

    def _gen_date(self) -> str:
        now = datetime.now()
        d = now + timedelta(days=random.randint(-2, 0))
        return d.strftime("%B %d, %Y")

    def _gen_time(self) -> str:
        """FIX-⑪: 修正 12 点边界判断，使用标准 12 小时制算法。"""
        h = random.randint(0, 23)
        m = random.randint(0, 59)
        s = random.randint(0, 59)
        period = "AM" if h < 12 else "PM"   # FIX: < 12 而非 <= 12
        display_h = h % 12
        if display_h == 0:
            display_h = 12
        return f"{display_h}:{m:02d}:{s:02d} {period}"

    def _get_name_for_recipient(self, recipient: str) -> Tuple[str, str]:
        if recipient not in self._recipient_names:
            self._recipient_names[recipient] = (
                random.choice(FIRST_NAMES), random.choice(LAST_NAMES))
        return self._recipient_names[recipient]

    def _get_file_var(self, var_name: str) -> str:
        with self._lock:
            lines = self.file_vars.get(var_name, [])
            if not lines:
                return f"[%{var_name}]"
            return random.choice(lines)

    def render(self, template: str, recipient: str = "") -> str:
        def letnum_replacer(m):
            return random_letnum(int(m.group(1)), int(m.group(2)))
        result = re.sub(r"\[%LetNum\((\d+),\s*(\d+)\)\]", letnum_replacer, template)

        var_pattern = re.compile(r"\[%(\w+)\]")
        found_vars = set(var_pattern.findall(result))

        with self._lock:
            fname, lname = self._get_name_for_recipient(recipient) if recipient else (
                random.choice(FIRST_NAMES), random.choice(LAST_NAMES))

        values: Dict[str, str] = {}
        for var in found_vars:
            if var == "IPV4":
                values[var] = self._gen_ipv4()
            elif var == "IPV6":
                values[var] = self._gen_ipv6()
            elif var == "IPAddress":
                values[var] = self._gen_ip_address()
            elif var == "Date":
                values[var] = self._gen_date()
            elif var == "Time":
                values[var] = self._gen_time()
            elif var == "EMail":
                values[var] = recipient if recipient else "user@example.com"
            elif var == "FName":
                values[var] = fname
            elif var == "LName":
                values[var] = lname
            elif var == "PEmailAdd":
                with self._lock:
                    has_pe = var in self.file_vars and self.file_vars[var]
                if has_pe:
                    values[var] = self._get_file_var(var)
                elif recipient:
                    values[var] = recipient
                else:
                    values[var] = f"[%{var}]"
            else:
                values[var] = self._get_file_var(var)

        def replacer(m):
            return values.get(m.group(1), m.group(0))
        return var_pattern.sub(replacer, result)

    def get_all_vars_in_template(self, template: str) -> List[str]:
        simple = list(set(re.findall(r"\[%(\w+)\]", template)))
        parametric = list(set(re.findall(r"\[%LetNum\(\d+,\s*\d+\)\]", template)))
        return simple + ([f"LetNum(m,n)"] if parametric else [])

    def get_status_summary(self) -> str:
        lines = []
        with self._lock:
            paths = list(self.file_paths.items())
            for var, path in paths:
                count = len(self.file_vars.get(var, []))
                lines.append(f"  [%{var}] -> {path} ({count} 行)")
        return "\n".join(lines) if lines else "  (未加载任何文件变量)"