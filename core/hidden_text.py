# -*- coding: utf-8 -*-
"""HTML隐藏文本注入引擎 + 敏感词Unicode形近字替换引擎"""
from __future__ import annotations
import bisect
import random
import re
from typing import List, Tuple
from .constants import UNICODE_REPLACEMENTS, SPAM_WORDS, HIDDEN_TEMPLATES, HIDDEN_TAGS

def _random_font_family() -> str:
    fonts = ["Arial", "Helvetica", "Verdana", "Georgia", "Times", "Courier",
             "Tahoma", "Trebuchet MS", "Impact", "Comic Sans MS"]
    return random.choice(fonts)


def _gen_hidden_snippet(text: str) -> str:
    tag = random.choice(HIDDEN_TAGS)
    tpl = random.choice(HIDDEN_TEMPLATES)
    rand_big = random.randint(5000, 99999)
    return tpl.format(
        tag=tag, text=text, rand=rand_big,
        font_family=_random_font_family(),
        line_h=random.randint(12, 36),
        m1=random.randint(5, 30), m2=random.randint(5, 30), m3=random.randint(5, 30),
    )


def inject_hidden_text(html: str, hidden_texts: List[str],
                       count: int = 5, position: str = "random") -> str:
    if not hidden_texts:
        return html
    snippets = [_gen_hidden_snippet(random.choice(hidden_texts)) for _ in range(count)]

    if position == "top":
        return "\n".join(snippets) + "\n" + html
    elif position == "bottom":
        return html + "\n" + "\n".join(snippets)
    elif position == "between_paragraphs":
        split_points = list(re.finditer(r'(</p>|</div>|<br\s*/?>)', html, re.IGNORECASE))
        if not split_points:
            return html + "\n" + "\n".join(snippets)
        result = html
        offset = 0
        insert_positions = random.sample(split_points, min(count, len(split_points)))
        insert_positions.sort(key=lambda m: m.end())
        for i, match in enumerate(insert_positions):
            pos = match.end() + offset
            snippet = snippets[i % len(snippets)]
            result = result[:pos] + "\n" + snippet + result[pos:]
            offset += len(snippet) + 1
        return result
    else:  # random — FIX-⑦: 预计算安全位置，O(n) 一次扫描替代 O(n×count) 重复扫描
        # 一次性找出所有安全插入点（标签结束位置 > 后）
        safe_positions = []
        in_tag = False
        for idx, ch in enumerate(html):
            if ch == '<':
                in_tag = True
            elif ch == '>':
                in_tag = False
                safe_positions.append(idx + 1)
        if not safe_positions:
            return html + "\n".join(snippets)
        # 逆序插入，保持前面插入点位置不变
        chosen = sorted(random.sample(
            safe_positions, min(len(snippets), len(safe_positions))), reverse=True)
        result = html
        for pos, snippet in zip(chosen, snippets):
            result = result[:pos] + snippet + result[pos:]
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# 敏感词 Unicode 形近字替换引擎
# ═══════════════════════════════════════════════════════════════════════════════

def _build_html_tag_ranges(html: str) -> List[Tuple[int, int]]:
    """返回所有 HTML 标签（<...>）的 [start, end) 区间列表，用于跳过标签内内容。"""
    ranges: List[Tuple[int, int]] = []
    for m in re.finditer(r'<[^>]*>', html):
        ranges.append((m.start(), m.end()))
    return ranges


def _in_tag_range(pos: int, tag_ranges: List[Tuple[int, int]]) -> bool:
    """二分判断 pos 是否落在某个标签区间内。"""
    lo, hi = 0, len(tag_ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e = tag_ranges[mid]
        if pos < s:
            hi = mid - 1
        elif pos >= e:
            lo = mid + 1
        else:
            return True
    return False


def replace_spam_words_with_homoglyphs(text: str, rate: float = 0.4) -> str:
    """FIX-①: 逆序替换消除字符串位移 Bug。
    FIX-⑯: 跳过 HTML 标签内的内容，只替换文本节点，防止破坏 HTML 结构。
    """
    # 预计算所有标签区间，O(n) 一次完成
    tag_ranges = _build_html_tag_ranges(text)

    # 收集所有待替换区段（逆序处理，避免替换后位移）
    replacements: List[Tuple[int, int, str]] = []  # (start, end, new_word)

    for word in SPAM_WORDS:
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        for match in pattern.finditer(text):
            # FIX-⑯: 跳过 HTML 标签内的匹配（如 class="free-access"）
            if _in_tag_range(match.start(), tag_ranges):
                continue
            original = match.group()
            replaced = []
            for ch in original:
                if ch.lower() in UNICODE_REPLACEMENTS and random.random() < rate:
                    replaced.append(UNICODE_REPLACEMENTS.get(ch, ch))
                else:
                    replaced.append(ch)
            new_word = "".join(replaced)
            if new_word != original:
                replacements.append((match.start(), match.end(), new_word))

    # 合并重叠区段：不同敏感词可能在同一文本上重叠匹配，倒序逐段替换会破坏索引
    replacements.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    merged: List[Tuple[int, int, str]] = []
    cur_end = -1
    for start, end, new_word in replacements:
        if start >= cur_end:
            merged.append((start, end, new_word))
            cur_end = end
    # FIX-①: 按位置倒序应用替换，每次替换不影响前面区段的偏移量
    merged.sort(key=lambda x: x[0], reverse=True)
    result = text
    for start, end, new_word in merged:
        result = result[:start] + new_word + result[end:]
    return result