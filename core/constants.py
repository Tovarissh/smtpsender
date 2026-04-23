# -*- coding: utf-8 -*-
"""常量定义：敏感词表、Unicode形近字替换表、21种HTML隐藏模板"""
from typing import List, Dict, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# 垃圾邮件敏感词列表
# ═══════════════════════════════════════════════════════════════════════════════

SPAM_WORDS = [
    "100% free", "act now", "additional income", "be your own boss", "best price",
    "big bucks", "billion", "cash bonus", "consolidate debt", "double your",
    "earn money", "eliminate bad credit", "extra cash", "fast cash", "financial freedom",
    "free access", "free consultation", "free gift", "free info", "free membership",
    "free preview", "free quote", "free trial", "full refund", "get paid", "giveaway",
    "great offer", "guaranteed", "increase sales", "increase traffic", "instant",
    "lowest price", "make money", "money back", "new customers only", "no cost",
    "one time", "online biz opportunity", "potential earnings", "promise you",
    "pure profit", "risk-free", "satisfaction guaranteed", "save big money",
    "special promotion", "unsecured credit", "unsecured debt", "weight loss",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Unicode 形近字替换表（完整 A-Z 大小写）
# ═══════════════════════════════════════════════════════════════════════════════

UNICODE_REPLACEMENTS = {
    'a': '\u0430', 'b': '\u044c', 'c': '\u0441', 'd': '\u0501', 'e': '\u0435',
    'f': '\u0493', 'g': '\u0261', 'h': '\u04bb', 'i': '\u0456', 'j': '\u0458',
    'k': '\u03ba', 'l': '\u217c', 'm': '\u043c', 'n': '\u0578', 'o': '\u043e',
    'p': '\u0440', 'q': '\u0566', 'r': '\u0433', 's': '\u0455', 't': '\u0442',
    'u': '\u03c5', 'v': '\u03bd', 'w': '\u0448', 'x': '\u0445', 'y': '\u0443',
    'z': 'z',
    'A': '\u0410', 'B': '\u0412', 'C': '\u0421', 'D': '\u0501', 'E': '\u0415',
    'F': '\u0492', 'G': '\u0261', 'H': '\u041d', 'I': '\u0406', 'J': '\u0408',
    'K': '\u041a', 'L': '\u13b6', 'M': '\u041c', 'N': '\u039d', 'O': '\u041e',
    'P': '\u0420', 'Q': '\u051a', 'R': '\u0433', 'S': '\u0405', 'T': '\u0422',
    'U': '\u054d', 'V': '\u0474', 'W': '\u0461', 'X': '\u0425', 'Y': '\u04ae',
    'Z': '\u0396',
}


# ═══════════════════════════════════════════════════════════════════════════════
# 21 种 HTML 隐藏文本注入模板
# ═══════════════════════════════════════════════════════════════════════════════

HIDDEN_TAGS = ["span", "em", "i", "code", "b", "font"]

HIDDEN_TEMPLATES = [
    '<{tag} style="CLIP: rect(0px 0px 0px 0px); POSITION: absolute">{text}</{tag}>',
    '<{tag} hidden>{text}</{tag}>',
    '<{tag} hidden="hidden">{text}</{tag}>',
    '<{tag} hidden="">{text}</{tag}>',
    '<{tag} style="position: absolute; left: -{rand}em; display: none;">{text}</{tag}>',
    '<{tag} style="position:absolute;right:0px;width:0px;height:0px;">{text}</{tag}>',
    '<{tag} style="position:absolute;right:0px;width:0%;">{text}</{tag}>',
    '<{tag} style="overflow: hidden; display: inline-block; width: 0; height: 0">{text}</{tag}>',
    '<{tag} style="font-size:0.000px; font-family:{font_family}; line-height:normal">{text}</{tag}>',
    '<{tag} style="position:absolute; bottom:-{rand}px">{text}</{tag}>',
    '<{tag} style="POSITION: absolute; TOP: -{rand}px; LEFT: -{rand}px">{text}</{tag}>',
    '<{tag} style="font:0.000000px {font_family}">{text}</{tag}>',
    '<{tag} style="LINE-HEIGHT:{line_h}px; position:absolute; margin: {m1}px {m2}px {m3}px {rand}px ">{text}</{tag}>',
    '<{tag} style="display:inline-block;float:left;overflow:hidden;width:0px;height:0px">{text}</{tag}>',
    '<{tag} style="MARGIN-LEFT: -{rand}px">{text}</{tag}>',
    '<{tag} style="height:0.00000001px;OVERFLOW: hidden;position: absolute;">{text}</{tag}>',
    '<{tag} style="overflow:hidden;border-top:red 0px solid;height:{line_h}px;border-right:red 0px solid;width:{line_h}px;border-bottom:red 0px solid;float:left;border-left:red 0px solid;display:inline-block">&nbsp;&nbsp;&nbsp;{text}</{tag}>',
    '<{tag} style="display:none;">{text}</{tag}>',
    '<{tag} style="opacity: 0">{text}</{tag}>',
    '<{tag} style="color: transparent">{text}</{tag}>',
    '<{tag} style="visibility:hidden;position:absolute;overflow:hidden;width:0;height:0">{text}</{tag}>',
]