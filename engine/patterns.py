#!/usr/bin/env python3
import re
from typing import List, Pattern

# ── verbatim from analysis/heuristic_patterns.py ─────────────────────────
PROBE_PATH_PATTERNS: List[str] = [
    r"/wp-admin", r"/wp-login", r"/wp-content", r"/wp-includes", r"/wordpress",
    r"/\.env", r"/\.git/", r"/\.aws", r"/\.svn", r"/\.hg",
    r"/phpmyadmin", r"/pma", r"/myadmin", r"/adminer",
    r"/administrator", r"/admin$", r"/admin/", r"/admin\.php",
    r"/actuator", r"/actuator/",
    r"/cgi-bin", r"/shell", r"/cmd", r"/exec", r"/eval", r"/\.bak",
]

PROBE_RE: Pattern = re.compile(
    "|".join(("(?:" + p + ")" for p in PROBE_PATH_PATTERNS)),
    re.IGNORECASE,
)

SUSPICIOUS_QS_PATTERNS: List[str] = [
    r"(^|&)[^&=]*union\s+select",
    r"(^|&)[^&=]*sleep\(\s*[0-9]",
    r"(^|&)[^&=]*benchmark\(",
    r"(^|&)[^&=]*(\.\./|\.\.%2f)",
    r"(^|&)[^&=]*(cmd|exec|eval|shell)[:=]",
]

SUSPICIOUS_QS_RE: Pattern = re.compile(
    "|".join(("(?:" + p + ")" for p in SUSPICIOUS_QS_PATTERNS)),
    re.IGNORECASE,
)
