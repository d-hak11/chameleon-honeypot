import re
from typing import List, Pattern, Tuple

# ────────────────────────────────────────────────────────────── probe paths
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

# ────────────────────────────────────────────────────────────── suspicious QS
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

# ────────────────────────────────────────────────────────────── UA categories
CRAWLER_UA_MARKERS: List[str] = [
    "googlebot", "bingbot", "yandexbot", "baiduspider",
    "facebookexternalhit", "twitterbot",
]

SCANNER_UA_MARKERS: List[str] = [
    "nikto", "nuclei", "openvas", "nessus", "acunetix",
    "nmap", "masscan", "zgrab", "gobuster", "dirbuster",
    "feroxbuster", "dirb", "wfuzz", "ffuf",
]

EXPLOIT_UA_MARKERS: List[str] = [
    "sqlmap", "commix", "xsstrike", "hydra", "medusa",
]

SCRIPT_UA_MARKERS: List[str] = [
    "curl/", "wget/", "python-requests", "go-http-client",
    "java/", "okhttp",
]


def get_ua_category(user_agent: str) -> str:
    low = (user_agent or "").lower()
    for m in EXPLOIT_UA_MARKERS:
        if m in low:
            return m.split("/")[0]
    for m in SCANNER_UA_MARKERS:
        if m in low:
            return m.split("/")[0]
    for m in CRAWLER_UA_MARKERS:
        if m in low:
            return m.split("/")[0]
    for m in SCRIPT_UA_MARKERS:
        if m in low:
            return m.split("/")[0]
    if "mozilla" in low and "compatible" not in low:
        return "browser"
    return "unknown"