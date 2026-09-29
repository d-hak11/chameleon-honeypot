#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from urllib import request
from urllib.error import HTTPError, URLError

DEFAULT_TARGET = "http://localhost:8080"
DEFAULT_PERSONA = "moodle"

# Per-persona expected signatures. "headers" maps header -> required substring.
PERSONAS = {
    "moodle": {
        "server": "nginx",
        "brand": "greenwood college",
        "lang": "en",
        "cookie": "MoodleSession",
        "login_markers": [
            'id="login"', "login/index.php", "logintoken",
            'name="username"', 'name="password"',
        ],
        "admin_path": "/admin/index.php",
        "headers": {
            "content-script-type": "text/javascript",
            "content-style-type": "text/css",
            "x-ua-compatible": "IE=edge",
            "pragma": "no-cache",
            "x-frame-options": "sameorigin",
            "cache-control": "no-store",
        },
    },
    "registry": {
        "admin_path": "/admin/index.php",
        "server": "nginx",
        "brand": "greenwood student records",
        "lang": "en",
        "cookie": "SISESSION",
        "login_markers": ['id="login"', "login/index.php",
                          'name="username"', 'name="password"'],
        "headers": {
            "x-frame-options": "sameorigin",
            "x-ua-compatible": "IE=edge",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store",
        },
    },
    "finance": {
        "admin_path": "/admin/index.php",
        "server": "nginx",
        "brand": "greenwood finance portal",
        "lang": "en",
        "cookie": "FIN_SESSION",
        "login_markers": ['id="login"', "login/index.php",
                          'name="username"', 'name="password"'],
        "headers": {
            "x-frame-options": "sameorigin",
            "x-ua-compatible": "IE=edge",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store",
        },
    },
    "research": {
        "admin_path": "/admin/index.php",
        "server": "nginx",
        "brand": "greenwood research portal",
        "lang": "en",
        "cookie": "RES_SESSION",
        "login_markers": ['id="login"', "login/index.php",
                          'name="username"', 'name="password"'],
        "headers": {
            "x-frame-options": "sameorigin",
            "x-ua-compatible": "IE=edge",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store",
        },
    },
}

SESSION_TOKEN_RE = r"^[0-9a-f]{32}$"
FORBIDDEN_HEADERS = ["via", "x-powered-by"]
FORBIDDEN_BODY = [":8080", "//moodle:", "localhost", "127.0.0.1"]


def parse_status(target):
    """Return the numeric status of the target root, or None if unreachable."""
    try:
        with request.urlopen(target, timeout=10) as resp:
            return resp.status
    except URLError:
        return None


def fetch(target: str, path: str):
    """Returns (status, headers, text, cookies); cookies keeps every Set-Cookie header."""
    url = target.rstrip("/") + path
    req = request.Request(url, headers={"User-Agent": "coherence-check/1.0"})
    try:
        resp = request.urlopen(req, timeout=15)
    except HTTPError as e:      # 4xx/5xx: inspect the error response body
        body = e.read().decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in e.headers.items()}
        cookies = e.headers.get_all("Set-Cookie") or []
        return e.code, headers, body, cookies
    with resp:
        body = resp.read().decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.status, headers, body, cookies


def find_session_token(cookies: list[str], cookiename: str) -> str | None:
    for value in cookies:
        m = re.search(r"{}=([0-9a-fA-F]+)".format(re.escape(cookiename)), value)
        if m:
            return m.group(1)
    return None


def announce(result: bool, message: str) -> None:
    mark = "ok  " if result else "FAIL"
    print(f"  [{mark}] {message}")
def main(argv: list[str]) -> int:
    target = argv[0] if argv else DEFAULT_TARGET
    persona = argv[1] if len(argv) > 1 else DEFAULT_PERSONA
    if persona not in PERSONAS:
        print(f"coherence_check: unknown persona {persona!r}; "
              f"choose from {sorted(PERSONAS)}", file=sys.stderr)
        return 2

    p = PERSONAS[persona]
    print(f"coherence_check: target={target} persona={persona}")

    if parse_status(target) is None:
        print(f"coherence_check: TARGET UNREACHABLE at {target} "
              f"(is the stack up?)")
        return 2

    fails: list[str] = []

    # --- Root page: headers + brand coherence ---
    print("coherence_check: GET /")
    status, headers, body, cookies = fetch(target, "/")
    lower = body.lower()
    announce(status == 200, f"status 200 (got {status})")
    if status != 200:
        fails.append("/ -> status")
    else:
        ok = headers.get("server", "") == p["server"]
        announce(ok, f"Server header is exactly '{p['server']}' "
                     f"(got {headers.get('server','')!r})")
        if not ok:
            fails.append("server header")
        for fbd in FORBIDDEN_HEADERS:
            ok = fbd not in headers
            announce(ok, f"no {fbd!r} header present")
            if not ok:
                fails.append(f"forbidden header {fbd}")
        for head, need in p["headers"].items():
            got = headers.get(head, "")
            ok = need.lower() in got.lower()
            announce(ok, f"header {head!r} contains {need!r} (got {got!r})")
            if not ok:
                fails.append(f"header {head}")
        tok = find_session_token(cookies, p["cookie"])
        ok = tok is not None and re.fullmatch(SESSION_TOKEN_RE, tok) is not None
        announce(ok, f"set-cookie {p['cookie']} is 32-hex (got {tok!r})")
        if not ok:
            fails.append("session cookie")
        if any(f in lower for f in FORBIDDEN_BODY):
            fails.append("internal URL leaked in body")

    # --- Login page: structural coherence ---
    print("coherence_check: GET /login/index.php")
    st2, _, body_login, _ = fetch(target, "/login/index.php")
    low = body_login.lower()
    announce(st2 == 200, f"login page status 200 (got {st2})")
    if st2 != 200:
        fails.append("login status")
    for sentinel in p["login_markers"]:
        ok = sentinel in body_login
        announce(ok, f"login page contains {sentinel!r}")
        if not ok:
            fails.append(f"login marker {sentinel}")
    ok_lb = p["brand"] in low and "log in" in low
    announce(ok_lb, "login page carries persona brand and 'log in'")
    if not ok_lb:
        fails.append("login brand")

    # --- Brand + language coherence across HTML pages ---
    print("coherence_check: brand/language coherence")
    for path, txt in (("/", body), ("/login/index.php", body_login)):
        okc = p["brand"] in txt.lower()
        okl = f'lang="{p["lang"]}"' in txt.lower()
        announce(okc, f"{path} contains brand '{p['brand']}'")
        announce(okl, f"{path} declares lang='{p['lang']}'")
        if not okc:
            fails.append(f"brand on {path}")
        if not okl:
            fails.append(f"lang on {path}")

    # --- Themed error page ---
    print("coherence_check: themed 404 on unknown path")
    st4, _, body404, _ = fetch(target, "/definitely-not-a-page-coherence9")
    low404 = body404.lower()
    ok = st4 == 404 and "error 404" in low404 and p["brand"] in low404
    announce(ok, f"404 themed by persona (status {st4}, brand+error markers)")
    if not ok:
        fails.append("themed 404")

    # --- robots.txt / sitemap ---
    for path, marker in (("/robots.txt", "user-agent"),
                         ("/sitemap.xml", "urlset")):
        st, _, txt, _ = fetch(target, path)
        ok = st == 200 and marker in txt.lower()
        announce(ok, f"{path} served with {marker!r} marker")
        if not ok:
            fails.append(f"{path}")

    # Honeytrap pages must carry the persona's brand and lang too.
    admin_path = p.get("admin_path")
    if admin_path:
        print(f"coherence_check: GET {admin_path} (honeytrap)")
        st5, _, body_admin, _ = fetch(target, admin_path)
        low_admin = body_admin.lower()
        announce(st5 == 200, f"admin trap status 200 (got {st5})")
        if st5 != 200:
            fails.append("admin trap status")
        else:
            okc = p["brand"] in low_admin
            okl = f'lang="{p["lang"]}"' in low_admin
            announce(okc, f"{admin_path} contains brand '{p['brand']}'")
            announce(okl, f"{admin_path} declares lang='{p['lang']}'")
            if not okc:
                fails.append("brand on admin trap")
            if not okl:
                fails.append("lang on admin trap")
            if any(f in low_admin for f in FORBIDDEN_BODY):
                fails.append("internal URL leaked in admin trap body")

    # --- Summary ---
    print("-" * 60)
    if fails:
        print(f"coherence_check: FAIL - {len(fails)} incoherence(s) "
              f"for persona {persona!r}:")
        for f in sorted(set(fails)):
            print(f"  - {f}")
        return 1
    print(f"coherence_check: PASS - persona {persona!r} is coherent")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

