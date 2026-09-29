#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_FILE = os.path.join(REPO, "secrets", "trap_secret.env")
ENV_VAR = "CHAMELEON_TRAP_SECRET"

# Matches the trap cookie line in nginx.conf.
COOKIE_RE = re.compile(
    r'(add_header\s+Set-Cookie\s+"(?P<name>[A-Za-z0-9_]+)='
    r'(?P<payload>[^.";]+)\.)(?P<mac>[0-9a-f]+)')


def mac_for(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def manifest_trap_keys(persona: str) -> dict:
    """That persona's own cookie_name and cookie_secret."""
    path = os.path.join(REPO, "personas", persona, "manifest.yml")
    keys = {}
    if not os.path.isfile(path):
        return keys
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            for k in ("cookie_name", "cookie_secret", "cookie_default_value"):
                if stripped.startswith(k + ":"):
                    keys[k] = stripped.split(":", 1)[1].split("#")[0].strip()
    return keys


def personas() -> list:
    root = os.path.join(REPO, "personas")
    out = []
    for name in sorted(os.listdir(root)):
        conf = os.path.join(root, name, "conf", "nginx.conf")
        if os.path.isfile(conf):
            out.append((name, conf))
    return out


def active_secret(persona: str) -> str:
    """Env override if set, else the persona's manifest default."""
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, encoding="utf-8") as f:
            for line in f:
                if line.startswith(ENV_VAR + "="):
                    return line.split("=", 1)[1].strip()
    return manifest_trap_keys(persona).get("cookie_secret", "")


def find_trap_cookie(text: str, cookie_name: str):
    """The Set-Cookie line for this persona's trap cookie (not its session cookie)."""
    for m in COOKIE_RE.finditer(text):
        if m.group("name") == cookie_name:
            return m
    return None


def check() -> int:
    source = ("secrets/trap_secret.env" if os.path.exists(SECRET_FILE)
              else "per-persona manifest defaults")
    print(f"trap secret source: {source}")
    bad = 0
    for name, conf in personas():
        keys = manifest_trap_keys(name)
        cookie_name = keys.get("cookie_name", "")
        secret = active_secret(name)
        if not cookie_name or not secret:
            print(f"  {name:10s} no cookie trap configured -- skipped")
            continue
        with open(conf, encoding="utf-8") as f:
            text = f.read()
        m = find_trap_cookie(text, cookie_name)
        if m is None:
            bad += 1
            print(f"  {name:10s} manifest configures cookie trap {cookie_name!r} but "
                  f"nginx.conf issues no such cookie -- the trap can never fire")
            continue
        want = mac_for(secret, m.group("payload"))
        ok = hmac.compare_digest(want, m.group("mac"))
        if not ok:
            bad += 1
        print(f"  {name:10s} {m.group('name')}={m.group('payload')}  "
              f"{'OK' if ok else 'MISMATCH -- nginx issues a cookie this secret will reject'}")
    if bad:
        print(f"\n{bad} persona(s) misconfigured: untouched traffic would be recorded as "
              f"fake_cookie_tampered, or the trap cannot fire at all. Run without --check "
              f"to resynchronise the MACs.", file=sys.stderr)
        return 1
    print("\nAll issued cookie MACs verify against the active secret.")
    return 0


def rotate() -> int:
    secret = secrets.token_hex(32)
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(f"{ENV_VAR}={secret}\n")
    os.chmod(SECRET_FILE, 0o600)
    print(f"wrote {os.path.relpath(SECRET_FILE, REPO)} (gitignored, mode 600)")

    changed = 0
    for name, conf in personas():
        cookie_name = manifest_trap_keys(name).get("cookie_name", "")
        if not cookie_name:
            continue
        with open(conf, encoding="utf-8") as f:
            text = f.read()
        m = find_trap_cookie(text, cookie_name)
        if m is None:
            print(f"  {name:10s} WARNING: no {cookie_name!r} Set-Cookie in nginx.conf; "
                  f"trap cannot fire", file=sys.stderr)
            continue
        new_mac = mac_for(secret, m.group("payload"))
        start, end = m.span("mac")
        text = text[:start] + new_mac + text[end:]
        with open(conf, "w", encoding="utf-8") as f:
            f.write(text)
        changed += 1
        print(f"  {name:10s} recomputed MAC for {m.group('name')}={m.group('payload')}")

    print(f"\n{changed} persona nginx.conf file(s) updated -- commit them: the MAC is "
          f"not secret (an HMAC does not reveal its key, and every client receives it), "
          f"but it must travel with the code that issues it.")
    print("Rebuild and restart the proxy so both sides pick up the change:")
    print("    docker compose up -d --build proxy")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true",
                   help="verify the issued MACs match the active secret; change nothing")
    args = p.parse_args()
    return check() if args.check else rotate()


if __name__ == "__main__":
    sys.exit(main())
