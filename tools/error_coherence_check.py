#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CADDY_CONFIG = REPO_ROOT / "proxy" / "caddy.json"
REFUSED_UPSTREAM = "127.0.0.1:1"  # loopback, guaranteed nothing listens: instant ECONNREFUSED

FORBIDDEN_SERVER_VALUES = {"caddy"}
FORBIDDEN_HEADERS = {"via", "x-powered-by", "x-caddy"}


def sh(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, cwd=REPO_ROOT, **kw)


def read_config() -> dict:
    with open(CADDY_CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)


def write_config(cfg: dict) -> None:
    with open(CADDY_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def find_proxy(cfg: dict) -> dict:
    for route in cfg["apps"]["http"]["servers"]["srv0"]["routes"]:
        for h in route.get("handle", []):
            if h.get("handler") == "reverse_proxy":
                return h
    raise ValueError("no reverse_proxy handler found")


def reload(container: str) -> None:
    # docker cp instead of the bind mount, which can go stale under WSL2.
    r = sh(["docker", "cp", str(CADDY_CONFIG), f"{container}:/tmp/error_check_caddy.json"])
    if r.returncode != 0:
        sys.exit(f"error_coherence_check: docker cp failed:\n{r.stderr}")
    r = sh(["docker", "exec", container, "sh", "-c",
           "curl -sS -X POST -H 'Content-Type: application/json' "
           "--data-binary @/tmp/error_check_caddy.json "
           "http://127.0.0.1:2019/load -w '\\nHTTP %{http_code}'"])
    if "HTTP 200" not in r.stdout:
        sys.exit(f"error_coherence_check: admin /load did not return 200:\n{r.stdout}\n{r.stderr}")


def live_upstream(container: str) -> str:
    r = sh(["docker", "exec", container, "sh", "-c",
           "curl -s http://127.0.0.1:2019/config/apps/http/servers/srv0/routes/0/handle"])
    handles = json.loads(r.stdout)
    for h in handles:
        if h.get("handler") == "reverse_proxy":
            return h["upstreams"][0]["dial"]
    raise ValueError("reverse_proxy not found in live config")


def fetch_raw_headers(target: str) -> str:
    r = sh(["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", "10", target])
    return r.stdout


def main() -> int:
    container = sys.argv[1] if len(sys.argv) > 1 else "chameleon-honeypot-proxy-1"
    target = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8080/"

    print("error_coherence_check: pausing engine (it will otherwise revert "
         "an upstream it doesn't recognise)")
    sh(["docker", "compose", "stop", "engine"])

    cfg = read_config()
    original_dial = find_proxy(cfg)["upstreams"][0]["dial"]
    ok = True

    try:
        print(f"error_coherence_check: forcing reverse_proxy -> {REFUSED_UPSTREAM} "
             "(refused synchronously, no timing dependence)")
        find_proxy(cfg)["upstreams"] = [{"dial": REFUSED_UPSTREAM}]
        write_config(cfg)
        reload(container)

        live = live_upstream(container)
        if live != REFUSED_UPSTREAM:
            sys.exit(f"error_coherence_check: live config shows {live!r}, not "
                    f"{REFUSED_UPSTREAM!r} -- the reload did not take effect, "
                    "cannot proceed with a meaningless test")
        print(f"error_coherence_check: confirmed live upstream is {live!r}")

        print(f"error_coherence_check: fetching {target} (expect a hard error)")
        raw = fetch_raw_headers(target)
        print("--- raw response headers ---")
        print(raw)
        print("--- end raw response headers ---")

        status_line = raw.splitlines()[0] if raw else ""
        if " 5" not in status_line and " 4" not in status_line:
            print(f"error_coherence_check: FAIL -- expected an error status, got {status_line!r}")
            ok = False

        lower_lines = [l.lower() for l in raw.splitlines()]
        server_lines = [l for l in lower_lines if l.startswith("server:")]
        if not server_lines:
            print("error_coherence_check: FAIL -- no Server header at all on the error response")
            ok = False
        else:
            for line in server_lines:
                value = line.split(":", 1)[1].strip()
                if value in FORBIDDEN_SERVER_VALUES:
                    print(f"error_coherence_check: FAIL -- Server header leaked: {line!r}")
                    ok = False
                elif value != "nginx":
                    print(f"error_coherence_check: FAIL -- Server header is {value!r}, want 'nginx'")
                    ok = False
                else:
                    print(f"error_coherence_check: Server header correctly reads 'nginx'")

        for line in lower_lines:
            header_name = line.split(":", 1)[0].strip()
            if header_name in FORBIDDEN_HEADERS:
                print(f"error_coherence_check: FAIL -- forbidden header present: {line!r}")
                ok = False

        if ok:
            print("error_coherence_check: PASS -- error path is coherent")

    finally:
        print("error_coherence_check: restoring original upstream and resuming engine")
        cfg = read_config()
        find_proxy(cfg)["upstreams"] = [{"dial": original_dial}]
        write_config(cfg)
        reload(container)
        restored = live_upstream(container)
        if restored != original_dial:
            print(f"error_coherence_check: WARNING -- restore did not take effect "
                 f"(live={restored!r}, want {original_dial!r}); check manually", file=sys.stderr)
        sh(["docker", "compose", "start", "engine"])

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
