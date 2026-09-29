#!/usr/bin/env python3
"""
switch_caddy.py -- Phase 3 switching mechanism.

The reverse_proxy upstream in the canonical Caddy JSON config is the only part
that changes when the honeypot rotates persona. This tool has two modes, used
together by tools/switch_persona.sh:

    set <config.json> <persona>            rewrite the upstream dial in the file
    load <admin-url> <config.json>         POST the file to the Caddy admin API

`load` talks to the Caddy admin API on the internal network (http://proxy:2019),
the same route the Phase 4 engine will use. The admin port is *never* published
to the host (see README.md).

Usage:
    python3 switch_caddy.py set  proxy/caddy.json registry
    python3 switch_caddy.py load http://proxy:2019 proxy/caddy.json
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

VALID_PERSONAS = {"moodle", "registry", "finance", "research"}
SRV = "srv0"


def find_proxy(cfg):
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get(SRV)
    if not srv:
        raise ValueError(f"no http server named {SRV} in config")
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "reverse_proxy":
                return handle
    raise ValueError("no reverse_proxy handler in config")


def find_persona_logger(cfg):
    """The log_append handler that stamps each access-log line with the
    persona actually serving it (Phase 4) -- kept in sync with the upstream
    here so a manual switch doesn't leave request-level attribution stale."""
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get(SRV)
    if not srv:
        return None
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "log_append" and handle.get("key") == "persona":
                return handle
    return None


def find_timing_probe(cfg):
    """The Phase 5 timing_probe handler (proxy/timingprobe/) -- its `persona`
    field must track the upstream so it reads the right manifest.yml timing
    block; kept in sync here for the same reason as find_persona_logger."""
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get(SRV)
    if not srv:
        return None
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "timing_probe":
                return handle
    return None


def cmd_set(path, persona):
    if persona not in VALID_PERSONAS:
        sys.exit(f"switch_caddy: unknown persona {persona!r}; "
                 f"valid: {sorted(VALID_PERSONAS)}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    find_proxy(cfg)["upstreams"] = [{"dial": f"{persona}:80"}]
    logger = find_persona_logger(cfg)
    if logger is not None:
        logger["value"] = persona
    probe = find_timing_probe(cfg)
    if probe is not None:
        probe["persona"] = persona
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print(f"switch_caddy: config {path} now targets {persona}:80")


def cmd_load(admin, path):
    with open(path, "r", encoding="utf-8") as f:
        body = f.read().encode("utf-8")
    req = urllib.request.Request(
        admin.rstrip("/") + "/load",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as e:
        sys.exit(f"switch_caddy: admin /load failed HTTP {e.code}: "
                 f"{e.read().decode('utf-8', 'replace')}")
    print(f"switch_caddy: /load accepted (HTTP {resp.status}); "
          f"proxy upstream updated at runtime")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    mode = argv[0]
    if mode == "set" and len(argv) == 3:
        cmd_set(argv[1], argv[2])
        return 0
    if mode == "load" and len(argv) == 3:
        cmd_load(argv[1], argv[2])
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
