#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

SRV = "srv0"
VALID_PERSONAS = {"moodle", "registry", "finance", "research"}


def _route_handles(cfg: dict) -> list:
    srv = cfg["apps"]["http"]["servers"].get(SRV)
    if not srv:
        raise ValueError(f"no http server named {SRV} in config")
    handles = []
    for route in srv.get("routes", []):
        handles.extend(route.get("handle", []))
    return handles


def find_proxy(cfg: dict) -> dict:
    for h in _route_handles(cfg):
        if h.get("handler") == "reverse_proxy":
            return h
    raise ValueError("no reverse_proxy handler in config")


def find_log_append(cfg: dict, key: str):
    for h in _route_handles(cfg):
        if h.get("handler") == "log_append" and h.get("key") == key:
            return h
    return None


def find_timing_probe(cfg: dict):
    for h in _route_handles(cfg):
        if h.get("handler") == "timing_probe":
            return h
    return None


def find_traps(cfg: dict):
    for h in _route_handles(cfg):
        if h.get("handler") == "traps":
            return h
    return None


def apply_context(cfg: dict, persona: str, run_id: str, probe_rate: float) -> None:
    if persona not in VALID_PERSONAS:
        raise ValueError(f"unknown persona {persona!r}; valid: {sorted(VALID_PERSONAS)}")
    if not (0.0 <= probe_rate <= 1.0):
        raise ValueError(f"probe_rate must be in [0.0, 1.0], got {probe_rate}")

    find_proxy(cfg)["upstreams"] = [{"dial": f"{persona}:80"}]

    persona_logger = find_log_append(cfg, "persona")
    if persona_logger is not None:
        persona_logger["value"] = persona

    run_id_logger = find_log_append(cfg, "run_id")
    if run_id_logger is None:
        raise ValueError("no run_id log_append handler in config -- "
                         "was proxy/caddy.json regenerated without it?")
    run_id_logger["value"] = run_id

    probe = find_timing_probe(cfg)
    if probe is not None:
        probe["persona"] = persona
        probe["probe_rate"] = probe_rate

    traps = find_traps(cfg)
    if traps is not None:
        traps["persona"] = persona


def load_config(admin_url: str, cfg: dict, timeout: float = 15.0) -> None:
    body = json.dumps(cfg).encode("utf-8")
    req = urllib.request.Request(
        admin_url.rstrip("/") + "/load",
        data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        sys.exit(f"set_context: admin /load failed HTTP {e.code}: "
                 f"{e.read().decode('utf-8', 'replace')}")
    if resp.status != 200:
        sys.exit(f"set_context: admin /load returned HTTP {resp.status}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("config_path")
    p.add_argument("admin_url")
    p.add_argument("--persona", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--probe-rate", type=float, required=True)
    args = p.parse_args()

    with open(args.config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    apply_context(cfg, args.persona, args.run_id, args.probe_rate)

    with open(args.config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")

    load_config(args.admin_url, cfg)
    print(f"set_context: persona={args.persona} run_id={args.run_id} "
          f"probe_rate={args.probe_rate}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
