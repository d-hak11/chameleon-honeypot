#!/usr/bin/env python3
import json
import os
import shutil
import urllib.error
import urllib.request
from typing import List, Optional

_HEALTH_UA = "chameleon-engine/1.0"


def read_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_config(path: str, cfg: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def find_proxy(cfg: dict):
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get("srv0")
    if srv is None:
        raise ValueError("no http server srv0 in config")
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "reverse_proxy":
                return handle
    raise ValueError("no reverse_proxy handler in config")


def find_persona_logger(cfg: dict):
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get("srv0")
    if srv is None:
        raise ValueError("no http server srv0 in config")
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "log_append" and handle.get("key") == "persona":
                return handle
    return None


def find_timing_probe(cfg: dict):
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get("srv0")
    if srv is None:
        raise ValueError("no http server srv0 in config")
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "timing_probe":
                return handle
    return None


def find_traps(cfg: dict):
    servers = cfg["apps"]["http"]["servers"]
    srv = servers.get("srv0")
    if srv is None:
        raise ValueError("no http server srv0 in config")
    for route in srv.get("routes", []):
        for handle in route.get("handle", []):
            if handle.get("handler") == "traps":
                return handle
    return None


def set_upstream(cfg: dict, persona: str) -> None:
    find_proxy(cfg)["upstreams"] = [{"dial": f"{persona}:80"}]
    logger = find_persona_logger(cfg)
    if logger is not None:
        logger["value"] = persona
    probe = find_timing_probe(cfg)
    if probe is not None:
        probe["persona"] = persona
    traps = find_traps(cfg)
    if traps is not None:
        traps["persona"] = persona


def persona_reachable(persona: str, timeout: float = 3.0) -> bool:
    url = f"http://{persona}/"
    req = urllib.request.Request(url, headers={"User-Agent": _HEALTH_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def load_config(admin_url: str, cfg: dict, timeout: float = 10.0) -> bool:
    body = json.dumps(cfg).encode("utf-8")
    req = urllib.request.Request(
        admin_url.rstrip("/") + "/load",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False


class Actuator:
    """Owns the runtime Caddy config; the committed proxy/caddy.json is only a seed."""

    def __init__(self, config_path: str, admin_url: str,
                 rotation: List[str], timeout: float = 3.0,
                 seed_path: Optional[str] = None):
        self.config_path = config_path
        self.admin_url = admin_url
        self.rotation = list(rotation)
        self.timeout = timeout
        self.seed_path = seed_path
        self._seed_if_missing()

    def _seed_if_missing(self) -> None:
        if not self.seed_path or os.path.exists(self.config_path):
            return
        parent = os.path.dirname(self.config_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        shutil.copyfile(self.seed_path, self.config_path)

    def current_persona(self) -> str:
        cfg = read_config(self.config_path)
        dial = find_proxy(cfg)["upstreams"][0]["dial"]
        return dial.split(":")[0]

    def switch_to(self, desired: str) -> Optional[str]:
        """Switch to desired (or any reachable persona); returns the persona served, or None."""
        current = self.current_persona()
        if desired == current:
            return current
        order = [desired] + [p for p in self.rotation
                             if p not in (desired, current)]
        chosen = None
        for p in order:
            if persona_reachable(p, self.timeout):
                chosen = p
                break
        if chosen is None:
            return None

        cfg = read_config(self.config_path)
        set_upstream(cfg, chosen)
        write_config(self.config_path, cfg)
        if not load_config(self.admin_url, cfg):
            # Admin API refused it -- roll the canonical file back.
            rollback = read_config(self.config_path)
            set_upstream(rollback, current)
            write_config(self.config_path, rollback)
            return None
        return chosen