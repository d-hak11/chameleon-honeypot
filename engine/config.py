#!/usr/bin/env python3
import os
from typing import List


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_csv(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return list(default)
    return [part.strip() for part in raw.split(",") if part.strip()]


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


class Config:
    def __init__(self) -> None:
        # Input / output touchpoints.
        self.admin_url = os.environ.get("CADDY_ADMIN_URL", "http://proxy:2019")
        # Runtime state on a volume, not the repo (see Actuator).
        self.caddy_config = os.environ.get(
            "CADDY_CONFIG", "/var/lib/chameleon/caddy-active.json")
        # The committed, read-only seed copied to caddy_config on first run.
        self.caddy_seed_config = os.environ.get(
            "CADDY_SEED_CONFIG", "/etc/chameleon/caddy.json")
        self.access_log = os.environ.get("ACCESS_LOG", "/var/log/caddy/access.json")
        self.decisions_log = os.environ.get("DECISIONS_LOG", "/tmp/decisions.jsonl")

        # Loop pacing.
        self.tick_seconds = _get_float("TICK_SECONDS", 1.0)
        self.evaluate_interval = _get_float("EVALUATE_INTERVAL", 10.0)

        # Sessionisation.
        self.session_idle = _get_float("SESSION_IDLE", 1800.0)   # 30 min split gap
        self.recent_window = _get_float("RECENT_WINDOW", 60.0)   # classifier window
        self.min_requests = _get_int("MIN_REQUESTS", 4)
        self.min_distinct_paths = _get_int("MIN_DISTINCT_PATHS", 5)

        # Policy / actuation.
        self.switch_dwell = _get_float("SWITCH_DWELL", 45.0)     # min between switches
        self.quiet_settle = _get_float("QUIET_SETTLE", 600.0)    # restore default after
        self.health_timeout = _get_float("HEALTH_TIMEOUT", 3.0)
        # Active = seen within this many seconds; rotation waits until nothing is active.
        self.active_grace = _get_float("ACTIVE_GRACE", 15.0)

        # Exclude private/loopback sources as our own infra (set false for local dev).
        self.exclude_private = _get_bool("EXCLUDE_PRIVATE", True)
        self.exclude_ips = _get_csv("EXCLUDE_IPS", [])

        self.state_file = os.environ.get("STATE_FILE", "/tmp/chameleon-engine-state.json")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"Config(admin={self.admin_url!r}, access={self.access_log!r}, "
                f"eval={self.evaluate_interval}s, window={self.recent_window}s, "
                f"dwell={self.switch_dwell}s, settle={self.quiet_settle}s)")