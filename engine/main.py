#!/usr/bin/env python3
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import actuate
import classify
import config
import policy
import session
import tail

from classify import HOSTILE


class ShutdownRequested(Exception):
    """Raised on SIGTERM so the loop can flush state and exit cleanly."""


def _install_sigterm_handler() -> None:
    def _handler(signum: int, frame: object) -> None:
        raise ShutdownRequested()
    signal.signal(signal.SIGTERM, _handler)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_line(**fields: object) -> None:
    fields.setdefault("ts", utcnow())
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()


class DecisionsLog:
    """Append-only log of hostile classifications and switches; keeps several rotated generations."""

    def __init__(self, path: str, max_bytes: int = 10_000_000, keep: int = 5):
        self.path = path
        self.max_bytes = max_bytes
        self.keep = keep

    def append(self, obj: Dict[str, object]) -> None:
        try:
            if self._size() > self.max_bytes:
                self._rotate()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
        except OSError as err:
            log_line(level="warn", event="decisions_log_error", error=str(err))

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _rotate(self) -> None:
        oldest = f"{self.path}.{self.keep}"
        try:
            discarded = os.path.getsize(oldest)
        except OSError:
            discarded = 0
        if discarded:
            log_line(level="warn", event="decisions_log_discarded",
                     path=oldest, bytes=discarded,
                     note="oldest retained generation dropped by rotation")
        try:
            for n in range(self.keep, 0, -1):
                src = self.path if n == 1 else f"{self.path}.{n - 1}"
                if os.path.exists(src):
                    os.replace(src, f"{self.path}.{n}")
        except OSError as err:
            log_line(level="warn", event="decisions_log_rotate_error", error=str(err))


def save_state(path: str, tracker: session.SessionTracker) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(session.to_dict(tracker), f)
    except OSError as err:
        log_line(level="warn", event="state_save_error", error=str(err))


def load_state(path: str, default_idle: float) -> session.SessionTracker:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return session.from_dict(data)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as err:
        log_line(level="info", event="state_load_skipped", reason=str(err))
        return session.SessionTracker(idle=default_idle)


def collect_rows(cfg: config.Config, tracker: session.SessionTracker,
                 now: float, current_persona: str, exclude_ips: List[str]
                 ) -> Tuple[List[Dict[str, object]], int]:
    tracker.expire(now)
    rows: List[Dict[str, object]] = []
    hostile_count = 0
    for sess in tracker.sessions.values():
        if cfg.exclude_private and sess.source_private:
            continue
        if sess.ip in exclude_ips:
            continue
        feats = session.session_features(sess, now, cfg.recent_window,
                                         cfg.min_requests, cfg.min_distinct_paths)
        if feats["count"] == 0:
            continue
        cls = classify.classify(feats)
        rate = feats.get("rate")
        # Prefer the per-request persona stamp; fall back for older log lines.
        row: Dict[str, object] = {
            "event": "evaluation",
            "ts": utcnow(),
            # Salted hash in production, never the raw address.
            "source": sess.ip,
            "label": cls.label,
            "confidence": round(cls.confidence, 3),
            "reasons": cls.reasons,
            "count": feats["count"],
            "lifetime_req": feats["lifetime"],
            "rate": round(float(rate), 3) if rate is not None else None,
            "distinct_paths": feats.get("distinct_paths", 0),
            "errors": feats.get("errors", 0),
            "persona": feats.get("persona") or current_persona,
            "personas_seen": feats.get("personas_seen", []),
            "last_seen": sess.last_seen,
        }
        rows.append(row)
        log_line(**row)
        if cls.label in HOSTILE:
            hostile_count += 1
    return rows, hostile_count


def evaluate(cfg: config.Config, tracker: session.SessionTracker,
             switcher: policy.SwitchPolicy, actuator: actuate.Actuator,
             decisions: DecisionsLog, now: float) -> None:
    rows, hostile_count = collect_rows(cfg, tracker, now, switcher.current,
                                       cfg.exclude_ips)

    for row in rows:
        if row["label"] in HOSTILE:
            decisions.append(row)

    # Active = seen within active_grace; policy defers switches while any source is active.
    classifications: List[Tuple[str, str, float, bool]] = [
        (str(r["source"]), str(r["label"]), float(r["confidence"]),
         (now - float(r["last_seen"])) < cfg.active_grace)
        for r in rows
    ]
    current = actuator.current_persona()
    target, reason, hot = switcher.decide(classifications, now, current)

    if target is not None:
        served = actuator.switch_to(target)
        if served is None:
            log_line(level="warn", event="switch_failed", wanted=target,
                     persona=switcher.current, reason=reason)
            decisions.append({"event": "switch_failed", "ts": utcnow(),
                              "wanted": target, "persona": switcher.current,
                              "reason": reason})
        else:
            switcher.current = served
            switcher.last_switch = now
            log_line(level="info", event="switch", from_persona=current,
                     persona=served, wanted=target, reason=reason)
            decisions.append({"event": "switch", "ts": utcnow(),
                              "from_persona": current, "persona": served,
                              "wanted": target, "reason": reason,
                              "hostile_sessions": hostile_count})

    log_line(level="info", event="evaluation_summary",
             sessions=len(rows), hostile=hostile_count,
             labels={label: sum(1 for r in rows if r["label"] == label)
                     for label in sorted({r["label"] for r in rows})},
             persona=switcher.current, hot=hot, reason=reason)


def main() -> int:
    _install_sigterm_handler()
    cfg = config.Config()
    log_line(level="info", event="engine_start",
             admin=cfg.admin_url, config=cfg.caddy_config,
             access_log=cfg.access_log, decisions_log=cfg.decisions_log,
             exclude_ips=cfg.exclude_ips, rotation=list(policy.ROTATION))

    tailer = tail.JSONLinesTailer(cfg.access_log, start="end", poll=0.2)
    if os.path.exists(cfg.state_file):
        tracker = load_state(cfg.state_file, cfg.session_idle)
        log_line(level="info", event="state_loaded", path=cfg.state_file,
                 sessions=len(tracker.sessions))
    else:
        tracker = session.SessionTracker(idle=cfg.session_idle)
    actuator = actuate.Actuator(cfg.caddy_config, cfg.admin_url,
                                policy.ROTATION, timeout=cfg.health_timeout,
                                seed_path=cfg.caddy_seed_config)
    switcher = policy.SwitchPolicy(dwell=cfg.switch_dwell,
                                   quiet_settle=cfg.quiet_settle,
                                   default_persona=policy.ROTATION[0])
    decisions = DecisionsLog(cfg.decisions_log)

    try:
        current = actuator.current_persona()
    except Exception as err:
        current = policy.ROTATION[0]
        log_line(level="warn", event="config_read_error", error=str(err))
    switcher.current = current
    switcher.last_switch = time.time()
    log_line(level="info", event="engine_ready", persona=current)

    last_eval = 0.0
    while True:
        try:
            now = time.time()
            for entry in tailer.poll():
                rec = session.parse_request(entry)
                if rec is not None:
                    tracker.add(rec)
            if now - last_eval >= cfg.evaluate_interval:
                last_eval = now
                evaluate(cfg, tracker, switcher, actuator, decisions, now)
            time.sleep(cfg.tick_seconds)
        except ShutdownRequested:
            save_state(cfg.state_file, tracker)
            log_line(level="info", event="engine_stop", reason="sigterm",
                     state_saved=cfg.state_file)
            return 0
        except KeyboardInterrupt:
            save_state(cfg.state_file, tracker)
            log_line(level="info", event="engine_stop", reason="sigint",
                     state_saved=cfg.state_file)
            return 0
        except Exception as err:
            log_line(level="error", event="engine_error", error=str(err))
            time.sleep(5.0)


if __name__ == "__main__":
    sys.exit(main())
