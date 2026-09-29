#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from heuristic_patterns import PROBE_RE, SUSPICIOUS_QS_RE, get_ua_category

ACCESS_MSG = "handled request"

# Matches engine SESSION_IDLE, but kept independent (no shared code path).
DEFAULT_IDLE_SECONDS = 1800.0

# Plausibility ceiling on rate; exceeding it nulls rate and sets rate_implausible.
MAX_PLAUSIBLE_RATE_PER_SEC = 200.0

FIELDNAMES = [
    "session_id", "run_id", "source_hash", "source_private", "first_seen", "last_seen", "duration_seconds",
    "count", "rate", "rate_implausible",
    "distinct_paths", "path_count_total", "repeat_visit_count",
    "path_entropy", "path_ordering_alphabetical_score",
    "method_diversity", "methods",
    "errors", "n404", "status_2xx_ratio", "status_4xx_ratio", "status_5xx_ratio",
    "probes", "probe_ratio",
    "suspicious_qs", "query_count", "query_present_ratio",
    "query_string_mean_length", "query_string_max_length",
    "user_agents", "primary_ua_category",
    "persona", "personas_seen",
    "pre_probe_interval_mean", "post_probe_interval_mean",
    "pre_timing_probe_interval_mean", "post_timing_probe_interval_mean",
    "timing_probe_interval_delta_ms",
    "post_probe_request_count", "post_probe_repeat_visit_count",
    "trap_hits", "trap_ids_hit", "trap_diversity", "first_trap_idx",
    "hidden_field_tampered", "fake_cookie_tampered", "weak_credential_used",
    "header_order_fingerprint", "header_order_consistent",
    "connection_reused_ratio",
    "probe_count",
    "probe_delay_ms_values", "abandoned_count", "abandonment_rate",
    "abandon_after_ms_values",
    "bytes", "avg_duration",
]


@dataclass
class Request:
    ts: float
    # Session key: salted source_hash in production, remote_ip in local dev.
    ip: str
    remote_port: str
    method: str
    uri: str
    status: int
    size: int
    duration: float
    user_agent: str
    persona: str
    header_names: Tuple[str, ...]  # in wire order, as Caddy logged them
    source_private: bool
    probe_applied: bool
    probe_delay_ms: Optional[int]
    client_abandoned: Optional[bool]
    abandon_after_ms: Optional[int]
    # Per-repetition run_id keeps back-to-back generated runs from merging into one session.
    run_id: str
    trap_triggered: bool
    trap_id: Optional[str]
    trap_field_modified: Optional[bool]

    @property
    def path(self) -> str:
        return self.uri.split("?", 1)[0].lower()

    @property
    def query(self) -> str:
        return self.uri.split("?", 1)[1] if "?" in self.uri else ""


def _is_private(raw_ip: str) -> bool:
    """Fallback when source_private is missing: private/loopback means our own infra."""
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback
            or addr.is_link_local or addr.is_reserved)


def parse_line(entry: dict) -> Optional[Request]:
    if entry.get("msg") != ACCESS_MSG:
        return None
    req = entry.get("request")
    if not isinstance(req, dict):
        return None
    try:
        ts = float(entry["ts"])
    except (KeyError, TypeError, ValueError):
        return None
    if not ts:
        return None
    headers = req.get("headers") or {}
    ua = headers.get("User-Agent")
    if isinstance(ua, list):
        ua = ua[0] if ua else ""
    raw_ip = str(req.get("remote_ip") or "")
    source_hash = str(entry.get("source_hash") or "")
    if entry.get("source_private") is not None:
        source_private = bool(entry.get("source_private"))
    else:
        source_private = _is_private(raw_ip)

    return Request(
        ts=ts,
        ip=source_hash or raw_ip or "?",
        source_private=source_private,
        remote_port=str(req.get("remote_port") or ""),
        method=str(req.get("method") or ""),
        uri=str(req.get("uri") or ""),
        status=int(entry.get("status") or 0),
        size=int(entry.get("size") or 0),
        duration=float(entry.get("duration") or 0.0),
        user_agent=str(ua or ""),
        persona=str(entry.get("persona") or ""),
        header_names=tuple(headers.keys()),
        probe_applied=bool(entry.get("probe_applied") or False),
        probe_delay_ms=(int(entry["probe_delay_ms"])
                       if entry.get("probe_delay_ms") is not None else None),
        client_abandoned=(bool(entry["client_abandoned"])
                          if entry.get("client_abandoned") is not None else None),
        abandon_after_ms=(int(entry["abandon_after_ms"])
                          if entry.get("abandon_after_ms") is not None else None),
        run_id=str(entry.get("run_id") or ""),
        trap_triggered=bool(entry.get("trap_triggered") or False),
        trap_id=(str(entry["trap_id"]) if entry.get("trap_id") is not None else None),
        trap_field_modified=(bool(entry["trap_field_modified"])
                             if entry.get("trap_field_modified") is not None else None),
    )


def read_requests(paths: Sequence[str]) -> List[Request]:
    """Dedup on (ts, remote_port, duration, uri, ip): un-rotated logs overlap across shipped files."""
    requests: List[Request] = []
    seen: set = set()
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec = parse_line(entry)
                if rec is None:
                    continue
                key = (rec.ts, rec.remote_port, rec.duration, rec.uri, rec.ip)
                if key in seen:
                    continue
                seen.add(key)
                requests.append(rec)
    return requests


def sessionise(requests: List[Request], idle_seconds: float) -> List[List[Request]]:
    """Group by source with an idle gap; a run_id change also forces a boundary."""
    by_ip: Dict[str, List[Request]] = {}
    for r in sorted(requests, key=lambda r: (r.ip, r.ts)):
        by_ip.setdefault(r.ip, []).append(r)

    sessions: List[List[Request]] = []
    for ip in sorted(by_ip):
        recs = by_ip[ip]
        current: List[Request] = [recs[0]]
        for r in recs[1:]:
            gap_exceeded = r.ts - current[-1].ts > idle_seconds
            run_changed = r.run_id != current[-1].run_id
            if gap_exceeded or run_changed:
                sessions.append(current)
                current = []
            current.append(r)
        sessions.append(current)
    return sessions


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _header_fingerprint(header_names: Tuple[str, ...]) -> str:
    """Fingerprint of header name order (distinguishes clients even if UA is spoofed)."""
    joined = "|".join(header_names)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def session_id(ip: str, first_ts: float) -> str:
    raw = f"{ip}:{first_ts:.6f}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def extract(session: List[Request]) -> Dict[str, object]:
    n = len(session)
    ts_list = [r.ts for r in session]
    first_seen, last_seen = ts_list[0], ts_list[-1]
    duration = last_seen - first_seen
    rate = (n - 1) / duration if duration > 0 else None  # null, not Infinity
    rate_implausible = rate is not None and rate > MAX_PLAUSIBLE_RATE_PER_SEC
    if rate_implausible:
        rate = None

    paths_seq = [r.path for r in session]
    distinct_paths = len(set(paths_seq))
    repeat_visit_count = n - distinct_paths

    alpha_pairs = sum(1 for i in range(len(paths_seq) - 1)
                      if paths_seq[i] < paths_seq[i + 1])
    alpha_score = alpha_pairs / (len(paths_seq) - 1) if len(paths_seq) > 1 else 0.0

    methods = sorted({r.method for r in session})
    errors = sum(1 for r in session if r.status >= 400)
    n404 = sum(1 for r in session if r.status == 404)

    probe_flags = [bool(PROBE_RE.search(r.path)) for r in session]
    probes = sum(probe_flags)
    suspicious = sum(1 for r in session if SUSPICIOUS_QS_RE.search(r.query))
    query_lengths = [len(r.query) for r in session if r.query]

    user_agents = sorted({r.user_agent for r in session if r.user_agent})
    ua_counts: Dict[str, int] = {}
    for r in session:
        if r.user_agent:
            ua_counts[r.user_agent] = ua_counts.get(r.user_agent, 0) + 1
    # Sort first so ties break alphabetically.
    primary_ua = (max(sorted(ua_counts), key=lambda u: ua_counts[u])
                 if ua_counts else "")

    personas_seen = sorted({r.persona for r in session if r.persona})

    first_probe_idx = next((i for i, flag in enumerate(probe_flags) if flag), None)
    pre_probe_interval_mean: Optional[float] = None
    post_probe_interval_mean: Optional[float] = None
    if first_probe_idx is not None:
        pre_gaps = [ts_list[i + 1] - ts_list[i] for i in range(first_probe_idx)]
        post_gaps = [ts_list[i + 1] - ts_list[i]
                    for i in range(first_probe_idx, len(ts_list) - 1)]
        if pre_gaps:
            pre_probe_interval_mean = sum(pre_gaps) / len(pre_gaps)
        if post_gaps:
            post_probe_interval_mean = sum(post_gaps) / len(post_gaps)

    # Gaps use arrival time (ts - duration): ts is completion time, which would leak the hold into the baseline.
    first_timing_probe_idx = next(
        (i for i, r in enumerate(session) if r.probe_applied), None)
    pre_timing_probe_interval_mean: Optional[float] = None
    post_timing_probe_interval_mean: Optional[float] = None
    if first_timing_probe_idx is not None:
        arrival_ts_list = [r.ts - r.duration for r in session]
        pre_tp_gaps = [arrival_ts_list[i + 1] - arrival_ts_list[i]
                       for i in range(first_timing_probe_idx)]
        post_tp_gaps = [arrival_ts_list[i + 1] - arrival_ts_list[i]
                        for i in range(first_timing_probe_idx, len(arrival_ts_list) - 1)]
        if pre_tp_gaps:
            pre_timing_probe_interval_mean = sum(pre_tp_gaps) / len(pre_tp_gaps)
        if post_tp_gaps:
            post_timing_probe_interval_mean = sum(post_tp_gaps) / len(post_tp_gaps)

    # Signed interval change across the hold in ms (negative = sped up).
    timing_probe_interval_delta_ms: Optional[float] = None
    if (pre_timing_probe_interval_mean is not None
            and post_timing_probe_interval_mean is not None):
        timing_probe_interval_delta_ms = (
            (post_timing_probe_interval_mean - pre_timing_probe_interval_mean) * 1000.0)

    post_probe_request_count: Optional[int] = None
    post_probe_repeat_visit_count: Optional[int] = None
    if first_timing_probe_idx is not None:
        seen_before_and_including_probe = set(paths_seq[:first_timing_probe_idx + 1])
        post_probe_paths = paths_seq[first_timing_probe_idx + 1:]
        post_probe_request_count = len(post_probe_paths)
        post_probe_repeat_visit_count = sum(
            1 for p in post_probe_paths if p in seen_before_and_including_probe)

    trap_flags = [r.trap_triggered for r in session]
    trap_hits = sum(trap_flags)
    trap_ids_hit = sorted({r.trap_id for r in session if r.trap_id})
    first_trap_idx = next((i for i, flag in enumerate(trap_flags) if flag), None)
    hidden_field_tampered = any(r.trap_id == "hidden_field_modified" for r in session)
    fake_cookie_tampered = any(r.trap_id == "fake_cookie_tampered" for r in session)
    weak_credential_used = any(r.trap_id == "weak_credential_used" for r in session)

    fingerprints = [_header_fingerprint(r.header_names) for r in session]
    header_order_fingerprint = fingerprints[0] if fingerprints else ""
    header_order_consistent = len(set(fingerprints)) <= 1

    # connection_reused: derived from remote_port staying constant between requests.
    reused = sum(1 for i in range(1, n)
                if session[i].remote_port == session[i - 1].remote_port
                and session[i].remote_port != "")
    connection_reused_ratio = reused / (n - 1) if n > 1 else 0.0

    # Requests actually held by timing_probe (not PROBE_RE path hits).
    probe_count = sum(1 for r in session if r.probe_applied)

    probed = [r for r in session if r.probe_applied]
    probed_delays = [r.probe_delay_ms for r in probed if r.probe_delay_ms is not None]
    abandon_flags = [r.client_abandoned for r in probed if r.client_abandoned is not None]
    abandoned_count = sum(1 for f in abandon_flags if f)
    abandonment_rate = abandoned_count / len(abandon_flags) if abandon_flags else None
    abandon_after = [r.abandon_after_ms for r in probed
                     if r.client_abandoned and r.abandon_after_ms is not None]

    return {
        "session_id": session_id(session[0].ip, first_seen),
        "run_id": session[0].run_id,
        "source_hash": session[0].ip,
        # Exposed rather than dropped: excluding rows is an analysis decision.
        "source_private": session[0].source_private,
        "first_seen": round(first_seen, 6),
        "last_seen": round(last_seen, 6),
        "duration_seconds": round(duration, 6),
        "count": n,
        "rate": round(rate, 6) if rate is not None else None,
        "rate_implausible": rate_implausible,
        "distinct_paths": distinct_paths,
        "path_count_total": n,
        "repeat_visit_count": repeat_visit_count,
        "path_entropy": round(_entropy("".join(paths_seq)), 6),
        "path_ordering_alphabetical_score": round(alpha_score, 6),
        "method_diversity": len(methods),
        "methods": "|".join(methods),
        "errors": errors,
        "n404": n404,
        "status_2xx_ratio": round(sum(1 for r in session if 200 <= r.status < 300) / n, 6),
        "status_4xx_ratio": round(sum(1 for r in session if 400 <= r.status < 500) / n, 6),
        "status_5xx_ratio": round(sum(1 for r in session if r.status >= 500) / n, 6),
        "probes": probes,
        "probe_ratio": round(probes / n, 6),
        "suspicious_qs": suspicious,
        "query_count": len(query_lengths),
        "query_present_ratio": round(len(query_lengths) / n, 6),
        "query_string_mean_length": (round(sum(query_lengths) / len(query_lengths), 3)
                                     if query_lengths else 0.0),
        "query_string_max_length": max(query_lengths) if query_lengths else 0,
        "user_agents": "|".join(user_agents),
        "primary_ua_category": get_ua_category(primary_ua),
        "persona": session[-1].persona,
        "personas_seen": "|".join(personas_seen),
        "pre_probe_interval_mean": (round(pre_probe_interval_mean, 6)
                                    if pre_probe_interval_mean is not None else None),
        "post_probe_interval_mean": (round(post_probe_interval_mean, 6)
                                     if post_probe_interval_mean is not None else None),
        "pre_timing_probe_interval_mean": (round(pre_timing_probe_interval_mean, 6)
                                           if pre_timing_probe_interval_mean is not None else None),
        "post_timing_probe_interval_mean": (round(post_timing_probe_interval_mean, 6)
                                            if post_timing_probe_interval_mean is not None else None),
        "timing_probe_interval_delta_ms": (round(timing_probe_interval_delta_ms, 3)
                                           if timing_probe_interval_delta_ms is not None else None),
        "post_probe_request_count": post_probe_request_count,
        "post_probe_repeat_visit_count": post_probe_repeat_visit_count,
        "trap_hits": trap_hits,
        "trap_ids_hit": "|".join(trap_ids_hit),
        "trap_diversity": len(trap_ids_hit),
        "first_trap_idx": first_trap_idx,
        "hidden_field_tampered": hidden_field_tampered,
        "fake_cookie_tampered": fake_cookie_tampered,
        "weak_credential_used": weak_credential_used,
        "header_order_fingerprint": header_order_fingerprint,
        "header_order_consistent": header_order_consistent,
        "connection_reused_ratio": round(connection_reused_ratio, 6),
        "probe_count": probe_count,
        "probe_delay_ms_values": "|".join(str(d) for d in probed_delays),
        "abandoned_count": abandoned_count,
        "abandonment_rate": (round(abandonment_rate, 6)
                             if abandonment_rate is not None else None),
        "abandon_after_ms_values": "|".join(str(a) for a in abandon_after),
        "bytes": sum(r.size for r in session),
        "avg_duration": round(sum(r.duration for r in session) / n, 6),
    }


def write_csv(rows: List[Dict[str, object]], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", help="Caddy access log file(s) (JSON lines)")
    parser.add_argument("--out", required=True, help="output CSV path")
    parser.add_argument("--idle-seconds", type=float, default=DEFAULT_IDLE_SECONDS,
                        help=f"session idle gap in seconds (default {DEFAULT_IDLE_SECONDS})")
    args = parser.parse_args(argv)

    requests = read_requests(args.logs)
    sessions = sessionise(requests, args.idle_seconds)
    # Sort output rows deterministically: by first_seen, then ip.
    rows = sorted((extract(s) for s in sessions),
                 key=lambda row: (row["first_seen"], row["source_hash"]))
    write_csv(rows, args.out)
    print(f"extract_features: {len(rows)} sessions from {len(requests)} requests "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
