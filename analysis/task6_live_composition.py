#!/usr/bin/env python3
from __future__ import annotations

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise


def bucket(n: int) -> str:
    if n == 1:
        return "1"
    if 2 <= n <= 3:
        return "2-3"
    if 4 <= n <= 9:
        return "4-9"
    return "10+"


def compute(requests, label: str):
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    ext_sessions = []
    for s in sessions:
        feats = extract(s)
        if not feats["source_private"]:
            ext_sessions.append(feats)

    counts = {"1": 0, "2-3": 0, "4-9": 0, "10+": 0}
    for f in ext_sessions:
        counts[bucket(f["count"])] += 1
    total = len(ext_sessions)
    multi = total - counts["1"]

    print(f"\n{label}")
    print(f"  external sessions: {total}")
    if total:
        for b in ("1", "2-3", "4-9", "10+"):
            print(f"    {b:5s} requests: {counts[b]:4d}  ({100*counts[b]/total:.1f}%)")
        print(f"  multi-request share (count>=2): {multi}/{total} ({100*multi/total:.1f}%)")
    return counts, total


def main() -> int:
    paths = sorted(glob.glob("live-data/**/access.json", recursive=True))
    print(f"Reading {len(paths)} raw log files (read_requests() de-duplicates "
         f"on ts/remote_port/duration/uri/ip internally)")
    requests = read_requests(paths)
    print(f"Total de-duplicated request records: {len(requests)}")

    # Raw line count, for comparison against the deduplicated count.
    raw_lines = 0
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            raw_lines += sum(1 for _ in f)
    print(f"Total raw lines across all {len(paths)} files (includes non-request "
         f"log lines and the cross-snapshot duplication): {raw_lines}")

    ext_requests = [r for r in requests if not r.source_private]
    print(f"External (non-private) requests: {len(ext_requests)}")

    all_sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    all_feats = [extract(s) for s in all_sessions]
    ext_feats = [f for f in all_feats if not f["source_private"]]

    print(f"\nTotal sessions (all, incl. internal): {len(all_sessions)}")
    print(f"External sessions: {len(ext_feats)}")
    print(f"Distinct source_hash (external): {len(set(f['source_hash'] for f in ext_feats))}")
    print(f"Distinct source_hash (all): {len(set(f['source_hash'] for f in all_feats))}")

    counts, total = compute(requests, "FULL CAPTURE (2026-09-07 through 2026-09-18)")

    largest = max(ext_feats, key=lambda f: f["count"])
    print(f"\nLargest external session: {largest['count']} requests "
         f"(session_id={largest['session_id']}, source_hash={largest['source_hash'][:16]}...)")

    # Exposure-time cutoffs on the SAME de-duplicated data.
    first_ts = min(r.ts for r in requests)
    print(f"\nExposure-time simulation (same de-duplicated data, filtered by ts cutoff "
         f"from first observed request at {first_ts:.0f}):")
    for hours in (4.5, 24, 24 * 6, 24 * 11):
        cutoff = first_ts + hours * 3600
        subset = [r for r in requests if r.ts <= cutoff]
        compute(subset, f"exposure <= {hours}h ({len(subset)} de-duplicated requests in window)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
