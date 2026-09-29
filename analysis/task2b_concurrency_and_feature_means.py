#!/usr/bin/env python3
from __future__ import annotations

import csv
import glob
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise
from prefix_features import find_log_files, read_requests_dedup


def nmap_concurrency_check(sample_size: int = 30) -> None:
    rows = list(csv.DictReader(open("generation/stage4_labelled.csv")))
    nmap_run_ids = [r["run_id"] for r in rows
                    if r["tool"] == "nmap" and r["behaviour_class"] == "broad_scanning"][:sample_size]

    paths = find_log_files("generation/stage4_raw_logs")
    requests = read_requests_dedup(paths)
    by_run = {}
    for r in requests:
        if r.run_id in nmap_run_ids:
            by_run.setdefault(r.run_id, []).append(r)

    total_pairs = 0
    total_overlap = 0
    sessions_with_overlap = 0
    max_concurrent = 0
    for rid, reqs in by_run.items():
        reqs = sorted(reqs, key=lambda r: r.ts)
        if len(reqs) < 2:
            continue
        windows = [(r.ts - r.duration, r.ts) for r in reqs]
        had_overlap = False
        for i in range(len(windows) - 1):
            total_pairs += 1
            if windows[i + 1][0] < windows[i][1]:
                total_overlap += 1
                had_overlap = True
        if had_overlap:
            sessions_with_overlap += 1
        events = sorted([(a, 1) for a, b in windows] + [(b, -1) for a, b in windows])
        cur = mx = 0
        for _, delta in events:
            cur += delta
            mx = max(mx, cur)
        max_concurrent = max(max_concurrent, mx)

    print(f"nmap::sweep_default concurrency check ({len(by_run)} sessions examined, "
         f"raw request arrival/completion windows from deduplicated logs):")
    print(f"  sessions with >=1 overlapping consecutive request pair: "
         f"{sessions_with_overlap}/{len(by_run)}")
    print(f"  consecutive-pair windows overlapping: {total_overlap}/{total_pairs} "
         f"({100*total_overlap/total_pairs:.1f}%)")
    print(f"  max simultaneous in-flight requests observed in any single session: "
         f"{max_concurrent}")
    print(f"  characterisation: NOT purely sequential (some overlap, up to "
         f"{max_concurrent} simultaneous), but far less concurrent than gobuster's "
         f"sustained -t 20/-t 5 thread pool (only {100*total_overlap/total_pairs:.0f}% "
         f"of pairs overlap, briefly, vs. gobuster's near-permanent overlap)")


def feature_means() -> None:
    gen_rows = list(csv.DictReader(open("generation/stage4_labelled.csv")))

    def gmean(field):
        vals = [float(r[field]) for r in gen_rows if r[field] not in ("", "None")]
        return statistics.mean(vals), len(vals)

    paths = sorted(glob.glob("live-data/**/access.json", recursive=True))
    requests = read_requests(paths)
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    live_feats = [extract(s) for s in sessions]
    live_feats = [f for f in live_feats if not f["source_private"]]

    def lmean(field):
        vals = [float(f[field]) for f in live_feats if f.get(field) not in (None, "")]
        return statistics.mean(vals), len(vals)

    print(f"\n{'feature':30s} {'generated mean':>16s} {'live mean (dedup)':>20s}")
    for field in ("distinct_paths", "method_diversity", "query_present_ratio",
                  "connection_reused_ratio"):
        gm, gn = gmean(field)
        lm, ln = lmean(field)
        print(f"{field:30s} {gm:16.4f} {lm:20.4f}   (gen n={gn}, live n={ln})")

    print("\nconnection_reused_ratio, multi-request live sessions only (count>1), "
         "for a like-for-like comparison against sessions that could show reuse at all:")
    crr = [f["connection_reused_ratio"] for f in live_feats if f["count"] > 1]
    print(f"  n={len(crr)}  mean={statistics.mean(crr):.4f}  median={statistics.median(crr):.4f}")


def main() -> int:
    nmap_concurrency_check()
    feature_means()
    return 0


if __name__ == "__main__":
    sys.exit(main())
