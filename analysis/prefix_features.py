#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extract_features import DEFAULT_IDLE_SECONDS, FIELDNAMES, extract, sessionise, parse_line

PREFIX_HORIZONS = [5, 10, 20]
EXTRA_FIELDS = ["tool", "tool_version", "config_name", "manifest_run_id", "behaviour_class"]


def find_log_files(raw_dir: str):
    return (glob.glob(os.path.join(raw_dir, "**", "*.json"), recursive=True) +
            glob.glob(os.path.join(raw_dir, "**", "*.json.gz"), recursive=True))


def read_requests_dedup(paths):
    """Gzip-aware read_requests() with the same dedup key."""
    import json
    seen = set()
    requests = []
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
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


def load_labelled_map(path: str):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    by_id = {r["session_id"]: r for r in rows}
    probed_ids = {r["session_id"] for r in rows
                  if (r.get("probe_count") or "0") not in ("", "0") and float(r["probe_count"]) > 0}
    return by_id, probed_ids


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--raw-logs", default="generation/stage4_raw_logs")
    p.add_argument("--labelled", default="generation/stage4_labelled.csv")
    p.add_argument("--out-dir", default="generation")
    args = p.parse_args(argv)

    labelled_map, probed_ids = load_labelled_map(args.labelled)
    print(f"{len(labelled_map)} labelled sessions, {len(probed_ids)} with probe_count>0 "
          f"(this is the population prefix evaluation restricts to, matching item 1's "
          f"RF analysis population).")

    paths = find_log_files(args.raw_logs)
    print(f"Reading {len(paths)} raw log files...")
    requests = read_requests_dedup(paths)
    print(f"{len(requests)} deduplicated request records.")
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    print(f"{len(sessions)} sessions after sessionising.")

    # Restrict to sessions whose session_id is in the probed population.
    qualifying = []
    for session in sessions:
        full_feats = extract(session)
        sid = full_feats["session_id"]
        if sid in probed_ids:
            qualifying.append((sid, session))
    print(f"{len(qualifying)}/{len(probed_ids)} probed sessions matched by session_id "
          f"in the raw logs (some mismatch is expected if raw logs don't cover 100% "
          f"of the labelled CSV's source range).")

    fieldnames = FIELDNAMES + EXTRA_FIELDS
    for n in PREFIX_HORIZONS:
        out_path = os.path.join(args.out_dir, f"stage4_prefix{n}.csv")
        count_included = 0
        with open(out_path, "w", newline="", encoding="utf-8") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=fieldnames)
            writer.writeheader()
            for sid, session in qualifying:
                if len(session) < n:
                    continue
                feats = extract(session[:n])
                meta = labelled_map[sid]
                for field in EXTRA_FIELDS:
                    feats[field] = meta.get(field, "")
                writer.writerow(feats)
                count_included += 1
        print(f"N={n:3d}: {count_included}/{len(qualifying)} sessions had >= {n} requests "
              f"-> {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
