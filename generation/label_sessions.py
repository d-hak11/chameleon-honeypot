#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import sys
from typing import Dict, List

import yaml

RUN_SUFFIX_RE = re.compile(r"-r\d+$")

MANIFEST_LABEL_FIELDS = [
    "tool", "tool_version", "config_name", "config_args",
    "target_list_size", "timeout_budget",
    "behaviour_class", "network_profile", "active_persona",
    "probe_rate", "repetition",
]


def load_manifest(path: str) -> Dict[str, dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    runs = data.get("runs") or []
    by_id: Dict[str, dict] = {}
    for run in runs:
        run_id = str(run.get("run_id") or "")
        if not run_id:
            raise ValueError(f"manifest entry missing run_id: {run!r}")
        if run_id in by_id:
            raise ValueError(f"duplicate run_id in manifest: {run_id!r}")
        by_id[run_id] = run
    return by_id


def base_run_id(session_run_id: str) -> str:
    """Strip the -rNN repetition suffix to get the manifest run_id."""
    return RUN_SUFFIX_RE.sub("", session_run_id)


def label_rows(rows: List[Dict[str, str]], manifest: Dict[str, dict],
              drop_unmatched: bool = False
              ) -> tuple[List[Dict[str, object]], int]:
    """Returns (labelled_rows, dropped_count); fails on unmatched run_ids unless drop_unmatched."""
    labelled = []
    errors = []
    dropped = 0
    for row in rows:
        session_run_id = row.get("run_id", "")
        if not session_run_id:
            if drop_unmatched:
                dropped += 1
                continue
            errors.append(f"session {row.get('session_id')}: empty run_id -- "
                          "not from a controlled generation run, cannot label")
            continue
        base = base_run_id(session_run_id)
        manifest_run = manifest.get(base)
        if manifest_run is None:
            if drop_unmatched:
                dropped += 1
                continue
            errors.append(f"session {row.get('session_id')}: run_id "
                          f"{session_run_id!r} (base {base!r}) has no matching "
                          "entry in the manifest")
            continue
        merged = dict(row)
        merged["manifest_run_id"] = base
        for field in MANIFEST_LABEL_FIELDS:
            merged[field] = manifest_run.get(field)
        labelled.append(merged)

    if errors:
        for e in errors:
            print(f"label_sessions: ERROR: {e}", file=sys.stderr)
        raise SystemExit(
            f"label_sessions: {len(errors)} session(s) could not be labelled "
            "-- refusing to write a partially-labelled dataset. Fix the "
            "manifest or exclude these sessions explicitly, don't default "
            "their label."
        )
    return labelled, dropped


def write_csv(rows: List[Dict[str, object]], fieldnames: List[str], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("features_csv", help="output of analysis/extract_features.py")
    p.add_argument("manifest_yml", help="generation/run_manifest.yml")
    p.add_argument("--out", required=True)
    p.add_argument("--drop-unmatched", action="store_true",
                   help="Allowlist by manifest: drop and count rows whose "
                        "run_id has no manifest entry (empty run_id or no "
                        "match) instead of failing loudly. Use for final "
                        "extraction from a log that may carry stale/"
                        "interrupted-run contamination.")
    args = p.parse_args(argv)

    with open(args.features_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        base_fields = reader.fieldnames or []
        rows = list(reader)

    manifest = load_manifest(args.manifest_yml)
    labelled, dropped = label_rows(rows, manifest, drop_unmatched=args.drop_unmatched)

    fieldnames = base_fields + ["manifest_run_id"] + MANIFEST_LABEL_FIELDS
    write_csv(labelled, fieldnames, args.out)
    print(f"label_sessions: {len(labelled)} sessions labelled -> {args.out}")
    if args.drop_unmatched:
        print(f"label_sessions: {dropped} session(s) excluded by allowlist "
             "(no matching manifest run_id)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
