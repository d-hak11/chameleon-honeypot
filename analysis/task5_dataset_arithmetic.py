#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter

import yaml


def main() -> int:
    manifest = yaml.safe_load(open("generation/run_manifest_stage4.yml"))
    expected = set()
    for r in manifest["runs"]:
        base = r["run_id"]
        for i in range(1, r["repetition"] + 1):
            expected.add(f"{base}-r{i:02d}")
    print(f"Expected run_id-rNN slots (10 x 4 x 4 x 18): {len(expected)}")

    rows = list(csv.DictReader(open("generation/stage4_labelled.csv")))
    print(f"Actual sessions in stage4_labelled.csv: {len(rows)}")

    print("\nSessions per (tool, config_name):")
    for k, v in sorted(Counter((r["tool"], r["config_name"]) for r in rows).items()):
        print(f"  {k}: {v}")
    print("\nSessions per network_profile:", dict(sorted(Counter(r["network_profile"] for r in rows).items())))
    print("Sessions per active_persona:", dict(sorted(Counter(r["active_persona"] for r in rows).items())))

    by_run_id = Counter(r["run_id"] for r in rows)
    present = set(by_run_id)
    missing = expected - present
    extra_present = present - expected

    print(f"\nDistinct run_ids present: {len(present)}")
    print(f"Expected slots with ZERO sessions (missing): {len(missing)}")
    for m in sorted(missing):
        print(f"  {m}")

    print(f"Present run_ids not in the expected set: {len(extra_present)}")

    dupes = {k: v for k, v in by_run_id.items() if v > 1}
    extra_rows = sum(v - 1 for v in dupes.values())
    print(f"\nrun_ids producing exactly 2 sessions: {sum(1 for v in dupes.values() if v == 2)}")
    print(f"run_ids producing exactly 3 sessions: {sum(1 for v in dupes.values() if v == 3)}")
    print(f"Extra rows contributed by split run_ids: {extra_rows}")

    print(f"\nReconciliation: {len(expected)} expected - {len(missing)} missing "
         f"+ {extra_rows} split-extra = {len(expected) - len(missing) + extra_rows} "
         f"(actual: {len(rows)})")

    print("\nSplit run_ids: source_hash of each session under that run_id "
         "(if they differ, the split reflects a source-identity change mid-run, "
         "not a sessioniser idle-gap artefact under one identity):")
    for rid in sorted(dupes):
        matches = [r for r in rows if r["run_id"] == rid]
        hashes = [r["source_hash"][:12] for r in matches]
        counts = [r["count"] for r in matches]
        print(f"  {rid}: {len(matches)} sessions, source_hash={hashes}, count={counts}")

    print(f"\nDistinct source_hash values across all {len(rows)} sessions: "
         f"{len(set(r['source_hash'] for r in rows))}")
    hc = Counter(r["source_hash"][:16] for r in rows)
    print("Distribution (top 5):")
    for h, c in hc.most_common(5):
        print(f"  {h}: {c}")
    print(f"  ... plus {max(0, len(hc) - 5)} more source_hash values, "
         f"{sum(1 for c in hc.values() if c <= 3)} of which appear <=3 times each")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
