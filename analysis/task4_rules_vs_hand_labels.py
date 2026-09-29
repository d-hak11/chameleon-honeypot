#!/usr/bin/env python3
from __future__ import annotations

import csv
import glob
import os
import statistics
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "engine"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import classify  # engine/classify.py -- classify() [RF] and classify_rules() [old]
from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise
from label_live_sessions import find_live_logs

POLICY_ACTION = {
    "active_backend_testing": "hold",
    "broad_scanning": "rotate",
    "indexing": "rotate",
    "insufficient_data": "none",
    "unknown_mixed": "none",
}


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def load_live_sessions(live_dir: str):
    paths = find_live_logs(live_dir)
    requests = read_requests(paths)
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    out = {}
    for session in sessions:
        feats = extract(session)
        out[feats["session_id"]] = (feats, session)
    return out


def compute_cv(session) -> float:
    ts_list = sorted(r.ts for r in session)
    gaps = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
    if not gaps:
        return 0.0
    mean_gap = sum(gaps) / len(gaps)
    if mean_gap <= 0:
        return 0.0
    return statistics.pstdev(gaps) / mean_gap


def build_rule_feats(feats: dict, session) -> dict:
    n = feats["count"]
    duration = feats["duration_seconds"]
    rate = (n - 1) / duration if duration > 0 else None
    return {
        "count": n,
        "min_requests": 4,
        "min_distinct_paths": 5,
        "rate": rate,
        "cv": compute_cv(session),
        "distinct_paths": feats["distinct_paths"],
        "probes": feats["probes"],
        "errors": feats["errors"],
        "suspicious_qs": feats["suspicious_qs"],
        "query_count": feats["query_count"],
    }


def build_content_feats(feats: dict) -> dict:
    out = {"count": feats["count"], "min_requests": 4, "min_distinct_paths": 5}
    for name in classify._MODEL.features:
        out[name] = to_float(feats.get(name))
    return out


def main() -> int:
    with open("analysis/live_labels_final.csv", newline="", encoding="utf-8") as f:
        hand_labels = {row["session_id"]: row for row in csv.DictReader(f)}
    print(f"{len(hand_labels)} hand-labelled sessions loaded")

    live_sessions = load_live_sessions("live-data")
    print(f"{len(live_sessions)} sessions reconstructed from live-data/\n")

    missing = set(hand_labels) - set(live_sessions)
    if missing:
        print(f"WARNING: {len(missing)} hand-labelled session_id(s) not found in the "
             f"current live-data/ reconstruction: {sorted(missing)}", file=sys.stderr)

    RULE_LABELS = ["broad_scanning", "indexing", "active_backend_testing", "insufficient_data"]
    HAND_LABELS = ["broad_scanning", "indexing", "active_backend_testing",
                   "insufficient_data", "unknown_mixed"]

    confusion = Counter()
    rf_action_agree = 0
    rule_action_agree = 0
    erroneous_rotations = []  # hand says hold (abt), rule/RF says rotate
    unnecessary_holds = []    # hand says rotate (broad/indexing), rule/RF says hold
    abt_by_rules = []
    n_scored = 0

    for sid, row in hand_labels.items():
        if sid not in live_sessions:
            continue
        feats, session = live_sessions[sid]
        hand_label = row["label"]
        hand_action = POLICY_ACTION[hand_label]

        rule_feats = build_rule_feats(feats, session)
        rule_result = classify.classify_rules(rule_feats)
        rule_action = POLICY_ACTION[rule_result.label]

        content_feats = build_content_feats(feats)
        rf_result = classify.classify(content_feats)
        rf_action = POLICY_ACTION[rf_result.label]

        n_scored += 1
        confusion[(hand_label, rule_result.label)] += 1

        if rule_action == hand_action:
            rule_action_agree += 1
        else:
            if hand_action == "hold" and rule_action == "rotate":
                erroneous_rotations.append((sid, hand_label, rule_result.label, "rules"))
            elif hand_action == "rotate" and rule_action == "hold":
                unnecessary_holds.append((sid, hand_label, rule_result.label, "rules"))

        if rf_action == hand_action:
            rf_action_agree += 1
        else:
            if hand_action == "hold" and rf_action == "rotate":
                erroneous_rotations.append((sid, hand_label, rf_result.label, "rf"))
            elif hand_action == "rotate" and rf_action == "hold":
                unnecessary_holds.append((sid, hand_label, rf_result.label, "rf"))

        if rule_result.label == "active_backend_testing":
            dp = feats["distinct_paths"] or 1
            abt_by_rules.append({
                "session_id": sid, "count": feats["count"], "distinct_paths": dp,
                "req_per_path": feats["count"] / dp,
                "query_share": feats["query_present_ratio"],
                "hand_label": hand_label,
                "top_paths": sorted(Counter(r.path for r in session).most_common(3)),
            })

    print(f"Scored {n_scored}/{len(hand_labels)} sessions "
         f"(0 missing from reconstruction: {len(missing)==0})\n")

    print("=" * 78)
    print("CONFUSION MATRIX: hand label (rows) vs classify_rules() prediction (cols)")
    print("=" * 78)
    header = "true \\ pred".ljust(24) + "".join(f"{c:>18s}" for c in RULE_LABELS)
    print(header)
    for h in HAND_LABELS:
        row = "".join(f"{confusion[(h,c)]:>18d}" for c in RULE_LABELS)
        print(f"{h:<24s}{row}")

    print(f"\nPOLICY ACTION agreement, classify_rules() vs hand-label-implied action: "
         f"{rule_action_agree}/{n_scored} ({100*rule_action_agree/n_scored:.1f}%)")
    print(f"POLICY ACTION agreement, production RF vs hand-label-implied action: "
         f"{rf_action_agree}/{n_scored} ({100*rf_action_agree/n_scored:.1f}%)")

    print(f"\nErroneous rotations (hand label implies HOLD i.e. active_backend_testing, "
         f"classifier says ROTATE): {len(erroneous_rotations)}")
    for sid, hand, pred, who in erroneous_rotations:
        print(f"  [{who:5s}] {sid}: hand={hand} -> predicted={pred}")

    print(f"\nUnnecessary holds (hand label implies ROTATE i.e. broad_scanning/indexing, "
         f"classifier says HOLD): {len(unnecessary_holds)}")
    for sid, hand, pred, who in unnecessary_holds:
        print(f"  [{who:5s}] {sid}: hand={hand} -> predicted={pred}")

    print(f"\n{'='*78}")
    print(f"Sessions classify_rules() called active_backend_testing: {len(abt_by_rules)}")
    print("=" * 78)
    for s in abt_by_rules:
        print(f"  {s['session_id']}  hand_label={s['hand_label']:24s}  "
             f"count={s['count']:4d}  distinct_paths={s['distinct_paths']:3d}  "
             f"req/path={s['req_per_path']:.2f}  query_share={s['query_share']:.2f}  "
             f"top_paths={s['top_paths']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
