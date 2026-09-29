#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "engine"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import classify  # engine/classify.py

POLICY_ACTION = {
    "active_backend_testing": "hold",
    "broad_scanning": "rotate",
    "indexing": "rotate",
    "insufficient_data": "none",
}


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def build_rule_feats(row: dict) -> dict:
    """Features shaped for the old rule-based classifier, approximated from the CSV."""
    n = int(to_float(row["count"]))
    return {
        "count": n,
        "min_requests": 4,
        "min_distinct_paths": 5,
        "rate": to_float(row.get("rate")) if row.get("rate") not in (None, "") else None,
        "cv": 0.0,  # not present in the batch CSV
        "distinct_paths": int(to_float(row["distinct_paths"])),
        "probes": int(to_float(row["probes"])),
        "errors": int(to_float(row["errors"])),
        "suspicious_qs": int(to_float(row["suspicious_qs"])),
        "query_count": int(to_float(row["query_count"])),
    }


def build_content_feats(row: dict) -> dict:
    feats = {
        "count": int(to_float(row["count"])),
        "min_requests": 4,
        "min_distinct_paths": 5,
    }
    for name in classify._MODEL.features:
        feats[name] = to_float(row.get(name))
    return feats


def main(argv=None) -> int:
    path = argv[0] if argv else (sys.argv[1] if len(sys.argv) > 1 else
                                  "generation/stage4_labelled.csv")
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    print(f"{len(rows)} generated sessions loaded from {path}")

    label_agree = 0
    action_agree = 0
    action_disagreements = []
    label_confusion = {}

    for row in rows:
        rule_feats = build_rule_feats(row)
        content_feats = build_content_feats(row)

        old = classify.classify_rules(rule_feats)
        new = classify.classify(content_feats)

        if old.label == new.label:
            label_agree += 1
        key = (old.label, new.label)
        label_confusion[key] = label_confusion.get(key, 0) + 1

        old_action = POLICY_ACTION[old.label]
        new_action = POLICY_ACTION[new.label]
        if old_action == new_action:
            action_agree += 1
        else:
            action_disagreements.append({
                "session_id": row.get("session_id"),
                "tool": row.get("tool"),
                "behaviour_class": row.get("behaviour_class"),
                "old_label": old.label, "old_action": old_action,
                "new_label": new.label, "new_action": new_action,
            })

    n = len(rows)
    print(f"\nLabel agreement: {label_agree}/{n} ({100*label_agree/n:.2f}%)")
    print("Label confusion (old_label -> new_label): count")
    for (o, nlab), c in sorted(label_confusion.items(), key=lambda kv: -kv[1]):
        marker = "" if o == nlab else "  <-- disagreement"
        print(f"  {o:24s} -> {nlab:24s} : {c}{marker}")

    print(f"\nPOLICY ACTION agreement: {action_agree}/{n} ({100*action_agree/n:.2f}%)")
    if action_disagreements:
        print(f"\n{len(action_disagreements)} session(s) where the two classifiers "
             f"imply a DIFFERENT rotation decision (not just a different label):")
        by_tool = {}
        for d in action_disagreements:
            by_tool.setdefault((d["tool"], d["behaviour_class"]), []).append(d)
        for (tool, cls), items in sorted(by_tool.items(), key=lambda kv: -len(kv[1])):
            print(f"  {tool}/{cls}: {len(items)} sessions, e.g. "
                 f"old={items[0]['old_label']}({items[0]['old_action']}) "
                 f"new={items[0]['new_label']}({items[0]['new_action']})")
    else:
        print("0 policy-action disagreements -- every session that would have "
             "triggered a rotation/hold decision under the old classifier "
             "triggers the identical decision under the new one.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
