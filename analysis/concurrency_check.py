#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
import sys
from typing import Dict, List, Optional

# Concurrency per tool-config, transcribed from run_manifest_stage4.yml's config_args.
CONCURRENCY = {
    "gobuster": "concurrent",
    "nikto": "sequential",
    "wget": "sequential",
    "sh": "sequential",
    "sqlmap": "sequential",
    "nmap": "nmap (own scheduler)",
}


def to_float(v: Optional[str]) -> Optional[float]:
    if v in (None, "", "None"):
        return None
    try:
        return float(v)
    except ValueError:
        return None


def one_way_anova(groups: List[List[float]]) -> Optional[float]:
    """F-ratio for independent groups; None if degenerate."""
    groups = [g for g in groups if len(g) >= 2]
    if len(groups) < 2:
        return None
    all_vals = [v for g in groups for v in g]
    grand_mean = statistics.mean(all_vals)
    n_total = len(all_vals)
    k = len(groups)

    ss_between = sum(len(g) * (statistics.mean(g) - grand_mean) ** 2 for g in groups)
    ss_within = sum((v - statistics.mean(g)) ** 2 for g in groups for v in g)

    df_between = k - 1
    df_within = n_total - k
    if df_within <= 0 or ss_within == 0:
        return None

    ms_between = ss_between / df_between
    ms_within = ss_within / df_within
    return ms_between / ms_within


def main(argv=None) -> int:
    path = argv[0] if argv else (sys.argv[1] if len(sys.argv) > 1 else
                                  "generation/stage4_labelled.csv")
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    rows = [r for r in rows
            if (to_float(r.get("probe_count")) or 0) > 0
            and to_float(r.get("timing_probe_interval_delta_ms")) is not None]

    by_class_tool: Dict[tuple, List[float]] = {}
    by_class: Dict[str, List[float]] = {}
    for r in rows:
        cls, tool = r["behaviour_class"], r["tool"]
        v = to_float(r["timing_probe_interval_delta_ms"])
        by_class_tool.setdefault((cls, tool), []).append(v)
        by_class.setdefault(cls, []).append(v)

    print(f"concurrency_check: {len(rows)} probed sessions with a valid "
          f"timing_probe_interval_delta_ms\n")

    print("Class-level means (as reported in Finding 2):")
    for cls in sorted(by_class):
        vals = by_class[cls]
        print(f"  {cls:24s} n={len(vals):4d} mean={statistics.mean(vals):7.2f}ms "
              f"sd={statistics.pstdev(vals):7.2f}")

    print("\nDecomposed by tool within class (manifest-declared concurrency "
          "in brackets):")
    for cls in sorted(by_class):
        print(f"  {cls}:")
        tools_in_class = sorted(t for (c, t) in by_class_tool if c == cls)
        for tool in tools_in_class:
            vals = by_class_tool[(cls, tool)]
            tag = CONCURRENCY.get(tool, "?")
            print(f"    {tool:10s} [{tag:22s}] n={len(vals):4d} "
                  f"mean={statistics.mean(vals):7.2f}ms sd={statistics.pstdev(vals):7.2f}")

    print("\nWithin-class one-way ANOVA on timing_probe_interval_delta_ms, "
          "grouped by tool:")
    for cls in sorted(by_class):
        tools_in_class = sorted(t for (c, t) in by_class_tool if c == cls)
        groups = [by_class_tool[(cls, t)] for t in tools_in_class]
        f = one_way_anova(groups)
        f_str = f"F={f:.2f}" if f is not None else "F=n/a (degenerate)"
        print(f"  {cls:24s} tools={tools_in_class}  {f_str}")

    # Pool sequential vs concurrent tools across classes, ignoring class label.
    seq_vals, conc_vals = [], []
    for (cls, tool), vals in by_class_tool.items():
        tag = CONCURRENCY.get(tool)
        if tag == "sequential":
            seq_vals.extend(vals)
        elif tag == "concurrent":
            conc_vals.extend(vals)
    print("\nPooled across ALL classes, by manifest-declared concurrency "
          "only (nmap excluded -- own scheduler, not a simple thread count):")
    print(f"  sequential tools (nikto, wget, sh, sqlmap): n={len(seq_vals):4d} "
          f"mean={statistics.mean(seq_vals):7.2f}ms sd={statistics.pstdev(seq_vals):7.2f}")
    print(f"  concurrent tools (gobuster):                n={len(conc_vals):4d} "
          f"mean={statistics.mean(conc_vals):7.2f}ms sd={statistics.pstdev(conc_vals):7.2f}")
    f = one_way_anova([seq_vals, conc_vals])
    print(f"  F={f:.2f}" if f is not None else "  F=n/a")

    return 0


if __name__ == "__main__":
    sys.exit(main())
