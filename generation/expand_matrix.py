#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

GENERATION_DIR = Path(__file__).resolve().parent
BASE_MANIFEST = GENERATION_DIR / "run_manifest.yml"
PROFILES_PATH = GENERATION_DIR / "network_profiles.yml"

PERSONAS = ["moodle", "registry", "finance", "research"]

# Cross-class matched pairs: same tool, content-identical, different class.
MATCHED_PAIR_TOOLS = {"nmap", "wget"}

FIXED_FIELDS = ["tool", "tool_version", "config_name", "config_args",
                "target_list_size", "timeout_budget", "behaviour_class"]


def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dedupe_base_combos(manifest: dict) -> List[dict]:
    """One entry per (tool, config_name), taking fixed fields from its first definition."""
    seen: Dict[Tuple[str, str], dict] = {}
    order: List[Tuple[str, str]] = []
    for run in manifest.get("runs", []):
        key = (run["tool"], run["config_name"])
        if key not in seen:
            seen[key] = {k: run[k] for k in FIXED_FIELDS}
            order.append(key)
        else:
            for field in FIXED_FIELDS:
                if seen[key][field] != run[field]:
                    sys.exit(f"expand_matrix: {key} has inconsistent {field!r} "
                            f"across manifest entries -- refusing to guess "
                            f"which one is authoritative")
    return [seen[k] for k in order]


def expand(base_combos: List[dict], profiles: List[str], personas: List[str],
          repetition: int, probe_rate: float) -> List[dict]:
    runs = []
    for combo in base_combos:
        for profile in profiles:
            for persona in personas:
                run_id = (f"stage4-{combo['behaviour_class']}-{combo['tool']}-"
                         f"{combo['config_name']}-{profile}-{persona}")
                run = dict(combo)
                run["run_id"] = run_id
                run["network_profile"] = profile
                run["active_persona"] = persona
                run["probe_rate"] = probe_rate
                run["repetition"] = repetition
                runs.append(run)
    return runs


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repetition", type=int, default=18)
    p.add_argument("--probe-rate", type=float, default=0.3)
    p.add_argument("--out", default=str(GENERATION_DIR / "run_manifest_stage4.yml"))
    args = p.parse_args()

    manifest = load_yaml(BASE_MANIFEST)
    profiles = list(load_yaml(PROFILES_PATH)["profiles"].keys())
    base_combos = dedupe_base_combos(manifest)

    runs = expand(base_combos, profiles, PERSONAS, args.repetition, args.probe_rate)

    matched_pair_sessions = sum(r["repetition"] for r in runs
                               if r["tool"] in MATCHED_PAIR_TOOLS)
    total_sessions = sum(r["repetition"] for r in runs)

    print(f"expand_matrix: {len(base_combos)} base tool-configs x "
         f"{len(profiles)} profiles x {len(PERSONAS)} personas x "
         f"{args.repetition} repetitions")
    print(f"expand_matrix: {len(runs)} manifest entries, {total_sessions} sessions total")
    print(f"expand_matrix: matched-pair (nmap/wget) share: "
         f"{matched_pair_sessions}/{total_sessions} "
         f"({100*matched_pair_sessions/total_sessions:.1f}%)")

    header = f"""# GENERATED FILE -- do not hand-edit. Produced by generation/expand_matrix.py
# from the tool-configs already verified in run_manifest.yml (Stages 1-3,
# 2b-2d). Regenerate with:
#   python3 generation/expand_matrix.py --repetition {args.repetition} --probe-rate {args.probe_rate} --out {args.out}
#
# {len(base_combos)} base tool-configs x {len(profiles)} network profiles x
# {len(PERSONAS)} personas x {args.repetition} repetitions = {total_sessions} sessions.
# Matched-pair (nmap sweep/focused_deep, wget single/recursive -- content-
# identical by construction within each pair, different class) share:
# {matched_pair_sessions}/{total_sessions} ({100*matched_pair_sessions/total_sessions:.1f}%).
#
# probe_rate={args.probe_rate} for all entries -- Stage 4 turns the timing
# probe on, per approval. See personas/*/manifest.yml for the timing ranges
# this draws from.
"""

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.dump({"runs": runs}, f, default_flow_style=False, sort_keys=False)

    print(f"expand_matrix: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
