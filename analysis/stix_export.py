#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import os
import statistics
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stix2
from stix2.properties import (IntegerProperty, ListProperty, StringProperty,
                              TimestampProperty)

from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise
from label_live_sessions import find_live_logs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from engine.classify import classify  # noqa: E402

MIN_REQUESTS = 4
MIN_DISTINCT_PATHS = 5


@stix2.CustomObject(
    "x-chameleon-behavior-assessment",
    [
        ("session_id_hash", StringProperty(required=True)),
        ("source_hash", StringProperty(required=True)),
        ("behaviour_class", StringProperty(required=True)),
        ("confidence_pct", IntegerProperty(required=True)),
        ("reasons", ListProperty(StringProperty, required=True)),
        ("request_count", IntegerProperty(required=True)),
        ("distinct_paths", IntegerProperty(required=True)),
        ("duration_seconds", StringProperty(required=True)),
        ("persona_targeted", StringProperty(required=False)),
        ("first_observed", TimestampProperty(required=True)),
        ("last_observed", TimestampProperty(required=True)),
    ],
)
class BehaviorAssessment:
    pass


def compute_cv(session) -> float:
    """Same raw-ts CV as the live engine (not arrival-time corrected)."""
    ts_list = [r.ts for r in session]
    gaps = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
    if not gaps:
        return 0.0
    mean_gap = sum(gaps) / len(gaps)
    if mean_gap <= 0:
        return 0.0
    std_gap = statistics.pstdev(gaps)
    return std_gap / mean_gap


def build_classify_feats(session, full_feats: Dict[str, object]) -> Dict[str, object]:
    return {
        "count": full_feats["count"],
        "min_requests": MIN_REQUESTS,
        "min_distinct_paths": MIN_DISTINCT_PATHS,
        "rate": full_feats["rate"],
        "cv": compute_cv(session),
        "distinct_paths": full_feats["distinct_paths"],
        "probes": full_feats["probes"],
        "errors": full_feats["errors"],
        "suspicious_qs": full_feats["suspicious_qs"],
        "query_count": full_feats["query_count"],
    }


def to_stix_ts(unix_ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(unix_ts, tz=datetime.timezone.utc)


def build_bundle(live_dir: str) -> tuple:
    paths = find_live_logs(live_dir)
    requests = read_requests(paths)
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)

    identity = stix2.Identity(
        name="Chameleon Honeypot",
        identity_class="system",
        description="Stimulus-driven adaptive-persona web honeypot -- "
                    "behavioural classification export, not raw IOCs.",
    )

    objects = [identity]
    excluded_insufficient = 0
    excluded_private = 0
    class_counts: Dict[str, int] = {}

    for session in sessions:
        full_feats = extract(session)
        if full_feats["source_private"]:
            excluded_private += 1
            continue
        if full_feats["count"] < MIN_REQUESTS:
            excluded_insufficient += 1
            continue

        cf = build_classify_feats(session, full_feats)
        result = classify(cf)
        if result.label == "insufficient_data":
            excluded_insufficient += 1
            continue

        class_counts[result.label] = class_counts.get(result.label, 0) + 1
        obj = BehaviorAssessment(
            session_id_hash=full_feats["session_id"],
            source_hash=full_feats["source_hash"],
            behaviour_class=result.label,
            confidence_pct=int(round(result.confidence * 100)),
            reasons=result.reasons,
            request_count=full_feats["count"],
            distinct_paths=full_feats["distinct_paths"],
            duration_seconds=f"{full_feats['duration_seconds']:.3f}",
            persona_targeted=full_feats.get("persona") or None,
            first_observed=to_stix_ts(full_feats["first_seen"]),
            last_observed=to_stix_ts(full_feats["last_seen"]),
            created_by_ref=identity.id,
            allow_custom=True,
        )
        objects.append(obj)

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    stats = {
        "total_sessions": len(sessions),
        "excluded_private": excluded_private,
        "excluded_insufficient_data": excluded_insufficient,
        "exported": len(objects) - 1,
        "class_counts": class_counts,
    }
    return bundle, stats


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--live-dir", default="live-data")
    p.add_argument("--out", default="analysis/chameleon_stix_bundle.json")
    args = p.parse_args(argv)

    bundle, stats = build_bundle(args.live_dir)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"Wrote {args.out}")
    print(f"Sessions seen: {stats['total_sessions']}")
    print(f"  excluded (internal/private source): {stats['excluded_private']}")
    print(f"  excluded (insufficient_data / <{MIN_REQUESTS} requests): "
          f"{stats['excluded_insufficient_data']}")
    print(f"  exported as behaviour-assessment objects: {stats['exported']}")
    print(f"  class breakdown: {stats['class_counts']}")

    with open(args.out, encoding="utf-8") as f:
        raw = f.read()
    parsed = stix2.parse(raw, allow_custom=True)
    assert len(parsed.objects) == len(bundle.objects), (
        f"round-trip object count mismatch: wrote {len(bundle.objects)}, "
        f"parsed back {len(parsed.objects)}")
    type_counts: Dict[str, int] = {}
    for obj in parsed.objects:
        type_counts[obj.type] = type_counts.get(obj.type, 0) + 1
    print(f"\nValidation: stix2.parse() round-trip succeeded, "
         f"{len(parsed.objects)} objects, types={type_counts}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
