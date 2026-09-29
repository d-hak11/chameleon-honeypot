#!/usr/bin/env python3
import os
from dataclasses import dataclass
from typing import Dict, List

from rf_inference import ContentRandomForest

HOSTILE = {"active_backend_testing", "indexing"}

_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "models", "content_rf.json")
_MODEL = ContentRandomForest.load(_MODEL_PATH)


@dataclass
class Classification:
    label: str
    confidence: float
    reasons: List[str]


def classify(feats: Dict[str, object]) -> Classification:
    n = int(feats.get("count", 0))
    min_req = int(feats.get("min_requests", 4))
    if n < min_req:
        return Classification("insufficient_data", 0.0,
                              [f"fewer than {min_req} requests"])

    result = _MODEL.predict(feats)
    label = result["label"]
    confidence = result["confidence"]
    proba = result["proba"]

    # Distinct-path floor applies only to broad_scanning vs indexing, not active_backend_testing.
    min_paths = int(feats.get("min_distinct_paths", 5))
    distinct_paths = int(feats.get("distinct_paths", 0))
    if label != "active_backend_testing" and distinct_paths < min_paths:
        return Classification("insufficient_data", 0.0,
                              [f"fewer than {min_paths} distinct paths -- "
                               "cannot distinguish broad_scanning from indexing"])
    ranked = sorted(proba.items(), key=lambda kv: -kv[1])
    proba_str = ", ".join(f"{c}={p:.2f}" for c, p in ranked)
    return Classification(label, confidence,
                          [f"RandomForest (content features): {proba_str}"])


# Old rule-based classifier, kept as the reference for the RF swap and as a fallback.
def classify_rules(feats: Dict[str, object]) -> Classification:
    n = int(feats.get("count", 0))
    min_req = int(feats.get("min_requests", 4))
    if n < min_req:
        return Classification("insufficient_data", 0.0,
                              [f"fewer than {min_req} requests"])

    rate = float(feats.get("rate") or 0.0)
    cv = float(feats.get("cv", 0.0))
    distinct_paths = int(feats.get("distinct_paths", 0))
    probes = int(feats.get("probes", 0))
    probe_ratio = probes / n if n > 0 else 0.0
    errors = int(feats.get("errors", 0))
    error_ratio = errors / n if n > 0 else 0.0
    suspicious = int(feats.get("suspicious_qs", 0))
    query_count = int(feats.get("query_count", 0))
    query_ratio = query_count / n if n > 0 else 0.0

    # active_backend_testing: concentrated, queries, SQLi
    if suspicious > 0 and n >= 4:
        return Classification("active_backend_testing", 0.85,
                              [f"suspicious query string (n={suspicious})"])

    if query_ratio >= 0.3 and distinct_paths <= 5 and n >= 8:
        return Classification("active_backend_testing", 0.8,
                              [f"concentrated endpoints ({distinct_paths}u) with queries"])

    if n >= 15 and distinct_paths <= 4 and rate < 2.0:
        return Classification("active_backend_testing", 0.7,
                              [f"deep probing: {n} reqs over {distinct_paths} paths"])

    # indexing: many paths, high 404, systematic
    if probes >= 5 and probe_ratio >= 0.3 and distinct_paths >= 5:
        return Classification("indexing", 0.8,
                              [f"path enumeration: {probes} probes over {distinct_paths} paths"])

    if distinct_paths >= 10 and error_ratio >= 0.5:
        return Classification("indexing", 0.85,
                              [f"systematic discovery: {distinct_paths} paths, {error_ratio:.0%} errors"])

    if rate >= 2.0 and n >= 10 and distinct_paths >= 5:
        return Classification("indexing", 0.8,
                              [f"rapid path walk: {rate:.1f}/s over {distinct_paths} paths"])

    if distinct_paths >= 5 and cv < 0.5 and n >= 8:
        return Classification("indexing", 0.7,
                              [f"regular enumeration cadence (cv={cv:.2f})"])

    min_paths = int(feats.get("min_distinct_paths", 5))
    if distinct_paths < min_paths:
        return Classification("insufficient_data", 0.0,
                              [f"fewer than {min_paths} distinct paths -- "
                               "cannot distinguish broad_scanning from indexing"])

    if n >= max(min_req, 4):
        return Classification("broad_scanning", 0.5,
                              [f"shallow scan: {n} reqs, {distinct_paths} paths"])

    return Classification("broad_scanning", 0.0, ["insufficient evidence"])
