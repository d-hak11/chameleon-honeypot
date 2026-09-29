#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import math
from typing import Dict, List

from patterns import PROBE_RE, SUSPICIOUS_QS_RE

FEATURE_ORDER: List[str] = [
    "count", "distinct_paths", "repeat_visit_count", "path_entropy",
    "path_ordering_alphabetical_score", "method_diversity",
    "errors", "n404", "status_2xx_ratio", "status_4xx_ratio", "status_5xx_ratio",
    "probes", "probe_ratio", "suspicious_qs", "query_count",
    "query_present_ratio", "query_string_mean_length", "query_string_max_length",
    "header_order_consistent", "connection_reused_ratio", "bytes",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _header_fingerprint(header_names) -> str:
    joined = "|".join(header_names)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def compute(records: List) -> Dict[str, object]:
    n = len(records)
    if n == 0:
        return {name: 0 for name in FEATURE_ORDER}

    paths_seq = [r.path for r in records]
    distinct_paths = len(set(paths_seq))
    repeat_visit_count = n - distinct_paths

    alpha_pairs = sum(1 for i in range(len(paths_seq) - 1)
                      if paths_seq[i] < paths_seq[i + 1])
    alpha_score = alpha_pairs / (len(paths_seq) - 1) if len(paths_seq) > 1 else 0.0

    path_entropy = _entropy("".join(paths_seq))

    methods = sorted({r.method for r in records})
    method_diversity = len(methods)

    errors = sum(1 for r in records if r.status >= 400)
    n404 = sum(1 for r in records if r.status == 404)
    status_2xx_ratio = sum(1 for r in records if 200 <= r.status < 300) / n
    status_4xx_ratio = sum(1 for r in records if 400 <= r.status < 500) / n
    status_5xx_ratio = sum(1 for r in records if r.status >= 500) / n

    probes = sum(1 for r in records if PROBE_RE.search(r.path))
    probe_ratio = probes / n

    suspicious_qs = sum(1 for r in records if SUSPICIOUS_QS_RE.search(r.query))

    query_lengths = [len(r.query) for r in records if r.query]
    query_count = len(query_lengths)
    query_present_ratio = query_count / n
    query_string_mean_length = (sum(query_lengths) / len(query_lengths)
                                if query_lengths else 0.0)
    query_string_max_length = max(query_lengths) if query_lengths else 0

    fingerprints = [_header_fingerprint(tuple(r.headers.keys())) for r in records]
    header_order_consistent = len(set(fingerprints)) <= 1

    reused = sum(1 for i in range(1, n)
                if records[i].remote_port == records[i - 1].remote_port
                and records[i].remote_port != "")
    connection_reused_ratio = reused / (n - 1) if n > 1 else 0.0

    total_bytes = sum(r.size for r in records)

    # Rounding must match extract_features.py exactly; the model was trained on rounded values.
    return {
        "count": n,
        "distinct_paths": distinct_paths,
        "repeat_visit_count": repeat_visit_count,
        "path_entropy": round(path_entropy, 6),
        "path_ordering_alphabetical_score": round(alpha_score, 6),
        "method_diversity": method_diversity,
        "errors": errors,
        "n404": n404,
        "status_2xx_ratio": round(status_2xx_ratio, 6),
        "status_4xx_ratio": round(status_4xx_ratio, 6),
        "status_5xx_ratio": round(status_5xx_ratio, 6),
        "probes": probes,
        "probe_ratio": round(probe_ratio, 6),
        "suspicious_qs": suspicious_qs,
        "query_count": query_count,
        "query_present_ratio": round(query_present_ratio, 6),
        "query_string_mean_length": round(query_string_mean_length, 3),
        "query_string_max_length": query_string_max_length,
        "header_order_consistent": header_order_consistent,
        "connection_reused_ratio": round(connection_reused_ratio, 6),
        "bytes": total_bytes,
    }
