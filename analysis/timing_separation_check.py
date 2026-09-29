#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import random
import statistics
import sys
from typing import Dict, List, Optional, Tuple

CLASS_ORDER = ["broad_scanning", "active_backend_testing", "indexing"]

GROUP_C = [
    "count", "distinct_paths", "repeat_visit_count", "path_entropy",
    "path_ordering_alphabetical_score", "method_diversity",
    "errors", "n404", "status_2xx_ratio", "status_4xx_ratio", "status_5xx_ratio",
    "probes", "probe_ratio", "suspicious_qs", "query_count",
    "query_present_ratio", "query_string_mean_length", "query_string_max_length",
    "header_order_consistent", "connection_reused_ratio", "bytes",
]

GROUP_P = [
    "duration_seconds", "rate", "avg_duration",
    "pre_probe_interval_mean", "post_probe_interval_mean",
    "pre_timing_probe_interval_mean",
]

GROUP_R = [
    "abandoned_count", "abandonment_rate",
    "post_timing_probe_interval_mean", "timing_probe_interval_delta_ms",
    "post_probe_request_count", "post_probe_repeat_visit_count",
]


def to_float(v: Optional[str]) -> Optional[float]:
    if v in (None, "", "None"):
        return None
    if v in ("True", "False"):
        return 1.0 if v == "True" else 0.0
    try:
        return float(v)
    except ValueError:
        return None


def load_matrix(rows: List[Dict[str, str]], feature_names: List[str]
                ) -> Tuple[List[List[Optional[float]]], List[str]]:
    X = [[to_float(r.get(f)) for f in feature_names] for r in rows]
    y = [r["behaviour_class"] for r in rows]
    return X, y


def stratified_folds(y: List[str], k: int, seed: int) -> List[List[int]]:
    rng = random.Random(seed)
    by_class: Dict[str, List[int]] = {}
    for i, cls in enumerate(y):
        by_class.setdefault(cls, []).append(i)
    folds: List[List[int]] = [[] for _ in range(k)]
    for cls, idxs in by_class.items():
        rng.shuffle(idxs)
        for j, idx in enumerate(idxs):
            folds[j % k].append(idx)
    return folds


def impute(train_X: List[List[Optional[float]]], test_X: List[List[Optional[float]]]
          ) -> Tuple[List[List[float]], List[List[float]]]:
    n_features = len(train_X[0])
    medians = []
    for j in range(n_features):
        vals = [row[j] for row in train_X if row[j] is not None]
        medians.append(statistics.median(vals) if vals else 0.0)

    def fill(X):
        return [[row[j] if row[j] is not None else medians[j]
                 for j in range(n_features)] for row in X]

    return fill(train_X), fill(test_X)


class GaussianNB:
    def fit(self, X: List[List[float]], y: List[str]) -> "GaussianNB":
        self.classes = sorted(set(y))
        self.priors = {c: y.count(c) / len(y) for c in self.classes}
        n_features = len(X[0])
        self.means: Dict[str, List[float]] = {}
        self.vars: Dict[str, List[float]] = {}
        for c in self.classes:
            rows = [X[i] for i in range(len(X)) if y[i] == c]
            means = [statistics.mean(r[j] for r in rows) for j in range(n_features)]
            variances = [max(statistics.pvariance([r[j] for r in rows]), 1e-6)
                        for j in range(n_features)]
            self.means[c] = means
            self.vars[c] = variances
        return self

    def _log_likelihood(self, x: List[float], c: str) -> float:
        import math
        ll = math.log(self.priors[c])
        for j, v in enumerate(x):
            mean, var = self.means[c][j], self.vars[c][j]
            ll += -0.5 * math.log(2 * math.pi * var) - ((v - mean) ** 2) / (2 * var)
        return ll

    def predict(self, X: List[List[float]]) -> List[str]:
        return [max(self.classes, key=lambda c: self._log_likelihood(x, c))
               for x in X]


def macro_f1(y_true: List[str], y_pred: List[str]) -> Tuple[float, Dict[str, float]]:
    per_class = {}
    for c in CLASS_ORDER:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == c and p == c)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != c and p == c)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == c and p != c)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
             if (precision + recall) else 0.0)
        per_class[c] = f1
    return statistics.mean(per_class.values()), per_class


def cv_predictions(rows: List[Dict[str, str]], feature_names: List[str],
                   folds: List[List[int]]
                   ) -> Tuple[List[float], List[float], List[Dict[str, float]], List[str]]:
    """Returns per-fold metrics and pooled predictions aligned to fold order."""
    X, y = load_matrix(rows, feature_names)
    accs, f1s, per_class_list = [], [], []
    pooled_pred: List[str] = []
    for i in range(len(folds)):
        test_idx = folds[i]
        train_idx = [j for j in range(len(y)) if j not in set(test_idx)]
        train_X = [X[j] for j in train_idx]
        train_y = [y[j] for j in train_idx]
        test_X = [X[j] for j in test_idx]
        test_y = [y[j] for j in test_idx]
        train_X, test_X = impute(train_X, test_X)
        model = GaussianNB().fit(train_X, train_y)
        pred_y = model.predict(test_X)
        pooled_pred.extend(pred_y)
        acc = sum(1 for t, p in zip(test_y, pred_y) if t == p) / len(test_y)
        f1, per_class = macro_f1(test_y, pred_y)
        accs.append(acc)
        f1s.append(f1)
        per_class_list.append(per_class)
    return accs, f1s, per_class_list, pooled_pred


def paired_report(name_a: str, f1_a: List[float], name_b: str, f1_b: List[float]) -> None:
    deltas = [b - a for a, b in zip(f1_a, f1_b)]
    mean_d = statistics.mean(deltas)
    sd_d = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
    sem_d = sd_d / (len(deltas) ** 0.5) if len(deltas) > 1 else 0.0
    ci_lo, ci_hi = mean_d - 1.96 * sem_d, mean_d + 1.96 * sem_d
    print(f"  paired per-fold macro-F1 delta ({name_b} - {name_a}): "
         f"{[round(d, 5) for d in deltas]}")
    print(f"    mean={mean_d:+.5f}  sd={sd_d:.5f}  "
         f"95% CI (normal approx over folds)=[{ci_lo:+.5f}, {ci_hi:+.5f}]")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("labelled_csv")
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)

    with open(args.labelled_csv, newline="", encoding="utf-8") as f:
        all_rows = list(csv.DictReader(f))

    rows = [r for r in all_rows
           if to_float(r.get("probe_count")) and to_float(r.get("probe_count")) > 0]
    print(f"timing_separation_check: {len(rows)}/{len(all_rows)} sessions had "
         f"at least one probed request -- restricting all three feature sets "
         f"to this identical subset")
    print("class counts: " + ", ".join(
        f"{c}={sum(1 for r in rows if r['behaviour_class']==c)}" for c in CLASS_ORDER))

    print(f"\nC -- non-timing interaction features ({len(GROUP_C)}): {GROUP_C}")
    print(f"P -- passive timing ({len(GROUP_P)}): {GROUP_P}")
    print(f"R -- probe-response only ({len(GROUP_R)}): {GROUP_R}")

    _, y_all = load_matrix(rows, GROUP_C)
    folds = stratified_folds(y_all, args.folds, args.seed)

    acc_c, f1_c, pc_c, pred_c = cv_predictions(rows, GROUP_C, folds)
    acc_cp, f1_cp, pc_cp, pred_cp = cv_predictions(rows, GROUP_C + GROUP_P, folds)
    acc_cpr, f1_cpr, pc_cpr, pred_cpr = cv_predictions(rows, GROUP_C + GROUP_P + GROUP_R, folds)

    def summarize(name, accs, f1s, pcs):
        print(f"\n{name}:")
        print(f"  per-fold accuracy: {[round(a, 5) for a in accs]}")
        print(f"  per-fold macro-F1: {[round(f, 5) for f in f1s]}")
        print(f"  mean accuracy={statistics.mean(accs):.5f} (sd={statistics.pstdev(accs):.5f})  "
             f"mean macro-F1={statistics.mean(f1s):.5f} (sd={statistics.pstdev(f1s):.5f})")
        per_class_mean = {c: statistics.mean(pc[c] for pc in pcs) for c in CLASS_ORDER}
        per_class_sd = {c: statistics.pstdev([pc[c] for pc in pcs]) for c in CLASS_ORDER}
        for c in CLASS_ORDER:
            print(f"    {c:24s} F1 mean={per_class_mean[c]:.5f} sd={per_class_sd[c]:.5f}")

    summarize("C", acc_c, f1_c, pc_c)
    summarize("C+P", acc_cp, f1_cp, pc_cp)
    summarize("C+P+R", acc_cpr, f1_cpr, pc_cpr)

    print("\nPaired increments (same folds, same rows throughout):")
    paired_report("C", f1_c, "C+P", f1_cp)
    paired_report("C+P", f1_cp, "C+P+R", f1_cpr)

    n_diff_c_cp = sum(1 for a, b in zip(pred_c, pred_cp) if a != b)
    n_diff_cp_cpr = sum(1 for a, b in zip(pred_cp, pred_cpr) if a != b)
    n = len(pred_c)
    print(f"\nDirect prediction agreement (pooled out-of-fold predictions, n={n}):")
    print(f"  predictions that changed C -> C+P:     {n_diff_c_cp}/{n} ({100*n_diff_c_cp/n:.3f}%)")
    print(f"  predictions that changed C+P -> C+P+R: {n_diff_cp_cpr}/{n} ({100*n_diff_cp_cpr/n:.3f}%)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
