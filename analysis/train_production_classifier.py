#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupKFold
from sklearn.metrics import f1_score, confusion_matrix, precision_recall_fscore_support

from timing_separation_check import GROUP_C, CLASS_ORDER

RF_KWARGS = dict(n_estimators=500, class_weight="balanced", min_samples_leaf=5,
                 random_state=42, n_jobs=-1)

# Must match engine/content_features.py FEATURE_ORDER (asserted below).
EXPECTED_FEATURE_ORDER = [
    "count", "distinct_paths", "repeat_visit_count", "path_entropy",
    "path_ordering_alphabetical_score", "method_diversity",
    "errors", "n404", "status_2xx_ratio", "status_4xx_ratio", "status_5xx_ratio",
    "probes", "probe_ratio", "suspicious_qs", "query_count",
    "query_present_ratio", "query_string_mean_length", "query_string_max_length",
    "header_order_consistent", "connection_reused_ratio", "bytes",
]


def export_tree(tree) -> dict:
    """One tree as parallel arrays; children_left == -1 marks a leaf."""
    t = tree.tree_
    n_nodes = t.node_count
    children_left = t.children_left.tolist()
    children_right = t.children_right.tolist()
    feature = t.feature.tolist()
    threshold = t.threshold.tolist()
    leaf_value = []
    for i in range(n_nodes):
        if children_left[i] == -1:  # leaf (sklearn's TREE_LEAF)
            counts = t.value[i][0]
            total = counts.sum()
            leaf_value.append((counts / total).tolist() if total > 0 else None)
        else:
            leaf_value.append(None)
    return {
        "children_left": children_left,
        "children_right": children_right,
        "feature": feature,
        "threshold": threshold,
        "leaf_value": leaf_value,
    }


def cv_report(df: pd.DataFrame, features: list) -> None:
    """CV is for reporting only; the deployed model is fit on all data."""
    X = df[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    y = df["behaviour_class"].to_numpy()
    groups = df["session_id"].to_numpy()
    gkf = GroupKFold(n_splits=5)
    folds = list(gkf.split(X, y, groups=groups))
    pooled_pred = np.empty(len(y), dtype=object)
    per_fold_f1 = []
    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        model = RandomForestClassifier(**RF_KWARGS)
        model.fit(X_train, y[train_idx])
        pred = model.predict(X_test)
        pooled_pred[test_idx] = pred
        per_fold_f1.append(f1_score(y[test_idx], pred, average="macro", labels=CLASS_ORDER))
    print(f"CV (5-fold, full dataset, C-only, documentation only -- not the "
          f"deployed model): per-fold macro-F1={[round(f, 5) for f in per_fold_f1]}, "
          f"mean={np.mean(per_fold_f1):.5f}")
    p_, r_, f_, support = precision_recall_fscore_support(
        y, pooled_pred, labels=CLASS_ORDER, zero_division=0)
    for i, c in enumerate(CLASS_ORDER):
        print(f"    {c:24s} precision={p_[i]:.4f}  recall={r_[i]:.4f}  "
              f"F1={f_[i]:.4f}  support={support[i]}")
    cm = confusion_matrix(y, pooled_pred, labels=CLASS_ORDER)
    print(f"  confusion matrix (rows=true, cols=pred), order {CLASS_ORDER}:")
    for i, row in enumerate(cm):
        print(f"    {CLASS_ORDER[i]:24s} {row}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", default="generation/stage4_labelled.csv")
    p.add_argument("--out", default="engine/models/content_rf.json")
    args = p.parse_args(argv)

    assert GROUP_C == EXPECTED_FEATURE_ORDER, (
        "timing_separation_check.GROUP_C has drifted from "
        "engine/content_features.FEATURE_ORDER -- update EXPECTED_FEATURE_ORDER "
        "here (and engine/content_features.py) to match before training, or "
        "the exported model's feature order will not match what the live "
        "engine computes.")

    df = pd.read_csv(args.train)
    print(f"{len(df)} generated sessions, full dataset (no probe_count restriction "
          f"-- see module docstring). Class counts: " + ", ".join(
              f"{c}={int((df['behaviour_class'] == c).sum())}" for c in CLASS_ORDER))

    cv_report(df, GROUP_C)

    print("\nTraining final deployed model on the FULL dataset (all "
         f"{len(df)} sessions, no held-out fold -- CV above already validated "
         "the approach; this is the model that ships).")
    X_full_raw = df[GROUP_C].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    y_full = df["behaviour_class"].to_numpy()
    imp = SimpleImputer(strategy="median")
    X_full = imp.fit_transform(X_full_raw)
    model = RandomForestClassifier(**RF_KWARGS)
    model.fit(X_full, y_full)

    classes = model.classes_.tolist()
    trees = [export_tree(est) for est in model.estimators_]
    impute_medians = {feat: float(val) for feat, val in zip(GROUP_C, imp.statistics_)}

    export = {
        "classes": classes,
        "features": GROUP_C,
        "impute_medians": impute_medians,
        "n_estimators": len(trees),
        "trained_on": len(df),
        "trees": trees,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(export, f)
    size_mb = os.path.getsize(args.out) / (1024 * 1024)
    print(f"\nWrote {args.out} ({size_mb:.2f} MB), {len(trees)} trees, "
         f"classes={classes}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
