#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, confusion_matrix, precision_recall_fscore_support

from timing_separation_check import GROUP_C, GROUP_P, GROUP_R, CLASS_ORDER

FEATURES = GROUP_C + GROUP_P + GROUP_R
RF_KWARGS = dict(n_estimators=500, class_weight="balanced", min_samples_leaf=5,
                 random_state=42, n_jobs=-1)


def build_X(df: pd.DataFrame, features) -> np.ndarray:
    return df[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)


def run_group_cv(df: pd.DataFrame, groups: np.ndarray, label: str, n_splits: int,
                 features=None) -> dict:
    X = build_X(df, features or FEATURES)
    y = df["behaviour_class"].to_numpy()
    n_groups = len(set(groups))
    gkf = GroupKFold(n_splits=n_splits)
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

    macro_f1_pooled = f1_score(y, pooled_pred, average="macro", labels=CLASS_ORDER)
    cm = confusion_matrix(y, pooled_pred, labels=CLASS_ORDER)
    p_, r_, f_, support = precision_recall_fscore_support(
        y, pooled_pred, labels=CLASS_ORDER, zero_division=0)

    print(f"\n{label}: {n_groups} groups, {len(y)} sessions")
    print(f"  per-fold macro-F1: {[round(f, 5) for f in per_fold_f1]}")
    print(f"  mean per-fold macro-F1={np.mean(per_fold_f1):.5f} (sd={np.std(per_fold_f1):.5f})  "
         f"pooled macro-F1={macro_f1_pooled:.5f}")
    for i, c in enumerate(CLASS_ORDER):
        print(f"    {c:24s} precision={p_[i]:.4f}  recall={r_[i]:.4f}  F1={f_[i]:.4f}  support={support[i]}")
    print(f"  confusion matrix (rows=true, cols=pred), order {CLASS_ORDER}:")
    for i, row in enumerate(cm):
        print(f"    {CLASS_ORDER[i]:24s} {row}")

    return {"macro_f1_pooled": macro_f1_pooled, "per_fold_f1": per_fold_f1, "cm": cm}


def config_grouped_check(train_path: str, features=None, population: str = "probed") -> float:
    df = pd.read_csv(train_path)
    if population == "probed":
        df = df[pd.to_numeric(df["probe_count"], errors="coerce").fillna(0) > 0].reset_index(drop=True)
    groups = (df["tool"].astype(str) + "::" + df["config_name"].astype(str)).to_numpy()
    unique_configs = sorted(set(groups))
    feats = features or FEATURES
    feat_label = "C+P+R" if feats == FEATURES else "C+P (no R)"
    print("=" * 70)
    print(f"CONFIG-GROUPED SPLIT (leave-one-tool-config-out), population={population}, "
         f"features={feat_label}")
    print("=" * 70)
    print(f"{len(unique_configs)} unique (tool, config_name) groups: {unique_configs}")
    counts_per_group = pd.Series(groups).value_counts().to_dict()
    print(f"sessions per group: {counts_per_group}")
    result = run_group_cv(df, groups, "Config-grouped CV (leave-one-config-out)",
                          n_splits=len(unique_configs), features=feats)
    return result["macro_f1_pooled"]


def prefix_check(prefix_dir: str, baseline_f1: float) -> None:
    print("\n" + "=" * 70)
    print("PREFIX EVALUATION (online-decision-horizon features only)")
    print("=" * 70)
    for n in (5, 10, 20):
        path = os.path.join(prefix_dir, f"stage4_prefix{n}.csv")
        if not os.path.exists(path):
            print(f"\nN={n}: {path} not found -- run analysis/prefix_features.py first.")
            continue
        df = pd.read_csv(path)
        if df.empty:
            print(f"\nN={n}: {path} is empty.")
            continue
        groups = df["session_id"].to_numpy()
        n_unique = len(set(groups))
        if n_unique == len(groups):
            print(f"\nN={n}: every session_id unique among {len(groups)} rows -- "
                 f"GroupKFold(n_splits=5) here is equivalent to a plain 5-fold split, "
                 f"same caveat as item 1's RF analysis (not leakage protection, just "
                 f"consistency with the rest of the project's CV convention).")
        result = run_group_cv(df, groups, f"Prefix N={n}", n_splits=5)
        delta = result["macro_f1_pooled"] - baseline_f1
        print(f"  delta vs full-session baseline ({baseline_f1:.5f}): {delta:+.5f}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", default="generation/stage4_labelled.csv")
    p.add_argument("--prefix-dir", default="generation")
    # From item 1's RF C+P+R run (analysis/rf_analysis.py): pooled macro-F1 = 1.00000.
    p.add_argument("--baseline-f1", type=float, default=1.0)
    args = p.parse_args(argv)

    config_f1 = config_grouped_check(args.train)

    print("\n" + "!" * 70)
    if args.baseline_f1 - config_f1 > 0.05:
        print(f"FLAG: config-grouped macro-F1 ({config_f1:.5f}) is more than 0.05 below "
             f"the full-session baseline ({args.baseline_f1:.5f}) -- the ceiling result "
             f"may be tool-config matching, not behaviour generalisation. Report this "
             f"prominently, do not average it away.")
    else:
        print(f"Config-grouped macro-F1 ({config_f1:.5f}) is within 0.05 of the baseline "
             f"({args.baseline_f1:.5f}) -- no sharp drop from holding out entire "
             f"configurations. Consistent with genuine behaviour generalisation, not "
             f"pure tool-config matching, though see the individual class-level numbers "
             f"above for any single class hiding a problem behind a good macro average.")
    print("!" * 70)

    # Probed-only data leaves broad_scanning with one config, so re-run on the full population (C+P).
    print("\n" + "=" * 70)
    print("SUPPLEMENTARY: config-grouped check on the FULL population (C+P only, "
         "no R -- see comment above on why the probed-only run above cannot "
         "fairly test broad_scanning's cross-config generalisation)")
    print("=" * 70)
    config_grouped_check(args.train, features=GROUP_C + GROUP_P, population="all")

    prefix_check(args.prefix_dir, args.baseline_f1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
