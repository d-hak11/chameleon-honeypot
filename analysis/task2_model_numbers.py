#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import GroupKFold
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.preprocessing import StandardScaler

from timing_separation_check import GROUP_C, GROUP_P, GROUP_R, CLASS_ORDER

RF_KWARGS = dict(n_estimators=500, class_weight="balanced", min_samples_leaf=5,
                 random_state=42, n_jobs=-1)


def build_X(df, features):
    # Stored as "True"/"False" strings; map to 0/1 before numeric coercion.
    df = df.copy()
    if "header_order_consistent" in df.columns:
        df["header_order_consistent"] = df["header_order_consistent"].map(
            {"True": 1, "False": 0, True: 1, False: 0}
        ).fillna(df["header_order_consistent"])
    return df[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)


def standard_folds(df):
    groups = df["session_id"].to_numpy()
    gkf = GroupKFold(n_splits=5)
    folds = list(gkf.split(df, df["behaviour_class"], groups=groups))
    n_unique = len(set(groups))
    print(f"GroupKFold on session_id: {n_unique} unique groups for {len(groups)} rows "
         f"({'equivalent to plain 5-fold' if n_unique == len(groups) else 'grouping active'})")
    return folds


def run_model(df, features, folds, model_name):
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    pooled_pred = np.empty(len(y), dtype=object)
    per_fold_f1 = []
    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_train, y_test = y[train_idx], y[test_idx]

        if model_name == "nb":
            # Scale first: GaussianNB's variance floor is relative to the largest feature variance.
            scaler = StandardScaler().fit(X_train)
            X_train, X_test = scaler.transform(X_train), scaler.transform(X_test)
            model = GaussianNB()
            model.fit(X_train, y_train)
        elif model_name == "hgb":
            model = HistGradientBoostingClassifier(random_state=42)
            sw = compute_sample_weight("balanced", y_train)
            model.fit(X_train, y_train, sample_weight=sw)
        else:
            raise ValueError(model_name)

        pred = model.predict(X_test)
        pooled_pred[test_idx] = pred
        per_fold_f1.append(f1_score(y_test, pred, average="macro", labels=CLASS_ORDER))
    return pooled_pred, per_fold_f1


def report_nested(df, model_name, label):
    folds = standard_folds(df)
    feature_sets = {"C": GROUP_C, "C+P": GROUP_C + GROUP_P, "C+P+R": GROUP_C + GROUP_P + GROUP_R}
    results = {}
    print(f"\n--- {label} ---")
    for name, feats in feature_sets.items():
        pred, per_fold = run_model(df, feats, folds, model_name)
        results[name] = pred
        print(f"  {name:7s} per-fold macro-F1={[round(f,5) for f in per_fold]}  "
             f"mean={np.mean(per_fold):.5f}")
    names = list(feature_sets.keys())
    for a, b in zip(names, names[1:]):
        n_diff = int(np.sum(results[a] != results[b]))
        print(f"  predictions changed {a} -> {b}: {n_diff}/{len(results[a])} "
             f"({100*n_diff/len(results[a]):.3f}%)")
    return results


def grouped_permutation_importance_standard_split(df, folds, n_repeats=10):
    from sklearn.inspection import permutation_importance
    features = GROUP_C + GROUP_P + GROUP_R
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    p_idx = [features.index(f) for f in GROUP_P]
    r_idx = [features.index(f) for f in GROUP_R]

    group_p_drops, group_r_drops = [], []
    rng = np.random.RandomState(42)
    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_train, y_test = y[train_idx], y[test_idx]
        model = RandomForestClassifier(**RF_KWARGS)
        model.fit(X_train, y_train)
        baseline = f1_score(y_test, model.predict(X_test), average="macro", labels=CLASS_ORDER)

        for idx_group, drops in ((p_idx, group_p_drops), (r_idx, group_r_drops)):
            fold_drops = []
            for _ in range(n_repeats):
                Xp = X_test.copy()
                for j in idx_group:
                    Xp[:, j] = rng.permutation(Xp[:, j])
                score = f1_score(y_test, model.predict(Xp), average="macro", labels=CLASS_ORDER)
                fold_drops.append(baseline - score)
            drops.append(np.mean(fold_drops))

    print("\nGrouped permutation importance (RF, C+P+R, standard session-id split, "
         "POST-dedup-fix):")
    print(f"  P group ({len(p_idx)} features): mean drop={np.mean(group_p_drops):+.5f} "
         f"(sd={np.std(group_p_drops):.5f})  per-fold={[round(v,5) for v in group_p_drops]}")
    print(f"  R group ({len(r_idx)} features): mean drop={np.mean(group_r_drops):+.5f} "
         f"(sd={np.std(group_r_drops):.5f})  per-fold={[round(v,5) for v in group_r_drops]}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", default="generation/stage4_labelled.csv")
    args = p.parse_args(argv)

    df = pd.read_csv(args.train)
    df = df[pd.to_numeric(df["probe_count"], errors="coerce").fillna(0) > 0].reset_index(drop=True)
    print(f"{len(df)} probed sessions loaded (post-nmap-dedup-fix data)")

    report_nested(df, "nb", "GAUSSIAN NB (standard split, post-dedup-fix)")
    report_nested(df, "hgb", "HIST GRADIENT BOOSTING (standard split, post-dedup-fix)")

    folds = standard_folds(df)
    grouped_permutation_importance_standard_split(df, folds)

    return 0


if __name__ == "__main__":
    sys.exit(main())
