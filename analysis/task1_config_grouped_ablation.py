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
from sklearn.inspection import permutation_importance

from timing_separation_check import GROUP_C, GROUP_P, GROUP_R, CLASS_ORDER

RF_KWARGS = dict(n_estimators=500, class_weight="balanced", min_samples_leaf=5,
                 random_state=42, n_jobs=-1)


def build_X(df: pd.DataFrame, features) -> np.ndarray:
    return df[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)


def fold_split(df: pd.DataFrame):
    groups = (df["tool"].astype(str) + "::" + df["config_name"].astype(str)).to_numpy()
    unique = sorted(set(groups))
    gkf = GroupKFold(n_splits=len(unique))
    folds = list(gkf.split(df, df["behaviour_class"], groups=groups))
    return groups, unique, folds


def run_cv(df: pd.DataFrame, features: list, folds, groups) -> dict:
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    n = len(y)
    pooled_pred = np.empty(n, dtype=object)
    per_fold_f1 = []
    held_out_config = []

    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_train, y_test = y[train_idx], y[test_idx]

        model = RandomForestClassifier(**RF_KWARGS)
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        pooled_pred[test_idx] = pred
        per_fold_f1.append(f1_score(y_test, pred, average="macro", labels=CLASS_ORDER))
        held_out_config.append(sorted(set(groups[test_idx]))[0] if len(test_idx) else "?")

    cm = confusion_matrix(y, pooled_pred, labels=CLASS_ORDER)
    return {"pooled_pred": pooled_pred, "y": y, "cm": cm,
            "per_fold_f1": per_fold_f1, "held_out_config": held_out_config}


def per_class_f1_by_fold(y, pooled_pred, test_idx_per_fold) -> dict:
    """Per-fold per-class F1, so folds with zero support can be excluded explicitly."""
    out = {c: [] for c in CLASS_ORDER}
    for test_idx in test_idx_per_fold:
        yt = y[test_idx]
        pt = pooled_pred[test_idx]
        p_, r_, f_, support = precision_recall_fscore_support(
            yt, pt, labels=CLASS_ORDER, zero_division=0)
        for i, c in enumerate(CLASS_ORDER):
            out[c].append((f_[i], int(support[i])))
    return out


def report_nested(df: pd.DataFrame, feature_sets: dict, label: str) -> dict:
    print("=" * 78)
    print(f"{label}: {len(df)} sessions")
    print("=" * 78)
    groups, unique_configs, folds = fold_split(df)
    print(f"{len(unique_configs)} unique (tool, config_name) groups: {unique_configs}")
    test_idx_per_fold = [test_idx for _, test_idx in folds]

    results = {}
    for name, feats in feature_sets.items():
        res = run_cv(df, feats, folds, groups)
        results[name] = res
        pooled_f1 = f1_score(res["y"], res["pooled_pred"], average="macro", labels=CLASS_ORDER)
        print(f"\n{name} ({len(feats)} features):")
        print(f"  per-fold macro-F1: {[round(f, 4) for f in res['per_fold_f1']]}")
        print(f"  pooled macro-F1: {pooled_f1:.5f}   mean-of-folds: "
             f"{np.mean(res['per_fold_f1']):.5f}")

        by_class = per_class_f1_by_fold(res["y"], res["pooled_pred"], test_idx_per_fold)
        for c in CLASS_ORDER:
            vals = by_class[c]
            usable = [f for f, supp in vals if supp > 0]
            zero_support_folds = [res["held_out_config"][i] for i, (f, supp) in enumerate(vals)
                                  if supp == 0]
            mean_f1 = np.mean(usable) if usable else float("nan")
            note = ""
            if zero_support_folds:
                note = (f"  [excluded {len(zero_support_folds)} fold(s) with zero true "
                        f"support: {zero_support_folds}]")
            print(f"    {c:24s} mean F1 over {len(usable)}/{len(vals)} folds = {mean_f1:.4f}{note}")

        print(f"  confusion matrix (rows=true, cols=pred), order {CLASS_ORDER}:")
        for i, row in enumerate(res["cm"]):
            print(f"    {CLASS_ORDER[i]:24s} {row}")

    names = list(feature_sets.keys())
    print(f"\nPrediction-change counts ({label}):")
    for a, b in zip(names, names[1:]):
        pa, pb = results[a]["pooled_pred"], results[b]["pooled_pred"]
        n_diff = int(np.sum(pa != pb))
        print(f"  {a} -> {b}: {n_diff}/{len(pa)} ({100*n_diff/len(pa):.2f}%) predictions changed")

    return results


def grouped_permutation_importance(df: pd.DataFrame, features: list,
                                   group_defs: dict, folds, n_repeats: int = 10) -> None:
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    idx_of = {f: i for i, f in enumerate(features)}

    drops = {name: [] for name in group_defs}
    rng = np.random.RandomState(42)

    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_test = y[test_idx]

        model = RandomForestClassifier(**RF_KWARGS)
        model.fit(X_train, y[train_idx])
        baseline = f1_score(y_test, model.predict(X_test), average="macro", labels=CLASS_ORDER)

        for name, group_feats in group_defs.items():
            cols = [idx_of[f] for f in group_feats if f in idx_of]
            if not cols:
                continue
            fold_drops = []
            for _ in range(n_repeats):
                Xp = X_test.copy()
                for c in cols:
                    Xp[:, c] = rng.permutation(Xp[:, c])
                score = f1_score(y_test, model.predict(Xp), average="macro", labels=CLASS_ORDER)
                fold_drops.append(baseline - score)
            drops[name].append(np.mean(fold_drops))

    print("\nGrouped permutation importance on the config-grouped C+P+R model "
         "(held-out folds, macro-F1 drop when the group is shuffled together):")
    for name, vals in drops.items():
        print(f"  {name:12s} ({len(group_defs[name])} features) mean drop="
             f"{np.mean(vals):+.5f} (sd={np.std(vals):.5f})  per-fold={[round(v,4) for v in vals]}")


def broad_scanning_config_check(df: pd.DataFrame) -> None:
    configs = sorted(set(
        (t, c) for t, c, cls in zip(df["tool"], df["config_name"], df["behaviour_class"])
        if cls == "broad_scanning"))
    print(f"\nbroad_scanning tool-configs present in this population: {configs}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", default="generation/stage4_labelled.csv")
    args = p.parse_args(argv)

    df_full = pd.read_csv(args.train)
    df_probed = df_full[pd.to_numeric(df_full["probe_count"], errors="coerce").fillna(0) > 0].reset_index(drop=True)

    print(f"Full population: {len(df_full)} sessions. Probed population: {len(df_probed)} sessions.\n")

    broad_scanning_config_check(df_probed)
    print("(if this is a single config, leave-one-config-out on the probed "
         "population removes ALL broad_scanning training data in that fold -- "
         "its F1 in that fold is undefined, not zero, and must be excluded "
         "from the class average, not averaged in.)\n")

    # --- Run 1: probed population, C / C+P / C+P+R ---
    feature_sets_probed = {
        "C": GROUP_C,
        "C+P": GROUP_C + GROUP_P,
        "C+P+R": GROUP_C + GROUP_P + GROUP_R,
    }
    results_probed = report_nested(df_probed, feature_sets_probed,
                                   "RUN 1: probed population (2,240), leave-one-config-out")

    _, _, folds_probed = fold_split(df_probed)
    grouped_permutation_importance(
        df_probed, GROUP_C + GROUP_P + GROUP_R,
        {"P": GROUP_P, "R": GROUP_R, "P+R": GROUP_P + GROUP_R},
        folds_probed)

    # --- Run 2: full population, C / C+P only ---
    feature_sets_full = {
        "C": GROUP_C,
        "C+P": GROUP_C + GROUP_P,
    }
    report_nested(df_full, feature_sets_full,
                 "RUN 2: full population (2,904), leave-one-config-out, C vs C+P only "
                 "(R undefined for unprobed sessions)")

    print("\n" + "=" * 78)
    print("PLAIN ANSWER: does timing add anything when content is below ceiling?")
    print("=" * 78)
    c_f1 = f1_score(results_probed["C"]["y"], results_probed["C"]["pooled_pred"],
                    average="macro", labels=CLASS_ORDER)
    cpr_f1 = f1_score(results_probed["C+P+R"]["y"], results_probed["C+P+R"]["pooled_pred"],
                      average="macro", labels=CLASS_ORDER)
    n_diff = int(np.sum(results_probed["C"]["pooled_pred"] != results_probed["C+P+R"]["pooled_pred"]))
    print(f"C pooled macro-F1={c_f1:.5f}  C+P+R pooled macro-F1={cpr_f1:.5f}  "
         f"delta={cpr_f1-c_f1:+.5f}  predictions changed C->C+P+R: {n_diff}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
