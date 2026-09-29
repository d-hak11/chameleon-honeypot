#!/usr/bin/env python3
from __future__ import annotations

import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold
from sklearn.impute import SimpleImputer
from sklearn.metrics import (f1_score, balanced_accuracy_score, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.inspection import permutation_importance
from sklearn.utils.class_weight import compute_sample_weight

sys.path.insert(0, "analysis")
from timing_separation_check import GROUP_C, GROUP_P, GROUP_R, to_float, CLASS_ORDER

# Mirrors engine/policy.py: active_backend_testing holds, broad_scanning/indexing rotate.
POLICY_ACTION = {
    "active_backend_testing": "hold",
    "broad_scanning": "rotate",
    "indexing": "rotate",
}


def load_data(path: str):
    df = pd.read_csv(path)
    df = df[pd.to_numeric(df["probe_count"], errors="coerce").fillna(0) > 0].reset_index(drop=True)
    return df


def build_X(df: pd.DataFrame, features: list) -> np.ndarray:
    return df[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)


def run_cv(df: pd.DataFrame, features: list, model_name: str, folds: list
          ) -> dict:
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    n = len(y)
    pooled_pred = np.empty(n, dtype=object)
    per_fold_f1, per_fold_bal_acc = [], []
    per_fold_prf = []

    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_train, y_test = y[train_idx], y[test_idx]

        if model_name == "rf":
            model = RandomForestClassifier(
                n_estimators=500, class_weight="balanced",
                min_samples_leaf=5, random_state=42, n_jobs=-1)
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
        per_fold_bal_acc.append(balanced_accuracy_score(y_test, pred))
        p, r, f, _ = precision_recall_fscore_support(
            y_test, pred, labels=CLASS_ORDER, zero_division=0)
        per_fold_prf.append((p, r, f))

    cm = confusion_matrix(y, pooled_pred, labels=CLASS_ORDER)
    return {
        "per_fold_f1": per_fold_f1, "per_fold_bal_acc": per_fold_bal_acc,
        "per_fold_prf": per_fold_prf, "pooled_pred": pooled_pred, "y": y, "cm": cm,
    }


def summarize(name: str, result: dict) -> None:
    f1s = result["per_fold_f1"]
    baccs = result["per_fold_bal_acc"]
    print(f"\n{name}:")
    print(f"  per-fold macro-F1:         {[round(f, 5) for f in f1s]}")
    print(f"  per-fold balanced accuracy: {[round(b, 5) for b in baccs]}")
    print(f"  mean macro-F1={np.mean(f1s):.5f} (sd={np.std(f1s):.5f})  "
         f"mean balanced accuracy={np.mean(baccs):.5f} (sd={np.std(baccs):.5f})")
    prf = result["per_fold_prf"]
    for ci, c in enumerate(CLASS_ORDER):
        p_mean = np.mean([fold[0][ci] for fold in prf])
        r_mean = np.mean([fold[1][ci] for fold in prf])
        print(f"    {c:24s} precision={p_mean:.4f}  recall={r_mean:.4f}")
    print("  confusion matrix (rows=true, cols=pred), order "
         f"{CLASS_ORDER}:")
    for i, row in enumerate(result["cm"]):
        print(f"    {CLASS_ORDER[i]:24s} {row}")


def paired_report(name_a: str, res_a: dict, name_b: str, res_b: dict) -> None:
    deltas = [b - a for a, b in zip(res_a["per_fold_f1"], res_b["per_fold_f1"])]
    mean_d = np.mean(deltas)
    sd_d = np.std(deltas)
    sem_d = sd_d / (len(deltas) ** 0.5) if len(deltas) > 1 else 0.0
    print(f"  paired per-fold macro-F1 delta ({name_b} - {name_a}): "
         f"{[round(d, 5) for d in deltas]}")
    print(f"    mean={mean_d:+.5f}  sd={sd_d:.5f}  "
         f"95% CI={mean_d-1.96*sem_d:+.5f}, {mean_d+1.96*sem_d:+.5f}]")
    n_diff = int(np.sum(res_a["pooled_pred"] != res_b["pooled_pred"]))
    n = len(res_a["pooled_pred"])
    print(f"  predictions that changed {name_a} -> {name_b}: {n_diff}/{n} "
         f"({100*n_diff/n:.3f}%)")


def induced_action_matrix(pooled_pred: np.ndarray, y: np.ndarray) -> None:
    true_action = np.array([POLICY_ACTION[c] for c in y])
    pred_action = np.array([POLICY_ACTION[c] for c in pooled_pred])
    print("\nInduced-action confusion matrix (rotate vs hold, per engine/policy.py):")
    for ta in ("hold", "rotate"):
        row = [int(np.sum((true_action == ta) & (pred_action == pa)))
              for pa in ("hold", "rotate")]
        print(f"  true={ta:6s}  pred_hold={row[0]:5d}  pred_rotate={row[1]:5d}")

    erroneous_rotation = int(np.sum((true_action == "hold") & (pred_action == "rotate")))
    n_hold = int(np.sum(true_action == "hold"))
    unnecessary_hold = int(np.sum((true_action == "rotate") & (pred_action == "hold")))
    n_rotate = int(np.sum(true_action == "rotate"))
    scanning_indexing_confusion = int(np.sum(
        (y != pooled_pred) & (true_action == "rotate") & (pred_action == "rotate")))
    print(f"\n  erroneous rotation during a protected interaction "
         f"(true=hold, predicted=rotate): {erroneous_rotation}/{n_hold} "
         f"({100*erroneous_rotation/n_hold:.2f}%) -- SEVERE: terminates a "
         f"protected interaction")
    print(f"  unnecessary holding (true=rotate, predicted=hold): "
         f"{unnecessary_hold}/{n_rotate} ({100*unnecessary_hold/n_rotate:.2f}%) "
         f"-- missed rotation opportunity, not a terminated interaction")
    print(f"  scanning<->indexing confusion (both true rotate, wrong class "
         f"but same action): {scanning_indexing_confusion}/{n_rotate} "
         f"({100*scanning_indexing_confusion/n_rotate:.2f}%) -- NO "
         f"operational consequence")


def permutation_importance_report(df: pd.DataFrame, features: list, folds: list) -> None:
    X = build_X(df, features)
    y = df["behaviour_class"].to_numpy()
    p_idx = [features.index(f) for f in GROUP_P]
    r_idx = [features.index(f) for f in GROUP_R]

    individual_importances = {f: [] for f in features}
    group_p_drops, group_r_drops = [], []

    for train_idx, test_idx in folds:
        imp = SimpleImputer(strategy="median")
        X_train = imp.fit_transform(X[train_idx])
        X_test = imp.transform(X[test_idx])
        y_train, y_test = y[train_idx], y[test_idx]
        model = RandomForestClassifier(
            n_estimators=500, class_weight="balanced",
            min_samples_leaf=5, random_state=42, n_jobs=-1)
        model.fit(X_train, y_train)

        baseline = f1_score(y_test, model.predict(X_test), average="macro", labels=CLASS_ORDER)

        # Individual, sklearn's own implementation (single-feature shuffles).
        r = permutation_importance(model, X_test, y_test, scoring="f1_macro",
                                   n_repeats=10, random_state=42, n_jobs=-1)
        for j, f in enumerate(features):
            individual_importances[f].append(r.importances_mean[j])

        # Shuffle a whole feature group together so correlated features can't cover for each other.
        rng = np.random.RandomState(42)
        for idx_group, drops in ((p_idx, group_p_drops), (r_idx, group_r_drops)):
            fold_drops = []
            for _ in range(10):
                X_perturbed = X_test.copy()
                for j in idx_group:
                    X_perturbed[:, j] = rng.permutation(X_perturbed[:, j])
                perturbed_score = f1_score(
                    y_test, model.predict(X_perturbed), average="macro", labels=CLASS_ORDER)
                fold_drops.append(baseline - perturbed_score)
            drops.append(np.mean(fold_drops))

    print("\nPermutation importance (RF, C+P+R feature set, held-out folds, "
         "macro-F1 drop when shuffled):")
    print("  GROUP shuffles (all columns in the group permuted together --"
         " correlation-robust):")
    print(f"    P group ({len(p_idx)} features) shuffled together: "
         f"mean drop={np.mean(group_p_drops):+.5f} (sd={np.std(group_p_drops):.5f})")
    print(f"    R group ({len(r_idx)} features) shuffled together: "
         f"mean drop={np.mean(group_r_drops):+.5f} (sd={np.std(group_r_drops):.5f})")
    print("  individual feature importances (secondary -- timing features are "
         "heavily inter-correlated, so these UNDERSTATE each one's true "
         "group contribution; use the group numbers above as primary):")
    for f in features:
        vals = individual_importances[f]
        tag = "C" if f in GROUP_C else ("P" if f in GROUP_P else "R")
        print(f"    [{tag}] {f:36s} mean drop={np.mean(vals):+.5f} (sd={np.std(vals):.5f})")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "generation/stage4_labelled.csv"
    df = load_data(path)
    print(f"rf_analysis: {len(df)} probed sessions loaded from {path}")
    print("class counts: " + ", ".join(
        f"{c}={int((df['behaviour_class']==c).sum())}" for c in CLASS_ORDER))

    gkf = GroupKFold(n_splits=5)
    groups = df["session_id"].to_numpy()
    n_unique_groups = len(set(groups))
    print(f"GroupKFold on session_id: {n_unique_groups} unique groups for {len(groups)} rows")
    if n_unique_groups == len(groups):
        print("  every session_id is unique, so this is equivalent to an "
             "ungrouped 5-fold split (no grouping effect) -- flagging this "
             "since GroupKFold only changes behaviour when groups span "
             "multiple rows")
    folds = list(gkf.split(df, df["behaviour_class"], groups=groups))

    feature_sets = {
        "C": GROUP_C,
        "C+P": GROUP_C + GROUP_P,
        "C+P+R": GROUP_C + GROUP_P + GROUP_R,
    }

    print("\n" + "=" * 70)
    print("RANDOM FOREST (the specified methodology)")
    print("=" * 70)
    rf_results = {}
    for name, feats in feature_sets.items():
        rf_results[name] = run_cv(df, feats, "rf", folds)
        summarize(f"RF {name}", rf_results[name])

    print("\nRF paired increments:")
    paired_report("C", rf_results["C"], "C+P", rf_results["C+P"])
    paired_report("C+P", rf_results["C+P"], "C+P+R", rf_results["C+P+R"])

    print("\n" + "=" * 70)
    print("HIST GRADIENT BOOSTING (third confirmatory check)")
    print("=" * 70)
    hgb_results = {}
    for name, feats in feature_sets.items():
        hgb_results[name] = run_cv(df, feats, "hgb", folds)
        summarize(f"HGB {name}", hgb_results[name])
    print("\nHGB paired increments:")
    paired_report("C", hgb_results["C"], "C+P", hgb_results["C+P"])
    paired_report("C+P", hgb_results["C+P"], "C+P+R", hgb_results["C+P+R"])

    print("\n" + "=" * 70)
    print("INDUCED-ACTION CONFUSION MATRIX (RF, C+P+R)")
    print("=" * 70)
    induced_action_matrix(rf_results["C+P+R"]["pooled_pred"], rf_results["C+P+R"]["y"])

    print("\n" + "=" * 70)
    print("PERMUTATION IMPORTANCE (RF, C+P+R)")
    print("=" * 70)
    permutation_importance_report(df, GROUP_C + GROUP_P + GROUP_R, folds)

    return 0


if __name__ == "__main__":
    sys.exit(main())
