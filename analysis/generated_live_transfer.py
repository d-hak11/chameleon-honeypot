#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support)

from timing_separation_check import GROUP_C, GROUP_P, GROUP_R, CLASS_ORDER
from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise
from label_live_sessions import find_live_logs

FEATURES = GROUP_C + GROUP_P + GROUP_R
SCORABLE_LABELS = set(CLASS_ORDER)  # broad_scanning, active_backend_testing, indexing


def load_generated(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[pd.to_numeric(df["probe_count"], errors="coerce").fillna(0) > 0].reset_index(drop=True)
    return df


def load_live_features(live_dir: str) -> pd.DataFrame:
    paths = find_live_logs(live_dir)
    requests = read_requests(paths)
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)
    rows = []
    for session in sessions:
        feats = extract(session)
        if feats["source_private"]:
            continue
        if feats["count"] < 4:
            continue
        rows.append(feats)
    return pd.DataFrame(rows)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train", default="generation/stage4_labelled.csv")
    p.add_argument("--live-labels", default="analysis/live_labels_final.csv")
    p.add_argument("--live-dir", default="live-data")
    args = p.parse_args(argv)

    if not os.path.exists(args.live_labels):
        print(f"No live labels found at {args.live_labels}. "
              f"Run analysis/label_live_sessions.py first -- this script "
              f"does not train until hand labels exist.", file=sys.stderr)
        return 1
    with open(args.live_labels, newline="", encoding="utf-8") as f:
        label_rows = list(csv.DictReader(f))
    if not label_rows:
        print(f"{args.live_labels} exists but has zero labelled rows. Nothing to test on.",
              file=sys.stderr)
        return 1

    train_df = load_generated(args.train)
    live_feat_df = load_live_features(args.live_dir)
    label_df = pd.DataFrame(label_rows)[["session_id", "label", "confidence"]]
    live_df = live_feat_df.merge(label_df, on="session_id", how="inner")

    missing = set(label_df["session_id"]) - set(live_feat_df["session_id"])
    if missing:
        print(f"WARNING: {len(missing)} labelled session_id(s) not found in the "
              f"recomputed live features (stale label file vs. current live-data/?): "
              f"{sorted(missing)[:5]}{'...' if len(missing) > 5 else ''}", file=sys.stderr)

    train_sources = set(train_df["source_hash"])
    live_sources = set(live_df["source_hash"])
    overlap = train_sources & live_sources
    assert not overlap, (
        f"Train/test source_hash overlap detected ({len(overlap)} shared sources) -- "
        f"the source-address-disjoint requirement is violated; refusing to proceed.")
    print(f"Source-address-disjoint check passed: {len(train_sources)} generated "
          f"source_hash value(s), {len(live_sources)} live source_hash value(s), "
          f"0 overlap.")

    scorable = live_df[live_df["label"].isin(SCORABLE_LABELS)].copy()
    excluded = live_df[~live_df["label"].isin(SCORABLE_LABELS)]
    print(f"\n{len(live_df)} hand-labelled live sessions total.")
    print(f"  scorable (one of {sorted(SCORABLE_LABELS)}): {len(scorable)}")
    if len(excluded):
        exc_counts = excluded["label"].value_counts().to_dict()
        print(f"  excluded from scoring (not a trained class): {len(excluded)} -- {exc_counts}")
    if scorable.empty:
        print("No scorable live sessions yet (all insufficient_data/unknown_mixed, "
              "or labelling not started). Nothing to report.", file=sys.stderr)
        return 1

    X_train_raw = train_df[FEATURES].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    y_train = train_df["behaviour_class"].to_numpy()
    for feat in FEATURES:
        if feat not in scorable.columns:
            scorable[feat] = np.nan
    X_test_raw = scorable[FEATURES].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    y_test = scorable["label"].to_numpy()

    imp = SimpleImputer(strategy="median")
    X_train = imp.fit_transform(X_train_raw)
    X_test = imp.transform(X_test_raw)

    model = RandomForestClassifier(
        n_estimators=500, class_weight="balanced", min_samples_leaf=5,
        random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    print(f"\nTrained on {len(y_train)} generated sessions "
          f"(class counts: " + ", ".join(
              f"{c}={int((y_train == c).sum())}" for c in CLASS_ORDER) + ")")
    print(f"Tested on {len(y_test)} live sessions "
          f"(class counts: " + ", ".join(
              f"{c}={int((y_test == c).sum())}" for c in CLASS_ORDER) + ")\n")

    p_, r_, f_, support = precision_recall_fscore_support(
        y_test, pred, labels=CLASS_ORDER, zero_division=0)
    print("Per-class precision/recall/F1 on the LIVE test set:")
    # n<2 can't support a rate estimate, so report such classes as not evaluable.
    MIN_EVALUABLE_SUPPORT = 2
    for i, c in enumerate(CLASS_ORDER):
        if support[i] < MIN_EVALUABLE_SUPPORT:
            print(f"  {c:24s} NOT EVALUABLE -- n={support[i]}, reflecting genuine "
                  f"scarcity of this behaviour in the labelled live sample "
                  f"(not a 0% or 100% score; there is nothing a single session "
                  f"can support a rate estimate from)")
        else:
            print(f"  {c:24s} precision={p_[i]:.4f}  recall={r_[i]:.4f}  "
                  f"F1={f_[i]:.4f}  support={support[i]}")

    cm = confusion_matrix(y_test, pred, labels=CLASS_ORDER)
    print(f"\nConfusion matrix (rows=true live label, cols=predicted), order {CLASS_ORDER}:")
    for i, row in enumerate(cm):
        print(f"  {CLASS_ORDER[i]:24s} {row}")

    evaluable = [i for i in range(len(CLASS_ORDER)) if support[i] >= MIN_EVALUABLE_SUPPORT]
    excluded_classes = [CLASS_ORDER[i] for i in range(len(CLASS_ORDER)) if i not in evaluable]
    macro_f1 = float(np.mean([f_[i] for i in evaluable])) if evaluable else float("nan")
    print(f"\nLive-test macro-F1 (evaluable classes only): {macro_f1:.4f}")
    if excluded_classes:
        print(f"  excluded from this average (not evaluable, n<{MIN_EVALUABLE_SUPPORT}): "
              f"{excluded_classes} -- averaging in their 0.0 would not be a real "
              f"finding about those classes, just an artefact of n")
    print("(Compare against the GENERATED-side cross-validated macro-F1 reported "
          "in DEVELOPMENT_RECORD.md Sec. 12 item 1 -- this number is the actual "
          "transfer result; the CV number is not a substitute for it.)")

    if "confidence" in scorable.columns:
        print("\nBreakdown by annotator confidence:")
        conf_order = ["high", "medium-high", "medium", "low-medium", "low"]
        seen_confs = set(scorable["confidence"].dropna().unique())
        for conf in conf_order + sorted(seen_confs - set(conf_order)):
            sub = scorable[scorable["confidence"] == conf]
            if sub.empty:
                continue
            print(f"  {conf}: n={len(sub)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
