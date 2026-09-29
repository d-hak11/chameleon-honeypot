#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import os
import sys
from collections import Counter
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extract_features import DEFAULT_IDLE_SECONDS, extract, read_requests, sessionise

LABELS = {
    "b": "broad_scanning",
    "i": "indexing",
    "a": "active_backend_testing",
    "n": "insufficient_data",
    "m": "unknown_mixed",
}
CONFIDENCE = {"h": "high", "m": "medium", "l": "low", "": "medium"}

OUT_FIELDNAMES = ["session_id", "source_hash", "label", "confidence", "notes", "labelled_at"]


def find_live_logs(live_dir: str) -> List[str]:
    return sorted(glob.glob(os.path.join(live_dir, "**", "access.json"), recursive=True))


def load_existing(out_path: str) -> Dict[str, dict]:
    if not os.path.exists(out_path):
        return {}
    with open(out_path, newline="", encoding="utf-8") as f:
        return {row["session_id"]: row for row in csv.DictReader(f)}


def build_sessions(live_dir: str) -> List[dict]:
    paths = find_live_logs(live_dir)
    if not paths:
        print(f"No access.json files found under {live_dir}/", file=sys.stderr)
        return []
    requests = read_requests(paths)
    sessions = sessionise(requests, DEFAULT_IDLE_SECONDS)

    out = []
    for session in sessions:
        feats = extract(session)
        if feats["source_private"]:
            continue
        if feats["count"] < 4:
            continue
        top = Counter(r.path for r in session).most_common(5)
        uas = sorted({r.user_agent for r in session if r.user_agent})
        feats["_top_paths"] = top
        feats["_user_agents"] = uas
        out.append(feats)
    out.sort(key=lambda f: f["first_seen"])
    return out


def print_summary(idx: int, total: int, feats: dict, already: int) -> None:
    n = feats["count"]
    dp = feats["distinct_paths"] or 1
    req_per_path = n / dp
    rate = feats["rate"]
    rate_str = f"{rate:.2f}/s" if rate is not None else "n/a (implausible or zero-duration)"
    top_str = ", ".join(f"{p}({c})" for p, c in feats["_top_paths"])
    print(f"\n[{idx}/{total}] session {feats['session_id']}  (labelled so far: {already})")
    print(f"  count={n}  distinct_paths={dp}  req/path={req_per_path:.1f}  "
          f"404%={feats['status_4xx_ratio']*100:.0f}%  "
          f"query%={feats['query_present_ratio']*100:.0f}%  "
          f"rate={rate_str}  dur={feats['duration_seconds']:.1f}s")
    print(f"  top paths: {top_str}")


def report(out_path: str, sessions: Optional[List[dict]] = None) -> None:
    existing = load_existing(out_path)
    if not existing:
        print("No labels recorded yet.")
        return
    by_label_sources: Dict[str, set] = {}
    by_label_count: Dict[str, int] = {}
    for row in existing.values():
        lbl = row["label"]
        by_label_sources.setdefault(lbl, set()).add(row["source_hash"])
        by_label_count[lbl] = by_label_count.get(lbl, 0) + 1
    print(f"\n{len(existing)} sessions labelled, written to {out_path}")
    print("Per-label distinct source_hash count (independent sources the label rests on):")
    for lbl in sorted(by_label_count):
        print(f"  {lbl:24s} sessions={by_label_count[lbl]:4d}  "
              f"distinct_sources={len(by_label_sources[lbl]):4d}")


SHEET_FIELDNAMES = [
    "session_id", "source_hash", "count", "distinct_paths", "requests_per_path",
    "pct_4xx", "pct_query_present", "rate_per_sec", "duration_seconds",
    "top_paths", "label", "confidence", "notes",
]

VALID_LABELS = set(LABELS.values())
VALID_CONFIDENCE = {"high", "medium-high", "medium", "low-medium", "low"}


def export_sheet(live_dir: str, out_path: str, existing_out: str) -> None:
    """Export unlabelled sessions to a CSV; existing sheet rows are preserved (append, not overwrite)."""
    sessions = build_sessions(live_dir)
    if not sessions:
        return
    existing_canonical = load_existing(existing_out)

    existing_sheet_rows: List[dict] = []
    existing_sheet_ids = set()
    if os.path.exists(out_path):
        with open(out_path, newline="", encoding="utf-8") as f:
            existing_sheet_rows = list(csv.DictReader(f))
        existing_sheet_ids = {r["session_id"] for r in existing_sheet_rows}

    todo = [s for s in sessions
            if s["session_id"] not in existing_canonical
            and s["session_id"] not in existing_sheet_ids]

    new_rows = []
    for feats in todo:
        n = feats["count"]
        dp = feats["distinct_paths"] or 1
        rate = feats["rate"]
        top_str = "; ".join(f"{p}({c})" for p, c in feats["_top_paths"])
        new_rows.append({
            "session_id": feats["session_id"],
            "source_hash": feats["source_hash"],
            "count": n,
            "distinct_paths": dp,
            "requests_per_path": round(n / dp, 2),
            "pct_4xx": round(feats["status_4xx_ratio"] * 100, 1),
            "pct_query_present": round(feats["query_present_ratio"] * 100, 1),
            "rate_per_sec": round(rate, 3) if rate is not None else "",
            "duration_seconds": round(feats["duration_seconds"], 1),
            "top_paths": top_str,
            "label": "",
            "confidence": "",
            "notes": "",
        })

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SHEET_FIELDNAMES)
        writer.writeheader()
        for row in existing_sheet_rows:
            writer.writerow(row)
        for row in new_rows:
            writer.writerow(row)

    if existing_sheet_rows:
        print(f"{out_path} already had {len(existing_sheet_rows)} rows -- preserved "
             f"unchanged. Appended {len(new_rows)} newly-qualifying session(s) "
             f"({len(existing_canonical)} already in {existing_out} and "
             f"{len(existing_sheet_ids)} already in the sheet were skipped).")
    else:
        print(f"Wrote {len(new_rows)} unlabelled sessions to {out_path} "
              f"({len(existing_canonical)} already labelled in {existing_out} "
              f"were skipped).")
    print(f"Valid label values: {sorted(VALID_LABELS)}")
    print(f"Valid confidence values: {sorted(VALID_CONFIDENCE)} (blank -> medium)")
    print(f"Fill in 'label' (required) and 'confidence' (optional) for the rows "
          f"you've assessed, save, then run --import-sheet {out_path!r}. "
          f"Leave 'label' blank on rows you haven't gotten to yet -- only "
          f"non-blank labels are imported, so you can import partway through.")


def import_sheet(sheet_path: str, out_path: str) -> None:
    """Append valid labels from a filled-in sheet to --out; rejects unknown labels."""
    with open(sheet_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    existing = load_existing(out_path)

    errors = []
    to_import = []
    for row in rows:
        label = (row.get("label") or "").strip()
        if not label:
            continue
        sid = row["session_id"]
        if sid in existing:
            continue
        if label not in VALID_LABELS:
            errors.append(f"session {sid}: unrecognised label {label!r} "
                          f"(valid: {sorted(VALID_LABELS)})")
            continue
        confidence = (row.get("confidence") or "").strip().lower() or "medium"
        if confidence not in VALID_CONFIDENCE:
            errors.append(f"session {sid}: unrecognised confidence {confidence!r} "
                          f"(valid: {sorted(VALID_CONFIDENCE)})")
            continue
        to_import.append({
            "session_id": sid,
            "source_hash": row["source_hash"],
            "label": label,
            "confidence": confidence,
            "notes": (row.get("notes") or "").strip(),
            "labelled_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat(),
        })

    if errors:
        for e in errors:
            print(f"import_sheet: ERROR: {e}", file=sys.stderr)
        print(f"\n{len(errors)} row(s) had errors and were NOT imported. "
             f"Fix these values in {sheet_path} and re-run --import-sheet -- "
             f"everything else below was still imported.", file=sys.stderr)

    if not to_import:
        print("No new valid labels to import.")
        return

    out_is_new = not os.path.exists(out_path)
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDNAMES)
        if out_is_new:
            writer.writeheader()
        for row in to_import:
            writer.writerow(row)

    print(f"Imported {len(to_import)} label(s) into {out_path}.")
    report(out_path)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--live-dir", default="live-data")
    p.add_argument("--out", default="analysis/live_labels_final.csv")
    p.add_argument("--report", action="store_true",
                   help="Print the per-label distinct-source-hash summary and exit "
                        "without prompting for any new labels.")
    p.add_argument("--export-sheet", metavar="PATH",
                   help="Write unlabelled qualifying sessions to PATH as a plain CSV "
                        "with blank label/confidence/notes columns, for editing in "
                        "a spreadsheet instead of the terminal. Does not prompt.")
    p.add_argument("--import-sheet", metavar="PATH",
                   help="Read a filled-in --export-sheet CSV from PATH and append "
                        "its non-blank, valid labels to --out. Does not prompt.")
    args = p.parse_args(argv)

    if args.report:
        report(args.out)
        return 0

    if args.export_sheet:
        export_sheet(args.live_dir, args.export_sheet, args.out)
        return 0

    if args.import_sheet:
        import_sheet(args.import_sheet, args.out)
        return 0

    sessions = build_sessions(args.live_dir)
    if not sessions:
        return 1
    existing = load_existing(args.out)
    qualifying_sources = {s["source_hash"] for s in sessions}
    print(f"{len(sessions)} qualifying sessions (count>=4, external) across "
          f"{len(qualifying_sources)} distinct source_hash values. "
          f"{len(existing)} already labelled.")

    out_is_new = not os.path.exists(args.out)
    f = open(args.out, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=OUT_FIELDNAMES)
    if out_is_new:
        writer.writeheader()
        f.flush()

    import datetime
    todo = [s for s in sessions if s["session_id"] not in existing]
    print(f"{len(todo)} remaining to label. Commands: b/i/a/n/m=label, "
          f"v=reveal user-agent, s=skip (ask again later), q=quit and save.\n")

    try:
        for i, feats in enumerate(todo, 1):
            print_summary(i, len(todo), feats, len(existing))
            while True:
                choice = input(
                    "label [b=broad_scanning i=indexing a=active_backend_testing "
                    "n=insufficient_data m=unknown_mixed | v=show UA s=skip q=quit]: "
                ).strip().lower()
                if choice == "q":
                    raise KeyboardInterrupt
                if choice == "s":
                    break
                if choice == "v":
                    uas = feats["_user_agents"] or ["(none recorded)"]
                    print(f"  User-Agent(s): {' | '.join(uas)}")
                    continue
                if choice not in LABELS:
                    print(f"  not a recognised command: {choice!r}")
                    continue
                label = LABELS[choice]
                conf_raw = input("confidence [h/m/l, default m]: ").strip().lower()
                if conf_raw not in CONFIDENCE:
                    conf_raw = "m"
                confidence = CONFIDENCE[conf_raw]
                notes = input("notes (optional, enter to skip): ").strip()
                writer.writerow({
                    "session_id": feats["session_id"],
                    "source_hash": feats["source_hash"],
                    "label": label,
                    "confidence": confidence,
                    "notes": notes,
                    "labelled_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })
                f.flush()
                existing[feats["session_id"]] = {"label": label}
                break
    except (KeyboardInterrupt, EOFError):
        print("\nSaving and exiting.")
    finally:
        f.close()

    report(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
