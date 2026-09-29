#!/usr/bin/env python3
import csv
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import extract_features as ef

PASS = 0


def check(name, got, want=None, pred=None):
    global PASS
    ok = pred(got) if pred else (got == want)
    if ok:
        PASS += 1
        print(f"  ok  {name}")
    else:
        print(f"  FAIL {name}: got {got!r}, want {want!r}")
        sys.exit(1)


def access(ts, ip, uri, status=200, ua="curl/8.5.0", method="GET", size=1200,
          duration=0.02, persona="moodle", headers=None, run_id=""):
    hdrs = dict(headers or {})
    hdrs.setdefault("User-Agent", [ua])
    hdrs.setdefault("Accept", ["*/*"])
    return {
        "level": "info", "ts": ts, "logger": "http.log.access.access",
        "msg": "handled request",
        "request": {
            "remote_ip": ip, "remote_port": "12345", "client_ip": ip,
            "proto": "HTTP/1.1", "method": method, "host": "localhost:8080",
            "uri": uri, "headers": hdrs,
        },
        "bytes_read": 0, "user_id": "", "duration": duration, "size": size,
        "status": status, "resp_headers": {"Server": ["nginx"]},
        "persona": persona,
        "run_id": run_id,
    }


def write_log(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_sessionisation_and_idle_gap():
    print("sessionisation")
    t0 = 1_000_000.0
    entries = (
        [access(t0 + i * 5.0, "10.0.0.1", "/a") for i in range(3)] +
        # same IP, but 3000s later -- beyond the default 1800s idle gap.
        [access(t0 + 3000.0 + i * 5.0, "10.0.0.1", "/b") for i in range(2)] +
        [access(t0 + 1.0, "10.0.0.2", "/x")]
    )
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "access.json")
        write_log(path, entries)
        requests = ef.read_requests([path])
        sessions = ef.sessionise(requests, ef.DEFAULT_IDLE_SECONDS)
        check("three sessions total", len(sessions), 3)
        sizes = sorted(len(s) for s in sessions)
        check("session sizes", sizes, [1, 2, 3])


def test_full_session_rate_is_stable():
    print("full_session_rate")
    t0 = 2_000_000.0
    entries = [access(t0 + i * 5.0, "10.0.0.3", f"/path{i}") for i in range(12)]
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("rate computed over full span", feats["rate"], round(11 / 55.0, 6))
    check("duration_seconds spans first to last", feats["duration_seconds"], 55.0)


def test_single_request_rate_is_null_not_infinite():
    print("json_safety")
    e = access(3_000_000.0, "10.0.0.4", "/")
    session = [ef.parse_line(e)]
    feats = ef.extract(session)
    check("single-request session has null rate", feats["rate"], None)
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out.csv")
        ef.write_csv([feats], out)
        with open(out, "r", encoding="utf-8") as f:
            content = f.read()
    check("no Infinity token anywhere in the CSV", "Infinity" in content, False)


def test_implausible_rate_is_nulled_and_flagged():
    print("rate_sanity_bound")
    t0 = 3_500_000.0
    # 6 requests in 12ms: finite but implausible rate, as seen in real Stage 4 data.
    entries = [access(t0 + i * 0.0024, "10.0.0.9", f"/x{i}") for i in range(6)]
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("implausible rate is nulled, not reported as a huge number",
         feats["rate"], None)
    check("implausible rate is flagged, distinguishing it from a genuine "
         "zero-duration null", feats["rate_implausible"], True)

    slow_entries = [access(t0 + i * 1.0, "10.0.0.10", f"/y{i}") for i in range(6)]
    slow_session = [ef.parse_line(e) for e in slow_entries]
    slow_feats = ef.extract(slow_session)
    check("a plausible rate is left alone", slow_feats["rate"], 1.0)
    check("a plausible rate is not flagged", slow_feats["rate_implausible"], False)

    single = [ef.parse_line(access(t0, "10.0.0.11", "/"))]
    single_feats = ef.extract(single)
    check("zero-duration null is NOT flagged as implausible (different "
         "failure mode)", single_feats["rate_implausible"], False)


def test_path_entropy_and_ordering():
    print("path_features")
    t0 = 4_000_000.0
    # Alphabetically ascending distinct paths -- a wordlist-order signature.
    entries = [access(t0 + i, "10.0.0.5", p)
              for i, p in enumerate(["/a", "/b", "/c", "/d", "/e"])]
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("distinct_paths", feats["distinct_paths"], 5)
    check("fully ascending order score", feats["path_ordering_alphabetical_score"], 1.0)
    check("path entropy is positive for varied paths", feats["path_entropy"] > 0, True)


def test_pre_post_probe_interval():
    print("pre_post_probe")
    t0 = 5_000_000.0
    entries = (
        [access(t0 + i * 10.0, "10.0.0.6", f"/page{i}") for i in range(3)] +
        [access(t0 + 30.0 + i * 0.2, "10.0.0.6", "/wp-admin") for i in range(4)]
    )
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("pre-probe interval is the slow pace",
         feats["pre_probe_interval_mean"], 10.0)
    check("post-probe interval is much faster than pre-probe",
         feats["post_probe_interval_mean"] < feats["pre_probe_interval_mean"], True)


def test_pre_post_timing_probe_interval():
    print("pre_post_timing_probe")
    t0 = 5_500_000.0
    entries = (
        [access(t0 + i * 10.0, "10.0.0.13", f"/ordinary{i}") for i in range(3)] +
        [access(t0 + 30.0 + i * 0.2, "10.0.0.13", f"/ordinary{3+i}") for i in range(4)]
    )
    for i, e in enumerate(entries):
        e["probe_applied"] = (i == 3)
        e["probe_delay_ms"] = 150 if i == 3 else None
        e["client_abandoned"] = False if i == 3 else None
        e["abandon_after_ms"] = None
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("pre-timing-probe interval is the slow pace",
         feats["pre_timing_probe_interval_mean"], 10.0)
    check("post-timing-probe interval is much faster",
         feats["post_timing_probe_interval_mean"] <
         feats["pre_timing_probe_interval_mean"], True)
    check("PROBE_RE-anchored fields are untouched (no /wp-admin-style path here)",
         feats["pre_probe_interval_mean"], None)
    check("timing_probe_interval_delta_ms is negative (sped up after the hold)",
         feats["timing_probe_interval_delta_ms"] < 0, True)


def test_timing_probe_interval_uses_arrival_time_not_completion_time():
    print("timing_probe_interval_arrival_time_fix")
    t0 = 5_700_000.0
    # Only the probed request carries a hold in its duration, so arrival- vs completion-time gaps differ.
    durations = [0.01, 0.01, 0.01, 0.15, 0.01]
    arrivals = [t0 + 0.0, t0 + 1.0, t0 + 2.0, t0 + 3.0, None]
    arrivals[4] = arrivals[3] + durations[3] + 1.0
    ts_values = [a + d for a, d in zip(arrivals, durations)]

    entries = [access(ts_values[i], "10.0.0.16", f"/p{i}", duration=durations[i])
              for i in range(5)]
    for i, e in enumerate(entries):
        e["probe_applied"] = (i == 3)
        e["probe_delay_ms"] = 150 if i == 3 else None
        e["client_abandoned"] = False if i == 3 else None
        e["abandon_after_ms"] = None
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)

    check("pre-timing-probe interval is the clean 1.0s think-time, not "
         "inflated by the probed request's own hold",
         round(feats["pre_timing_probe_interval_mean"], 6), 1.0)
    check("post-timing-probe interval includes the hold in its first gap "
         "(think-time + the 0.15s duration), by design",
         round(feats["post_timing_probe_interval_mean"], 6), 1.15)
    check("delta reflects the hold showing up in post, not a phantom "
         "speed-up caused by an inflated pre baseline",
         round(feats["timing_probe_interval_delta_ms"], 3), 150.0)


def test_post_probe_continuation_and_retries():
    print("post_probe_continuation")
    t0 = 5_600_000.0
    paths = ["/a", "/b", "/c", "/d", "/b", "/e"]
    entries = [access(t0 + i * 1.0, "10.0.0.14", p) for i, p in enumerate(paths)]
    for i, e in enumerate(entries):
        e["probe_applied"] = (i == 2)
        e["probe_delay_ms"] = 150 if i == 2 else None
        e["client_abandoned"] = False if i == 2 else None
        e["abandon_after_ms"] = None
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("post_probe_request_count counts requests strictly after the probe",
         feats["post_probe_request_count"], 3)
    check("post_probe_repeat_visit_count counts only the re-requested /b",
         feats["post_probe_repeat_visit_count"], 1)

    no_probe_entries = [access(t0 + 100 + i, "10.0.0.15", f"/x{i}") for i in range(4)]
    no_probe_session = [ef.parse_line(e) for e in no_probe_entries]
    no_probe_feats = ef.extract(no_probe_session)
    check("post_probe_request_count is None, not 0, when never probed",
         no_probe_feats["post_probe_request_count"], None)
    check("post_probe_repeat_visit_count is None, not 0, when never probed",
         no_probe_feats["post_probe_repeat_visit_count"], None)


def test_header_order_fingerprint():
    print("header_order_fingerprint")
    t0 = 6_000_000.0
    e1 = access(t0, "10.0.0.7", "/", headers={"Zebra": ["1"], "Apple": ["2"]})
    e2 = access(t0 + 1.0, "10.0.0.7", "/b", headers={"Zebra": ["1"], "Apple": ["2"]})
    e3 = access(t0 + 2.0, "10.0.0.7", "/c", headers={"Apple": ["2"], "Zebra": ["1"]})
    session = [ef.parse_line(e) for e in (e1, e2, e3)]
    feats = ef.extract(session)
    check("header order is not consistent across the session",
         feats["header_order_consistent"], False)

    same_order = [ef.parse_line(e) for e in (e1, e2)]
    feats2 = ef.extract(same_order)
    check("header order is consistent when it never changes",
         feats2["header_order_consistent"], True)
    check("fingerprint is a fixed-length deterministic hash",
         len(feats2["header_order_fingerprint"]), 16)


def test_connection_reused():
    print("connection_reused")
    t0 = 7_000_000.0
    e1 = access(t0, "10.0.0.8", "/a")
    e1["request"]["remote_port"] = "40000"
    e2 = access(t0 + 1.0, "10.0.0.8", "/b")
    e2["request"]["remote_port"] = "40000"   # same connection
    e3 = access(t0 + 2.0, "10.0.0.8", "/c")
    e3["request"]["remote_port"] = "40010"   # new connection
    session = [ef.parse_line(e) for e in (e1, e2, e3)]
    feats = ef.extract(session)
    check("one of two consecutive pairs reused the connection",
         feats["connection_reused_ratio"], 0.5)


def test_run_id_forces_session_boundary():
    print("run_id_segmentation")
    t0 = 10_000_000.0
    # Same source, no idle gap: runs must not merge.
    entries = (
        [access(t0 + i * 1.0, "10.0.0.20", f"/a{i}", run_id="run-A-r01")
         for i in range(5)] +
        [access(t0 + 5.0 + i * 1.0, "10.0.0.20", f"/b{i}", run_id="run-A-r02")
         for i in range(5)] +
        [access(t0 + 10.0 + i * 1.0, "10.0.0.20", f"/c{i}", run_id="run-B-r01")
         for i in range(5)]
    )
    reqs = [ef.parse_line(e) for e in entries]
    sessions = ef.sessionise(reqs, ef.DEFAULT_IDLE_SECONDS)
    check("three sessions despite zero idle gap between them", len(sessions), 3)
    ids = sorted(s[0].run_id for s in sessions)
    check("each session carries its own run_id",
         ids, ["run-A-r01", "run-A-r02", "run-B-r01"])
    for s in sessions:
        check(f"session {s[0].run_id} has no bleed from another run",
             all(r.run_id == s[0].run_id for r in s), True)

    feats = [ef.extract(s) for s in sessions]
    by_run = {f["run_id"]: f for f in feats}
    check("run-A-r01 count is exactly its own 5 requests",
         by_run["run-A-r01"]["count"], 5)
    check("run-A-r02 count is exactly its own 5 requests, not 10",
         by_run["run-A-r02"]["count"], 5)


def test_probe_fields_and_count():
    print("probe_fields")
    t0 = 9_000_000.0
    entries = []
    for i in range(6):
        e = access(t0 + i * 5.0, "10.0.0.11", f"/p{i}")
        if i in (3, 5):  # two probed requests, one completed, one abandoned
            e["probe_applied"] = True
            if i == 3:
                e["probe_delay_ms"] = 480
                e["client_abandoned"] = False
                e["abandon_after_ms"] = None
            else:
                e["probe_delay_ms"] = None
                e["client_abandoned"] = True
                e["abandon_after_ms"] = 120
        else:
            e["probe_applied"] = False
            e["probe_delay_ms"] = None
            e["client_abandoned"] = None
            e["abandon_after_ms"] = None
        entries.append(e)
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)
    check("probe_count counts only probe_applied requests", feats["probe_count"], 2)
    check("probe_delay_ms_values holds only probed requests with a delay",
         feats["probe_delay_ms_values"], "480")
    check("abandoned_count counts client_abandoned=True among probed",
         feats["abandoned_count"], 1)
    check("abandonment_rate is over probed requests with a known outcome",
         feats["abandonment_rate"], 0.5)
    check("abandon_after_ms_values holds only the abandoned request's value",
         feats["abandon_after_ms_values"], "120")

    # Pre-Phase-5 log lines (no probe fields at all) must still parse.
    legacy = access(t0 + 100.0, "10.0.0.12", "/x")
    rec = ef.parse_line(legacy)
    check("legacy log line without probe fields parses", rec is not None, True)
    check("legacy line defaults probe_applied to False", rec.probe_applied, False)
    check("legacy line defaults probe_delay_ms to None", rec.probe_delay_ms, None)


def test_trap_fields_and_aggregation():
    print("trap_fields")
    t0 = 9_500_000.0
    entries = []
    trap_hits = [
        (2, "admin_path_resolved", None),
        (4, "hidden_field_modified", True),
        (5, "fake_cookie_tampered", None),
    ]
    trap_at = {i: (tid, fm) for i, tid, fm in trap_hits}
    for i in range(7):
        e = access(t0 + i * 3.0, "10.0.0.17", f"/q{i}")
        if i in trap_at:
            tid, fm = trap_at[i]
            e["trap_triggered"] = True
            e["trap_id"] = tid
            e["trap_field_modified"] = fm
        else:
            e["trap_triggered"] = False
            e["trap_id"] = None
            e["trap_field_modified"] = None
        entries.append(e)
    session = [ef.parse_line(e) for e in entries]
    feats = ef.extract(session)

    check("trap_hits counts all trap_triggered requests", feats["trap_hits"], 3)
    check("trap_ids_hit is sorted, pipe-joined, distinct",
         feats["trap_ids_hit"],
         "admin_path_resolved|fake_cookie_tampered|hidden_field_modified")
    check("trap_diversity counts distinct trap types", feats["trap_diversity"], 3)
    check("first_trap_idx is the index of the first trap hit", feats["first_trap_idx"], 2)
    check("hidden_field_tampered is set from the hidden_field_modified trap_id",
         feats["hidden_field_tampered"], True)
    check("fake_cookie_tampered is set from the fake_cookie_tampered trap_id",
         feats["fake_cookie_tampered"], True)
    check("weak_credential_used is false when that trap never fired",
         feats["weak_credential_used"], False)

    quiet_entries = [access(t0 + 200 + i, "10.0.0.18", f"/r{i}") for i in range(3)]
    quiet_session = [ef.parse_line(e) for e in quiet_entries]
    quiet_feats = ef.extract(quiet_session)
    check("trap_hits is 0 with no trap interaction", quiet_feats["trap_hits"], 0)
    check("trap_ids_hit is empty string with no trap interaction",
         quiet_feats["trap_ids_hit"], "")
    check("first_trap_idx is None with no trap interaction",
         quiet_feats["first_trap_idx"], None)


def test_determinism():
    print("determinism")
    t0 = 8_000_000.0
    entries = (
        [access(t0 + i * 3.0, "10.0.0.9", f"/p{i % 5}") for i in range(9)] +
        [access(t0 + 5000.0 + i, "10.0.0.10", "/wp-login.php") for i in range(4)]
    )
    with tempfile.TemporaryDirectory() as d:
        log_a = os.path.join(d, "access.json")
        log_b = os.path.join(d, "access.json.1")
        write_log(log_a, entries[len(entries) // 2:])
        write_log(log_b, entries[:len(entries) // 2])

        out1 = os.path.join(d, "out1.csv")
        out2 = os.path.join(d, "out2.csv")
        ef.main([log_a, log_b, "--out", out1])
        ef.main([log_b, log_a, "--out", out2])

        with open(out1, "rb") as f:
            content1 = f.read()
        with open(out2, "rb") as f:
            content2 = f.read()
        check("byte-identical output regardless of input file order",
             content1, content2)

        with open(out1, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        check("two sessions extracted", len(rows), 2)


def main():
    test_sessionisation_and_idle_gap()
    test_full_session_rate_is_stable()
    test_single_request_rate_is_null_not_infinite()
    test_implausible_rate_is_nulled_and_flagged()
    test_path_entropy_and_ordering()
    test_pre_post_probe_interval()
    test_pre_post_timing_probe_interval()
    test_timing_probe_interval_uses_arrival_time_not_completion_time()
    test_post_probe_continuation_and_retries()
    test_header_order_fingerprint()
    test_connection_reused()
    test_run_id_forces_session_boundary()
    test_probe_fields_and_count()
    test_trap_fields_and_aggregation()
    test_determinism()
    print(f"\nAll {PASS} checks passed.")


if __name__ == "__main__":
    main()
