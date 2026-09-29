#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "engine"))

import content_features  # engine/
import extract_features as ef  # analysis/
import session as eng_session  # engine/

FAILURES = 0


def check(name: str, got, want) -> None:
    global FAILURES
    if got == want:
        print(f"  ok  {name}")
    else:
        FAILURES += 1
        print(f"  FAIL {name}: got {got!r}, want {want!r}")


def access(ts, ip="203.0.113.7", uri="/", status=200, method="GET",
           size=1200, duration=0.02, port="50000", ua="curl/8.5.0",
           headers=None, persona="moodle"):
    hdrs = headers if headers is not None else {"User-Agent": [ua], "Accept": ["*/*"]}
    return {
        "level": "info", "ts": ts, "logger": "http.log.access.access",
        "msg": "handled request",
        "request": {
            "remote_ip": ip, "remote_port": port, "client_ip": ip,
            "proto": "HTTP/1.1", "method": method, "host": "example",
            "uri": uri, "headers": hdrs,
        },
        "bytes_read": 0, "user_id": "", "duration": duration, "size": size,
        "status": status, "resp_headers": {"Server": ["nginx"]},
        "persona": persona, "source_private": False,
    }


def live_features(entries):
    """Exactly the path the engine takes: parse -> sessionise -> compute."""
    tracker = eng_session.SessionTracker(idle=1800.0)
    for e in entries:
        rec = eng_session.parse_request(e)
        assert rec is not None, "engine parser rejected a fixture entry"
        tracker.add(rec)
    sess = next(iter(tracker.sessions.values()))
    return content_features.compute(sess.all_records()), sess


def batch_features(entries):
    """Exactly the path training takes: parse -> extract over the session."""
    reqs = [ef.parse_line(e) for e in entries]
    assert all(r is not None for r in reqs), "batch parser rejected a fixture entry"
    return ef.extract(reqs)


def compare(label: str, entries) -> None:
    live, _ = live_features(entries)
    batch = batch_features(entries)
    mismatches = []
    for name in content_features.FEATURE_ORDER:
        a, b = live.get(name), batch.get(name)
        # bool is an int subclass; compare by value.
        if float(a) != float(b):
            mismatches.append(f"{name}: serve={a!r} train={b!r}")
    check(f"{label}: all {len(content_features.FEATURE_ORDER)} features identical",
          mismatches, [])


def test_patterns_are_identical() -> None:
    """Compare the regex lists directly: engine/ keeps its own copy."""
    print("pattern parity (engine/patterns.py vs analysis/heuristic_patterns.py)")

    import heuristic_patterns as ana
    import patterns as eng

    check("probe path patterns identical",
          eng.PROBE_PATH_PATTERNS, ana.PROBE_PATH_PATTERNS)
    check("suspicious query-string patterns identical",
          eng.SUSPICIOUS_QS_PATTERNS, ana.SUSPICIOUS_QS_PATTERNS)


def test_parity_across_fixtures() -> None:
    print("feature parity (engine/content_features.py vs analysis/extract_features.py)")

    t0 = 1_700_000_000.0

    compare("single request", [access(t0)])

    compare("repeated identical path",
            [access(t0 + i, uri="/login/index.php") for i in range(6)])

    compare("mixed statuses and methods", [
        access(t0 + 0, uri="/", status=200),
        access(t0 + 1, uri="/admin/", status=404, method="POST", size=90),
        access(t0 + 2, uri="/wp-admin", status=404),
        access(t0 + 3, uri="/boom", status=500),
        access(t0 + 4, uri="/forbidden", status=403),
    ])

    compare("ratios that do not terminate", [
        access(t0 + 0, uri="/a", status=200),
        access(t0 + 1, uri="/b", status=404),
        access(t0 + 2, uri="/c", status=500),
    ])

    compare("query strings of differing length", [
        access(t0 + 0, uri="/s?q=1"),
        access(t0 + 1, uri="/s?q=abcdefghij"),
        access(t0 + 2, uri="/s?q=abc"),
        access(t0 + 3, uri="/plain"),
    ])

    compare("suspicious query strings", [
        access(t0 + 0, uri="/x?id=1 union select 1,2"),
        access(t0 + 1, uri="/x?file=../../etc/passwd"),
        access(t0 + 2, uri="/x?cmd=ls"),
        access(t0 + 3, uri="/x?ok=1"),
    ])

    compare("connection reuse via remote_port continuity", [
        access(t0 + 0, uri="/a", port="40001"),
        access(t0 + 1, uri="/b", port="40001"),
        access(t0 + 2, uri="/c", port="40002"),
        access(t0 + 3, uri="/d", port="40002"),
        access(t0 + 4, uri="/e", port="40003"),
    ])

    compare("inconsistent header ordering", [
        access(t0 + 0, uri="/a", headers={"User-Agent": ["x"], "Accept": ["*/*"]}),
        access(t0 + 1, uri="/b", headers={"Accept": ["*/*"], "User-Agent": ["x"]}),
        access(t0 + 2, uri="/c", headers={"User-Agent": ["x"], "Accept": ["*/*"]}),
    ])

    compare("probe-pattern paths", [
        access(t0 + 0, uri="/wp-admin"),
        access(t0 + 1, uri="/phpmyadmin/"),
        access(t0 + 2, uri="/normal-page"),
    ])


def test_whole_session_survives_repeated_evaluation() -> None:
    print("repeated evaluation (regression: recent() must not evict)")

    t0 = 1_700_000_000.0
    window = 60.0
    entries = [access(t0 + i * 10, uri=f"/p{i}") for i in range(20)]
    tracker = eng_session.SessionTracker(idle=1800.0)
    for e in entries:
        tracker.add(eng_session.parse_request(e))
    sess = next(iter(tracker.sessions.values()))
    now = t0 + 19 * 10

    first = eng_session.session_features(sess, now, window)
    second = eng_session.session_features(sess, now, window)
    third = eng_session.session_features(sess, now, window)

    check("records retained after three evaluations", len(sess.all_records()), 20)
    for name in content_features.FEATURE_ORDER:
        if first[name] != second[name] or second[name] != third[name]:
            check(f"{name} stable across evaluations",
                  (second[name], third[name]), (first[name], first[name]))
    check("count is whole-session, not windowed", first["count"], 20)
    check("distinct_paths is whole-session, not windowed", first["distinct_paths"], 20)


def test_retention_cap_is_flagged() -> None:
    print("retention cap")

    t0 = 1_700_000_000.0
    tracker = eng_session.SessionTracker(idle=1800.0)
    over = eng_session.MAX_RETAINED_REQUESTS + 25
    for i in range(over):
        tracker.add(eng_session.parse_request(access(t0 + i * 0.01, uri=f"/p{i}")))
    sess = next(iter(tracker.sessions.values()))

    check("retained records capped", len(sess.all_records()),
          eng_session.MAX_RETAINED_REQUESTS)
    check("truncation is flagged", sess.truncated, True)
    check("lifetime count still reflects everything seen", sess.request_count, over)
    feats = eng_session.session_features(sess, t0 + over * 0.01, 60.0)
    check("truncation surfaced in features", feats["truncated"], True)


def main() -> int:
    test_patterns_are_identical()
    test_parity_across_fixtures()
    test_whole_session_survives_repeated_evaluation()
    test_retention_cap_is_flagged()
    print()
    if FAILURES:
        print(f"{FAILURES} check(s) FAILED")
        return 1
    print("All feature-parity checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
