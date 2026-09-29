#!/usr/bin/env python3
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import classify
import config
import main as engine_main
import policy
import session
import tail

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


def access(ts, ip, uri, status=200, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        method="GET", size=1200, duration=0.02, persona="moodle"):
    return {
        "level": "info", "ts": ts, "logger": "http.log.access.access",
        "msg": "handled request",
        "request": {
            "remote_ip": ip, "remote_port": "12345", "client_ip": ip,
            "proto": "HTTP/1.1", "method": method, "host": "localhost:8080",
            "uri": uri, "headers": {"User-Agent": [ua], "Accept": ["*/*"]},
        },
        "bytes_read": 0, "user_id": "", "duration": duration, "size": size,
        "status": status, "resp_headers": {"Server": ["nginx"]},
        "persona": persona,
    }


def test_tailer():
    print("tailer")
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        path = f.name
    try:
        with open(path, "w") as f:
            f.write(json.dumps(access(1000.0, "1.2.3.4", "/a")) + "\n")
        t = tail.JSONLinesTailer(path, start="beginning", poll=0.01)
        got = t.poll()
        check("reads existing line from start", len(got), 1)

        with open(path, "a") as f:
            f.write(json.dumps(access(1000.5, "1.2.3.4", "/b")) + "\n")
        got = t.poll()
        check("picks up appended line", len(got), 1)
        check("appended line uri", got[0]["request"]["uri"], "/b")

        # Rotation: writer replaces the file.
        os.replace(path, path + ".1")
        with open(path, "w") as f:
            f.write(json.dumps(access(1001.0, "5.6.7.8", "/rotated")) + "\n")
        got = t.poll()
        check("resumes after rotation", len(got), 1)
        check("rotated line ip", got[0]["request"]["remote_ip"], "5.6.7.8")
    finally:
        for p in (path, path + ".1"):
            try:
                os.unlink(p)
            except OSError:
                pass


def make_window(entries, window=60.0, idle=600.0):
    tr = session.SessionTracker(idle=idle)
    for e in entries:
        rec = session.parse_request(e)
        if rec is not None:
            tr.add(rec)
    now = entries[-1]["ts"]
    sess = next(iter(tr.sessions.values()))
    return session.session_features(sess, now, window)


def test_classification():
    print("classify")
    t0 = 1700000000.0

    broad_paths = ["/", "/about", "/contact", "/products", "/blog", "/faq"]
    broad = [access(t0 + i * 1.0, "10.0.0.2", p, status=200, ua="curl/8.5.0")
             for i, p in enumerate(broad_paths)]
    feats = make_window(broad)
    got = classify.classify(feats)
    check("diverse-but-shallow -> broad_scanning", got.label, "broad_scanning")

    # Indexing: many distinct paths, high 404 ratio, systematic pace.
    paths_idx = [f"/{chr(97+i)}" for i in range(26)]
    indexer = []
    for i in range(40):
        indexer.append(access(t0 + i * 0.1, "10.0.0.3",
                              paths_idx[i % len(paths_idx)],
                              status=404, ua="gobuster/3.5"))
    feats = make_window(indexer)
    check("indexer distinct paths", feats["distinct_paths"] >= 10, True)
    got = classify.classify(feats)
    check("many paths + 404 -> indexing", got.label, "indexing")

    # 20 requests: the RF needs more than a single-digit count for this shape.
    exploit = []
    for i in range(20):
        exploit.append(access(t0 + 20.0 + i * 0.5, "10.0.0.4",
                              f"/login/index.php?id=1%27%20AND%20{i}%3D{i}--",
                              ua="sqlmap/1.8"))
    feats = make_window(exploit)
    got = classify.classify(feats)
    check("suspicious qs -> active_backend_testing", got.label,
          "active_backend_testing")

    # Active backend testing: many requests on few paths with query params.
    deep = []
    for i in range(20):
        uri = "/course/view.php?id=" + str(i % 5) + "&page=" + str(i)
        deep.append(access(t0 + 40.0 + i * 0.8, "10.0.0.5", uri))
    feats = make_window(deep)
    got = classify.classify(feats)
    check("many reqs few paths -> active_backend_testing", got.label,
          "active_backend_testing")

    few = [access(t0 + 60.0 + i * 5.0, "10.0.0.6", "/") for i in range(2)]
    feats = make_window(few)
    got = classify.classify(feats)
    check("below min -> insufficient_data", got.label, "insufficient_data")


def test_parse_filter():
    print("parse")
    startup = {"level": "info", "ts": 1.0, "logger": "http.log",
               "msg": "server running", "name": "srv0"}
    check("startup entry skipped", session.parse_request(startup), None)
    bad = {"msg": "handled request", "request": {"method": "GET"}}
    check("missing ts skipped", session.parse_request(bad), None)


def test_policy():
    print("policy")
    t = 1000.0

    switcher = policy.SwitchPolicy(dwell=0.0, quiet_settle=1.0)
    switcher.last_switch = t - 2.0
    switcher.current = "moodle"
    target, reason, hot = switcher.decide(
        [("10.0.0.2", "active_backend_testing", 0.9, False)], t, "moodle")
    check("active_backend_testing -> hold", target, None)
    check("hot flag still true", hot, True)
    check("hold reason", reason, "hold (active_backend_testing)")

    target, reason, hot = switcher.decide(
        [("10.0.0.2", "indexing", 0.9, False)], t, "moodle")
    check("indexing -> rotates", target in {"registry", "finance", "research"}, True)
    check("indexing reason", reason, "indexing traffic present")

    # broad_scanning -> rotate immediately when not active.
    target, reason, hot = switcher.decide(
        [("10.0.0.2", "broad_scanning", 0.9, False)], t, "moodle")
    check("broad_scanning -> rotates", target in {"registry", "finance", "research"}, True)
    check("broad_scanning reason", reason, "broad scanning detected")

    # Dwell respected.
    switcher.dwell = 60.0
    switcher.last_switch = t - 5.0
    target, reason, hot = switcher.decide(
        [("10.0.0.2", "indexing", 0.9, False)], t, "moodle")
    check("dwell blocks switch", target, None)

    # Quiet settle restores default (only when no active traffic).
    switcher2 = policy.SwitchPolicy(dwell=0.0, quiet_settle=10.0,
                                    default_persona="moodle")
    switcher2.current = "research"
    switcher2.last_switch = t - 2.0
    switcher2.last_hostile = t - 20.0
    target, reason, hot = switcher2.decide(
        [], t + 20.0, "research")
    check("quiet restores default", target, "moodle")


def test_queued_reason_refreshes():
    print("queued_reason_refresh")
    switcher = policy.SwitchPolicy(dwell=0.0, quiet_settle=600.0,
                                   default_persona="moodle")
    switcher.current = "moodle"
    switcher.last_switch = 0.0
    t = 5000.0
    ROTATION_OTHERS = {"registry", "finance", "research"}

    target, reason, hot = switcher.decide(
        [("10.0.0.9", "broad_scanning", 0.5, True)], t, "moodle")
    check("first tick holds, does not fire", target, None)
    check("initial held reason is broad_scanning",
         switcher.pending_reason, "broad scanning detected")
    check("held target is a valid rotation persona",
         switcher.pending_target in ROTATION_OTHERS, True)

    for i in range(4):
        target, reason, hot = switcher.decide(
            [("10.0.0.9", "indexing", 0.8, True)], t + 10.0 * (i + 1), "moodle")
        check(f"tick {i + 2} still holds", target, None)
        check(f"tick {i + 2} reason matches this tick's class",
             switcher.pending_reason, "indexing traffic present")
        check(f"tick {i + 2} target is a valid rotation persona",
             switcher.pending_target in ROTATION_OTHERS, True)

    target, reason, hot = switcher.decide(
        [("10.0.0.9", "indexing", 0.8, False)], t + 100.0, "moodle")
    check("rotation fires to a valid rotation persona",
         target in ROTATION_OTHERS, True)
    check("fired reason reflects the class that actually drove the decision",
         reason, "indexing traffic present")


def test_insufficient_distinct_paths():
    print("insufficient_distinct_paths")
    t0 = 8_000_000.0

    reqs = [access(t0 + i * 1.0, "10.0.0.11", "/a" if i % 2 == 0 else "/b")
            for i in range(6)]
    feats = make_window(reqs)
    check("request count is sufficient", feats["count"] >= 4, True)
    check("distinct_paths is below the indexing threshold",
         feats["distinct_paths"] < 5, True)
    got = classify.classify(feats)
    check("insufficient distinct paths -> insufficient_data", got.label,
         "insufficient_data")

    # It must not be eligible to enqueue -- let alone fire -- a rotation.
    switcher = policy.SwitchPolicy(dwell=0.0, quiet_settle=600.0,
                                   default_persona="moodle")
    switcher.current = "moodle"
    switcher.last_switch = 0.0
    target, reason, hot = switcher.decide(
        [("10.0.0.11", got.label, got.confidence, True)], t0 + 10.0, "moodle")
    check("insufficient_data does not hold a pending rotation",
         switcher.pending_target, None)
    check("insufficient_data does not fire a rotation", target, None)


def test_mid_session_rotation_hold():
    print("mid_session_rotation")
    switcher = policy.SwitchPolicy(dwell=0.0, quiet_settle=600.0,
                                   default_persona="moodle")
    switcher.current = "moodle"
    switcher.last_switch = 0.0
    active_grace = 15.0

    tr = session.SessionTracker(idle=1800.0)
    t0 = 2_000_000.0
    probe_paths = ["/wp-admin", "/.env", "/phpmyadmin", "/.git/config",
                  "/wp-login", "/actuator", "/xmlrpc.php", "/adminer"]
    # 60 requests, one every 2s -> a scan spread over 118 seconds.
    request_times = [t0 + i * 2.0 for i in range(60)]
    idx = 0
    current_persona = "moodle"
    switch_ticks = []

    for tick in range(0, 181, 10):
        now = t0 + tick
        while idx < len(request_times) and request_times[idx] <= now:
            e = access(request_times[idx], "10.0.0.9",
                      probe_paths[idx % len(probe_paths)], status=404,
                      ua="gobuster/3.5")
            rec = session.parse_request(e)
            tr.add(rec)
            idx += 1
        tr.expire(now)
        rows = []
        for sess in tr.sessions.values():
            feats = session.session_features(sess, now, window=60.0, min_requests=4)
            if feats["count"] == 0:
                continue
            cls = classify.classify(feats)
            active = (now - sess.last_seen) < active_grace
            rows.append((sess.ip, cls.label, cls.confidence, active))
        target, reason, hot = switcher.decide(rows, now, current_persona)
        if target is not None:
            switch_ticks.append(tick)
            current_persona = target
            switcher.last_switch = now

    check("no switch while the 60-request/2min attack is arriving",
          any(tick <= 118 for tick in switch_ticks), False)
    check("queued rotation is eventually applied once traffic quiets",
          len(switch_ticks) >= 1, True)


def test_persona_per_request():
    print("persona_per_request")
    tr = session.SessionTracker(idle=1800.0)
    t0 = 3_000_000.0
    for i, persona in enumerate(["moodle", "moodle", "finance", "finance"]):
        e = access(t0 + i * 5.0, "10.0.0.7", "/", persona=persona)
        rec = session.parse_request(e)
        tr.add(rec)
    now = t0 + 15.0
    feats = session.session_features(tr.sessions["10.0.0.7"], now, window=60.0)
    check("personas_seen records both personas", feats["personas_seen"],
         ["finance", "moodle"])
    check("persona reflects the most recent request, not a single snapshot",
         feats["persona"], "finance")

    cfg = config.Config()
    # RFC1918 fixtures: run with private-source exclusion off.
    cfg.exclude_private = False
    rows, _ = engine_main.collect_rows(cfg, tr, now, "moodle", [])
    check("evaluation row attributes the request-level persona",
         rows[0]["persona"], "finance")
    check("evaluation row surfaces the mid-session switch",
         rows[0]["personas_seen"], ["finance", "moodle"])


def test_private_source_exclusion():
    print("private_source_exclusion")
    t0 = 1_500_000.0

    for own in ("127.0.0.1", "172.17.0.1", "172.18.0.1", "172.20.0.1",
                "10.0.0.1", "192.168.1.50", "169.254.1.1"):
        rec = session.parse_request(access(t0, own, "/"))
        check(f"{own} recognised as our own infrastructure",
             rec.source_private, True)

    for attacker in ("45.83.64.12", "8.8.8.8", "185.220.101.5"):
        rec = session.parse_request(access(t0, attacker, "/"))
        check(f"{attacker} treated as real traffic", rec.source_private, False)

    # End-to-end through collect_rows: private in, nothing out.
    cfg = config.Config()
    cfg.exclude_private = True
    tr = session.SessionTracker(idle=1800.0)
    for i in range(8):
        tr.add(session.parse_request(access(t0 + i, "172.18.0.1", f"/wp-admin{i}")))
    rows, hostile = engine_main.collect_rows(cfg, tr, t0 + 8, "moodle", [])
    check("private source produces no evaluation rows", len(rows), 0)
    check("private source contributes no hostile count", hostile, 0)

    # Same traffic from a public address is evaluated normally.
    tr2 = session.SessionTracker(idle=1800.0)
    for i in range(8):
        tr2.add(session.parse_request(access(t0 + i, "45.83.64.12", f"/wp-admin{i}")))
    _stdout, sys.stdout = sys.stdout, open(os.devnull, "w")
    try:
        rows2, _ = engine_main.collect_rows(cfg, tr2, t0 + 8, "moodle", [])
    finally:
        sys.stdout = _stdout
    check("public source is still evaluated", len(rows2), 1)

    hashed = access(t0, "203.0.113.9", "/")
    del hashed["request"]["remote_ip"]
    hashed["source_hash"] = "a1b2c3d4e5f6a7b8"
    hashed["source_private"] = True
    rec = session.parse_request(hashed)
    check("pseudonymised line groups by source_hash", rec.ip, "a1b2c3d4e5f6a7b8")
    check("pseudonymised line honours the stamped private flag",
         rec.source_private, True)


def test_session_expiry():
    print("session_expiry")
    tr = session.SessionTracker(idle=30.0)
    e = access(5000.0, "172.18.0.1", "/")
    rec = session.parse_request(e)
    tr.add(rec)

    tr.expire(5010.0)
    check("session still present within idle window", "172.18.0.1" in tr.sessions, True)

    tr.expire(5031.0)
    check("session closed and removed once idle elapses",
         "172.18.0.1" in tr.sessions, False)

    cfg = config.Config()
    # RFC1918 fixtures: run with private-source exclusion off.
    cfg.exclude_private = False
    tr2 = session.SessionTracker(idle=cfg.session_idle)
    check("idle timeout defaults to 30 minutes", cfg.session_idle, 1800.0)


def test_json_safety():
    print("json_safety")
    tr = session.SessionTracker(idle=1800.0)
    e = access(6000.0, "10.0.0.8", "/")
    rec = session.parse_request(e)
    tr.add(rec)

    feats = session.session_features(tr.sessions["10.0.0.8"], 6000.0, window=60.0)
    check("single-request session gets a null rate, not Infinity",
         feats["rate"], None)

    cfg = config.Config()
    # RFC1918 fixtures: run with private-source exclusion off.
    cfg.exclude_private = False
    _stdout, sys.stdout = sys.stdout, open(os.devnull, "w")
    try:
        rows, _ = engine_main.collect_rows(cfg, tr, 6000.0, "moodle", [])
    finally:
        sys.stdout = _stdout
    line = json.dumps(rows[0])
    check("emitted row has no Infinity token", "Infinity" in line, False)
    reparsed = json.loads(line)
    check("emitted row round-trips through json.loads", reparsed["rate"], None)


def test_state_roundtrip():
    print("state_roundtrip")
    tr = session.SessionTracker(idle=1800.0)
    for uri in ["/a", "/b", "/c"]:
        e = access(7000.0, "10.0.0.5", uri)
        tr.add(session.parse_request(e))
    dumped = json.loads(json.dumps(session.to_dict(tr)))
    restored = session.from_dict(dumped)
    check("restored tracker has the same session", list(restored.sessions), ["10.0.0.5"])
    check("restored session preserves request_count",
         restored.sessions["10.0.0.5"].request_count, 3)
    check("restored session preserves requests",
         len(restored.sessions["10.0.0.5"].requests), 3)


def main():
    test_tailer()
    test_classification()
    test_parse_filter()
    test_policy()
    test_queued_reason_refreshes()
    test_insufficient_distinct_paths()
    test_mid_session_rotation_hold()
    test_persona_per_request()
    test_private_source_exclusion()
    test_session_expiry()
    test_json_safety()
    test_state_roundtrip()
    print(f"\nAll {PASS} checks passed.")


if __name__ == "__main__":
    main()
