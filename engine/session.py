#!/usr/bin/env python3
import dataclasses
import ipaddress
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

ACCESS_MSG = "handled request"


def _is_private_source(raw_ip: str) -> bool:
    """Loopback / RFC1918 / link-local: our own infrastructure."""
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback
            or addr.is_link_local or addr.is_reserved)


@dataclass
class RequestRecord:
    ts: float
    # Salted source_hash in production, raw remote_ip in local dev.
    ip: str
    method: str
    uri: str
    status: int
    size: int
    duration: float
    user_agent: str
    host: str
    proto: str
    remote_port: str
    headers: Dict[str, List[str]]
    # Persona stamped per request by Caddy, so it can't race a switch.
    persona: str = ""
    # Set by the proxy before it discards the raw address.
    source_private: bool = False

    @property
    def path(self) -> str:
        """Path without the query string, lowercased for stable matching."""
        return self.uri.split("?", 1)[0].lower()

    @property
    def query(self) -> str:
        return self.uri.split("?", 1)[1] if "?" in self.uri else ""


def parse_request(entry: dict) -> Optional[RequestRecord]:
    """Parse one access-log entry, or None for non-request lines."""
    if entry.get("msg") != ACCESS_MSG:
        return None
    req = entry.get("request")
    if not isinstance(req, dict):
        return None
    try:
        ts = float(entry["ts"])
    except (KeyError, TypeError, ValueError):
        return None
    if not ts:
        return None
    headers = req.get("headers") or {}
    ua = headers.get("User-Agent")
    if isinstance(ua, list):
        ua = ua[0] if ua else ""
    headers_norm = {
        str(k): [str(v)] if not isinstance(v, list) else [str(x) for x in v]
        for k, v in headers.items()
    }
    raw_ip = str(req.get("remote_ip") or "")
    source_hash = str(entry.get("source_hash") or "")
    if entry.get("source_private") is not None:
        source_private = bool(entry.get("source_private"))
    else:
        source_private = _is_private_source(raw_ip)

    return RequestRecord(
        ts=ts,
        ip=source_hash or raw_ip or "?",
        source_private=source_private,
        method=str(req.get("method") or ""),
        uri=str(req.get("uri") or ""),
        status=int(entry.get("status") or 0),
        size=int(entry.get("size") or 0),
        duration=float(entry.get("duration") or 0.0),
        user_agent=str(ua or ""),
        host=str(req.get("host") or ""),
        proto=str(req.get("proto") or ""),
        remote_port=str(req.get("remote_port") or ""),
        headers=headers_norm,
        persona=str(entry.get("persona") or ""),
    )


# Cap on retained records per session; never binds in practice.
MAX_RETAINED_REQUESTS = 5000


@dataclass
class Session:
    ip: str
    first_seen: float
    last_seen: float
    requests: Deque[RequestRecord] = field(default_factory=deque)
    request_count: int = 0
    source_private: bool = False
    truncated: bool = False

    def add(self, rec: RequestRecord) -> None:
        self.requests.append(rec)
        if len(self.requests) > MAX_RETAINED_REQUESTS:
            self.requests.popleft()
            self.truncated = True
        if rec.source_private:
            self.source_private = True
        self.request_count += 1
        self.last_seen = max(self.last_seen, rec.ts)
        self.first_seen = min(self.first_seen, rec.ts)

    def recent(self, window: float, now: float) -> List[RequestRecord]:
        """Must not evict: all_records() needs the full history."""
        cutoff = now - window
        return [r for r in self.requests if r.ts >= cutoff]

    def all_records(self) -> List[RequestRecord]:
        """Whole session, up to MAX_RETAINED_REQUESTS (sets truncated if capped)."""
        return list(self.requests)


class SessionTracker:
    def __init__(self, idle: float = 1800.0):
        self.idle = idle
        self.sessions: Dict[str, Session] = {}

    def add(self, rec: RequestRecord) -> Session:
        sess = self.sessions.get(rec.ip)
        if sess is None:
            sess = Session(ip=rec.ip, first_seen=rec.ts, last_seen=rec.ts)
            self.sessions[rec.ip] = sess
        sess.add(rec)
        return sess

    def expire(self, now: float) -> None:
        stale = [ip for ip, s in self.sessions.items() if now - s.last_seen > self.idle]
        for ip in stale:
            del self.sessions[ip]


def session_features(sess: Session, now: float, window: float,
                     min_requests: int = 4, min_distinct_paths: int = 5
                     ) -> Dict[str, object]:
    """Windowed fields for logging plus whole-session content features for the classifier."""
    import content_features

    content_feats = content_features.compute(sess.all_records())

    recs = sess.recent(window, now)
    feats: Dict[str, object] = {
        "ip": sess.ip,
        "count": len(recs),
        "lifetime": sess.request_count,
        "min_requests": min_requests,
        "min_distinct_paths": min_distinct_paths,
    }
    if not recs:
        feats.update(content_feats)
        feats["truncated"] = sess.truncated
        return feats

    gaps = [recs[i + 1].ts - recs[i].ts for i in range(len(recs) - 1)]
    span = recs[-1].ts - recs[0].ts
    # Zero-length window: emit null, not infinity (invalid JSON).
    rate = (len(recs) - 1) / span if span > 0 else None
    mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
    var_gap = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps) if gaps else 0.0
    std_gap = var_gap ** 0.5
    cv = std_gap / mean_gap if mean_gap > 0 else 0.0  # coefficient of variation

    personas_seen = sorted({r.persona for r in recs if r.persona})

    feats.update({
        # --- Windowed cadence, for the evaluation-row log only ---
        "span": span,
        "rate": rate,
        "mean_gap": mean_gap,
        "std_gap": std_gap,
        "cv": cv,
        "avg_duration": sum(r.duration for r in recs) / len(recs),
        # Requested keep-alive, not observed reuse (that's connection_reused_ratio).
        "connection_keepalive_ratio": (
            sum(1 for r in recs
                if r.headers.get("connection", [""])[0].lower() == "keep-alive")
            / len(recs)),
        # --- Persona attribution (per-request, not a single snapshot) ---
        "persona": recs[-1].persona,
        "personas_seen": personas_seen,
    })
    # Whole-session content features; the windowed fields above are logging only.
    feats.update(content_feats)
    feats["truncated"] = sess.truncated
    return feats


# ---------------------------------------------------------------- state persistence

def to_dict(tracker: "SessionTracker") -> Dict[str, object]:
    """Serialise tracker state for a graceful-shutdown flush (see main.py)."""
    return {
        "idle": tracker.idle,
        "sessions": {
            ip: {
                "first_seen": sess.first_seen,
                "last_seen": sess.last_seen,
                "request_count": sess.request_count,
                "source_private": sess.source_private,
                "truncated": sess.truncated,
                "requests": [dataclasses.asdict(r) for r in sess.requests],
            }
            for ip, sess in tracker.sessions.items()
        },
    }


def from_dict(data: Dict[str, object]) -> "SessionTracker":
    """Rebuild a tracker from a previous to_dict() flush."""
    tracker = SessionTracker(idle=float(data.get("idle", 1800.0)))
    for ip, sdata in (data.get("sessions") or {}).items():
        sess = Session(ip=ip, first_seen=float(sdata["first_seen"]),
                       last_seen=float(sdata["last_seen"]))
        sess.request_count = int(sdata.get("request_count", 0))
        sess.source_private = bool(sdata.get("source_private", False))
        sess.truncated = bool(sdata.get("truncated", False))
        for rdata in sdata.get("requests", []):
            sess.requests.append(RequestRecord(**rdata))
        tracker.sessions[ip] = sess
    return tracker