#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Case-insensitive, word-bounded patterns.
GIVEAWAY_PATTERNS = [
    # Project identity / research markers
    r"\bhoneypot\b",
    r"\bdecoy\b",
    r"\bcanary\b",
    r"\bchameleon\b",
    r"\bresearch (honeypot|study|purposes)\b",
    r"university of warwick",
    r"\bwmg\b",
    r"\bwarwick\b",
    r"project-record",
    # Match placeholder as content, not the HTML attribute.
    r"\bplaceholder\b(?!\s*=)",
    r"stimulus engine",
    # Tool / tooling vocabulary
    r"\bnikto\b",
    r"\bsqlmap\b",
    r"\bnmap\b",
    r"\bopenvas\b",
    r"\bmetasploit\b",
    r"\bgobuster\b",
    r"\bdirbuster\b",
    r"\bwpscan\b",
    # Proxy / orchestration / CI markers that must never appear in served output
    r"\bcaddy\b",
    r"\bdocker\b",
    r"docker-compose",
    r"\bcompose\b",
    r"\bkubernetes\b",
    r"http://localhost:",
    r"http://127\.0\.0\.1",
    r"//moodle:",  # internal service hostname
    r":8080",
    r"nginx:alpine",
    # Engineering scent
    r"\btodo\b",
    r"\bfixme\b",
    r"lorem ipsum",
    r"\bstub\b",
    r"\bautocrlf\b",
    # Detection-relevant header text that should not leak into body markup
    r"x-powered-by",
]

TEXT_SUFFIXES = {
    ".html", ".htm", ".txt", ".xml", ".css", ".svg", ".js", ".json", ".md",
}

# Compile the giveaway patterns once, after their definition above.
GIVEAWAY_RE = [re.compile(p, re.IGNORECASE) for p in GIVEAWAY_PATTERNS]


def discover_static_dirs(root: Path) -> list[Path]:
    dirs = []
    for persona in sorted(root.iterdir()):
        if persona.is_dir():
            static = persona / "static"
            if static.is_dir():
                dirs.append(static)
    return dirs


def scan_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found = [rx.pattern for rx in GIVEAWAY_RE if rx.search(text)]
    return found


def main(argv: list[str]) -> int:
    root_arg = argv[1] if len(argv) > 1 else str(REPO / "personas")
    root = Path(root_arg)

    if not root.is_dir():
        print(f"give_away_scan: no such directory: {root}", file=sys.stderr)
        return 2

    static_dirs = discover_static_dirs(root)
    if not static_dirs:
        print(
            f"give_away_scan: no persona `static` directories under {root}",
            file=sys.stderr,
        )
        return 2

    failures: list[tuple[Path, list[str]]] = []
    files_scanned = 0
    for static in static_dirs:
        for path in sorted(static.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            files_scanned += 1
            hits = scan_file(path)
            if hits:
                failures.append((path, hits))

    print(f"give_away_scan: scanned {files_scanned} served files "
          f"across {len(static_dirs)} persona(s)")
    if not failures:
        print("give_away_scan: PASS - no give-aways found")
        return 0

    print("give_away_scan: FAIL - potential give-aways:")
    for path, hits in failures:
        print(f"  {path.relative_to(REPO)}:")
        for term in hits:
            print(f"      contains '{term}'")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
