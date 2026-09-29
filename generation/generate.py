#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import yaml


class GracefulShutdown(Exception):
    """Raised on SIGTERM so main()'s finally block restores the engine and context."""


def _handle_sigterm(signum: int, frame) -> None:
    raise GracefulShutdown(f"received signal {signum}")

# Line-buffer stdout so progress shows when piped.
sys.stdout.reconfigure(line_buffering=True)

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATION_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = GENERATION_DIR / "run_manifest.yml"
PROFILES_PATH = GENERATION_DIR / "network_profiles.yml"
CADDY_CONFIG_HOST = REPO_ROOT / "proxy" / "caddy.json"

PROJECT = REPO_ROOT.name
NETWORK = f"{PROJECT}_default"
ADMIN_URL = "http://proxy:2019"


def sh(cmd: List[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO_ROOT, text=True,
                          capture_output=True, **kw)


def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def select_runs(manifest: dict, prefix: Optional[str]) -> List[dict]:
    runs = manifest.get("runs") or []
    if prefix:
        runs = [r for r in runs if str(r["run_id"]).startswith(prefix)]
    return runs


def load_checkpoint(path: Path) -> set:
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(json.load(f))


def append_checkpoint(path: Path, run_id: str) -> None:
    # Read-modify-write so an interruption loses at most the run in flight.
    done = load_checkpoint(path)
    done.add(run_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sorted(done), f)


def engine_pause() -> None:
    print("generate: pausing engine for the generation session")
    r = sh(["docker", "compose", "stop", "engine"])
    if r.returncode != 0:
        sys.exit(f"generate: could not pause engine:\n{r.stderr}")


def engine_resume() -> None:
    print("generate: resuming engine")
    sh(["docker", "compose", "start", "engine"])


def clear_context() -> None:
    """Reset run_id, persona and probe_rate so later traffic isn't mislabelled."""
    print("generate: clearing run context (run_id, back to default persona, probe off)")
    apply_context("moodle", "", 0.0)


def build_attacker() -> None:
    r = sh(["docker", "compose", "--profile", "attack", "build", "attacker"])
    if r.returncode != 0:
        sys.exit(f"generate: attacker build failed:\n{r.stderr}")


def apply_context(persona: str, run_id: str, probe_rate: float) -> None:
    """Runs set_context.py inside the compose network (the admin API isn't published)."""
    cmd = [
        "docker", "run", "--rm", "--network", NETWORK,
        "-v", f"{GENERATION_DIR}:/gen:ro",
        "-v", f"{REPO_ROOT / 'proxy'}:/config",
        "python:3-alpine", "python", "/gen/set_context.py",
        "/config/caddy.json", ADMIN_URL,
        "--persona", persona, "--run-id", run_id,
        "--probe-rate", str(probe_rate),
    ]
    r = sh(cmd)
    if r.returncode != 0:
        sys.exit(f"generate: set_context failed for run {run_id}:\n{r.stdout}\n{r.stderr}")
    print(f"  {r.stdout.strip()}")


def netem_and_tool_command(profile: dict, tool_cmd: str, timeout_budget: int) -> str:
    delay = profile["delay_ms"]
    jitter = profile["jitter_ms"]
    loss = profile["loss_pct"]
    netem = (f"tc qdisc replace dev eth0 root netem "
            f"delay {delay}ms {jitter}ms distribution normal loss {loss}%")
    return f"{netem} && timeout {timeout_budget} {tool_cmd}"


def substitute_target(config_args: str) -> str:
    return config_args.replace("{target_host}", "proxy").replace(
        "{target_url}", "http://proxy:80")


def run_one(run: dict, rep_index: int, profiles: Dict[str, dict],
           dry_run: bool, checkpoint_path: Optional[Path] = None,
           completed: Optional[set] = None) -> Dict[str, object]:
    run_id = f"{run['run_id']}-r{rep_index:02d}"

    if completed is not None and run_id in completed:
        print(f"\n=== {run_id} === SKIPPED (already checkpointed)")
        return {"run_id": run_id, "manifest_run_id": run["run_id"], "status": "skipped (checkpoint)"}

    persona = run["active_persona"]
    profile = profiles[run["network_profile"]]
    args = substitute_target(run["config_args"])
    tool_cmd = f"{run['tool']} {args}"
    full_cmd = netem_and_tool_command(profile, tool_cmd, int(run["timeout_budget"]))

    print(f"\n=== {run_id} ===")
    print(f"  class={run['behaviour_class']} tool={run['tool']} "
         f"config={run['config_name']} profile={run['network_profile']} "
         f"persona={persona} probe_rate={run['probe_rate']}")
    print(f"  cmd: {full_cmd}")

    if dry_run:
        return {"run_id": run_id, "status": "dry-run"}

    apply_context(persona, run_id, float(run["probe_rate"]))
    time.sleep(1.0)

    start = time.time()
    result = sh([
        "docker", "compose", "--profile", "attack", "run", "--rm",
        "attacker", "sh", "-c", full_cmd,
    ])
    elapsed = time.time() - start

    # Only timeout's own codes (124/137) mean the run failed; tools use their own exit codes.
    timed_out = result.returncode in (124, 137)
    if timed_out:
        status = f"TIMED OUT (exit={result.returncode})"
    elif result.returncode == 0:
        status = "ok"
    else:
        status = f"completed, tool exit={result.returncode} (not treated as failure)"
    print(f"  -> {status} in {elapsed:.1f}s")
    if timed_out:
        print(f"  stdout (tail): {result.stdout[-500:]}")
        print(f"  stderr (tail): {result.stderr[-500:]}")

    # Timed-out runs aren't checkpointed, so a restart retries them.
    if checkpoint_path is not None and not timed_out:
        append_checkpoint(checkpoint_path, run_id)

    return {
        "run_id": run_id, "manifest_run_id": run["run_id"],
        "status": status, "elapsed_s": round(elapsed, 1),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", default=str(MANIFEST_PATH),
                   help="manifest YAML to read (default: run_manifest.yml)")
    p.add_argument("--prefix", help="only run manifest entries whose run_id "
                                    "starts with this (e.g. stage1)")
    p.add_argument("--checkpoint", default=str(GENERATION_DIR / "checkpoint.json"),
                   help="checkpoint file for resumability (default: "
                        "generation/checkpoint.json)")
    p.add_argument("--reset-checkpoint", action="store_true",
                   help="ignore and overwrite any existing checkpoint file")
    p.add_argument("--dry-run", action="store_true",
                   help="print what would run without touching anything")
    p.add_argument("--skip-engine-pause", action="store_true",
                   help="dangerous: leaves the engine running during "
                        "generation. For debugging only.")
    args = p.parse_args()

    if shutil.which("docker") is None:
        sys.exit("generate: docker not found on PATH")

    signal.signal(signal.SIGTERM, _handle_sigterm)

    manifest = load_yaml(Path(args.manifest))
    profiles = load_yaml(PROFILES_PATH)["profiles"]
    runs = select_runs(manifest, args.prefix)
    if not runs:
        sys.exit(f"generate: no manifest entries match prefix {args.prefix!r}")

    checkpoint_path = Path(args.checkpoint)
    if args.reset_checkpoint and checkpoint_path.exists():
        checkpoint_path.unlink()
    completed = load_checkpoint(checkpoint_path) if not args.dry_run else set()

    total_sessions = sum(r["repetition"] for r in runs)
    print(f"generate: {len(runs)} manifest entr{'y' if len(runs)==1 else 'ies'} selected, "
         f"{total_sessions} sessions total, {len(completed)} already checkpointed")

    if not args.dry_run:
        build_attacker()
        if not args.skip_engine_pause:
            engine_pause()

    results: List[Dict[str, object]] = []
    interrupted = False
    try:
        for run in runs:
            for rep in range(1, int(run["repetition"]) + 1):
                results.append(run_one(run, rep, profiles, args.dry_run,
                                       checkpoint_path, completed))
    except (GracefulShutdown, KeyboardInterrupt) as e:
        interrupted = True
        print(f"\ngenerate: interrupted ({e}) -- running cleanup "
             "(clear context, resume engine) before exiting")
    finally:
        if not args.dry_run:
            clear_context()
        if not args.dry_run and not args.skip_engine_pause:
            engine_resume()

    if interrupted:
        print(f"generate: {len(results)} run(s) completed before interruption; "
             f"already-checkpointed run_ids are safe to resume from "
             f"({args.checkpoint})")
        return 130

    done_count = sum(1 for r in results if r["status"] not in
                     ("skipped (checkpoint)",) and "TIMED OUT" not in r["status"])
    skipped_count = sum(1 for r in results if r["status"] == "skipped (checkpoint)")
    timed_out_count = sum(1 for r in results if "TIMED OUT" in r["status"])
    print(f"\n=== summary: {done_count} completed, {skipped_count} skipped "
         f"(already done), {timed_out_count} timed out ===")
    for r in results:
        if r["status"] != "skipped (checkpoint)":
            print(f"  {r}")

    log_path = GENERATION_DIR / "generation_log.jsonl"
    if not args.dry_run:
        with open(log_path, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps({**r, "ts": time.time()}) + "\n")
        print(f"\ngenerate: provenance appended to {log_path}")

    failed = [r for r in results if "TIMED OUT" in r.get("status", "")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
