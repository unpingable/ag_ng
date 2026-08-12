#!/usr/bin/env python3
"""Run bounded AG local development evidence and capture exact command logs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def git_status() -> str:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8", "replace").strip()


def run_step(index: int, name: str, argv: list[str], output: Path) -> dict[str, Any]:
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    completed = subprocess.run(
        argv,
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    ended = dt.datetime.now(dt.timezone.utc).isoformat()
    stem = f"{index:02d}-{name}"
    write_exclusive(output / f"{stem}.stdout", completed.stdout)
    write_exclusive(output / f"{stem}.stderr", completed.stderr)
    record = {
        "name": name,
        "argv": argv,
        "started_at_utc": started,
        "ended_at_utc": ended,
        "exit_code": completed.returncode,
        "stdout_sha256": sha256(completed.stdout),
        "stderr_sha256": sha256(completed.stderr),
    }
    write_exclusive(output / f"{stem}.json", canonical_bytes(record))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty-development", action="store_true")
    args = parser.parse_args()

    status = git_status()
    if status and not args.allow_dirty_development:
        parser.error("source tree is dirty; commit it or pass --allow-dirty-development")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)

    preflight = subprocess.run(
        [
            "python3",
            str(REPO / "qualification/operational/preflight.py"),
            "--profile",
            "local",
            "--output",
            str(args.output / "preflight"),
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    write_exclusive(args.output / "preflight.stdout", preflight.stdout)
    write_exclusive(args.output / "preflight.stderr", preflight.stderr)

    commands = [
        ("harness-self-test", ["python3", "qualification/operational/self_test.py"]),
        ("build-loopctl", ["cargo", "build", "--locked", "-p", "ag-app", "--bin", "ag-loopctl"]),
        ("kernel", ["cargo", "test", "--locked", "-p", "ag-campaign", "--test", "governed_loop"]),
        ("store", ["cargo", "test", "--locked", "-p", "ag-store", "--test", "governed_campaign_store"]),
        ("engine", ["cargo", "test", "--locked", "-p", "ag-app", "--test", "governed_loop_engine"]),
        ("executor-adapter", ["cargo", "test", "--locked", "-p", "ag-app", "effect_executor_adapter::tests"]),
        (
            "multiprocess-contention",
            [
                "python3",
                "qualification/operational/multiprocess_contention.py",
                "--ag-loopctl",
                "target/debug/ag-loopctl",
                "--output",
                str(args.output / "multiprocess"),
            ],
        ),
        ("release-isolation-scan", ["bash", "scripts/verify-effectd-isolation.sh"]),
    ]
    records = []
    if preflight.returncode == 0:
        for index, (name, argv) in enumerate(commands, 1):
            record = run_step(index, name, argv, args.output)
            records.append(record)
            if record["exit_code"] != 0:
                break

    passed = preflight.returncode == 0 and len(records) == len(commands) and all(
        record["exit_code"] == 0 for record in records
    )
    result = {
        "schema": "ag.operational-local-development-run.v1",
        "authority_use": "none",
        "qualification_status": "not_assessed",
        "development_check": "passed" if passed else "failed",
        "dirty_development_mode": bool(status),
        "source_status_sha256": sha256((status + "\n").encode()),
        "limitations": [
            "No deployed service was exercised.",
            "No abrupt power loss or block-I/O fault was injected.",
            "No provider-specific physical effect was qualified.",
            "A passing result is development evidence only."
        ],
        "preflight_exit_code": preflight.returncode,
        "steps": records,
    }
    write_exclusive(args.output / "result.json", canonical_bytes(result))
    print(json.dumps({"development_check": result["development_check"], "output": str(args.output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
