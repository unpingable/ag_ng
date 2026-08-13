#!/usr/bin/env python3
"""Exercise the AG campaign store through independent competing processes.

This is development evidence for process-level contention. It is not a
power-loss test and emits no qualification claim.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def invoke(argv: list[str]) -> dict[str, Any]:
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    ended = dt.datetime.now(dt.timezone.utc).isoformat()
    return {
        "argv": argv,
        "started_at_utc": started,
        "ended_at_utc": ended,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace"),
        "stderr": completed.stderr.decode("utf-8", "replace"),
        "stdout_sha256": sha256(completed.stdout),
        "stderr_sha256": sha256(completed.stderr),
    }


def competing(argv: list[str], count: int) -> list[dict[str, Any]]:
    barrier = threading.Barrier(count)

    def one(index: int) -> dict[str, Any]:
        barrier.wait()
        result = invoke(argv)
        result["writer"] = index
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(one, index) for index in range(count)]
        return [future.result() for future in futures]


def run_or_raise(argv: list[str]) -> dict[str, Any]:
    result = invoke(argv)
    if result["exit_code"] != 0:
        raise RuntimeError(f"command failed: {argv!r}: {result['stderr'].strip()}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ag-loopctl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--writers", type=int, default=8)
    args = parser.parse_args()
    if args.writers < 2:
        parser.error("--writers must be at least 2")

    program = args.ag_loopctl.resolve(strict=True)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = args.output / "campaign.sqlite"
    genesis_path = args.output / "genesis.json"
    halt_path = args.output / "halt.json"
    clock_path = args.output / "qualification-fixture-not-authority-clock"
    catalog_path = args.output / "qualification-fixture-not-authority-catalog.json"
    clock_bytes = b"#!/bin/sh\nprintf '1000\\n'\n"
    catalog_bytes = canonical_bytes({
        "schema": "ag.governed-loop.exact-work-catalog/v1",
        "policy_basis": "sha256:" + "d" * 64,
        "entries": {},
    })
    write_exclusive(clock_path, clock_bytes, mode=0o700)
    write_exclusive(catalog_path, catalog_bytes)

    def pinned(path: Path, data: bytes) -> dict[str, str]:
        return {"path": str(path.resolve()), "identity": sha256(data)}

    genesis = {
        "campaign": "sha256:" + "a" * 64,
        "occurrence": "00000000-0000-4000-8000-000000000001",
        "program": "sha256:" + "b" * 64,
        "residuals": [],
        "budget": {
            "retry_limit": 1,
            "retries_used": 0,
            "probe_limit": 1,
            "probes_used": 0,
            "escalation_limit": 1,
            "escalations_used": 0,
        },
        "idempotency_key": "sha256:" + "e" * 64,
        "governed_ag_policy_root": {
            "schema": "ag.governed-loop.ag-policy-root/v1",
            "policy_label": "qualification-fixture-not-authority",
            "consequence_clock": pinned(clock_path, clock_bytes),
            "observation_resolver": pinned(clock_path, clock_bytes),
            "standing_resolver": pinned(clock_path, clock_bytes),
            "exact_work_catalog": pinned(catalog_path, catalog_bytes),
            "controlling_review": None,
        },
        "governed_repair_verifier_root": None,
        "governed_docket_adapter_root": None,
    }
    halt = {"reason": "sha256:" + "c" * 64}
    write_exclusive(genesis_path, canonical_bytes(genesis))
    write_exclusive(halt_path, canonical_bytes(halt))

    init = run_or_raise([str(program), "init", "--database", str(database), "--genesis", str(genesis_path)])
    initial_state = json.loads(init["stdout"])["state_digest"]
    halt_argv = [
        str(program),
        "halt",
        "--database",
        str(database),
        "--input",
        str(halt_path),
        "--expected-state",
        initial_state,
    ]
    first = competing(halt_argv, args.writers)
    first_successes = [item for item in first if item["exit_code"] == 0]
    status_one = run_or_raise([str(program), "status", "--database", str(database)])
    replay = run_or_raise([str(program), "replay", "--database", str(database)])
    second = competing(halt_argv, max(2, args.writers // 2))
    status_two = run_or_raise([str(program), "status", "--database", str(database)])

    passed = (
        len(first_successes) == 1
        and all(item["exit_code"] != 0 for item in second)
        and status_one["stdout"] == status_two["stdout"]
        and '"halted"' in status_two["stdout"]
    )
    record = {
        "schema": "ag.multiprocess-contention-development-evidence.v1",
        "authority_use": "none",
        "qualification_status": "not_assessed",
        "development_check": "passed" if passed else "failed",
        "limitations": [
            "This uses ordinary process termination, not abrupt power loss.",
            "This does not establish filesystem, disk-cache, or deployed-host behavior.",
            "The halt transition is authority-safe and creates no physical effect."
        ],
        "program": {"path": str(program), "sha256": sha256(program.read_bytes())},
        "database": str(database),
        "writers": args.writers,
        "init": init,
        "first_competition": first,
        "first_success_count": len(first_successes),
        "replay": replay,
        "second_competition": second,
        "state_unchanged_after_second_competition": status_one["stdout"] == status_two["stdout"],
        "final_status": status_two,
    }
    write_exclusive(args.output / "result.json", canonical_bytes(record))
    print(json.dumps({"development_check": record["development_check"], "output": str(args.output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
