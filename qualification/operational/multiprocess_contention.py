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


# Published test-only Ed25519 PKCS#8 material. It authenticates no deployment
# authority and exists only so genesis validation exercises the real key path.
TEST_ISSUER_PKCS8_HEX = (
    "3051020101300506032b657004220420c226c22f628685cd349518c28eff015f"
    "d216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f263132"
    "75119934a021918f5d37d100ad2f27acbaf776"
)


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
    root = args.output.resolve()
    database = root / "campaign.sqlite"
    genesis_path = root / "genesis.json"
    halt_path = root / "halt.json"
    genesis = {
        "campaign": "sha256:" + "a" * 64,
        "occurrence": "00000000-0000-4000-8000-000000000001",
        "program": "sha256:" + "b" * 64,
        "expected_ag_work": "sha256:" + "f" * 64,
        "residuals": [],
        "budget": {
            "retry_limit": 1,
            "retries_used": 0,
            "probe_limit": 1,
            "probes_used": 0,
            "escalation_limit": 1,
            "escalations_used": 0,
        },
    }
    halt = {"reason": "sha256:" + "c" * 64}
    write_exclusive(genesis_path, canonical_bytes(genesis))
    write_exclusive(halt_path, canonical_bytes(halt))

    catalog_path = root / "catalog.json"
    trust_path = root / "docket-trust.json"
    issuer_key_path = root / "issuer.pk8"
    profile_path = root / "runtime-profile.json"
    catalog = {
        "schema": "ag.governed-loop.exact-work-catalog/v1",
        "entries": {
            "fixture.work/v1": {
                "work_schema": "fixture.work/v1",
                "subject": "sha256:" + "d" * 64,
                "scope": "sha256:" + "e" * 64,
                "precondition": {"required": [], "forbidden": []},
            }
        },
    }
    write_exclusive(catalog_path, canonical_bytes(catalog))
    write_exclusive(trust_path, canonical_bytes({}))
    write_exclusive(issuer_key_path, bytes.fromhex(TEST_ISSUER_PKCS8_HEX))

    def pinned(path: Path) -> dict[str, str]:
        return {"path": str(path), "identity": sha256(path.read_bytes())}

    profile = {
        "schema": "ag.governed-loop.runtime-profile/v1",
        "profile_label": "multiprocess-contention-development",
        "observation_resolver": pinned(program),
        "observation_resolver_id": "unused-observation-resolver/v1",
        "standing_resolver": pinned(program),
        "standing_resolver_id": "unused-standing-resolver/v1",
        "max_standing_ttl_ms": 60_000,
        "exact_work_catalog": pinned(catalog_path),
        "controlling_review": None,
        "docket": {
            "schema": "ag.governed-loop.docket-root/v1",
            "docket_program": pinned(program),
            "state_directory": str(root / "docket-state"),
            "trust_config": pinned(trust_path),
            "standing_resolver": pinned(program),
            "executor_adapter": pinned(program),
            "issuer_principal": "ag-contention-fixture",
            "issuer_key_id": "fixture-key-1",
            "issuer_key": pinned(issuer_key_path),
        },
        "human_verifier": None,
    }
    write_exclusive(profile_path, canonical_bytes(profile))

    init = run_or_raise([
        str(program), "init", "--database", str(database), "--genesis", str(genesis_path),
        "--runtime-profile", str(profile_path),
    ])
    halt_argv = [str(program), "halt", "--database", str(database), "--input", str(halt_path)]
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
