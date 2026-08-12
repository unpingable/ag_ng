#!/usr/bin/env python3
"""Capture operational-harness prerequisites without exercising authority."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import stat as stat_module
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).resolve().parent
PROFILES = {
    "local": {
        "tools": ["bash", "cargo", "git", "python3", "readelf", "strings"],
        "environment_paths": [],
    },
    "trusted-host": {
        "tools": ["bash", "bwrap", "cargo", "git", "readelf", "strings", "systemctl"],
        "environment_paths": ["AG_QUAL_HOST_DECLARATION"],
    },
    "deployed-service": {
        "tools": ["ag-loopctl", "git", "python3"],
        "environment_paths": [
            "AG_QUAL_OBSERVATION_RESOLVER",
            "AG_QUAL_STANDING_RESOLVER",
            "AG_QUAL_DOCKET_BIN",
            "AG_QUAL_DOCKET_STANDING_RESOLVER",
            "AG_QUAL_EXECUTOR",
            "AG_QUAL_EXECUTOR_CONFIG",
            "AG_QUAL_DEPLOYMENT_MANIFEST",
        ],
    },
    "fault-injection": {
        "tools": ["git", "python3", "qemu-img", "qemu-system-x86_64"],
        "environment_paths": [
            "AG_QUAL_FAULT_VM_IMAGE",
            "AG_QUAL_FAULT_CONTROLLER",
            "AG_QUAL_DISPOSABLE_EXECUTOR_TARGET",
        ],
    },
}
NONFILE_PATHS = {"AG_QUAL_DISPOSABLE_EXECUTOR_TARGET"}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def command(argv: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "error": str(error)}
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace").strip(),
        "stderr": completed.stderr.decode("utf-8", "replace").strip(),
    }


def tool_record(name: str) -> dict[str, Any]:
    found = shutil.which(name)
    if found is None and name == "ag-loopctl":
        candidate = REPO / "target" / "debug" / "ag-loopctl"
        found = str(candidate) if candidate.is_file() else None
    if found is None:
        return {"name": name, "present": False}
    path = Path(found).resolve()
    version = command([str(path), "--version"])
    return {
        "name": name,
        "present": True,
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "version_probe": version,
    }


def git_value(*args: str) -> str:
    result = command(["git", *args])
    if result.get("exit_code") != 0:
        return ""
    return str(result.get("stdout", ""))


def source_record() -> dict[str, Any]:
    status = git_value("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "repository": str(REPO),
        "branch": git_value("branch", "--show-current"),
        "head": git_value("rev-parse", "HEAD"),
        "tree": git_value("rev-parse", "HEAD^{tree}"),
        "dirty": bool(status),
        "status_sha256": sha256_bytes((status + "\n").encode()),
        "status": status.splitlines(),
    }


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def host_record() -> dict[str, Any]:
    pid1 = read_text(Path("/proc/1/comm"))
    boot_id = read_text(Path("/proc/sys/kernel/random/boot_id"))
    return {
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": os.geteuid(),
        "pid1_comm": pid1,
        "boot_id": boot_id,
        "repository_mount_probe": command(["findmnt", "--json", "--target", str(REPO)]),
    }


def environment_path_record(name: str) -> dict[str, Any]:
    raw = os.environ.get(name)
    if not raw:
        return {"name": name, "configured": False}
    path = Path(raw)
    try:
        metadata = path.stat()
    except OSError as error:
        return {
            "name": name,
            "configured": True,
            "path": str(path),
            "exists": False,
            "stat_error": str(error),
        }
    exists = True
    is_file = stat_module.S_ISREG(metadata.st_mode)
    size = metadata.st_size
    hashable = is_file and size is not None and size <= 32 * 1024 * 1024
    return {
        "name": name,
        "configured": True,
        "path": str(path),
        "exists": exists,
        "is_file": is_file,
        "size_bytes": size,
        "sha256": sha256_file(path) if hashable else None,
        "hash_capture": "unlocked_read" if hashable else "omitted_nonfile_or_over_32_mib",
        "snapshot_consistency": "not_established",
    }


def harness_record() -> list[dict[str, str]]:
    records = []
    for path in sorted(HARNESS.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            records.append({"path": str(path.relative_to(REPO)), "sha256": sha256_file(path)})
    return records


def write_exclusive(path: Path, value: Any) -> None:
    data = canonical_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = PROFILES[args.profile]
    tools = [tool_record(name) for name in profile["tools"]]
    paths = [environment_path_record(name) for name in profile["environment_paths"]]
    prerequisites_observed = all(item["present"] for item in tools) and all(
        item["configured"]
        and item["exists"]
        and (item["name"] in NONFILE_PATHS or item.get("is_file", False))
        for item in paths
    )
    if args.profile == "trusted-host":
        prerequisites_observed = prerequisites_observed and read_text(Path("/proc/1/comm")) == "systemd"

    record = {
        "schema": "ag.operational-preflight.v1",
        "authority_use": "evidence_only",
        "qualification_status": "not_assessed",
        "execution": "preflight_only",
        "profile": args.profile,
        "prerequisites_observed": prerequisites_observed,
        "warning": "Prerequisite presence is not evidence that an operational premise passed.",
        "source": source_record(),
        "host": host_record(),
        "tools": tools,
        "environment_paths": paths,
        "harness_files": harness_record(),
    }
    write_exclusive(args.output / "preflight.json", record)
    print(json.dumps({"output": str(args.output), "prerequisites_observed": prerequisites_observed}))
    return 0 if prerequisites_observed else 2


if __name__ == "__main__":
    raise SystemExit(main())
