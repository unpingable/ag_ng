#!/usr/bin/python3
"""Freeze factual identity for one already-running GCL V1 worker session."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Any


SESSION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
ROOT_SHA = "00afb09883966d2f1cfdcf133eac14b010f0ae8651ebf153105428f3ee90bb8b"
QEMU_SHA = "8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
PORTER_COMMIT = "5931698b7b071c560862144c34b779eefe262688"


class Refusal(RuntimeError):
    pass


def run(argv: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=input_bytes, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def text(argv: list[str]) -> str:
    return run(argv).stdout.decode("utf-8").strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stat_identity(path: Path) -> dict[str, Any]:
    value = path.stat()
    return {
        "path": str(path),
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": oct(value.st_mode & 0o777),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "size": value.st_size,
    }


def ssh_fingerprint(public_line: str) -> str:
    fields = public_line.split()
    wire = base64.b64decode(fields[1], validate=True)
    value = base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{value}"


def known_fingerprints(path: Path) -> set[str]:
    values: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 3 and not fields[0].startswith("#"):
            values.add(ssh_fingerprint(" ".join(fields[1:3])))
    return values


def qmp(socket_path: Path, commands: list[str]) -> dict[str, Any]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(str(socket_path))
    stream = client.makefile("rwb", buffering=0)
    greeting = json.loads(stream.readline())
    results: dict[str, Any] = {"greeting": greeting}
    for command in ["qmp_capabilities", *commands]:
        stream.write((json.dumps({"execute": command}) + "\n").encode("utf-8"))
        while True:
            response = json.loads(stream.readline())
            if "return" in response:
                results[command] = response["return"]
                break
            if "error" in response:
                raise Refusal(f"QMP {command} failed: {response['error']}")
    client.close()
    return results


def systemd_properties(unit: str) -> dict[str, str]:
    names = [
        "ActiveState",
        "SubState",
        "Type",
        "MainPID",
        "ControlGroup",
        "MemoryAccounting",
        "MemoryMax",
        "MemorySwapMax",
        "CPUAccounting",
        "CPUQuotaPerSecUSec",
        "TasksAccounting",
        "TasksMax",
        "IOAccounting",
        "KillMode",
        "TimeoutStartUSec",
        "TimeoutStopUSec",
        "RuntimeMaxUSec",
        "Restart",
        "NoNewPrivileges",
        "UMask",
        "WorkingDirectory",
        "ExecMainStartTimestampMonotonic",
    ]
    output = text(["systemctl", "--user", "show", unit, *[f"--property={name}" for name in names]])
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.partition("=")
        result[key] = value
    return result


def require_systemd(properties: dict[str, str], session_path: Path) -> int:
    expected = {
        "ActiveState": "active",
        "SubState": "running",
        "Type": "exec",
        "MemoryAccounting": "yes",
        "MemoryMax": str(8 * 1024**3),
        "MemorySwapMax": "0",
        "CPUAccounting": "yes",
        "CPUQuotaPerSecUSec": "4s",
        "TasksAccounting": "yes",
        "TasksMax": "512",
        "IOAccounting": "yes",
        "KillMode": "control-group",
        "TimeoutStartUSec": "2min",
        "TimeoutStopUSec": "30s",
        "RuntimeMaxUSec": "12h",
        "Restart": "no",
        "NoNewPrivileges": "yes",
        "UMask": "0077",
        "WorkingDirectory": str(session_path),
    }
    for key, value in expected.items():
        if properties.get(key) != value:
            raise Refusal(f"systemd property mismatch: {key}={properties.get(key)!r}")
    pid = int(properties.get("MainPID", "0"))
    if pid <= 0:
        raise Refusal("systemd MainPID is absent")
    return pid


def proc_identity(pid: int, expected_argv: list[str], unit: str) -> dict[str, Any]:
    proc = Path("/proc") / str(pid)
    argv = [value.decode("utf-8") for value in (proc / "cmdline").read_bytes().split(b"\0") if value]
    if argv != expected_argv:
        raise Refusal("QEMU process argv differs from launch spec")
    stat_line = (proc / "stat").read_text()
    start_ticks = stat_line[stat_line.rfind(")") + 2 :].split()[19]
    cgroup = (proc / "cgroup").read_text().strip()
    if unit not in cgroup:
        raise Refusal("QEMU process is outside the exact unit cgroup")
    return {
        "pid": pid,
        "start_ticks": start_ticks,
        "exe": os.readlink(proc / "exe"),
        "argv": argv,
        "cgroup": cgroup,
    }


def strict_ssh_argv(worker: Path, port: int) -> list[str]:
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-p", str(port),
        "-i", str(worker / "gcl-v1-worker-ssh"),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={worker / 'known_hosts-r3'}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey",
        "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no",
        "-o", "RequestTTY=no", "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2", "-o", "TCPKeepAlive=yes",
        "--", "gcl-parent@127.0.0.1",
    ]


def main() -> int:
    if len(sys.argv) != 2 or not SESSION_RE.fullmatch(sys.argv[1]):
        raise Refusal("usage: freeze-session.py <session-id>")
    session_id = sys.argv[1]
    here = Path(__file__).resolve().parent
    repo = here.parent.parent
    custody = repo / ".campaign-local" / "gcl-v1"
    worker = custody / "worker"
    session = custody / "sessions" / session_id
    unit = f"gcl-v1vm-{session_id}.service"
    port = 23022
    if not session.is_dir():
        raise Refusal("session custody is absent")

    launch_spec = json.loads((session / "launch-spec.json").read_text())
    if launch_spec.get("session_id") != session_id or launch_spec.get("unit") != unit:
        raise Refusal("launch spec substitution")
    ag_commit = text(["git", "-C", str(repo), "rev-parse", "HEAD"])
    ag_tree = text(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"])
    if text(["git", "-C", str(repo), "status", "--porcelain"]):
        raise Refusal("AG worktree is not clean")
    if launch_spec.get("ag_commit") != ag_commit or launch_spec.get("ag_tree") != ag_tree:
        raise Refusal("AG source changed after launch")
    if launch_spec.get("launcher_sha256") != sha256(here / "launch-session.sh"):
        raise Refusal("launcher changed after launch")
    launch_argv = launch_spec["systemd_run_argv"]
    separator = launch_argv.index("--")
    expected_qemu_argv = launch_argv[separator + 1 :]
    properties = systemd_properties(unit)
    pid = require_systemd(properties, session)
    process = proc_identity(pid, expected_qemu_argv, unit)
    pidfile = int((session / "qemu.pid").read_text().strip())
    if pidfile != pid:
        raise Refusal("QEMU pidfile differs from systemd MainPID")
    qmp_facts = qmp(session / "qmp.sock", ["query-kvm", "query-status", "query-block"])
    if qmp_facts["query-kvm"] != {"enabled": True, "present": True}:
        raise Refusal("QMP does not report active KVM")
    if qmp_facts["query-status"].get("status") != "running":
        raise Refusal("QEMU is not running")

    initial_identity = json.loads((session / "initial-identity.json").read_text())
    if initial_identity.get("session_id") != session_id or initial_identity.get("capacity") != 3:
        raise Refusal("initial guest identity substitution")

    porter = Path("/data/git/porter")
    if text(["git", "-C", str(porter), "rev-parse", "HEAD"]) != PORTER_COMMIT:
        raise Refusal("Porter commit substitution")
    if text(["git", "-C", str(porter), "status", "--porcelain"]):
        raise Refusal("Porter worktree is not clean")
    porter_tree = text(["git", "-C", str(porter), "rev-parse", "HEAD^{tree}"])
    known_hosts = worker / "known_hosts-r3"
    client_public = worker / "gcl-v1-worker-ssh.pub"
    build_receipt = json.loads((custody / "build-root-r3" / "build-receipt.json").read_text())
    guest_fingerprint = build_receipt["guest_host_key_fingerprint"]
    if guest_fingerprint not in known_fingerprints(known_hosts):
        raise Refusal("pinned guest host key is absent")
    client_fingerprint = ssh_fingerprint(client_public.read_text().strip())

    expected_identity = {
        key: initial_identity[key]
        for key in (
            "schema", "session_id", "agent_sha256", "codex_sha256",
            "bwrap_sha256", "codex_version", "capacity",
        )
    }
    profile = {
        "schema": "porter.ssh-exact-profile.v1",
        "endpoint_id": f"endpoint-{session_id}",
        "session_id": session_id,
        "host": "127.0.0.1",
        "port": port,
        "user": "gcl-parent",
        "ssh_executable": "/usr/bin/ssh",
        "ssh_executable_sha256": sha256(Path("/usr/bin/ssh")),
        "identity_file": str(worker / "gcl-v1-worker-ssh"),
        "identity_public_file": str(client_public),
        "client_key_fingerprint": client_fingerprint,
        "known_hosts_file": str(known_hosts),
        "known_hosts_sha256": sha256(known_hosts),
        "guest_host_key_fingerprint": guest_fingerprint,
        "remote_root": "/var/lib/gcl-state",
        "workdir": "/var/lib/gcl-state",
        "identity_argv": ["/usr/local/libexec/gcl-worker-agent", "identity"],
        "expected_identity": expected_identity,
    }
    profile_path = session / "porter-exact-profile.json"
    profile_path.write_text(json.dumps(profile, sort_keys=True, indent=2) + "\n")
    profile_path.chmod(0o600)

    porter_runs = session / "porter-runs"
    up = run([
        str(porter / "porter"), "up", "--runs-dir", str(porter_runs),
        f"ssh-exact:{profile_path}",
    ])
    porter_run_id = up.stdout.decode("utf-8").strip()
    run([str(porter / "porter"), "seal", "--runs-dir", str(porter_runs), porter_run_id])
    porter_record_path = porter_runs / porter_run_id / "record.json"
    porter_record = json.loads(porter_record_path.read_text())
    observed = porter_record["substrate"]["observed"]["guest_transport_identity"]
    if observed.get("session_id") != session_id:
        raise Refusal("Porter observed a substituted session")

    unit_text = run(["systemctl", "--user", "cat", unit]).stdout
    (session / "systemd-unit.txt").write_bytes(unit_text)
    devices = {
        "root": {
            **stat_identity(worker / "gcl-v1-worker-root-r3.qcow2"),
            "sha256": sha256(worker / "gcl-v1-worker-root-r3.qcow2"),
            "qemu_read_only": True,
        },
        "state": {
            **stat_identity(worker / "gcl-v1-worker-state.raw"),
            "filesystem_label": text(["blkid", "-s", "LABEL", "-o", "value", str(worker / "gcl-v1-worker-state.raw")]),
            "filesystem_uuid": text(["blkid", "-s", "UUID", "-o", "value", str(worker / "gcl-v1-worker-state.raw")]),
        },
        "credentials": {
            **stat_identity(worker / "gcl-v1-worker-credentials.raw"),
            "filesystem_label": text(["blkid", "-s", "LABEL", "-o", "value", str(worker / "gcl-v1-worker-credentials.raw")]),
            "filesystem_uuid": text(["blkid", "-s", "UUID", "-o", "value", str(worker / "gcl-v1-worker-credentials.raw")]),
        },
    }
    if devices["root"]["sha256"] != ROOT_SHA or sha256(Path("/usr/bin/qemu-system-x86_64")) != QEMU_SHA:
        raise Refusal("immutable QEMU or root identity changed")

    manifest = {
        "schema": "ag.gcl-v1-measured-worker-session/v1",
        "session_id": session_id,
        "unit": unit,
        "capacity": 3,
        "resource_profile": properties,
        "systemd_unit_sha256": sha256(session / "systemd-unit.txt"),
        "launch_spec_sha256": sha256(session / "launch-spec.json"),
        "controller_source": {
            "commit": ag_commit,
            "tree": ag_tree,
            "launcher_sha256": sha256(here / "launch-session.sh"),
            "freezer_sha256": sha256(Path(__file__).resolve()),
        },
        "qemu": {
            "executable": "/usr/bin/qemu-system-x86_64",
            "sha256": QEMU_SHA,
            "process": process,
            "qmp": qmp_facts,
        },
        "devices": devices,
        "endpoint": {
            "socket": f"127.0.0.1:{port}",
            "known_hosts_sha256": sha256(known_hosts),
            "guest_host_key_fingerprint": guest_fingerprint,
            "client_public_key_fingerprint": client_fingerprint,
        },
        "guest": observed,
        "codex_configuration": {
            "executable_sha256": observed["codex_sha256"],
            "version": observed["codex_version"],
            "model": "gpt-5.6-sol",
            "reasoning_effort": "medium",
        },
        "porter": {
            "commit": PORTER_COMMIT,
            "tree": porter_tree,
            "profile_sha256": sha256(profile_path),
            "run_id": porter_run_id,
            "record_sha256": sha256(porter_record_path),
        },
        "network_identity": {
            "network_manager_profile": "crow-mellanox",
            "profile_uuid": "5a0cc298-0f9f-3039-b41b-6d4be111c0f8",
            "mac": "24:8a:07:f8:1d:91",
            "address": "192.168.69.30/22",
            "interface_name_is_not_identity": True,
        },
        "authority": None,
    }
    manifest_path = session / "session-manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    manifest_path.chmod(0o600)
    print(f"W3 session frozen: {session_id}")
    print(f"Manifest SHA-256: {sha256(manifest_path)}")
    print(f"Porter run: {porter_run_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refusal, subprocess.CalledProcessError, OSError, KeyError, ValueError) as error:
        print(f"freeze-session refusal: {error}", file=sys.stderr)
        raise SystemExit(1)
