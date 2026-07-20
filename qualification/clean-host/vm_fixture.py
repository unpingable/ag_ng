#!/usr/bin/python3
"""Fail-closed host helpers for the clean-VM qualification fixture.

This module renders deterministic NoCloud input, probes the real TCP/SSH
boundary, speaks the two QMP operations needed by the controller, and records
an immutable per-case wall-clock budget.  It deliberately does not launch a
hypervisor and never invokes a shell.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, NoReturn, Sequence


NOCLOUD_SCHEMA = "ag.clean-host-nocloud-fixture/v1"
READINESS_SCHEMA = "ag.clean-host-ssh-readiness/v1"
QMP_SCHEMA = "ag.clean-host-qmp-operation/v1"
CASE_START_SCHEMA = "ag.clean-host-case-start/v1"
CASE_DEADLINE_SCHEMA = "ag.clean-host-case-deadline/v1"
CASE_CHECK_SCHEMA = "ag.clean-host-case-deadline-check/v1"
CASE_FINISH_SCHEMA = "ag.clean-host-case-finish/v1"
OPERATION_FAILURE_SCHEMA = "ag.clean-host-fixture-operation-failure/v1"

CASE_DEADLINE_SECONDS = 1800
MAX_READINESS_SECONDS = 120
MAX_QMP_SECONDS = 30
MAX_QMP_LINE_BYTES = 1024 * 1024
MAX_SSH_OUTPUT_BYTES = 1024 * 1024

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
INSTANCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\Z"
)
USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,30}\Z")
PUBLIC_KEY_TYPES = frozenset(
    (
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    )
)
CASE_RESULTS = frozenset(("pass", "fail", "blocked", "not_run", "unsupported"))
PRIVATE_KEY_MARKERS = (
    b"PRIVATE KEY",
    b"OPENSSH PRIVATE",
    b"BEGIN RSA",
    b"BEGIN EC",
)


class FixtureError(ValueError):
    """A VM fixture input, operation, or record is unsafe or inconsistent."""


def _error(location: str, message: str) -> NoReturn:
    raise FixtureError(f"{location}: {message}")


def _require(condition: bool, location: str, message: str) -> None:
    if not condition:
        _error(location, message)


def canonical_json_bytes(value: Any) -> bytes:
    """Return sorted compact UTF-8 JSON followed by exactly one LF."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise FixtureError(f"value is not canonical JSON data: {error}") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def _load_canonical_json(path: Path) -> dict[str, Any]:
    raw = _read_regular_file(path, 1024 * 1024)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: _error("JSON", f"non-finite number {token}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"{path}: invalid UTF-8 JSON: {error}") from error
    _require(type(value) is dict, str(path), "must contain a JSON object")
    _require(raw == canonical_json_bytes(value), str(path), "is not canonical JSON")
    return value


def _sha256_reference(data: bytes) -> dict[str, Any]:
    return {"length": len(data), "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}"}


def _open_regular_nofollow(path: Path, *, executable: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FixtureError(f"{path}: cannot open safely: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        _require(stat.S_ISREG(metadata.st_mode), str(path), "must be a regular file")
        _require(metadata.st_nlink == 1, str(path), "must have exactly one hard link")
        if executable:
            _require(metadata.st_mode & 0o111 != 0, str(path), "is not executable")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_file(path: Path, maximum: int) -> bytes:
    descriptor = _open_regular_nofollow(path)
    try:
        metadata = os.fstat(descriptor)
        _require(metadata.st_size <= maximum, str(path), f"exceeds {maximum} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            _require(total <= maximum, str(path), f"exceeds {maximum} bytes")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise FixtureError(
            f"{path}: refusing to replace existing output: {error}"
        ) from error
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _error(str(path), "short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new_file(path, canonical_json_bytes(value))


def _reserve_json_output(path: Path) -> int:
    _require(path.is_absolute(), "output", "must be an absolute path")
    _require_existing_directory(path.parent, "output parent")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return os.open(path, flags, 0o600)
    except OSError as error:
        raise FixtureError(
            f"{path}: cannot reserve result before operation: {error}"
        ) from error


def _publish_reserved_json(descriptor: int, path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, str(path), "short result write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_existing_directory(path: Path, location: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FixtureError(f"{location}: cannot inspect directory: {error}") from error
    _require(
        stat.S_ISDIR(metadata.st_mode), location, "must be an existing real directory"
    )


def _utc_text(moment: dt.datetime) -> str:
    _require(moment.tzinfo is not None, "UTC timestamp", "must be timezone-aware")
    return (
        moment.astimezone(dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _validate_public_key(path: Path) -> str:
    raw = _read_regular_file(path, 16384)
    _require(
        not any(marker in raw for marker in PRIVATE_KEY_MARKERS),
        str(path),
        "private key material is forbidden",
    )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise FixtureError(f"{path}: public key is not ASCII: {error}") from error
    _require(
        "\x00" not in text and "\r" not in text,
        str(path),
        "contains forbidden control bytes",
    )
    lines = text.splitlines()
    _require(len(lines) == 1, str(path), "must contain exactly one public key line")
    fields = lines[0].strip().split()
    _require(len(fields) >= 2, str(path), "is not an OpenSSH public key")
    key_type, encoded = fields[0], fields[1]
    _require(
        key_type in PUBLIC_KEY_TYPES, str(path), "uses an unsupported public key type"
    )
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FixtureError(f"{path}: invalid public key base64: {error}") from error
    _require(len(decoded) >= 16, str(path), "public key payload is implausibly short")
    encoded_type_length = int.from_bytes(decoded[:4], "big")
    _require(
        0 < encoded_type_length <= len(decoded) - 4,
        str(path),
        "public key wire type length is invalid",
    )
    try:
        encoded_type = decoded[4 : 4 + encoded_type_length].decode("ascii")
    except UnicodeDecodeError as error:
        raise FixtureError(
            f"{path}: public key wire type is not ASCII: {error}"
        ) from error
    _require(
        encoded_type == key_type,
        str(path),
        "public key text and wire types differ",
    )
    # Comments are intentionally dropped so host-local labels cannot alter seed bytes.
    return f"{key_type} {encoded}"


def render_nocloud(
    output_dir: Path,
    *,
    instance_id: str,
    hostname: str,
    username: str,
    authorized_key_file: Path,
) -> dict[str, Any]:
    """Create deterministic NoCloud meta-data and user-data in a new directory."""

    _require(
        INSTANCE_ID_RE.fullmatch(instance_id) is not None,
        "instance-id",
        "is not a safe identifier",
    )
    _require(
        HOSTNAME_RE.fullmatch(hostname) is not None,
        "hostname",
        "is not a valid DNS hostname",
    )
    _require(
        USERNAME_RE.fullmatch(username) is not None,
        "username",
        "is not a safe Linux username",
    )
    public_key = _validate_public_key(authorized_key_file)

    meta_data = (
        f"instance-id: {json.dumps(instance_id)}\n"
        f"local-hostname: {json.dumps(hostname)}\n"
    ).encode("utf-8")
    user_data = (
        "#cloud-config\n"
        "disable_root: true\n"
        "growpart:\n"
        '  devices: ["/"]\n'
        "  ignore_growroot_disabled: false\n"
        '  mode: "auto"\n'
        f"hostname: {json.dumps(hostname)}\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "preserve_hostname: false\n"
        "resize_rootfs: true\n"
        "ssh_pwauth: false\n"
        "users:\n"
        f"  - name: {json.dumps(username)}\n"
        '    groups: ["sudo"]\n'
        "    lock_passwd: true\n"
        '    shell: "/bin/bash"\n'
        '    sudo: ["ALL=(ALL) NOPASSWD:ALL"]\n'
        "    ssh_authorized_keys:\n"
        f"      - {json.dumps(public_key)}\n"
    ).encode("utf-8")

    try:
        output_dir.mkdir(mode=0o755)
    except OSError as error:
        raise FixtureError(
            f"{output_dir}: must be a new output directory: {error}"
        ) from error
    try:
        _write_new_file(output_dir / "meta-data", meta_data)
        _write_new_file(output_dir / "user-data", user_data)
        record = {
            "authorized_key": _sha256_reference(public_key.encode("ascii") + b"\n"),
            "files": {
                "meta-data": _sha256_reference(meta_data),
                "user-data": _sha256_reference(user_data),
            },
            "hostname": hostname,
            "instance_id": instance_id,
            "private_key_copied": False,
            "schema": NOCLOUD_SCHEMA,
            "username": username,
        }
        _write_new_json(output_dir / "fixture.v1.json", record)
        return record
    except BaseException:
        # Preserve any partial directory: overwriting it on retry would hide the failure.
        raise


class SystemClock:
    """Linux boot-time clock plus auditable UTC timestamps."""

    def now_ns(self) -> int:
        clock_id = getattr(time, "CLOCK_BOOTTIME", None)
        if clock_id is None:
            _error("clock", "CLOCK_BOOTTIME is required on a supported Linux host")
        return time.clock_gettime_ns(clock_id)

    def utc_now(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def boot_id(self) -> str:
        value = (
            _read_regular_file(Path("/proc/sys/kernel/random/boot_id"), 128)
            .decode("ascii")
            .strip()
        )
        _require(
            re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
            )
            is not None,
            "boot-id",
            "kernel boot ID is malformed",
        )
        return value


def _validate_absolute_file(path: Path, location: str) -> None:
    _require(path.is_absolute(), location, "must be an absolute path")
    descriptor = _open_regular_nofollow(path)
    os.close(descriptor)


def _file_identity(path: Path, maximum: int) -> dict[str, Any]:
    payload = _read_regular_file(path, maximum)
    return {"path": str(path), **_sha256_reference(payload)}


def _stream_record(data: bytes) -> dict[str, Any]:
    _require(len(data) <= MAX_SSH_OUTPUT_BYTES, "SSH output", "exceeds bounded capture")
    return {
        "base64": base64.b64encode(data).decode("ascii"),
        **_sha256_reference(data),
    }


def _default_tcp_probe(
    host: str, port: int, timeout_seconds: float
) -> tuple[str, int | None]:
    family = (
        socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    )
    address: tuple[Any, ...] = (
        (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    )
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.settimeout(timeout_seconds)
        probe.connect(address)
        return "connected", None
    except socket.timeout:
        return "timeout", None
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            return "connection_refused", error.errno
        return "os_error", error.errno
    finally:
        probe.close()


def _run_pinned_ssh(
    ssh_executable: Path,
    argv: list[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    descriptor = _open_regular_nofollow(ssh_executable, executable=True)
    try:
        metadata = os.fstat(descriptor)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            executable_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        identity = {
            "length": metadata.st_size,
            "path": str(ssh_executable),
            "sha256": f"sha256:{executable_sha256}",
        }
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            completed = subprocess.run(
                argv,
                executable=f"/proc/self/fd/{descriptor}",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
                close_fds=True,
                pass_fds=(descriptor,),
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            return {
                "executable": identity,
                "outcome": "timeout",
                "stderr": _stream_record(stderr),
                "stdout": _stream_record(stdout),
            }
        except OSError as error:
            return {
                "errno": error.errno,
                "executable": identity,
                "outcome": "launch_error",
                "stderr": _stream_record(b""),
                "stdout": _stream_record(b""),
            }
        outcome = "signal" if completed.returncode < 0 else "exit"
        record = {
            "executable": identity,
            "outcome": outcome,
            "stderr": _stream_record(completed.stderr),
            "stdout": _stream_record(completed.stdout),
        }
        if outcome == "signal":
            record["signal"] = -completed.returncode
        else:
            record["exit_code"] = completed.returncode
        return record
    finally:
        os.close(descriptor)


def wait_for_ssh(
    *,
    host: str,
    port: int,
    username: str,
    identity_file: Path,
    known_hosts_file: Path,
    ssh_executable: Path,
    remote_argv: Sequence[str],
    timeout_seconds: int,
    poll_interval_ms: int,
    connect_timeout_ms: int,
    ssh_attempt_timeout_seconds: int,
    clock: Any | None = None,
    tcp_probe: Callable[[str, int, float], tuple[str, int | None]] | None = None,
    ssh_runner: Callable[[Path, list[str], float], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Probe TCP then authenticated SSH until ready or the monotonic bound expires."""

    clock = SystemClock() if clock is None else clock
    tcp_probe = _default_tcp_probe if tcp_probe is None else tcp_probe
    ssh_runner = _run_pinned_ssh if ssh_runner is None else ssh_runner
    try:
        ipaddress.ip_address(host)
    except ValueError as error:
        raise FixtureError(f"host: must be a numeric IP address: {error}") from error
    _require(1 <= port <= 65535, "port", "must be in 1..65535")
    _require(USERNAME_RE.fullmatch(username) is not None, "username", "is not safe")
    _require(
        1 <= timeout_seconds <= MAX_READINESS_SECONDS,
        "timeout-seconds",
        f"must be in 1..{MAX_READINESS_SECONDS}",
    )
    _require(50 <= poll_interval_ms <= 5000, "poll-interval-ms", "must be in 50..5000")
    _require(
        50 <= connect_timeout_ms <= 10000, "connect-timeout-ms", "must be in 50..10000"
    )
    _require(
        1 <= ssh_attempt_timeout_seconds <= 30,
        "ssh-attempt-timeout-seconds",
        "must be in 1..30",
    )
    _validate_absolute_file(identity_file, "identity-file")
    _require(known_hosts_file.is_absolute(), "known-hosts-file", "must be absolute")
    _require_existing_directory(known_hosts_file.parent, "known-hosts-file parent")
    _require(
        not known_hosts_file.exists(),
        "known-hosts-file",
        "must be absent at a pristine fixture boundary",
    )
    _require(ssh_executable.is_absolute(), "ssh-executable", "must be absolute")
    _require(bool(remote_argv), "remote-argv", "must not be empty")
    _require(
        str(remote_argv[0]).startswith("/"),
        "remote-argv[0]",
        "must be an absolute remote executable",
    )
    for index, argument in enumerate(remote_argv):
        _require(
            type(argument) is str and argument != "",
            f"remote-argv[{index}]",
            "must be a nonempty string",
        )
        _require(
            "\x00" not in argument and "\n" not in argument and "\r" not in argument,
            f"remote-argv[{index}]",
            "contains forbidden control characters",
        )

    identity = _file_identity(identity_file, 1024 * 1024)
    rendered_remote_command = shlex.join(remote_argv)

    started_ns = clock.now_ns()
    started_utc = clock.utc_now()
    deadline_ns = started_ns + timeout_seconds * 1_000_000_000
    attempts: list[dict[str, Any]] = []
    ready = False
    while True:
        attempt_started = clock.now_ns()
        remaining_ns = deadline_ns - attempt_started
        if remaining_ns <= 0:
            break
        attempt: dict[str, Any] = {
            "attempt": len(attempts) + 1,
            "offset_ms": (attempt_started - started_ns) // 1_000_000,
            "ssh": None,
        }
        tcp_timeout = min(connect_timeout_ms / 1000, remaining_ns / 1_000_000_000)
        tcp_started = clock.now_ns()
        tcp_outcome, tcp_errno = tcp_probe(host, port, tcp_timeout)
        tcp_ended = clock.now_ns()
        _require(tcp_ended >= tcp_started, "TCP probe clock", "moved backwards")
        _require(
            tcp_outcome in {"connected", "connection_refused", "timeout", "os_error"},
            "TCP probe",
            "returned an unknown outcome",
        )
        attempt["tcp"] = {
            "duration_ms": (tcp_ended - tcp_started) // 1_000_000,
            "errno": tcp_errno,
            "outcome": tcp_outcome,
        }
        if tcp_outcome == "connected":
            ssh_remaining = deadline_ns - tcp_ended
            if ssh_remaining > 0:
                ssh_timeout = min(
                    ssh_attempt_timeout_seconds, ssh_remaining / 1_000_000_000
                )
                connect_seconds = max(1, min(10, (connect_timeout_ms + 999) // 1000))
                argv = [
                    str(ssh_executable),
                    "-F",
                    "/dev/null",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    f"ConnectTimeout={connect_seconds}",
                    "-o",
                    "ConnectionAttempts=1",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "GlobalKnownHostsFile=/dev/null",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                    "-o",
                    "PasswordAuthentication=no",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "ServerAliveCountMax=3",
                    "-o",
                    "ServerAliveInterval=10",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    f"UserKnownHostsFile={known_hosts_file}",
                    "-i",
                    str(identity_file),
                    "-p",
                    str(port),
                    f"{username}@{host}",
                    rendered_remote_command,
                ]
                ssh_started = clock.now_ns()
                ssh_record = ssh_runner(ssh_executable, argv, ssh_timeout)
                ssh_ended = clock.now_ns()
                _require(ssh_ended >= ssh_started, "SSH probe clock", "moved backwards")
                _require(
                    type(ssh_record) is dict
                    and ssh_record.get("outcome")
                    in {"exit", "signal", "timeout", "launch_error"},
                    "SSH probe",
                    "returned a malformed outcome",
                )
                attempt["ssh"] = {
                    "argv": argv,
                    "duration_ms": (ssh_ended - ssh_started) // 1_000_000,
                    **ssh_record,
                }
                ready = (
                    ssh_ended <= deadline_ns
                    and ssh_record["outcome"] == "exit"
                    and ssh_record.get("exit_code") == 0
                )
        attempts.append(attempt)
        if ready:
            break
        now_ns = clock.now_ns()
        remaining_ns = deadline_ns - now_ns
        if remaining_ns <= 0:
            break
        clock.sleep(min(poll_interval_ms / 1000, remaining_ns / 1_000_000_000))

    finished_ns = clock.now_ns()
    _require(finished_ns >= started_ns, "readiness clock", "moved backwards")
    _require(
        _file_identity(identity_file, 1024 * 1024) == identity,
        "identity-file",
        "changed during SSH readiness",
    )
    overrun_ns = max(0, finished_ns - deadline_ns)
    record = {
        "attempts": attempts,
        "deadline_overrun_ns": overrun_ns,
        "duration_ms": (finished_ns - started_ns) // 1_000_000,
        "finished_utc": _utc_text(clock.utc_now()),
        "identity_file": identity,
        "known_hosts": _file_identity(known_hosts_file, 1024 * 1024)
        if known_hosts_file.exists()
        else None,
        "poll_interval_ms": poll_interval_ms,
        "remote_argv": list(remote_argv),
        "rendered_remote_command": rendered_remote_command,
        "result": (
            "ready"
            if ready
            else "deadline_exceeded"
            if overrun_ns
            else "deadline_exhausted"
        ),
        "schema": READINESS_SCHEMA,
        "started_utc": _utc_text(started_utc),
        "target": {"host": host, "port": port, "username": username},
        "timeout_seconds": timeout_seconds,
    }
    return record, ready


class _QmpConnection:
    def __init__(self, path: Path, timeout_seconds: int) -> None:
        _require(path.is_absolute(), "qmp-socket", "must be an absolute path")
        _require(
            1 <= timeout_seconds <= MAX_QMP_SECONDS,
            "timeout-seconds",
            f"must be in 1..{MAX_QMP_SECONDS}",
        )
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout_seconds)
        self._deadline_ns = time.monotonic_ns() + timeout_seconds * 1_000_000_000
        try:
            self._socket.connect(str(path))
        except BaseException:
            self._socket.close()
            raise
        self._buffer = bytearray()

    def close(self) -> None:
        self._socket.close()

    def send(self, value: dict[str, Any]) -> None:
        self._set_remaining_timeout()
        self._socket.sendall(canonical_json_bytes(value))

    def receive(self) -> dict[str, Any]:
        while b"\n" not in self._buffer:
            self._set_remaining_timeout()
            chunk = self._socket.recv(65536)
            if not chunk:
                _error("QMP", "peer closed before a complete response")
            self._buffer.extend(chunk)
            _require(
                len(self._buffer) <= MAX_QMP_LINE_BYTES,
                "QMP",
                "response exceeds bounded line length",
            )
        raw, _, remainder = self._buffer.partition(b"\n")
        self._buffer = bytearray(remainder)
        try:
            value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FixtureError(f"QMP: malformed response: {error}") from error
        _require(type(value) is dict, "QMP", "response must be an object")
        return value

    def _set_remaining_timeout(self) -> None:
        remaining_ns = self._deadline_ns - time.monotonic_ns()
        _require(remaining_ns > 0, "QMP", "monotonic deadline is exhausted")
        self._socket.settimeout(remaining_ns / 1_000_000_000)


def _receive_qmp_reply(
    connection: Any,
    request_id: str,
    transcript: list[dict[str, Any]],
) -> dict[str, Any]:
    while True:
        message = connection.receive()
        transcript.append({"direction": "receive", "message": message})
        if "event" in message:
            continue
        _require(
            message.get("id") == request_id,
            "QMP",
            "reply ID does not match request",
        )
        _require(
            ("return" in message) != ("error" in message),
            "QMP",
            "reply must contain exactly one of return or error",
        )
        return message


def qmp_operation(
    socket_path: Path,
    operation: str,
    timeout_seconds: int,
    connection_factory: Callable[[Path, int], Any] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Negotiate QMP and perform one frozen observation or shutdown operation."""

    _require(
        operation in {"query-status", "system-powerdown", "quit"},
        "operation",
        "is not supported",
    )
    started = time.monotonic_ns()
    started_utc = dt.datetime.now(dt.timezone.utc)
    transcript: list[dict[str, Any]] = []
    connection_factory = (
        _QmpConnection if connection_factory is None else connection_factory
    )
    try:
        connection = connection_factory(socket_path, timeout_seconds)
        try:
            greeting = connection.receive()
            transcript.append({"direction": "receive", "message": greeting})
            _require(
                type(greeting.get("QMP")) is dict, "QMP", "missing protocol greeting"
            )
            capabilities = {"execute": "qmp_capabilities", "id": "ag-ng-capabilities"}
            transcript.append({"direction": "send", "message": capabilities})
            connection.send(capabilities)
            capability_reply = _receive_qmp_reply(
                connection, "ag-ng-capabilities", transcript
            )
            if "error" in capability_reply:
                outcome = "qmp_error"
                success = False
                response = capability_reply
            else:
                execute = {
                    "query-status": "query-status",
                    "quit": "quit",
                    "system-powerdown": "system_powerdown",
                }[operation]
                request = {"execute": execute, "id": "ag-ng-command"}
                transcript.append({"direction": "send", "message": request})
                connection.send(request)
                try:
                    response = _receive_qmp_reply(
                        connection, "ag-ng-command", transcript
                    )
                except (FixtureError, ConnectionResetError) as error:
                    peer_closed_after_quit = operation == "quit" and (
                        isinstance(error, ConnectionResetError)
                        or str(error) == "QMP: peer closed before a complete response"
                    )
                    if not peer_closed_after_quit:
                        raise
                    response = {
                        "accepted_without_reply": "peer_closed_after_quit_request"
                    }
                    transcript.append(
                        {
                            "direction": "transport",
                            "message": dict(response),
                        }
                    )
                    outcome = "accepted"
                    success = True
                else:
                    outcome = "qmp_error" if "error" in response else "accepted"
                    success = outcome == "accepted"
                if success and operation == "query-status":
                    returned = response["return"]
                    _require(
                        type(returned) is dict,
                        "QMP query-status",
                        "return must be an object",
                    )
                    _require(
                        type(returned.get("status")) is str,
                        "QMP query-status",
                        "missing string status",
                    )
                    _require(
                        type(returned.get("running")) is bool,
                        "QMP query-status",
                        "missing boolean running",
                    )
        finally:
            connection.close()
    except (OSError, socket.timeout) as error:
        outcome = "transport_error"
        success = False
        response = {
            "error": {
                "class": error.__class__.__name__,
                "errno": getattr(error, "errno", None),
                "message": str(error),
            }
        }
        transcript.append({"direction": "transport", "message": response})
    finished = time.monotonic_ns()
    _require(finished >= started, "QMP clock", "moved backwards")
    _require(
        finished - started <= timeout_seconds * 1_000_000_000,
        "QMP",
        "operation exceeded its monotonic bound",
    )
    return (
        {
            "duration_ms": (finished - started) // 1_000_000,
            "finished_utc": _utc_text(dt.datetime.now(dt.timezone.utc)),
            "operation": operation,
            "outcome": outcome,
            "response": response,
            "schema": QMP_SCHEMA,
            "socket": str(socket_path),
            "started_utc": _utc_text(started_utc),
            "timeout_seconds": timeout_seconds,
            "transcript": transcript,
        },
        success,
    )


def _strict_keys(value: dict[str, Any], keys: set[str], location: str) -> None:
    _require(
        set(value) == keys,
        location,
        f"fields differ: expected {sorted(keys)}, got {sorted(value)}",
    )


def _case_paths(state_dir: Path) -> tuple[Path, Path, Path]:
    return (
        state_dir / "case-start.v1.json",
        state_dir / "case-deadline.v1.json",
        state_dir / "case-finish.v1.json",
    )


def start_case(
    state_dir: Path, guest: str, case: str, clock: Any | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Persist immutable linked start and deadline records for one matrix case."""

    clock = SystemClock() if clock is None else clock
    _require_existing_directory(state_dir, "state-dir")
    _require(SAFE_ID_RE.fullmatch(guest) is not None, "guest", "is not a safe ID")
    _require(SAFE_ID_RE.fullmatch(case) is not None, "case", "is not a safe ID")
    start_path, deadline_path, finish_path = _case_paths(state_dir)
    _require(
        not start_path.exists()
        and not deadline_path.exists()
        and not finish_path.exists(),
        "case timing",
        "records already exist",
    )
    started_ns = clock.now_ns()
    started_utc = clock.utc_now()
    boot_id = clock.boot_id()
    start = {
        "boot_id": boot_id,
        "case": case,
        "clock": "CLOCK_BOOTTIME",
        "guest": guest,
        "schema": CASE_START_SCHEMA,
        "started_boottime_ns": started_ns,
        "started_utc": _utc_text(started_utc),
    }
    start_bytes = canonical_json_bytes(start)
    deadline = {
        "boot_id": boot_id,
        "case": case,
        "deadline_boottime_ns": started_ns + CASE_DEADLINE_SECONDS * 1_000_000_000,
        "deadline_seconds": CASE_DEADLINE_SECONDS,
        "deadline_utc": _utc_text(
            started_utc + dt.timedelta(seconds=CASE_DEADLINE_SECONDS)
        ),
        "guest": guest,
        "schema": CASE_DEADLINE_SCHEMA,
        "start": _sha256_reference(start_bytes),
    }
    _write_new_file(start_path, start_bytes)
    _write_new_json(deadline_path, deadline)
    return start, deadline


def _load_case_timing(
    state_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    _require_existing_directory(state_dir, "state-dir")
    start_path, deadline_path, _ = _case_paths(state_dir)
    start_bytes = _read_regular_file(start_path, 1024 * 1024)
    deadline_bytes = _read_regular_file(deadline_path, 1024 * 1024)
    start = _load_canonical_json(start_path)
    deadline = _load_canonical_json(deadline_path)
    _strict_keys(
        start,
        {
            "boot_id",
            "case",
            "clock",
            "guest",
            "schema",
            "started_boottime_ns",
            "started_utc",
        },
        "case-start",
    )
    _strict_keys(
        deadline,
        {
            "boot_id",
            "case",
            "deadline_boottime_ns",
            "deadline_seconds",
            "deadline_utc",
            "guest",
            "schema",
            "start",
        },
        "case-deadline",
    )
    _require(start["schema"] == CASE_START_SCHEMA, "case-start.schema", "is wrong")
    _require(
        deadline["schema"] == CASE_DEADLINE_SCHEMA, "case-deadline.schema", "is wrong"
    )
    _require(start["clock"] == "CLOCK_BOOTTIME", "case-start.clock", "is wrong")
    _require(
        type(start["started_boottime_ns"]) is int and start["started_boottime_ns"] >= 0,
        "case-start.started_boottime_ns",
        "is invalid",
    )
    _require(
        deadline["deadline_seconds"] == CASE_DEADLINE_SECONDS,
        "case-deadline.deadline_seconds",
        "differs from frozen 1800 seconds",
    )
    _require(
        deadline["deadline_boottime_ns"]
        == start["started_boottime_ns"] + CASE_DEADLINE_SECONDS * 1_000_000_000,
        "case-deadline.deadline_boottime_ns",
        "does not derive exactly from start",
    )
    _require(
        deadline["boot_id"] == start["boot_id"]
        and deadline["guest"] == start["guest"]
        and deadline["case"] == start["case"],
        "case-deadline",
        "identity differs from start",
    )
    _require(
        deadline["start"] == _sha256_reference(start_bytes),
        "case-deadline.start",
        "does not bind exact start bytes",
    )
    return start, deadline, start_bytes, deadline_bytes


def check_case(
    state_dir: Path, clock: Any | None = None
) -> tuple[dict[str, Any], bool]:
    """Return an exact deadline check without modifying case evidence."""

    clock = SystemClock() if clock is None else clock
    start, deadline, start_bytes, deadline_bytes = _load_case_timing(state_dir)
    _require(
        clock.boot_id() == start["boot_id"],
        "case timing",
        "controller boot changed; persisted monotonic deadline cannot be reused",
    )
    now_ns = clock.now_ns()
    _require(
        now_ns >= start["started_boottime_ns"],
        "case timing",
        "CLOCK_BOOTTIME moved backwards",
    )
    remaining_ns = deadline["deadline_boottime_ns"] - now_ns
    within = remaining_ns >= 0
    return (
        {
            "case": start["case"],
            "checked_boottime_ns": now_ns,
            "checked_utc": _utc_text(clock.utc_now()),
            "deadline": _sha256_reference(deadline_bytes),
            "guest": start["guest"],
            "remaining_ns": max(0, remaining_ns),
            "schema": CASE_CHECK_SCHEMA,
            "start": _sha256_reference(start_bytes),
            "status": "within_deadline" if within else "deadline_exceeded",
        },
        within,
    )


def finish_case(
    state_dir: Path,
    requested_result: str,
    summary: str,
    clock: Any | None = None,
) -> tuple[dict[str, Any], bool]:
    """Publish one immutable finish; a late requested pass becomes deadline_exceeded."""

    clock = SystemClock() if clock is None else clock
    _require(requested_result in CASE_RESULTS, "result", "is not a case result")
    _require(
        1 <= len(summary) <= 2048 and "\x00" not in summary,
        "summary",
        "must be 1..2048 characters without NUL",
    )
    start, deadline, start_bytes, deadline_bytes = _load_case_timing(state_dir)
    _, _, finish_path = _case_paths(state_dir)
    _require(not finish_path.exists(), "case-finish", "already exists")
    _require(
        clock.boot_id() == start["boot_id"],
        "case timing",
        "controller boot changed; persisted monotonic deadline cannot be reused",
    )
    finished_ns = clock.now_ns()
    _require(
        finished_ns >= start["started_boottime_ns"],
        "case timing",
        "CLOCK_BOOTTIME moved backwards",
    )
    within = finished_ns <= deadline["deadline_boottime_ns"]
    finish = {
        "case": start["case"],
        "deadline": _sha256_reference(deadline_bytes),
        "duration_ns": finished_ns - start["started_boottime_ns"],
        "effective_result": requested_result if within else "deadline_exceeded",
        "finished_boottime_ns": finished_ns,
        "finished_utc": _utc_text(clock.utc_now()),
        "guest": start["guest"],
        "requested_result": requested_result,
        "schema": CASE_FINISH_SCHEMA,
        "start": _sha256_reference(start_bytes),
        "summary": summary,
        "within_deadline": within,
    }
    _write_new_json(finish_path, finish)
    return finish, within


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value))
    sys.stdout.buffer.flush()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    nocloud = subparsers.add_parser("render-nocloud")
    nocloud.add_argument("--output-dir", type=Path, required=True)
    nocloud.add_argument("--instance-id", required=True)
    nocloud.add_argument("--hostname", required=True)
    nocloud.add_argument("--username", required=True)
    nocloud.add_argument("--authorized-key-file", type=Path, required=True)

    readiness = subparsers.add_parser("wait-ssh")
    readiness.add_argument("--output", type=Path, required=True)
    readiness.add_argument("--host", required=True)
    readiness.add_argument("--port", type=int, required=True)
    readiness.add_argument("--username", required=True)
    readiness.add_argument("--identity-file", type=Path, required=True)
    readiness.add_argument("--known-hosts-file", type=Path, required=True)
    readiness.add_argument("--ssh-executable", type=Path, required=True)
    readiness.add_argument("--timeout-seconds", type=int, required=True)
    readiness.add_argument("--poll-interval-ms", type=int, default=250)
    readiness.add_argument("--connect-timeout-ms", type=int, default=1000)
    readiness.add_argument("--ssh-attempt-timeout-seconds", type=int, default=10)
    readiness.add_argument("remote_argv", nargs=argparse.REMAINDER)

    qmp = subparsers.add_parser("qmp")
    qmp.add_argument("--output", type=Path, required=True)
    qmp.add_argument("--socket", type=Path, required=True)
    qmp.add_argument(
        "--operation",
        choices=("query-status", "system-powerdown", "quit"),
        required=True,
    )
    qmp.add_argument("--timeout-seconds", type=int, default=10)

    start = subparsers.add_parser("case-start")
    start.add_argument("--state-dir", type=Path, required=True)
    start.add_argument("--guest", required=True)
    start.add_argument("--case", required=True)

    check = subparsers.add_parser("case-check")
    check.add_argument("--state-dir", type=Path, required=True)

    finish = subparsers.add_parser("case-finish")
    finish.add_argument("--state-dir", type=Path, required=True)
    finish.add_argument("--result", choices=tuple(sorted(CASE_RESULTS)), required=True)
    finish.add_argument("--summary", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.subcommand == "render-nocloud":
            _emit(
                render_nocloud(
                    arguments.output_dir,
                    instance_id=arguments.instance_id,
                    hostname=arguments.hostname,
                    username=arguments.username,
                    authorized_key_file=arguments.authorized_key_file,
                )
            )
            return 0
        if arguments.subcommand == "wait-ssh":
            output_descriptor = _reserve_json_output(arguments.output)
            remote_argv = arguments.remote_argv
            if remote_argv and remote_argv[0] == "--":
                remote_argv = remote_argv[1:]
            if not remote_argv:
                remote_argv = ["/usr/bin/true"]
            try:
                record, success = wait_for_ssh(
                    host=arguments.host,
                    port=arguments.port,
                    username=arguments.username,
                    identity_file=arguments.identity_file,
                    known_hosts_file=arguments.known_hosts_file,
                    ssh_executable=arguments.ssh_executable,
                    remote_argv=remote_argv,
                    timeout_seconds=arguments.timeout_seconds,
                    poll_interval_ms=arguments.poll_interval_ms,
                    connect_timeout_ms=arguments.connect_timeout_ms,
                    ssh_attempt_timeout_seconds=arguments.ssh_attempt_timeout_seconds,
                )
            except Exception as error:
                failure = {
                    "error": f"{error.__class__.__name__}: {error}",
                    "operation": "wait-ssh",
                    "schema": OPERATION_FAILURE_SCHEMA,
                }
                _publish_reserved_json(output_descriptor, arguments.output, failure)
                raise FixtureError(
                    f"wait-ssh failed after output reservation: {error}"
                ) from error
            _publish_reserved_json(output_descriptor, arguments.output, record)
            _emit(record)
            return 0 if success else 3
        if arguments.subcommand == "qmp":
            output_descriptor = _reserve_json_output(arguments.output)
            try:
                record, success = qmp_operation(
                    arguments.socket, arguments.operation, arguments.timeout_seconds
                )
            except Exception as error:
                failure = {
                    "error": f"{error.__class__.__name__}: {error}",
                    "operation": f"qmp:{arguments.operation}",
                    "schema": OPERATION_FAILURE_SCHEMA,
                }
                _publish_reserved_json(output_descriptor, arguments.output, failure)
                raise FixtureError(
                    f"QMP failed after output reservation: {error}"
                ) from error
            _publish_reserved_json(output_descriptor, arguments.output, record)
            _emit(record)
            return 0 if success else 3
        if arguments.subcommand == "case-start":
            start, deadline = start_case(
                arguments.state_dir, arguments.guest, arguments.case
            )
            _emit({"deadline": deadline, "start": start})
            return 0
        if arguments.subcommand == "case-check":
            record, within = check_case(arguments.state_dir)
            _emit(record)
            return 0 if within else 3
        if arguments.subcommand == "case-finish":
            record, within = finish_case(
                arguments.state_dir, arguments.result, arguments.summary
            )
            _emit(record)
            return 0 if within else 3
        _error("subcommand", "unreachable")
    except FixtureError as error:
        print(f"vm_fixture: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
