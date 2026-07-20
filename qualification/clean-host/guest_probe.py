#!/usr/bin/python3
"""Collect fail-closed clean-host guest facts without launching subprocesses."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, NoReturn


SCHEMA = "ag.clean-host-guest-facts/v1"
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_CREATE_RULESET_SYSCALL = 444
MAX_SMALL_FILE_BYTES = 1024 * 1024
MAX_DPKG_STATUS_BYTES = 32 * 1024 * 1024

GUEST_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
OS_RELEASE_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
OS_ID_RE = re.compile(r"[a-z0-9][a-z0-9.+-]*\Z")
LSM_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
DPKG_FIELD_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]*):(?: ?)(.*)\Z")
DPKG_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+:~_-]*\Z")
ARCHITECTURES = {"aarch64": "arm64", "x86_64": "amd64"}
MOUNTINFO_ESCAPES = {
    "011": "\t",
    "012": "\n",
    "040": " ",
    "134": "\\",
}


class ProbeError(ValueError):
    """Required guest evidence is missing, malformed, or unavailable."""


def _error(location: str, message: str) -> NoReturn:
    raise ProbeError(f"{location}: {message}")


def _require(condition: bool, location: str, message: str) -> None:
    if not condition:
        _error(location, message)


def canonical_json_bytes(value: Any) -> bytes:
    """Render sorted compact UTF-8 JSON followed by exactly one line feed."""

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
        raise ProbeError(f"record: cannot encode canonical JSON: {error}") from error


def rooted_path(root: Path, absolute_path: str) -> Path:
    """Resolve a fixed absolute guest path below an injected fixture root."""

    path = Path(absolute_path)
    _require(path.is_absolute(), "path", f"{absolute_path!r} is not absolute")
    _require(".." not in path.parts, "path", f"{absolute_path!r} contains '..'")
    return root.joinpath(*path.parts[1:])


def _read_text(path: Path, maximum: int) -> str:
    try:
        with path.open("rb") as source:
            payload = source.read(maximum + 1)
    except OSError as error:
        raise ProbeError(f"{path}: cannot read required evidence: {error}") from error
    _require(len(payload) <= maximum, str(path), f"exceeds {maximum} bytes")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError(f"{path}: evidence is not UTF-8: {error}") from error


def _decode_os_release_value(value: str, location: str) -> str:
    if not value:
        return ""
    if value[0] == "'":
        _require(
            len(value) >= 2 and value[-1] == "'",
            location,
            "unterminated single-quoted value",
        )
        decoded = value[1:-1]
        _require("'" not in decoded, location, "unexpected single quote")
        return decoded
    if value[0] == '"':
        _require(
            len(value) >= 2 and value[-1] == '"',
            location,
            "unterminated double-quoted value",
        )
        encoded = value[1:-1]
        decoded: list[str] = []
        index = 0
        while index < len(encoded):
            character = encoded[index]
            if character != "\\":
                _require(character != '"', location, "unescaped double quote")
                decoded.append(character)
                index += 1
                continue
            _require(index + 1 < len(encoded), location, "trailing backslash")
            escaped = encoded[index + 1]
            _require(
                escaped in ('"', "\\", "$", "`"),
                location,
                f"unsupported escape \\{escaped}",
            )
            decoded.append(escaped)
            index += 2
        return "".join(decoded)
    _require(
        not any(character.isspace() or character in "'\"\\$`" for character in value),
        location,
        "malformed unquoted value",
    )
    return value


def parse_os_release(payload: str, location: str = "/etc/os-release") -> dict[str, str]:
    """Parse the non-executable subset of the os-release assignment format."""

    fields: dict[str, str] = {}
    for line_number, line in enumerate(payload.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        _require("=" in line, f"{location}:{line_number}", "missing '='")
        key, encoded = line.split("=", 1)
        _require(
            OS_RELEASE_KEY_RE.fullmatch(key) is not None,
            f"{location}:{line_number}",
            "invalid key",
        )
        _require(key not in fields, f"{location}:{line_number}", f"duplicate {key}")
        fields[key] = _decode_os_release_value(
            encoded, f"{location}:{line_number}:{key}"
        )
    for key in ("ID", "VERSION_ID"):
        _require(
            key in fields and bool(fields[key]), location, f"missing nonempty {key}"
        )
    _require(
        OS_ID_RE.fullmatch(fields["ID"]) is not None,
        f"{location}:ID",
        "invalid distribution identifier",
    )
    _require(
        not any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in fields["VERSION_ID"]
        ),
        f"{location}:VERSION_ID",
        "contains a control character",
    )
    return fields


def parse_dpkg_status(payload: str, location: str = "/var/lib/dpkg/status") -> str:
    """Return the exact installed Version field for the systemd package."""

    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    previous: str | None = None
    for line_number, line in enumerate(payload.splitlines() + [""], 1):
        if not line:
            if current:
                paragraphs.append(current)
                current = {}
                previous = None
            continue
        if line[0].isspace():
            _require(
                previous is not None, f"{location}:{line_number}", "orphan continuation"
            )
            current[previous] += "\n" + line[1:]
            continue
        match = DPKG_FIELD_RE.fullmatch(line)
        _require(match is not None, f"{location}:{line_number}", "malformed field")
        name, value = match.groups()
        key = name.lower()
        _require(key not in current, f"{location}:{line_number}", f"duplicate {name}")
        current[key] = value
        previous = key

    installed = [
        paragraph
        for paragraph in paragraphs
        if paragraph.get("package") == "systemd"
        and paragraph.get("status") == "install ok installed"
    ]
    _require(installed, location, "installed systemd package paragraph is absent")
    _require(len(installed) == 1, location, "multiple installed systemd paragraphs")
    version = installed[0].get("version", "")
    _require(bool(version), location, "installed systemd Version is absent")
    _require(
        DPKG_VERSION_RE.fullmatch(version) is not None,
        location,
        "installed systemd Version is malformed",
    )
    return version


def parse_active_lsms(payload: str, location: str = "/sys/kernel/security/lsm") -> str:
    value = payload.strip()
    _require(bool(value), location, "active LSM list is empty")
    _require("\n" not in value and "\r" not in value, location, "must be one line")
    names = value.split(",")
    _require(all(names), location, "contains an empty LSM name")
    _require(len(names) == len(set(names)), location, "contains a duplicate LSM")
    for name in names:
        _require(LSM_RE.fullmatch(name) is not None, location, f"invalid LSM {name!r}")
    return ",".join(names)


def parse_cgroup(payload: str, location: str = "/proc/self/cgroup") -> str:
    """Describe an exact unified-v2 path, or a syntactically valid other layout."""

    lines = payload.splitlines()
    _require(bool(lines), location, "contains no cgroup membership")
    entries: list[tuple[int, str, str]] = []
    hierarchy_ids: set[int] = set()
    for line_number, line in enumerate(lines, 1):
        parts = line.split(":", 2)
        _require(len(parts) == 3, f"{location}:{line_number}", "malformed membership")
        raw_hierarchy, controllers, path = parts
        _require(
            raw_hierarchy.isdigit(), f"{location}:{line_number}", "invalid hierarchy ID"
        )
        hierarchy = int(raw_hierarchy)
        _require(
            hierarchy not in hierarchy_ids,
            f"{location}:{line_number}",
            "duplicate hierarchy ID",
        )
        hierarchy_ids.add(hierarchy)
        _require(
            path.startswith("/"), f"{location}:{line_number}", "path is not absolute"
        )
        _require("\x00" not in path, f"{location}:{line_number}", "path contains NUL")
        if controllers:
            names = controllers.split(",")
            _require(all(names), f"{location}:{line_number}", "empty controller")
            _require(
                len(names) == len(set(names)),
                f"{location}:{line_number}",
                "duplicate controller",
            )
            for name in names:
                _require(
                    LSM_RE.fullmatch(name) is not None,
                    f"{location}:{line_number}",
                    "invalid controller",
                )
        entries.append((hierarchy, controllers, path))
    if entries == [(0, "", entries[0][2])]:
        return f"unified-v2:{entries[0][2]}"
    rendered = [
        f"{hierarchy}:{controllers}:{path}" for hierarchy, controllers, path in entries
    ]
    return "legacy-or-hybrid:" + ";".join(rendered)


def _unescape_mountinfo(value: str, location: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        _require(index + 3 < len(value), location, "truncated escape")
        token = value[index + 1 : index + 4]
        _require(token in MOUNTINFO_ESCAPES, location, f"unsupported escape \\{token}")
        decoded.append(MOUNTINFO_ESCAPES[token])
        index += 4
    return "".join(decoded)


def parse_root_filesystem(payload: str, location: str = "/proc/self/mountinfo") -> str:
    roots: list[tuple[str, str, str, str]] = []
    for line_number, line in enumerate(payload.splitlines(), 1):
        before, separator, after = line.partition(" - ")
        _require(bool(separator), f"{location}:{line_number}", "missing separator")
        left = before.split(" ")
        right = after.split(" ")
        _require(len(left) >= 6, f"{location}:{line_number}", "incomplete mount fields")
        _require(
            len(right) == 3, f"{location}:{line_number}", "incomplete filesystem fields"
        )
        mountpoint = _unescape_mountinfo(
            left[4], f"{location}:{line_number}:mountpoint"
        )
        if mountpoint != "/":
            continue
        mount_options = left[5]
        filesystem, source, super_options = right
        for field_name, value in (
            ("mount options", mount_options),
            ("filesystem", filesystem),
            ("super options", super_options),
        ):
            _require(bool(value), f"{location}:{line_number}", f"empty {field_name}")
        source = _unescape_mountinfo(source, f"{location}:{line_number}:source")
        roots.append((filesystem, mount_options, source, super_options))
    _require(roots, location, "root mount is absent")
    _require(len(roots) == 1, location, "root mount is ambiguous")
    filesystem, mount_options, source, super_options = roots[0]
    return (
        f"{filesystem} mount_options={mount_options} "
        f"source={source} super_options={super_options}"
    )


def query_landlock_abi() -> int:
    """Query the running kernel with landlock_create_ruleset(..., VERSION)."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
    except (AttributeError, OSError) as error:
        raise ProbeError(
            f"landlock ABI: cannot resolve libc syscall: {error}"
        ) from error
    syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = syscall(
        ctypes.c_long(LANDLOCK_CREATE_RULESET_SYSCALL),
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result >= 0:
        return int(result)
    error_number = ctypes.get_errno()
    if error_number in (errno.ENOSYS, errno.EOPNOTSUPP):
        return 0
    raise ProbeError(
        "landlock ABI: landlock_create_ruleset version query failed: "
        f"errno {error_number} ({os.strerror(error_number)})"
    )


def collect_guest_facts(
    guest_id: str,
    *,
    root: Path = Path("/"),
    uname_provider: Callable[[], Any] = os.uname,
    landlock_query: Callable[[], int] = query_landlock_abi,
) -> dict[str, Any]:
    """Collect the exact typed record, with injectable paths and kernel probes."""

    _require(
        GUEST_ID_RE.fullmatch(guest_id) is not None, "guest_id", "invalid identifier"
    )
    release = parse_os_release(
        _read_text(rooted_path(root, "/etc/os-release"), MAX_SMALL_FILE_BYTES)
    )
    machine = uname_provider()
    architecture = ARCHITECTURES.get(machine.machine)
    _require(
        architecture is not None,
        "architecture",
        f"unsupported machine {machine.machine!r}",
    )
    _require(bool(machine.release), "kernel", "uname release is empty")
    landlock_abi = landlock_query()
    _require(
        type(landlock_abi) is int and landlock_abi >= 0,
        "landlock ABI",
        "query returned an invalid value",
    )
    observed = {
        "active_lsms": parse_active_lsms(
            _read_text(
                rooted_path(root, "/sys/kernel/security/lsm"), MAX_SMALL_FILE_BYTES
            )
        ),
        "architecture": architecture,
        "cgroup": parse_cgroup(
            _read_text(rooted_path(root, "/proc/self/cgroup"), MAX_SMALL_FILE_BYTES)
        ),
        "distribution": release["ID"],
        "filesystem": parse_root_filesystem(
            _read_text(rooted_path(root, "/proc/self/mountinfo"), MAX_SMALL_FILE_BYTES)
        ),
        "kernel": machine.release,
        "landlock_abi": str(landlock_abi),
        "release": release["VERSION_ID"],
        "systemd": parse_dpkg_status(
            _read_text(rooted_path(root, "/var/lib/dpkg/status"), MAX_DPKG_STATUS_BYTES)
        ),
    }
    return {"guest_id": guest_id, "observed": observed, "schema": SCHEMA}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="emit canonical clean-host guest facts to standard output"
    )
    parser.add_argument("guest_id", help="frozen clean-host matrix guest identifier")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        record = collect_guest_facts(arguments.guest_id)
        sys.stdout.buffer.write(canonical_json_bytes(record))
        sys.stdout.buffer.flush()
        return 0
    except (ProbeError, OSError) as error:
        print(f"guest_probe: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
