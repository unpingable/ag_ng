#!/usr/bin/python3
"""Record and reopen clean-host qualification evidence.

This controller is deliberately small, rootless, and standard-library only.
It does not provision a particular hypervisor.  Instead it gives any VM driver
one fail-closed way to initialise the frozen matrix, execute exact controller
commands under bounded deadlines, seal the resulting evidence, and validate a
final non-authorizing receipt.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn, Sequence


COMMAND_SCHEMA = "ag.clean-host-command-record/v1"
CASE_CLOCK_SCHEMA = "ag.clean-host-case-wall-clock/v1"
CONTROLLER_SCHEMA = "ag.clean-host-controller-plan/v1"
MANIFEST_SCHEMA = "ag.clean-host-evidence-manifest/v1"
PHASE1_SCHEMA = "ag.clean-host-phase1-candidate/v1"
HOST_CONTRACT_SCHEMA = "ag.clean-host-phase1-host-contract/v1"
CANDIDATE_IDENTITY_SCHEMA = "ag.clean-host-candidate-identity/v1"
RECEIPT_SCHEMA = "ag.clean-host-package-qualification-receipt/v1"
VERIFICATION_SCHEMA = "ag.clean-host-evidence-verification-result/v1"
MATRIX_SCHEMA = "ag.clean-host-package-qualification-matrix/v1"
GUEST_FACTS_SCHEMA = "ag.clean-host-guest-facts/v1"
GUEST_FACTS_BINDING_SCHEMA = "ag.clean-host-guest-facts-binding/v1"
IMAGE_PROVENANCE_SCHEMA = "ag.clean-host-image-provenance/v1"
SNAPSHOT_BOUNDARY_SCHEMA = "ag.clean-host-snapshot-boundary/v1"
CANDIDATE_ARCHIVE_SCHEMA = "ag.clean-host-candidate-archive/v1"

AUTHORITY_USE = "evidence_only"
EXCLUDED_ROOT_PATHS = (
    "manifest.v1.json",
    "receipt.v1.json",
    "verification-result.v1.json",
)
FINAL_VERDICTS = frozenset(("QUALIFIED", "REQUALIFIED", "BLOCKED", "UNSUPPORTED"))
CASE_RESULTS = frozenset(("pass", "fail", "blocked", "not_run", "unsupported"))
PER_COMMAND_DEADLINE_SECONDS = 120
PER_CASE_DEADLINE_SECONDS = 1800
MANDATORY_ENROLLMENT_RELOAD = (
    "systemctl daemon-reload before effective-unit comparison and first start"
)
ACTIVATION_COMMAND_IDS = (
    "measure_genesis",
    "enroll_genesis",
    "verify_genesis",
    "daemon_reload",
    "verify_effective_unit",
    "show_effective_unit",
    "start_effectd",
    "authenticated_effectd_readiness",
)
GOVERNED_SOURCE_CWD = "/home/agqual/agent-governor-ng-0.1.0"
GUEST_CANDIDATE_ARCHIVE_PATH = "/home/agqual/agent-governor-ng-0.1.0.tar"
GUEST_SOURCE_MEASUREMENT_GIT_DIR = "/home/agqual/ag-ng-source-measure.git"
SSH_BUILD_TARGET = "agqual@127.0.0.1"
SSH_BUILD_REMOTE_TAILS = (
    (
        "/usr/bin/env",
        f"--chdir={GOVERNED_SOURCE_CWD}",
        "LC_ALL=C",
        "/usr/bin/dpkg-checkbuilddeps",
    ),
    (
        "/usr/bin/env",
        f"--chdir={GOVERNED_SOURCE_CWD}",
        "LC_ALL=C",
        "/usr/bin/dpkg-buildpackage",
        "--build=binary",
        "--no-sign",
    ),
)
SSH_ARCHIVE_MEASUREMENT_TAIL = (
    "/usr/bin/sha256sum",
    GUEST_CANDIDATE_ARCHIVE_PATH,
)
SSH_ARCHIVE_EXTRACTION_TAIL = (
    "/usr/bin/tar",
    "--extract",
    f"--file={GUEST_CANDIDATE_ARCHIVE_PATH}",
    "--directory=/home/agqual",
)
SSH_SOURCE_TREE_TAILS = (
    (
        "/usr/bin/git",
        "init",
        "--bare",
        GUEST_SOURCE_MEASUREMENT_GIT_DIR,
    ),
    (
        "/usr/bin/git",
        f"--git-dir={GUEST_SOURCE_MEASUREMENT_GIT_DIR}",
        f"--work-tree={GOVERNED_SOURCE_CWD}",
        "add",
        "--all",
        "--force",
    ),
    (
        "/usr/bin/git",
        f"--git-dir={GUEST_SOURCE_MEASUREMENT_GIT_DIR}",
        "write-tree",
    ),
)
SSH_GUEST_FACTS_TAIL = (
    "/usr/bin/sudo",
    "/usr/bin/python3",
    f"{GOVERNED_SOURCE_CWD}/qualification/clean-host/guest_probe.py",
    "debian-12-amd64",
)
SSH_APT_UPDATE_TAIL = (
    "/usr/bin/sudo",
    "/usr/bin/apt-get",
    "update",
)
SSH_BUILD_DEPENDENCY_INSTALL_TAIL = (
    "/usr/bin/sudo",
    "/usr/bin/apt-get",
    "--yes",
    "--no-install-recommends",
    "install",
    "build-essential",
    "debhelper",
    "bubblewrap",
    "cargo",
    "git",
    "python3",
    "rustc",
)
EXPECTED_BUILD_DEPENDENCY_REFUSAL = (
    "dpkg-checkbuilddeps: error: Unmet build dependencies: "
    "cargo (>= 1.94.0) rustc (>= 1.94.0)"
)
PHASE1_CONTRACT_INPUT_PATHS = (
    "qualification/clean-host/claim.v1.json",
    "qualification/clean-host/matrix.toml",
    "debian/control",
    "debian/rules",
    "packaging/systemd/ag-effectd.service",
    "packaging/systemd/sysusers.d/agent-governor-ng.conf",
    "packaging/systemd/tmpfiles.d/agent-governor-ng.conf",
    "docs/clean-host-activation-qualification.md",
    "docs/deployment.md",
)
DEPENDENCY_CLASSES = frozenset(
    (
        "declared_package_dependency",
        "explicitly_documented_operator_prerequisite",
        "optional_capability_with_typed_refusal",
        "undeclared_ambient_dependency",
    )
)
KNOWN_BLOCKERS = (
    "clean_offline_source_build_absent",
    "production_artifact_admission_ingress_absent",
    "expanded_system_call_filter_live_attestation_absent",
    "offline_store_upgrade_activation_absent",
)
COPIED_PYTHON_TOOL_NAMES = frozenset(("blocked_receipt.py", "vm_fixture.py"))
FIRST_GATE_COMMAND_IDS = (
    "fixture-render-nocloud",
    "nocloud-iso-create",
    "vm-overlay-create",
    "vm-launch",
    "fixture-ssh-readiness",
    "guest-apt-update",
    "guest-build-dependency-install",
    "candidate-archive-transfer",
    "guest-archive-sha256",
    "extract-candidate-archive",
    "source-tree-init",
    "source-tree-add",
    "source-tree-write",
    "guest-facts",
    "terminal-build-refusal",
    "terminal-dpkg-build-refusal",
    "vm-shutdown",
    "vm-exit-wait",
    "snapshot-convert",
    "snapshot-check",
    "snapshot-info",
)
CLAIM_LAYERS = (
    ("package_lifecycle", True),
    ("live_effectd_activation", True),
    ("shipped_stranger_workflow", True),
)
CLAIM_EXCLUSIONS = (
    "power_loss_and_torn_write",
    "disk_full_and_wal_fsync_fault_matrix",
    "unnamed_filesystem_and_cache_matrix",
    "simultaneous_clients_and_readers",
    "same_inode_aba_prevention",
    "external_anti_rollback",
    "tpm_key_ceremony",
    "production_worker_and_provider_readiness",
    "package_repository_and_signing",
    "changed_binary_or_config_upgrade_success",
    "confirmed_decommission_and_purge",
)
CLAIM_LAYER_RESULTS = frozenset(("pass", "blocked", "not_run", "unsupported"))
DEFECT_CLASSES = frozenset(
    (
        "package_contents",
        "package_metadata_or_maintainer_scripts",
        "systemd_configuration",
        "operator_tooling",
        "runtime_implementation",
        "test_harness",
        "documented_host_prerequisites",
        "unsupported_environment",
    )
)
MANDATORY_EVIDENCE_CATEGORIES = (
    "activation_and_receipt_identities",
    "command_ledger",
    "hostile_case_results",
    "hypervisor_and_host",
    "image_provenance",
    "installed_file_inventory",
    "reboot_and_recovery",
    "service_process_security_attestation",
    "snapshot_boundaries",
    "test_results",
    "user_group_permission_inventory",
)
AMBIENT_DEPENDENCIES = (
    "dev_null_exact_custody",
    "pinned_git_security_capability_xattr_enodata",
    "sealed_memfd_proc_self_fd_execution",
    "readable_proc_self_identity_and_mount_files",
)
PHASE1_REQUIRED_DEPENDENCIES = (
    ("source_build_packages", "declared_package_dependency"),
    (
        "offline_cargo_source_closure",
        "explicitly_documented_operator_prerequisite",
    ),
    (
        "qualification_controller_toolchain",
        "explicitly_documented_operator_prerequisite",
    ),
    (
        "clean_guest_bootstrap_tooling",
        "explicitly_documented_operator_prerequisite",
    ),
)
PHASE1_NARRATIVE_RECEIPTS = (
    (
        "1dfc3d11701c34ba0b5ea212a34527655905eda7:docs/release-checklist.md",
        14_725,
        "sha256:feb4fc569c3e0332ebe5158a1e233b30427065d077585b95208dd17f0d37d9e1",
        "closed_promotion_loop_baseline_10b7aa9_has_no_material_receipt",
    ),
    (
        "653933570bdd757a19d1f52243e27d241388e19b:docs/managed-pointer-activation-readiness.md",
        10_596,
        "sha256:67f5243f749384def41e306e0f212d5087e7b5294678115f76f43b7e261c35dd",
        "implementation_24efeef_local_hostile_tests_only_no_host_qualification_receipt",
    ),
)
PHASE1_REJECTED_ARTIFACTS = (
    (
        "/tmp/agent-governor-ng_0.1.0-1_amd64.deb",
        8_643_588,
        "sha256:93dabd36ae3a5735e3dc235cffa69080535fbdac8148abf437f3c276e0fdc21a",
    ),
    (
        "/tmp/agent-governor-ng-dbgsym_0.1.0-1_amd64.ddeb",
        913_196,
        "sha256:bde610194226d329b3b0699c1d23a4546320f61bfb643aede3162994e456b355",
    ),
    (
        "/tmp/agent-governor-ng_0.1.0-1_amd64.buildinfo",
        7_350,
        "sha256:1c7824e0a32e3ff9396fc85f238622cb39ea9bbc1cb5e170b492ff71cc77dd95",
    ),
    (
        "/tmp/agent-governor-ng_0.1.0-1_amd64.changes",
        1_480,
        "sha256:abfd878c1d9b46387fd37699df28ba87d6b899624103f602b4a2dd522cebae30",
    ),
)
CASE_FAMILIES = (
    "package_build_and_payload",
    "fresh_install_and_reboot",
    "genesis_measure_enroll_verify",
    "effectd_genesis_start_restart_reboot",
    "qualification_fixture_pointer_activation",
    "durable_head_restart_reconstruction",
    "hostile_systemd_and_process",
    "hostile_target_and_store",
    "remove_reinstall_reconstruct",
    "identical_bytes_packaging_upgrade",
    "changed_build_safe_refusal",
)
GUESTS = (
    ("debian-12-amd64", "debian", "12", "amd64"),
    ("debian-12-arm64", "debian", "12", "arm64"),
    ("ubuntu-24.04-amd64", "ubuntu", "24.04", "amd64"),
    ("ubuntu-24.04-arm64", "ubuntu", "24.04", "arm64"),
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_DIGEST_RE = re.compile(r"(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})\Z")
GIT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
EMPTY_SHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class QualificationError(ValueError):
    """Qualification evidence is unsafe, malformed, or inconsistent."""


def _error(location: str, message: str) -> NoReturn:
    raise QualificationError(f"{location}: {message}")


def _require(condition: bool, location: str, message: str) -> None:
    if not condition:
        _error(location, message)


def _strict_object(value: Any, location: str, keys: set[str]) -> dict[str, Any]:
    _require(type(value) is dict, location, "must be an object")
    actual = set(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    _require(not missing, location, f"missing fields: {', '.join(missing)}")
    _require(not extra, location, f"unknown fields: {', '.join(extra)}")
    return value


def _strict_list(value: Any, location: str) -> list[Any]:
    _require(type(value) is list, location, "must be an array")
    return value


def _strict_string(value: Any, location: str) -> str:
    _require(type(value) is str, location, "must be a string")
    return value


def _strict_bool(value: Any, location: str) -> bool:
    _require(type(value) is bool, location, "must be a boolean")
    return value


def _strict_int(value: Any, location: str) -> int:
    _require(type(value) is int, location, "must be an integer")
    return value


def _optional_string(value: Any, location: str) -> str | None:
    _require(value is None or type(value) is str, location, "must be null or a string")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(token: str) -> NoReturn:
    raise QualificationError(f"JSON contains non-finite number {token!r}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return canonical UTF-8 JSON followed by exactly one LF."""

    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise QualificationError(
            f"value is not canonical JSON data: {error}"
        ) from error


def load_canonical_json(path: Path) -> Any:
    """Load strict canonical JSON without accepting duplicate keys or NaN."""

    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError(f"{path}: is not UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, QualificationError) as error:
        raise QualificationError(f"{path}: invalid strict JSON: {error}") from error
    _require(
        raw == canonical_json_bytes(value),
        str(path),
        "must be canonical JSON followed by exactly one LF",
    )
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Publish a new regular file without overwriting an existing node."""

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def write_new_canonical_json(path: Path, value: Any) -> None:
    """Publish a new canonical JSON document without overwrite."""

    write_new_bytes(path, canonical_json_bytes(value))


def _validate_relative_path(value: Any, location: str) -> str:
    path = _strict_string(value, location)
    _require(path not in ("", "."), location, "must name a file below the root")
    _require("\\" not in path, location, "must use POSIX separators")
    _require("\x00" not in path, location, "must not contain NUL")
    pure = PurePosixPath(path)
    _require(not pure.is_absolute(), location, "must be relative")
    _require(
        all(component not in ("", ".", "..") for component in pure.parts),
        location,
        "must not contain empty, dot, or parent components",
    )
    _require(pure.as_posix() == path, location, "must already be normalized")
    return path


def _validate_sha256(value: Any, location: str) -> str:
    digest = _strict_string(value, location)
    _require(
        SHA256_RE.fullmatch(digest) is not None, location, "invalid SHA-256 digest"
    )
    return digest


def _validate_git_id(value: Any, location: str) -> str:
    identifier = _strict_string(value, location)
    _require(
        GIT_ID_RE.fullmatch(identifier) is not None, location, "invalid Git object id"
    )
    return identifier


def _validate_id(value: Any, location: str) -> str:
    identifier = _strict_string(value, location)
    _require(
        SAFE_ID_RE.fullmatch(identifier) is not None, location, "invalid bounded id"
    )
    return identifier


def _digest_open_file(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
        length += len(block)
    return f"sha256:{digest.hexdigest()}", length


def digest_regular_file(path: Path) -> tuple[str, int]:
    """Hash one stable, nonsymlink, regular file."""

    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode), str(path), "must be a regular file")
    with path.open("rb") as stream:
        descriptor = os.fstat(stream.fileno())
        _require(
            (descriptor.st_dev, descriptor.st_ino) == (before.st_dev, before.st_ino),
            str(path),
            "changed while opening",
        )
        digest, length = _digest_open_file(stream)
        after = os.fstat(stream.fileno())
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    _require(
        all(getattr(before, field) == getattr(after, field) for field in stable_fields),
        str(path),
        "changed while hashing",
    )
    _require(length == before.st_size, str(path), "length changed while hashing")
    return digest, length


def digest_regular_file_algorithm(path: Path, algorithm: str) -> tuple[str, int]:
    """Hash one stable regular file with SHA-256 or SHA-512."""

    _require(
        algorithm in ("sha256", "sha512"),
        "digest algorithm",
        "must be sha256 or sha512",
    )
    if algorithm == "sha256":
        return digest_regular_file(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode), str(path), "must be a regular file")
    digest_builder = hashlib.new(algorithm)
    length = 0
    with path.open("rb") as stream:
        descriptor = os.fstat(stream.fileno())
        _require(
            (descriptor.st_dev, descriptor.st_ino) == (before.st_dev, before.st_ino),
            str(path),
            "changed while opening",
        )
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest_builder.update(block)
            length += len(block)
        after = os.fstat(stream.fileno())
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    _require(
        all(getattr(before, field) == getattr(after, field) for field in stable_fields),
        str(path),
        "changed while hashing",
    )
    _require(length == before.st_size, str(path), "length changed while hashing")
    return f"{algorithm}:{digest_builder.hexdigest()}", length


def _executable_identity(descriptor: int, requested_path: str) -> dict[str, Any]:
    """Measure the descriptor that will actually be executed."""

    metadata = os.fstat(descriptor)
    _require(
        stat.S_ISREG(metadata.st_mode), requested_path, "must resolve to a regular file"
    )
    _require(metadata.st_mode & 0o111 != 0, requested_path, "must be executable")
    digest_builder = hashlib.sha256()
    length = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, length)
        if not block:
            break
        digest_builder.update(block)
        length += len(block)
    digest = f"sha256:{digest_builder.hexdigest()}"
    after = os.fstat(descriptor)
    _require(
        (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        requested_path,
        "executable changed while measuring",
    )
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "length": length,
        "mode": stat.S_IMODE(metadata.st_mode),
        "requested_path": requested_path,
        "resolved_path": str(Path(requested_path).resolve(strict=True)),
        "sha256": digest,
        "uid": metadata.st_uid,
    }


def _validate_executable_identity(value: Any, location: str) -> dict[str, Any]:
    identity = _strict_object(
        value,
        location,
        {
            "device",
            "gid",
            "inode",
            "length",
            "mode",
            "requested_path",
            "resolved_path",
            "sha256",
            "uid",
        },
    )
    for field in ("requested_path", "resolved_path"):
        path = _strict_string(identity[field], f"{location}.{field}")
        _require(Path(path).is_absolute(), f"{location}.{field}", "must be absolute")
    _validate_sha256(identity["sha256"], f"{location}.sha256")
    for field in ("device", "gid", "inode", "length", "mode", "uid"):
        _require(
            _strict_int(identity[field], f"{location}.{field}") >= 0,
            f"{location}.{field}",
            "must be nonnegative",
        )
    _require(identity["length"] > 0, f"{location}.length", "must be nonzero")
    _require(identity["mode"] & 0o111 != 0, f"{location}.mode", "must be executable")
    return identity


def _input_file_identity(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    _require(path.is_absolute(), path_text, "input path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode), path_text, "input must be a regular file"
        )
        _require(before.st_nlink == 1, path_text, "input must have one hard link")
        digest = hashlib.sha256()
        length = 0
        while True:
            block = os.pread(descriptor, 1024 * 1024, length)
            if not block:
                break
            digest.update(block)
            length += len(block)
        after = os.fstat(descriptor)
        _require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            path_text,
            "input changed while measuring",
        )
    finally:
        os.close(descriptor)
    return {
        "device": before.st_dev,
        "gid": before.st_gid,
        "inode": before.st_ino,
        "length": length,
        "mode": stat.S_IMODE(before.st_mode),
        "requested_path": path_text,
        "resolved_path": str(path.resolve(strict=True)),
        "sha256": f"sha256:{digest.hexdigest()}",
        "uid": before.st_uid,
    }


def _validate_input_file_identity(value: Any, location: str) -> dict[str, Any]:
    identity = _strict_object(
        value,
        location,
        {
            "device",
            "gid",
            "inode",
            "length",
            "mode",
            "requested_path",
            "resolved_path",
            "sha256",
            "uid",
        },
    )
    for field in ("requested_path", "resolved_path"):
        path = _strict_string(identity[field], f"{location}.{field}")
        _require(Path(path).is_absolute(), f"{location}.{field}", "must be absolute")
    _validate_sha256(identity["sha256"], f"{location}.sha256")
    for field in ("device", "gid", "inode", "length", "mode", "uid"):
        _require(
            _strict_int(identity[field], f"{location}.{field}") >= 0,
            f"{location}.{field}",
            "must be nonnegative",
        )
    return identity


def _validate_expected_outcome(value: Any, location: str) -> dict[str, Any]:
    expected = _strict_object(value, location, {"kind", "value"})
    kind = _strict_string(expected["kind"], f"{location}.kind")
    _require(
        kind in ("exit_code", "signal", "timeout", "launch_error"),
        f"{location}.kind",
        "unknown expected outcome",
    )
    if kind in ("exit_code", "signal"):
        value_number = _strict_int(expected["value"], f"{location}.value")
        _require(
            value_number >= 0 if kind == "exit_code" else value_number > 0,
            f"{location}.value",
            "invalid expected terminal value",
        )
    else:
        _require(expected["value"] is None, f"{location}.value", "must be null")
    return expected


def _outcome_matches(expected: dict[str, Any], outcome: dict[str, Any]) -> bool:
    kind = expected["kind"]
    if kind == "exit_code":
        return (
            outcome["exit_code"] == expected["value"]
            and outcome["signal"] is None
            and outcome["launch_error"] is None
            and not outcome["timed_out"]
        )
    if kind == "signal":
        return (
            outcome["signal"] == expected["value"]
            and outcome["exit_code"] is None
            and outcome["launch_error"] is None
            and not outcome["timed_out"]
        )
    if kind == "timeout":
        return outcome["timed_out"] and outcome["signal"] is not None
    return outcome["launch_error"] is not None


def _exact_ssh_prefix_end(argv: Sequence[str]) -> int | None:
    if not argv or argv[0] != "/usr/bin/ssh" or argv.count(SSH_BUILD_TARGET) != 1:
        return None
    target_index = argv.index(SSH_BUILD_TARGET)
    identity_flags = [index for index, item in enumerate(argv) if item == "-i"]
    port_flags = [index for index, item in enumerate(argv) if item == "-p"]
    known_hosts = [item for item in argv if item.startswith("UserKnownHostsFile=")]
    if (
        len(identity_flags) != 1
        or len(port_flags) != 1
        or len(known_hosts) != 1
        or identity_flags[0] + 1 >= len(argv)
        or port_flags[0] + 1 >= len(argv)
    ):
        return None
    identity_path = argv[identity_flags[0] + 1]
    port = argv[port_flags[0] + 1]
    known_hosts_path = known_hosts[0].split("=", 1)[1]
    if (
        not Path(identity_path).is_absolute()
        or not Path(known_hosts_path).is_absolute()
        or not port.isdigit()
    ):
        return None
    expected_prefix = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-i",
        identity_path,
        "-p",
        port,
        SSH_BUILD_TARGET,
    ]
    return target_index if list(argv[: target_index + 1]) == expected_prefix else None


def is_exact_ssh_build_command(argv: Sequence[str]) -> bool:
    """Return whether argv has one exact governed remote package-build tail."""

    target_index = _exact_ssh_prefix_end(argv)
    return (
        target_index is not None
        and tuple(argv[target_index + 1 :]) in SSH_BUILD_REMOTE_TAILS
    )


def is_exact_ssh_archive_measurement_command(argv: Sequence[str]) -> bool:
    """Return whether argv measures the fixed guest source archive exactly."""

    target_index = _exact_ssh_prefix_end(argv)
    return (
        target_index is not None
        and tuple(argv[target_index + 1 :]) == SSH_ARCHIVE_MEASUREMENT_TAIL
    )


def is_exact_ssh_tail(argv: Sequence[str], tail: Sequence[str]) -> bool:
    """Return whether argv uses the fixed SSH boundary and one exact tail."""

    target_index = _exact_ssh_prefix_end(argv)
    return target_index is not None and tuple(argv[target_index + 1 :]) == tuple(tail)


def is_copied_python_tool_argv(argv: Sequence[str]) -> bool:
    """Return whether argv lexically names one copied campaign Python tool."""

    return (
        len(argv) >= 2
        and argv[0] == "/usr/bin/python3"
        and Path(argv[1]).is_absolute()
        and Path(argv[1]).parent.name == "inputs"
        and Path(argv[1]).name in COPIED_PYTHON_TOOL_NAMES
    )


def _declared_input_paths(argv: Sequence[str]) -> list[str]:
    """Return the immutable file inputs whose bytes must be observed."""

    if argv[0] == "/usr/bin/ssh":
        _require(argv.count("-i") == 1, "argv", "SSH command requires one identity")
        identity_index = argv.index("-i") + 1
        _require(identity_index < len(argv), "argv", "SSH identity path is missing")
        known_hosts_options = [
            argument for argument in argv if argument.startswith("UserKnownHostsFile=")
        ]
        _require(
            len(known_hosts_options) == 1,
            "argv",
            "SSH command requires one run-local known-hosts file",
        )
        return [
            argv[identity_index],
            known_hosts_options[0].split("=", 1)[1],
        ]
    if argv[0] == "/usr/bin/scp":
        _require(argv.count("-i") == 1, "argv", "SCP command requires one identity")
        identity_index = argv.index("-i") + 1
        _require(identity_index < len(argv), "argv", "SCP identity path is missing")
        known_hosts_options = [
            argument for argument in argv if argument.startswith("UserKnownHostsFile=")
        ]
        _require(
            len(known_hosts_options) == 1,
            "argv",
            "SCP command requires one run-local known-hosts file",
        )
        _require(len(argv) >= 3, "argv", "SCP source path is missing")
        return [
            argv[identity_index],
            known_hosts_options[0].split("=", 1)[1],
            argv[-2],
        ]
    if is_copied_python_tool_argv(argv):
        paths = [argv[1]]
        if Path(argv[1]).name == "vm_fixture.py" and len(argv) >= 3:
            input_option = {
                "render-nocloud": "--authorized-key-file",
                "wait-ssh": "--identity-file",
            }.get(argv[2])
            if input_option is not None and argv.count(input_option) == 1:
                option_index = argv.index(input_option) + 1
                _require(
                    option_index < len(argv),
                    "argv",
                    f"{input_option} value is missing",
                )
                paths.append(argv[option_index])
        return paths
    if argv[0] == "/usr/bin/xorriso":
        _require(
            len(argv) == 11
            and argv[1:4] == ["-as", "mkisofs", "-output"]
            and argv[5:9] == ["-volid", "cidata", "-joliet", "-rock"],
            "argv",
            "NoCloud xorriso command has unexpected arguments",
        )
        return [argv[9], argv[10]]
    qemu_img_forms = (
        (("create", "-f", "qcow2", "-F", "qcow2", "-b"), 7, 9),
        (("convert", "-f", "qcow2", "-O", "qcow2"), 6, 8),
        (("check", "--output=json"), 3, 4),
        (("info", "--output=json", "--backing-chain"), 4, 5),
    )
    if argv[0] == "/usr/bin/qemu-img":
        for prefix, input_index, exact_length in qemu_img_forms:
            if tuple(argv[1 : 1 + len(prefix)]) == prefix:
                _require(
                    len(argv) == exact_length,
                    "argv",
                    "qemu-img evidence command has unexpected arguments",
                )
                return [argv[input_index]]
    if argv[0] == "/usr/bin/qemu-system-x86_64":
        readonly_drives = [
            argument
            for argument in argv
            if argument.startswith("if=virtio,format=raw,readonly=on,file=")
        ]
        if readonly_drives:
            _require(
                len(readonly_drives) == 1,
                "argv",
                "QEMU launch requires one immutable NoCloud drive",
            )
            return [readonly_drives[0].split("file=", 1)[1]]
    return []


def _require_real_directory_below(root: Path, directory: Path) -> None:
    """Reject symlinked or non-directory ancestry before executing a command."""

    root = root.resolve(strict=True)
    try:
        relative = directory.relative_to(root)
    except ValueError as error:
        raise QualificationError(
            f"{directory}: is outside evidence root {root}"
        ) from error
    current = root
    for component in relative.parts:
        current = current / component
        metadata = current.lstat()
        _require(
            stat.S_ISDIR(metadata.st_mode), str(current), "must be a real directory"
        )
    _require(
        directory.resolve(strict=True) == directory,
        str(directory),
        "must be an exact physical nonsymlink directory",
    )


def artifact_reference(root: Path, path: Path) -> dict[str, Any]:
    """Return a normalized path/digest/length reference within ``root``."""

    root = root.resolve(strict=True)
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError as error:
        raise QualificationError(f"{path}: is outside evidence root {root}") from error
    _validate_relative_path(relative, "artifact.path")
    digest, length = _digest_bundle_relative(root, relative)
    return {"path": relative, "sha256": digest, "length": length}


def _validate_artifact_reference(value: Any, location: str) -> dict[str, Any]:
    reference = _strict_object(value, location, {"length", "path", "sha256"})
    _validate_relative_path(reference["path"], f"{location}.path")
    _validate_sha256(reference["sha256"], f"{location}.sha256")
    _require(
        _strict_int(reference["length"], f"{location}.length") >= 0,
        f"{location}.length",
        "must be nonnegative",
    )
    return reference


def _parse_mountinfo_exact_mountpoints(payload: bytes) -> set[Path]:
    """Parse exact mountpoint paths from Linux ``/proc/self/mountinfo`` bytes."""

    mountpoints: set[Path] = set()
    for line_number, line in enumerate(payload.splitlines(), start=1):
        prefix, separator, _ = line.partition(b" - ")
        _require(bool(separator), f"mountinfo line {line_number}", "missing separator")
        fields = prefix.split()
        _require(
            len(fields) >= 6,
            f"mountinfo line {line_number}",
            "missing required fields",
        )
        encoded = fields[4]
        decoded = re.sub(
            rb"\\([0-7]{3})",
            lambda match: bytes((int(match.group(1), 8),)),
            encoded,
        )
        mountpoint = Path(os.fsdecode(decoded))
        _require(
            mountpoint.is_absolute(),
            f"mountinfo line {line_number}",
            "mountpoint must be absolute",
        )
        mountpoints.add(mountpoint)
    return mountpoints


def _mountinfo_exact_mountpoints() -> set[Path]:
    """Read the process mount table used to reject same-device bind mounts."""

    try:
        payload = Path("/proc/self/mountinfo").read_bytes()
    except OSError as error:
        raise QualificationError(
            f"/proc/self/mountinfo: cannot establish evidence mount custody: {error}"
        ) from error
    return _parse_mountinfo_exact_mountpoints(payload)


def _walk_bundle(root: Path) -> dict[str, Path]:
    """Enumerate every regular file and reject every unsafe filesystem node."""

    root = root.resolve(strict=True)
    root_stat = root.lstat()
    _require(stat.S_ISDIR(root_stat.st_mode), str(root), "must be a real directory")
    exact_mountpoints = _mountinfo_exact_mountpoints()
    files: dict[str, Path] = {}

    def visit(directory_fd: int, relative_parent: PurePosixPath | None) -> None:
        with os.scandir(directory_fd) as entries:
            ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
        for entry in ordered:
            relative = (
                PurePosixPath(entry.name)
                if relative_parent is None
                else relative_parent / entry.name
            )
            relative_text = _validate_relative_path(relative.as_posix(), "bundle path")
            absolute_node = root / relative_text
            _require(
                absolute_node not in exact_mountpoints,
                relative_text,
                "mount crossings are forbidden in an evidence bundle",
            )
            node = entry.stat(follow_symlinks=False)
            mode = node.st_mode
            _require(
                node.st_dev == root_stat.st_dev,
                relative_text,
                "mount crossings are forbidden in an evidence bundle",
            )
            if stat.S_ISLNK(mode):
                _error(relative_text, "symlinks are forbidden in an evidence bundle")
            if stat.S_ISDIR(mode):
                child_fd = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    _require(
                        (opened.st_dev, opened.st_ino, opened.st_mode)
                        == (node.st_dev, node.st_ino, node.st_mode),
                        relative_text,
                        "directory changed while opening",
                    )
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(mode):
                _error(relative_text, "nonregular evidence nodes are forbidden")
            _require(
                node.st_nlink == 1,
                relative_text,
                "hard-linked evidence files are forbidden",
            )
            _require(relative_text not in files, relative_text, "duplicate path")
            files[relative_text] = root / relative_text

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        visit(root_fd, None)
    finally:
        os.close(root_fd)
    return files


def _digest_bundle_relative(root: Path, relative: str) -> tuple[str, int]:
    """Open and hash a bundle file through descriptor-rooted nofollow ancestry."""

    relative = _validate_relative_path(relative, "bundle file")
    root = root.resolve(strict=True)
    root_metadata = root.lstat()
    exact_mountpoints = _mountinfo_exact_mountpoints()
    directory_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        parts = PurePosixPath(relative).parts
        current_path = root
        for component in parts[:-1]:
            current_path /= component
            _require(
                current_path not in exact_mountpoints,
                relative,
                "mount crossings are forbidden",
            )
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
            _require(
                os.fstat(directory_fd).st_dev == root_metadata.st_dev,
                relative,
                "mount crossings are forbidden",
            )
        _require(
            current_path / parts[-1] not in exact_mountpoints,
            relative,
            "mount crossings are forbidden",
        )
        file_fd = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd
        )
        try:
            before = os.fstat(file_fd)
            _require(stat.S_ISREG(before.st_mode), relative, "must be a regular file")
            _require(before.st_dev == root_metadata.st_dev, relative, "mount crossing")
            _require(before.st_nlink == 1, relative, "must have exactly one link")
            with os.fdopen(os.dup(file_fd), "rb") as stream:
                digest, length = _digest_open_file(stream)
            after = os.fstat(file_fd)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            _require(
                all(
                    getattr(before, field) == getattr(after, field)
                    for field in stable_fields
                ),
                relative,
                "changed while hashing",
            )
            _require(length == before.st_size, relative, "length changed while hashing")
            return digest, length
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


def build_manifest(root: Path) -> dict[str, Any]:
    """Build the exact evidence manifest for an unsealed bundle."""

    files = _walk_bundle(root)
    entries: list[dict[str, Any]] = []
    for relative in sorted(files, key=os.fsencode):
        if relative in EXCLUDED_ROOT_PATHS:
            continue
        digest, length = _digest_bundle_relative(root, relative)
        entries.append({"length": length, "path": relative, "sha256": digest})
    return {
        "algorithm": "sha256",
        "entries": entries,
        "excluded_root_paths": list(EXCLUDED_ROOT_PATHS),
        "root": ".",
        "schema": MANIFEST_SCHEMA,
    }


def validate_manifest(value: Any) -> dict[str, Any]:
    """Validate manifest syntax, ordering, uniqueness, and exclusions."""

    manifest = _strict_object(
        value,
        "manifest",
        {"algorithm", "entries", "excluded_root_paths", "root", "schema"},
    )
    _require(manifest["schema"] == MANIFEST_SCHEMA, "manifest.schema", "unknown schema")
    _require(manifest["algorithm"] == "sha256", "manifest.algorithm", "must be sha256")
    _require(manifest["root"] == ".", "manifest.root", "must be the bundle root")
    excluded = _strict_list(
        manifest["excluded_root_paths"], "manifest.excluded_root_paths"
    )
    _require(
        excluded == list(EXCLUDED_ROOT_PATHS),
        "manifest.excluded_root_paths",
        "must be the exact frozen root-path exclusion list",
    )
    entries = _strict_list(manifest["entries"], "manifest.entries")
    seen: set[str] = set()
    ordered: list[str] = []
    for index, raw_entry in enumerate(entries):
        location = f"manifest.entries[{index}]"
        entry = _validate_artifact_reference(raw_entry, location)
        path = entry["path"]
        _require(
            path not in EXCLUDED_ROOT_PATHS, f"{location}.path", "excluded root path"
        )
        _require(path not in seen, f"{location}.path", "duplicate manifest path")
        seen.add(path)
        ordered.append(path)
    _require(
        ordered == sorted(ordered, key=os.fsencode),
        "manifest.entries",
        "must be bytewise path sorted",
    )
    return manifest


def seal_bundle(root: Path) -> dict[str, Any]:
    """Create ``manifest.v1.json`` exactly once."""

    root = root.resolve(strict=True)
    manifest_path = root / EXCLUDED_ROOT_PATHS[0]
    _require(not manifest_path.exists(), str(manifest_path), "bundle is already sealed")
    for post_seal_path in EXCLUDED_ROOT_PATHS[1:]:
        _require(
            not (root / post_seal_path).exists(),
            str(root / post_seal_path),
            "post-seal result exists before sealing",
        )
    manifest = build_manifest(root)
    validate_manifest(manifest)
    write_new_canonical_json(manifest_path, manifest)
    verify_manifest_coverage(root, manifest)
    return artifact_reference(root, manifest_path)


def _verify_manifest_coverage_pass(root: Path, manifest: dict[str, Any]) -> None:
    """Run one exact file-set and content verification pass."""

    files = _walk_bundle(root)
    actual = set(files) - set(EXCLUDED_ROOT_PATHS)
    declared = {entry["path"] for entry in manifest["entries"]}
    missing = sorted(declared - actual)
    extra = sorted(actual - declared)
    _require(
        not missing, "manifest.entries", f"missing bundle files: {', '.join(missing)}"
    )
    _require(
        not extra, "manifest.entries", f"unmanifested bundle files: {', '.join(extra)}"
    )
    for index, entry in enumerate(manifest["entries"]):
        digest, length = _digest_bundle_relative(root, entry["path"])
        _require(
            digest == entry["sha256"],
            f"manifest.entries[{index}].sha256",
            "digest mismatch",
        )
        _require(
            length == entry["length"],
            f"manifest.entries[{index}].length",
            "length mismatch",
        )


def verify_manifest_coverage(root: Path, manifest: dict[str, Any]) -> None:
    """Recompute exact coverage twice to detect changes during verification."""

    root = root.resolve(strict=True)
    validate_manifest(manifest)
    _verify_manifest_coverage_pass(root, manifest)
    _verify_manifest_coverage_pass(root, manifest)


def _load_matrix(path: Path) -> dict[str, Any]:
    try:
        matrix = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError(f"{path}: invalid matrix: {error}") from error
    matrix = _strict_object(
        matrix,
        "matrix",
        {
            "guests",
            "mandatory_case_families",
            "mandatory_enrollment_reload",
            "per_case_deadline_seconds",
            "per_command_deadline_seconds",
            "schema",
        },
    )
    _require(matrix["schema"] == MATRIX_SCHEMA, "matrix.schema", "unknown schema")
    _require(
        matrix["mandatory_enrollment_reload"] == MANDATORY_ENROLLMENT_RELOAD,
        "matrix.mandatory_enrollment_reload",
        "differs from the frozen reload boundary",
    )
    guests = _strict_list(matrix["guests"], "matrix.guests")
    families = _strict_list(
        matrix["mandatory_case_families"], "matrix.mandatory_case_families"
    )
    guest_ids: list[str] = []
    observed_guests: list[tuple[str, str, str, str]] = []
    for index, raw_guest in enumerate(guests):
        location = f"matrix.guests[{index}]"
        guest = _strict_object(
            raw_guest,
            location,
            {"architecture", "distribution", "id", "image_digest", "release"},
        )
        guest_id = _validate_id(guest["id"], f"{location}.id")
        guest_ids.append(guest_id)
        _require(
            guest["image_digest"] == "UNENROLLED",
            f"{location}.image_digest",
            "source matrix images must remain unenrolled until receipt materialization",
        )
        observed_guests.append(
            (
                guest_id,
                _strict_string(guest["distribution"], f"{location}.distribution"),
                _strict_string(guest["release"], f"{location}.release"),
                _strict_string(guest["architecture"], f"{location}.architecture"),
            )
        )
    family_ids = [
        _validate_id(value, f"matrix.mandatory_case_families[{index}]")
        for index, value in enumerate(families)
    ]
    _require(
        len(guest_ids) == len(set(guest_ids)), "matrix.guests", "duplicate guest id"
    )
    _require(
        len(family_ids) == len(set(family_ids)),
        "matrix.mandatory_case_families",
        "duplicate family",
    )
    _require(
        tuple(observed_guests) == GUESTS,
        "matrix.guests",
        "must be the exact frozen guest matrix in order",
    )
    _require(
        tuple(family_ids) == CASE_FAMILIES,
        "matrix.mandatory_case_families",
        "must be the exact frozen case matrix in order",
    )
    command_deadline = _strict_int(
        matrix["per_command_deadline_seconds"],
        "matrix.per_command_deadline_seconds",
    )
    case_deadline = _strict_int(
        matrix["per_case_deadline_seconds"], "matrix.per_case_deadline_seconds"
    )
    _require(
        command_deadline == PER_COMMAND_DEADLINE_SECONDS,
        "matrix.per_command_deadline_seconds",
        "differs from the frozen command deadline",
    )
    _require(
        case_deadline == PER_CASE_DEADLINE_SECONDS,
        "matrix.per_case_deadline_seconds",
        "differs from the frozen case deadline",
    )
    return {
        "guest_ids": guest_ids,
        "family_ids": family_ids,
        "per_command_deadline_seconds": command_deadline,
        "per_case_deadline_seconds": case_deadline,
    }


def initialize_bundle(root: Path, matrix_path: Path) -> None:
    """Create one explicit case directory and plan for every frozen matrix cell."""

    matrix = _load_matrix(matrix_path)
    matrix_payload = matrix_path.read_bytes()
    source_root = matrix_path.resolve(strict=True).parent
    claim_path = source_root / "claim.v1.json"
    phase1_path = source_root / "phase1-starting-candidate.v1.json"
    host_contract_path = source_root / "phase1-host-contract.v1.json"
    harness_path = Path(__file__).resolve(strict=True)
    vm_fixture_path = source_root / "vm_fixture.py"
    blocked_receipt_path = source_root / "blocked_receipt.py"
    validate_claim_contract(load_canonical_json(claim_path))
    phase1_record = validate_phase1_record(load_canonical_json(phase1_path))
    validate_phase1_host_contract(load_canonical_json(host_contract_path))
    repository_root = source_root.parents[1]
    starting_commit = phase1_record["source"]["commit"]
    phase1_contract_payloads: list[tuple[str, bytes]] = []
    for reference in phase1_record["contract_inputs"]:
        path = reference["path"]
        payload = _git_output(repository_root, ("show", f"{starting_commit}:{path}"))
        digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        _require(
            digest == reference["sha256"] and len(payload) == reference["length"],
            f"phase1.contract_inputs[{path}]",
            "starting Git object bytes differ from the frozen Phase 1 reference",
        )
        phase1_contract_payloads.append((path, payload))
    host_contract_payload = host_contract_path.read_bytes()
    _require(
        f"sha256:{hashlib.sha256(host_contract_payload).hexdigest()}"
        == phase1_record["host_contract"]["sha256"]
        and len(host_contract_payload) == phase1_record["host_contract"]["length"],
        "phase1.host_contract",
        "host-contract bytes differ from the frozen Phase 1 reference",
    )
    status = _git_output(
        repository_root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    current_commit = (
        _git_output(repository_root, ("rev-parse", "HEAD")).decode("ascii").strip()
    )
    current_tree = (
        _git_output(repository_root, ("rev-parse", "HEAD^{tree}"))
        .decode("ascii")
        .strip()
    )
    current_branch = (
        _git_output(repository_root, ("rev-parse", "--abbrev-ref", "HEAD"))
        .decode("utf-8")
        .strip()
    )
    harness_payload = harness_path.read_bytes()
    publisher_payload = blocked_receipt_path.read_bytes()
    vm_fixture_payload = vm_fixture_path.read_bytes()
    tracked_harness_payload: bytes | None
    try:
        tracked_harness_payload = _git_output(
            repository_root,
            ("show", f"{current_commit}:qualification/clean-host/bundle.py"),
        )
    except QualificationError:
        tracked_harness_payload = None
    tracked_publisher_payload: bytes | None
    try:
        tracked_publisher_payload = _git_output(
            repository_root,
            (
                "show",
                f"{current_commit}:qualification/clean-host/blocked_receipt.py",
            ),
        )
    except QualificationError:
        tracked_publisher_payload = None
    tracked_vm_fixture_payload: bytes | None
    try:
        tracked_vm_fixture_payload = _git_output(
            repository_root,
            ("show", f"{current_commit}:qualification/clean-host/vm_fixture.py"),
        )
    except QualificationError:
        tracked_vm_fixture_payload = None
    candidate_identity = {
        "harness": {
            "matches_head": tracked_harness_payload == harness_payload,
            "path": "qualification/clean-host/bundle.py",
            "tracked_sha256": None
            if tracked_harness_payload is None
            else f"sha256:{hashlib.sha256(tracked_harness_payload).hexdigest()}",
            "working_sha256": f"sha256:{hashlib.sha256(harness_payload).hexdigest()}",
        },
        "publisher": {
            "matches_head": tracked_publisher_payload == publisher_payload,
            "path": "qualification/clean-host/blocked_receipt.py",
            "tracked_sha256": None
            if tracked_publisher_payload is None
            else f"sha256:{hashlib.sha256(tracked_publisher_payload).hexdigest()}",
            "working_sha256": f"sha256:{hashlib.sha256(publisher_payload).hexdigest()}",
        },
        "vm_fixture": {
            "matches_head": tracked_vm_fixture_payload == vm_fixture_payload,
            "path": "qualification/clean-host/vm_fixture.py",
            "tracked_sha256": None
            if tracked_vm_fixture_payload is None
            else f"sha256:{hashlib.sha256(tracked_vm_fixture_payload).hexdigest()}",
            "working_sha256": f"sha256:{hashlib.sha256(vm_fixture_payload).hexdigest()}",
        },
        "schema": CANDIDATE_IDENTITY_SCHEMA,
        "source": {
            "branch": current_branch,
            "commit": current_commit,
            "status_porcelain_sha256": f"sha256:{hashlib.sha256(status).hexdigest()}",
            "tree": current_tree,
            "worktree": "clean" if not status else "dirty",
        },
    }
    validate_candidate_identity(candidate_identity)
    input_payloads = (
        (claim_path, claim_path.read_bytes()),
        (phase1_path, phase1_path.read_bytes()),
        (host_contract_path, host_contract_payload),
        (harness_path, harness_payload),
        (vm_fixture_path, vm_fixture_payload),
        (blocked_receipt_path, publisher_payload),
    )
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    bundled_matrix = root / "matrix.toml"
    write_new_bytes(bundled_matrix, matrix_payload)
    inputs_root = root / "inputs"
    inputs_root.mkdir(mode=0o700)
    for (_, payload), destination in zip(
        input_payloads,
        (
            inputs_root / "claim.v1.json",
            inputs_root / "phase1-starting-candidate.v1.json",
            inputs_root / "phase1-host-contract.v1.json",
            inputs_root / "bundle.py",
            inputs_root / "vm_fixture.py",
            inputs_root / "blocked_receipt.py",
        ),
        strict=True,
    ):
        write_new_bytes(destination, payload)
    write_new_canonical_json(
        inputs_root / "candidate-identity.v1.json", candidate_identity
    )
    phase1_contract_root = inputs_root / "phase1-contract"
    phase1_contract_root.mkdir(mode=0o700)
    for relative_path, payload in phase1_contract_payloads:
        destination = phase1_contract_root / relative_path
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new_bytes(destination, payload)
    mandatory_root = root / "mandatory"
    mandatory_root.mkdir(mode=0o700)
    for category in MANDATORY_EVIDENCE_CATEGORIES:
        (mandatory_root / category).mkdir(mode=0o700)
    (root / "packages").mkdir(mode=0o700)
    matrix_digest, matrix_length = digest_regular_file(bundled_matrix)
    plan = {
        "case_ids": matrix["family_ids"],
        "guest_ids": matrix["guest_ids"],
        "matrix": {
            "length": matrix_length,
            "path": "matrix.toml",
            "sha256": matrix_digest,
        },
        "per_case_deadline_seconds": matrix["per_case_deadline_seconds"],
        "per_command_deadline_seconds": matrix["per_command_deadline_seconds"],
        "schema": CONTROLLER_SCHEMA,
    }
    write_new_canonical_json(root / "controller-plan.v1.json", plan)
    for guest_id in matrix["guest_ids"]:
        for family in matrix["family_ids"]:
            case_root = root / "guests" / guest_id / "cases" / family
            (case_root / "commands").mkdir(mode=0o700, parents=True)
            write_new_canonical_json(
                case_root / "case-plan.v1.json",
                {
                    "case_family": family,
                    "guest_id": guest_id,
                    "per_case_deadline_seconds": matrix["per_case_deadline_seconds"],
                    "per_command_deadline_seconds": matrix[
                        "per_command_deadline_seconds"
                    ],
                    "schema": CONTROLLER_SCHEMA,
                },
            )


def _load_controller_plan(root: Path) -> dict[str, Any]:
    plan = load_canonical_json(root / "controller-plan.v1.json")
    plan = _strict_object(
        plan,
        "controller-plan",
        {
            "case_ids",
            "guest_ids",
            "matrix",
            "per_case_deadline_seconds",
            "per_command_deadline_seconds",
            "schema",
        },
    )
    _require(
        plan["schema"] == CONTROLLER_SCHEMA, "controller-plan.schema", "unknown schema"
    )
    matrix_reference = _validate_artifact_reference(
        plan["matrix"], "controller-plan.matrix"
    )
    _require(
        matrix_reference["path"] == "matrix.toml",
        "controller-plan.matrix.path",
        "must name the bundled matrix",
    )
    _require(
        matrix_reference == artifact_reference(root, root / "matrix.toml"),
        "controller-plan.matrix",
        "does not bind the bundled matrix bytes",
    )
    matrix = _load_matrix(root / "matrix.toml")
    for field in ("guest_ids", "case_ids"):
        values = _strict_list(plan[field], f"controller-plan.{field}")
        for index, value in enumerate(values):
            _validate_id(value, f"controller-plan.{field}[{index}]")
        _require(
            len(values) == len(set(values)),
            f"controller-plan.{field}",
            "contains duplicates",
        )
    _require(
        plan["guest_ids"] == matrix["guest_ids"],
        "controller-plan.guest_ids",
        "differs from bundled matrix",
    )
    _require(
        plan["case_ids"] == matrix["family_ids"],
        "controller-plan.case_ids",
        "differs from bundled matrix",
    )
    for field in ("per_case_deadline_seconds", "per_command_deadline_seconds"):
        _require(
            _strict_int(plan[field], f"controller-plan.{field}") > 0,
            f"controller-plan.{field}",
            "must be positive",
        )
    _require(
        plan["per_command_deadline_seconds"] == PER_COMMAND_DEADLINE_SECONDS,
        "controller-plan.per_command_deadline_seconds",
        "differs from frozen matrix",
    )
    _require(
        plan["per_case_deadline_seconds"] == PER_CASE_DEADLINE_SECONDS,
        "controller-plan.per_case_deadline_seconds",
        "differs from frozen matrix",
    )
    return plan


def _parse_environment(values: Sequence[str]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for index, item in enumerate(values):
        location = f"environment[{index}]"
        _require("=" in item, location, "must be NAME=VALUE")
        name, value = item.split("=", 1)
        _require(
            ENV_NAME_RE.fullmatch(name) is not None,
            location,
            "invalid environment name",
        )
        _require(name not in environment, location, "duplicate environment name")
        environment[name] = value
    return dict(sorted(environment.items()))


def _timestamp() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _controller_boot_id() -> str:
    try:
        boot_id = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError as error:
        raise QualificationError(
            f"controller boot ID is unavailable: {error}"
        ) from error
    _require(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            boot_id,
        )
        is not None,
        "controller boot ID",
        "is malformed",
    )
    return boot_id


def _validate_case_clock(value: Any, guest_id: str, case_family: str) -> dict[str, Any]:
    clock = _strict_object(
        value,
        "case-wall-clock",
        {
            "case_family",
            "controller_boot_id",
            "deadline_boottime_ns",
            "deadline_seconds",
            "guest_id",
            "schema",
            "started_at",
            "started_boottime_ns",
        },
    )
    _require(
        clock["schema"] == CASE_CLOCK_SCHEMA, "case-wall-clock.schema", "wrong schema"
    )
    _require(clock["guest_id"] == guest_id, "case-wall-clock.guest_id", "wrong guest")
    _require(
        clock["case_family"] == case_family,
        "case-wall-clock.case_family",
        "wrong case",
    )
    _controller_id = _strict_string(
        clock["controller_boot_id"], "case-wall-clock.controller_boot_id"
    )
    _require(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            _controller_id,
        )
        is not None,
        "case-wall-clock.controller_boot_id",
        "is malformed",
    )
    started = _strict_int(
        clock["started_boottime_ns"], "case-wall-clock.started_boottime_ns"
    )
    deadline = _strict_int(
        clock["deadline_boottime_ns"], "case-wall-clock.deadline_boottime_ns"
    )
    _require(started >= 0, "case-wall-clock.started_boottime_ns", "must be nonnegative")
    _require(
        clock["deadline_seconds"] == PER_CASE_DEADLINE_SECONDS,
        "case-wall-clock.deadline_seconds",
        "differs from the frozen case deadline",
    )
    _require(
        deadline == started + PER_CASE_DEADLINE_SECONDS * 1_000_000_000,
        "case-wall-clock.deadline_boottime_ns",
        "does not derive from the frozen case deadline",
    )
    _strict_string(clock["started_at"], "case-wall-clock.started_at")
    return clock


def _load_or_start_case_clock(
    case_root: Path, guest_id: str, case_family: str
) -> tuple[dict[str, Any], Path]:
    clock_path = case_root / "case-wall-clock.v1.json"
    if not clock_path.exists():
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        clock = {
            "case_family": case_family,
            "controller_boot_id": _controller_boot_id(),
            "deadline_boottime_ns": started + PER_CASE_DEADLINE_SECONDS * 1_000_000_000,
            "deadline_seconds": PER_CASE_DEADLINE_SECONDS,
            "guest_id": guest_id,
            "schema": CASE_CLOCK_SCHEMA,
            "started_at": _timestamp(),
            "started_boottime_ns": started,
        }
        _validate_case_clock(clock, guest_id, case_family)
        write_new_canonical_json(clock_path, clock)
    clock = _validate_case_clock(load_canonical_json(clock_path), guest_id, case_family)
    _require(
        clock["controller_boot_id"] == _controller_boot_id(),
        str(clock_path),
        "controller reboot invalidates the monotonic case boundary",
    )
    return clock, clock_path


def record_command(
    root: Path,
    guest_id: str,
    case_family: str,
    command_id: str,
    argv: Sequence[str],
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int | None,
    expected_outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run exact argv with only the explicit environment and persist evidence."""

    root = root.resolve(strict=True)
    for sealed_path in EXCLUDED_ROOT_PATHS:
        _require(
            not (root / sealed_path).exists(),
            str(root / sealed_path),
            "cannot record into a sealed or finalized bundle",
        )
    plan = _load_controller_plan(root)
    _require(guest_id in plan["guest_ids"], "guest_id", "not in controller plan")
    _require(case_family in plan["case_ids"], "case_family", "not in controller plan")
    _validate_id(command_id, "command_id")
    _require(len(argv) > 0, "argv", "must not be empty")
    for index, argument in enumerate(argv):
        _require(
            type(argument) is str and "\x00" not in argument,
            f"argv[{index}]",
            "must be a NUL-free string",
        )
    _require(
        Path(argv[0]).is_absolute(), "argv[0]", "must be an absolute executable path"
    )
    expected_outcome = (
        {"kind": "exit_code", "value": 0}
        if expected_outcome is None
        else expected_outcome
    )
    _validate_expected_outcome(expected_outcome, "expected_outcome")
    cwd = cwd.resolve(strict=True)
    _require(cwd.is_dir(), "cwd", "must be a directory")
    case_root = root / "guests" / guest_id / "cases" / case_family
    commands_root = case_root / "commands"
    _require_real_directory_below(root, commands_root)
    basename = command_id
    record_path = commands_root / f"{basename}.command.v1.json"
    stdout_path = commands_root / f"{basename}.stdout"
    stderr_path = commands_root / f"{basename}.stderr"
    for output_path in (record_path, stdout_path, stderr_path):
        _require(not output_path.exists(), str(output_path), "command id already used")

    command_limit = plan["per_command_deadline_seconds"]
    requested_limit = command_limit if timeout_seconds is None else timeout_seconds
    _require(
        type(requested_limit) is int and requested_limit > 0,
        "timeout_seconds",
        "must be positive",
    )
    _require(
        requested_limit <= command_limit,
        "timeout_seconds",
        "exceeds frozen command deadline",
    )
    case_clock, case_clock_path = _load_or_start_case_clock(
        case_root, guest_id, case_family
    )
    preflight_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    remaining_ns = case_clock["deadline_boottime_ns"] - preflight_boottime_ns
    _require(remaining_ns > 0, "case deadline", "already exhausted")
    _require(
        remaining_ns >= 1_000_000_000,
        "case deadline",
        "less than one second remains",
    )
    effective_timeout = min(requested_limit, remaining_ns // 1_000_000_000)

    resolved_executable = Path(argv[0]).resolve(strict=True)
    executable_fd = os.open(
        resolved_executable,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    executable = _executable_identity(executable_fd, argv[0])
    try:
        if is_copied_python_tool_argv(argv):
            script_path = Path(argv[1])
            copied_tools = {
                root / "inputs" / "blocked_receipt.py",
                root / "inputs" / "vm_fixture.py",
            }
            resolved_script = script_path.resolve(strict=True)
            _require(
                script_path == resolved_script and resolved_script in copied_tools,
                "argv[1]",
                "copied campaign tool must be the canonical bundle-local input",
            )
        observed_inputs = [
            _input_file_identity(path) for path in _declared_input_paths(argv)
        ]
    except BaseException:
        os.close(executable_fd)
        raise

    stdout_fd: int | None = None
    stderr_fd: int | None = None
    try:
        stdout_fd = os.open(
            stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
        stderr_fd = os.open(
            stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
    except BaseException:
        for descriptor in (stderr_fd, stdout_fd):
            if descriptor is not None:
                os.close(descriptor)
        if stdout_fd is not None:
            try:
                stdout_path.unlink()
            except FileNotFoundError:
                pass
        os.close(executable_fd)
        raise
    started_at = _timestamp()
    started = time.monotonic_ns()
    started_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    return_code: int | None = None
    launch_error: str | None = None
    timed_out = False
    try:
        try:
            process = subprocess.Popen(
                list(argv),
                executable=f"/proc/self/fd/{executable_fd}",
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                close_fds=True,
                pass_fds=(executable_fd,),
                start_new_session=True,
            )
        except OSError as error:
            launch_error = (
                f"{error.__class__.__name__}: errno={error.errno}: {error.strerror}"
            )
        else:
            try:
                return_code = process.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                return_code = process.wait()
    finally:
        os.fsync(stdout_fd)
        os.fsync(stderr_fd)
        os.close(stdout_fd)
        os.close(stderr_fd)
    _require(
        _executable_identity(executable_fd, argv[0]) == executable,
        argv[0],
        "executable changed while the command ran",
    )
    os.close(executable_fd)
    for input_identity in observed_inputs:
        _require(
            _input_file_identity(input_identity["requested_path"]) == input_identity,
            input_identity["requested_path"],
            "SSH input changed while the command ran",
        )
    ended = time.monotonic_ns()
    ended_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    ended_at = _timestamp()
    duration_ms = max(0, (ended - started) // 1_000_000)
    stdout_ref = artifact_reference(root, stdout_path)
    stderr_ref = artifact_reference(root, stderr_path)
    outcome = {
        "exit_code": return_code
        if return_code is not None and return_code >= 0
        else None,
        "launch_error": launch_error,
        "signal": -return_code if return_code is not None and return_code < 0 else None,
        "timed_out": timed_out,
    }
    record = {
        "argv": list(argv),
        "case_family": case_family,
        "case_wall_clock": artifact_reference(root, case_clock_path),
        "command_id": command_id,
        "cwd": str(cwd),
        "duration_ms": duration_ms,
        "ended_at": ended_at,
        "ended_boottime_ns": ended_boottime_ns,
        "environment": environment,
        "executable": executable,
        "expected_outcome": expected_outcome,
        "guest_id": guest_id,
        "matched_expectation": _outcome_matches(expected_outcome, outcome),
        "outcome": outcome,
        "observed_inputs": observed_inputs,
        "schema": COMMAND_SCHEMA,
        "started_at": started_at,
        "started_boottime_ns": started_boottime_ns,
        "stderr": stderr_ref,
        "stdout": stdout_ref,
        "timeout_seconds": effective_timeout,
    }
    validate_command_record(record)
    write_new_canonical_json(record_path, record)
    return record


def validate_command_record(value: Any) -> dict[str, Any]:
    """Validate one persisted exact-command record."""

    record = _strict_object(
        value,
        "command",
        {
            "argv",
            "case_family",
            "case_wall_clock",
            "command_id",
            "cwd",
            "duration_ms",
            "ended_at",
            "ended_boottime_ns",
            "environment",
            "executable",
            "expected_outcome",
            "guest_id",
            "matched_expectation",
            "observed_inputs",
            "outcome",
            "schema",
            "started_at",
            "started_boottime_ns",
            "stderr",
            "stdout",
            "timeout_seconds",
        },
    )
    _require(record["schema"] == COMMAND_SCHEMA, "command.schema", "unknown schema")
    for field in ("guest_id", "case_family", "command_id"):
        _validate_id(record[field], f"command.{field}")
    cwd = _strict_string(record["cwd"], "command.cwd")
    _require(Path(cwd).is_absolute(), "command.cwd", "must be absolute")
    argv = _strict_list(record["argv"], "command.argv")
    _require(argv, "command.argv", "must not be empty")
    for index, argument in enumerate(argv):
        _require(
            type(argument) is str and "\x00" not in argument,
            f"command.argv[{index}]",
            "invalid argument",
        )
    _require(Path(argv[0]).is_absolute(), "command.argv[0]", "must be absolute")
    _validate_artifact_reference(record["case_wall_clock"], "command.case_wall_clock")
    environment = _strict_object(
        record["environment"],
        "command.environment",
        set(record["environment"]) if type(record["environment"]) is dict else set(),
    )
    for name, setting in environment.items():
        _require(
            ENV_NAME_RE.fullmatch(name) is not None,
            f"command.environment.{name}",
            "invalid name",
        )
        _strict_string(setting, f"command.environment.{name}")
    executable = _validate_executable_identity(
        record["executable"], "command.executable"
    )
    observed_inputs = _strict_list(record["observed_inputs"], "command.observed_inputs")
    for index, input_identity in enumerate(observed_inputs):
        _validate_input_file_identity(
            input_identity, f"command.observed_inputs[{index}]"
        )
    declared_inputs = _declared_input_paths(argv)
    _require(
        [identity["requested_path"] for identity in observed_inputs] == declared_inputs,
        "command.observed_inputs",
        "must identify exactly the command's declared immutable file inputs",
    )
    if is_copied_python_tool_argv(argv):
        _require(
            observed_inputs[0]["resolved_path"] == argv[1],
            "command.observed_inputs",
            "copied Python tool input must use its canonical path",
        )
    _require(
        executable["requested_path"] == argv[0],
        "command.executable.requested_path",
        "must equal command.argv[0]",
    )
    expected_outcome = _validate_expected_outcome(
        record["expected_outcome"], "command.expected_outcome"
    )
    matched_expectation = _strict_bool(
        record["matched_expectation"], "command.matched_expectation"
    )
    _require(
        list(environment) == sorted(environment),
        "command.environment",
        "must be name sorted",
    )
    for field in ("started_at", "ended_at"):
        timestamp = _strict_string(record[field], f"command.{field}")
        _require(timestamp.endswith("Z"), f"command.{field}", "must be UTC RFC3339")
        try:
            dt.datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
        except ValueError as error:
            raise QualificationError(
                f"command.{field}: invalid timestamp: {error}"
            ) from error
    _require(
        _strict_int(record["duration_ms"], "command.duration_ms") >= 0,
        "command.duration_ms",
        "must be nonnegative",
    )
    started_boottime_ns = _strict_int(
        record["started_boottime_ns"], "command.started_boottime_ns"
    )
    ended_boottime_ns = _strict_int(
        record["ended_boottime_ns"], "command.ended_boottime_ns"
    )
    _require(
        0 <= started_boottime_ns <= ended_boottime_ns,
        "command boottime",
        "must be nonnegative and monotonic",
    )
    _require(
        record["duration_ms"]
        <= (ended_boottime_ns - started_boottime_ns) // 1_000_000 + 1,
        "command.duration_ms",
        "is inconsistent with CLOCK_BOOTTIME",
    )
    _require(
        _strict_int(record["timeout_seconds"], "command.timeout_seconds") > 0,
        "command.timeout_seconds",
        "must be positive",
    )
    _require(
        record["timeout_seconds"] <= PER_COMMAND_DEADLINE_SECONDS,
        "command.timeout_seconds",
        "exceeds frozen command deadline",
    )
    for field in ("stdout", "stderr"):
        _validate_artifact_reference(record[field], f"command.{field}")
    outcome = _strict_object(
        record["outcome"],
        "command.outcome",
        {"exit_code", "launch_error", "signal", "timed_out"},
    )
    exit_code = outcome["exit_code"]
    caught_signal = outcome["signal"]
    _require(
        exit_code is None or (type(exit_code) is int and exit_code >= 0),
        "command.outcome.exit_code",
        "invalid exit code",
    )
    _require(
        caught_signal is None or (type(caught_signal) is int and caught_signal > 0),
        "command.outcome.signal",
        "invalid signal",
    )
    _optional_string(outcome["launch_error"], "command.outcome.launch_error")
    _strict_bool(outcome["timed_out"], "command.outcome.timed_out")
    terminal_count = sum(
        (
            exit_code is not None,
            caught_signal is not None,
            outcome["launch_error"] is not None,
        )
    )
    _require(
        terminal_count == 1, "command.outcome", "must have exactly one terminal outcome"
    )
    _require(
        not outcome["timed_out"] or caught_signal is not None,
        "command.outcome.timed_out",
        "timeout must end by signal",
    )
    _require(
        matched_expectation == _outcome_matches(expected_outcome, outcome),
        "command.matched_expectation",
        "does not match the recorded terminal outcome",
    )
    return record


def _validate_source_cut(value: Any, location: str) -> dict[str, Any]:
    source = _strict_object(
        value,
        location,
        {"branch", "commit", "status_porcelain_sha256", "tree", "worktree"},
    )
    _strict_string(source["branch"], f"{location}.branch")
    _validate_git_id(source["commit"], f"{location}.commit")
    _validate_git_id(source["tree"], f"{location}.tree")
    _validate_sha256(
        source["status_porcelain_sha256"], f"{location}.status_porcelain_sha256"
    )
    _require(
        source["worktree"] in ("clean", "dirty"),
        f"{location}.worktree",
        "invalid state",
    )
    if source["worktree"] == "clean":
        _require(
            source["status_porcelain_sha256"] == EMPTY_SHA256,
            f"{location}.status_porcelain_sha256",
            "clean worktree must bind the empty porcelain output",
        )
    return source


def validate_phase1_host_contract(value: Any) -> dict[str, Any]:
    """Validate the frozen supported-host assumptions and operator argv."""

    contract = _strict_object(
        value,
        "phase1-host-contract",
        {"activation_and_readiness_commands", "required_host_assumptions", "schema"},
    )
    _require(
        contract["schema"] == HOST_CONTRACT_SCHEMA,
        "phase1-host-contract.schema",
        "unknown schema",
    )
    commands = _strict_list(
        contract["activation_and_readiness_commands"],
        "phase1-host-contract.activation_and_readiness_commands",
    )
    command_ids: list[str] = []
    for index, raw_command in enumerate(commands):
        location = f"phase1-host-contract.activation_and_readiness_commands[{index}]"
        command = _strict_object(raw_command, location, {"argv", "id", "stdout_path"})
        command_id = _validate_id(command["id"], f"{location}.id")
        command_ids.append(command_id)
        argv = _strict_list(command["argv"], f"{location}.argv")
        _require(argv, f"{location}.argv", "must not be empty")
        for argument_index, argument in enumerate(argv):
            _strict_string(argument, f"{location}.argv[{argument_index}]")
        _require(Path(argv[0]).is_absolute(), f"{location}.argv[0]", "must be absolute")
        expected_stdout_path = (
            "/etc/agent-governor/genesis-measurement.json"
            if command_id == "measure_genesis"
            else None
        )
        _require(
            command["stdout_path"] == expected_stdout_path,
            f"{location}.stdout_path",
            "differs from the exact activation output contract",
        )
    _require(
        tuple(command_ids) == ACTIVATION_COMMAND_IDS,
        "phase1-host-contract.activation_and_readiness_commands",
        "must contain the exact activation/readiness command set in order",
    )
    assumptions = _strict_object(
        contract["required_host_assumptions"],
        "phase1-host-contract.required_host_assumptions",
        {
            "capability_envelope",
            "cgroup",
            "filesystem",
            "kernel_minimum",
            "landlock_abi_minimum",
            "procfs",
            "service_identity",
            "syscall_filter",
            "systemd_minimum",
            "supported_guests",
        },
    )
    for field in (
        "capability_envelope",
        "cgroup",
        "filesystem",
        "kernel_minimum",
        "procfs",
        "service_identity",
        "syscall_filter",
    ):
        _nonempty_string(assumptions[field], f"phase1-host-contract.{field}")
    _require(
        assumptions["kernel_minimum"] == "Linux 6.1",
        "phase1-host-contract.kernel_minimum",
        "differs from frozen support boundary",
    )
    _require(
        assumptions["landlock_abi_minimum"] == 3,
        "phase1-host-contract.landlock_abi_minimum",
        "must be 3",
    )
    _require(
        assumptions["systemd_minimum"] == 252,
        "phase1-host-contract.systemd_minimum",
        "must be 252",
    )
    supported = _strict_list(
        assumptions["supported_guests"], "phase1-host-contract.supported_guests"
    )
    _require(
        supported == [guest[0] for guest in GUESTS],
        "phase1-host-contract.supported_guests",
        "must match the frozen matrix",
    )
    return contract


def validate_candidate_identity(value: Any) -> dict[str, Any]:
    """Validate the source and harness identity measured when a bundle starts."""

    identity = _strict_object(
        value,
        "candidate-identity",
        {"harness", "publisher", "schema", "source", "vm_fixture"},
    )
    _require(
        identity["schema"] == CANDIDATE_IDENTITY_SCHEMA,
        "candidate-identity.schema",
        "unknown schema",
    )
    _validate_source_cut(identity["source"], "candidate-identity.source")
    for field, expected_path in (
        ("harness", "qualification/clean-host/bundle.py"),
        ("publisher", "qualification/clean-host/blocked_receipt.py"),
        ("vm_fixture", "qualification/clean-host/vm_fixture.py"),
    ):
        location = f"candidate-identity.{field}"
        tool = _strict_object(
            identity[field],
            location,
            {"matches_head", "path", "tracked_sha256", "working_sha256"},
        )
        _require(
            tool["path"] == expected_path,
            f"{location}.path",
            "must name the exact qualification tool",
        )
        _strict_bool(tool["matches_head"], f"{location}.matches_head")
        _validate_sha256(tool["working_sha256"], f"{location}.working_sha256")
        tracked = tool["tracked_sha256"]
        _require(
            tracked is None or type(tracked) is str,
            f"{location}.tracked_sha256",
            "must be null or a SHA-256 digest",
        )
        if tracked is not None:
            _validate_sha256(tracked, f"{location}.tracked_sha256")
        if tool["matches_head"]:
            _require(
                tracked == tool["working_sha256"],
                location,
                "matching tool bytes require equal tracked and working digests",
            )
    return identity


def validate_phase1_record(value: Any) -> dict[str, Any]:
    """Validate the canonical Phase 1 starting-candidate inventory."""

    record = _strict_object(
        value,
        "phase1",
        {
            "authority_use",
            "candidate_artifacts",
            "contract_inputs",
            "dependency_inventory",
            "host_contract",
            "host_capability_summary",
            "known_blockers",
            "recorded_at",
            "receipt_inventory",
            "reconstructs_standing",
            "schema",
            "source",
        },
    )
    _require(record["schema"] == PHASE1_SCHEMA, "phase1.schema", "unknown schema")
    _require(
        record["authority_use"] == AUTHORITY_USE,
        "phase1.authority_use",
        "must be evidence_only",
    )
    _require(
        record["reconstructs_standing"] is False,
        "phase1.reconstructs_standing",
        "must be false",
    )
    _strict_string(record["recorded_at"], "phase1.recorded_at")
    _validate_source_cut(record["source"], "phase1.source")
    contract_inputs = _strict_list(record["contract_inputs"], "phase1.contract_inputs")
    input_paths: list[str] = []
    for index, reference in enumerate(contract_inputs):
        validated = _validate_artifact_reference(
            reference, f"phase1.contract_inputs[{index}]"
        )
        input_paths.append(validated["path"])
    _require(
        tuple(input_paths) == PHASE1_CONTRACT_INPUT_PATHS,
        "phase1.contract_inputs",
        "must bind the exact candidate contract inputs in order",
    )
    host_contract = _validate_artifact_reference(
        record["host_contract"], "phase1.host_contract"
    )
    _require(
        host_contract["path"]
        == "qualification/clean-host/phase1-host-contract.v1.json",
        "phase1.host_contract.path",
        "must bind the frozen host contract",
    )
    artifacts = _strict_object(
        record["candidate_artifacts"],
        "phase1.candidate_artifacts",
        {"accepted", "rejected"},
    )
    accepted = _strict_list(
        artifacts["accepted"], "phase1.candidate_artifacts.accepted"
    )
    rejected = _strict_list(
        artifacts["rejected"], "phase1.candidate_artifacts.rejected"
    )
    for index, item in enumerate(accepted):
        location = f"phase1.candidate_artifacts.accepted[{index}]"
        candidate = _strict_object(item, location, {"length", "path", "sha256"})
        _strict_string(candidate["path"], f"{location}.path")
        _validate_sha256(candidate["sha256"], f"{location}.sha256")
        _require(
            _strict_int(candidate["length"], f"{location}.length") >= 0,
            f"{location}.length",
            "must be nonnegative",
        )
    rejected_identities: list[tuple[str, int, str]] = []
    for index, item in enumerate(rejected):
        location = f"phase1.candidate_artifacts.rejected[{index}]"
        candidate = _strict_object(
            item, location, {"length", "path", "reason", "sha256", "status"}
        )
        candidate_path = _strict_string(candidate["path"], f"{location}.path")
        _require(
            Path(candidate_path).is_absolute(),
            f"{location}.path",
            "must be absolute",
        )
        _validate_sha256(candidate["sha256"], f"{location}.sha256")
        candidate_length = _strict_int(candidate["length"], f"{location}.length")
        _require(
            candidate_length >= 0,
            f"{location}.length",
            "must be nonnegative",
        )
        _strict_string(candidate["reason"], f"{location}.reason")
        _require(
            candidate["status"] == "rejected", f"{location}.status", "must be rejected"
        )
        rejected_identities.append(
            (candidate_path, candidate_length, candidate["sha256"])
        )
    _require(
        tuple(rejected_identities) == PHASE1_REJECTED_ARTIFACTS,
        "phase1.candidate_artifacts.rejected",
        "must bind the exact four stale artifacts found at the starting cut",
    )
    dependencies = _strict_list(
        record["dependency_inventory"], "phase1.dependency_inventory"
    )
    ambient_ids: list[str] = []
    dependency_classes: dict[str, str] = {}
    for index, item in enumerate(dependencies):
        location = f"phase1.dependency_inventory[{index}]"
        dependency = _strict_object(
            item,
            location,
            {"classification", "consumers", "evidence", "id", "requirement"},
        )
        dependency_id = _validate_id(dependency["id"], f"{location}.id")
        classification = _strict_string(
            dependency["classification"], f"{location}.classification"
        )
        _require(
            dependency_id not in dependency_classes,
            f"{location}.id",
            "duplicate dependency",
        )
        dependency_classes[dependency_id] = classification
        _require(
            classification in DEPENDENCY_CLASSES,
            f"{location}.classification",
            "invalid dependency class",
        )
        consumers = _strict_list(dependency["consumers"], f"{location}.consumers")
        _require(consumers, f"{location}.consumers", "must not be empty")
        for consumer_index, consumer in enumerate(consumers):
            _validate_id(consumer, f"{location}.consumers[{consumer_index}]")
        _strict_string(dependency["requirement"], f"{location}.requirement")
        _strict_string(dependency["evidence"], f"{location}.evidence")
        if classification == "undeclared_ambient_dependency":
            ambient_ids.append(dependency_id)
    _require(
        tuple(ambient_ids) == AMBIENT_DEPENDENCIES,
        "phase1.dependency_inventory",
        "must contain the four frozen ambient defects in order",
    )
    for dependency_id, classification in PHASE1_REQUIRED_DEPENDENCIES:
        _require(
            dependency_classes.get(dependency_id) == classification,
            "phase1.dependency_inventory",
            f"missing or misclassified required dependency: {dependency_id}",
        )
    blockers = _strict_list(record["known_blockers"], "phase1.known_blockers")
    _require(
        blockers == list(KNOWN_BLOCKERS),
        "phase1.known_blockers",
        "must carry frozen blockers separately",
    )
    host = _strict_object(
        record["host_capability_summary"],
        "phase1.host_capability_summary",
        {
            "active_lsms",
            "architecture",
            "cgroup",
            "distribution",
            "filesystem",
            "hypervisor_tools",
            "kernel",
            "notes",
            "systemd",
        },
    )
    for field in host:
        if field in ("hypervisor_tools",):
            tools = _strict_list(host[field], f"phase1.host_capability_summary.{field}")
            for index, tool in enumerate(tools):
                _strict_string(tool, f"phase1.host_capability_summary.{field}[{index}]")
        else:
            _strict_string(host[field], f"phase1.host_capability_summary.{field}")
    receipts = _strict_list(record["receipt_inventory"], "phase1.receipt_inventory")
    narrative_receipts: list[dict[str, Any]] = []
    for index, item in enumerate(receipts):
        location = f"phase1.receipt_inventory[{index}]"
        receipt = _strict_object(
            item, location, {"digest", "kind", "length", "path", "schema", "status"}
        )
        _strict_string(receipt["kind"], f"{location}.kind")
        _strict_string(receipt["path"], f"{location}.path")
        _strict_string(receipt["schema"], f"{location}.schema")
        _strict_string(receipt["status"], f"{location}.status")
        _require(
            receipt["digest"] is None
            or SHA256_RE.fullmatch(
                _strict_string(receipt["digest"], f"{location}.digest")
            )
            is not None,
            f"{location}.digest",
            "invalid optional digest",
        )
        _require(
            receipt["length"] is None
            or (type(receipt["length"]) is int and receipt["length"] >= 0),
            f"{location}.length",
            "invalid optional length",
        )
        if receipt["kind"] == "narrative_qualification_only":
            narrative_receipts.append(receipt)
    _require(
        narrative_receipts
        == [
            {
                "digest": digest,
                "kind": "narrative_qualification_only",
                "length": length,
                "path": path,
                "schema": "none",
                "status": status,
            }
            for path, length, digest, status in PHASE1_NARRATIVE_RECEIPTS
        ],
        "phase1.receipt_inventory",
        "must bind the exact historical narrative bytes",
    )
    return record


def _validate_receipt_identity(value: Any, location: str) -> dict[str, Any]:
    identity = _strict_object(value, location, {"length", "path", "sha256"})
    return _validate_artifact_reference(identity, location)


def _validate_external_identity(value: Any, location: str) -> dict[str, Any]:
    identity = _strict_object(value, location, {"length", "sha256"})
    _validate_sha256(identity["sha256"], f"{location}.sha256")
    _require(
        _strict_int(identity["length"], f"{location}.length") > 0,
        f"{location}.length",
        "must be positive",
    )
    return identity


def _validate_observed_guest(value: Any, location: str) -> dict[str, Any]:
    observed = _strict_object(
        value,
        location,
        {
            "active_lsms",
            "architecture",
            "cgroup",
            "distribution",
            "filesystem",
            "kernel",
            "landlock_abi",
            "release",
            "systemd",
        },
    )
    for field in observed:
        _nonempty_string(observed[field], f"{location}.{field}")
    _require(
        observed["landlock_abi"].isdigit(),
        f"{location}.landlock_abi",
        "must be a decimal ABI number",
    )
    return observed


def validate_guest_facts_record(value: Any) -> dict[str, Any]:
    """Validate one canonical direct guest-probe record."""

    record = _strict_object(value, "guest-facts", {"guest_id", "observed", "schema"})
    _require(
        record["schema"] == GUEST_FACTS_SCHEMA,
        "guest-facts.schema",
        "unknown schema",
    )
    guest_id = _validate_id(record["guest_id"], "guest-facts.guest_id")
    guest = next((item for item in GUESTS if item[0] == guest_id), None)
    _require(guest is not None, "guest-facts.guest_id", "unknown frozen guest")
    observed = _validate_observed_guest(record["observed"], "guest-facts.observed")
    _require(
        (
            observed["distribution"],
            observed["release"],
            observed["architecture"],
        )
        == guest[1:],
        "guest-facts.observed",
        "does not describe its frozen guest",
    )
    return record


def validate_guest_facts_binding_record(value: Any) -> dict[str, Any]:
    """Validate one manifest-bound direct guest observation."""

    record = _strict_object(
        value,
        "guest-facts-binding",
        {"guest_id", "observation", "observed", "schema"},
    )
    _require(
        record["schema"] == GUEST_FACTS_BINDING_SCHEMA,
        "guest-facts-binding.schema",
        "unknown schema",
    )
    probe = validate_guest_facts_record(
        {
            "guest_id": record["guest_id"],
            "observed": record["observed"],
            "schema": GUEST_FACTS_SCHEMA,
        }
    )
    _validate_artifact_reference(
        record["observation"], "guest-facts-binding.observation"
    )
    _require(
        probe["guest_id"] == record["guest_id"],
        "guest-facts-binding.guest_id",
        "does not match its observation",
    )
    return record


def validate_image_provenance_record(value: Any) -> dict[str, Any]:
    """Validate one canonical external VM-image identity record."""

    record = _strict_object(
        value,
        "image-provenance",
        {"artifact", "bytes", "guest_id", "schema", "source", "source_digest"},
    )
    _require(
        record["schema"] == IMAGE_PROVENANCE_SCHEMA,
        "image-provenance.schema",
        "unknown schema",
    )
    guest_id = _validate_id(record["guest_id"], "image-provenance.guest_id")
    _require(
        guest_id in {guest[0] for guest in GUESTS},
        "image-provenance.guest_id",
        "unknown frozen guest",
    )
    _validate_external_identity(record["bytes"], "image-provenance.bytes")
    artifact = _validate_artifact_reference(
        record["artifact"], "image-provenance.artifact"
    )
    _require(
        {"length": artifact["length"], "sha256": artifact["sha256"]} == record["bytes"],
        "image-provenance.bytes",
        "differs from the manifest-covered image artifact",
    )
    _nonempty_string(record["source"], "image-provenance.source")
    source_digest = _nonempty_string(
        record["source_digest"], "image-provenance.source_digest"
    )
    _require(
        SOURCE_DIGEST_RE.fullmatch(source_digest) is not None,
        "image-provenance.source_digest",
        "invalid source digest",
    )
    return record


def validate_snapshot_boundary_record(value: Any) -> dict[str, Any]:
    """Validate a preserved first-gate failure snapshot boundary record."""

    record = _strict_object(
        value,
        "snapshot-boundary",
        {
            "boundary",
            "artifact",
            "final_source",
            "guest_id",
            "image_sha256",
            "schema",
            "snapshot_id",
            "starting_source",
        },
    )
    _require(
        record["schema"] == SNAPSHOT_BOUNDARY_SCHEMA,
        "snapshot-boundary.schema",
        "unknown schema",
    )
    _require(
        record["boundary"] == "preserved_first_gate_failure",
        "snapshot-boundary.boundary",
        "must name the exact preserved first-gate failure boundary",
    )
    _validate_id(record["snapshot_id"], "snapshot-boundary.snapshot_id")
    guest_id = _validate_id(record["guest_id"], "snapshot-boundary.guest_id")
    _require(
        guest_id in {guest[0] for guest in GUESTS},
        "snapshot-boundary.guest_id",
        "unknown frozen guest",
    )
    _validate_sha256(record["image_sha256"], "snapshot-boundary.image_sha256")
    artifact = _validate_artifact_reference(
        record["artifact"], "snapshot-boundary.artifact"
    )
    _require(
        artifact["length"] > 0,
        "snapshot-boundary.artifact.length",
        "must be nonzero",
    )
    _validate_source_cut(record["starting_source"], "snapshot-boundary.starting_source")
    _validate_source_cut(record["final_source"], "snapshot-boundary.final_source")
    return record


def candidate_archive_git_tree(path: Path, object_format: str) -> str:
    """Recompute a Git tree id from one uncompressed governed source tar."""

    _require(
        object_format in ("sha1", "sha256"),
        "archive object format",
        "must be sha1 or sha256",
    )
    _, archive_length = digest_regular_file(path)
    _require(
        0 < archive_length <= 512 * 1024 * 1024,
        str(path),
        "candidate archive must be nonempty and at most 512 MiB",
    )
    prefix = Path(GOVERNED_SOURCE_CWD).name
    root_node: dict[bytes, Any] = {}

    def object_id(kind: bytes, payload: bytes) -> bytes:
        digest = hashlib.new(object_format)
        digest.update(kind + b" " + str(len(payload)).encode("ascii") + b"\0")
        digest.update(payload)
        return digest.digest()

    def directory_for(parts: tuple[bytes, ...]) -> dict[bytes, Any]:
        node = root_node
        for component in parts:
            existing = node.get(component)
            if existing is None:
                child: dict[bytes, Any] = {}
                node[component] = child
                node = child
            else:
                _require(
                    type(existing) is dict,
                    str(path),
                    "archive path collides with a non-directory",
                )
                node = existing
        return node

    payload_total = 0
    try:
        with tarfile.open(path, mode="r:") as archive:
            for member in archive:
                name = member.name.removesuffix("/")
                pure = PurePosixPath(name)
                _require(
                    not pure.is_absolute()
                    and pure.parts
                    and all(part not in ("", ".", "..") for part in pure.parts),
                    str(path),
                    "archive contains an unsafe path",
                )
                _require(
                    pure.parts[0] == prefix,
                    str(path),
                    "archive entry is outside the governed top-level prefix",
                )
                relative_parts = pure.parts[1:]
                if not relative_parts:
                    _require(
                        member.isdir(),
                        str(path),
                        "top-level prefix is not a directory",
                    )
                    continue
                encoded_parts = tuple(
                    part.encode("utf-8", "surrogateescape") for part in relative_parts
                )
                _require(
                    all(
                        b"\0" not in part and b"/" not in part for part in encoded_parts
                    ),
                    str(path),
                    "archive path has a forbidden component",
                )
                parent = directory_for(encoded_parts[:-1])
                basename = encoded_parts[-1]
                if member.isdir():
                    existing = parent.get(basename)
                    _require(
                        existing is None or type(existing) is dict,
                        str(path),
                        "archive directory collides with a file",
                    )
                    if existing is None:
                        parent[basename] = {}
                    continue
                _require(
                    basename not in parent,
                    str(path),
                    "archive contains a duplicate path",
                )
                if member.isfile():
                    _require(
                        member.size >= 0
                        and payload_total + member.size <= archive_length,
                        str(path),
                        "archive payload exceeds its bounded container",
                    )
                    stream = archive.extractfile(member)
                    _require(
                        stream is not None,
                        str(path),
                        "regular member is unreadable",
                    )
                    payload = stream.read(member.size + 1)
                    _require(
                        len(payload) == member.size,
                        str(path),
                        "regular member length mismatch",
                    )
                    payload_total += len(payload)
                    mode = b"100755" if member.mode & 0o111 else b"100644"
                elif member.issym():
                    payload = member.linkname.encode("utf-8", "surrogateescape")
                    _require(
                        b"\0" not in payload,
                        str(path),
                        "symlink target contains NUL",
                    )
                    mode = b"120000"
                else:
                    _error(str(path), "archive contains an unsupported member type")
                parent[basename] = (mode, object_id(b"blob", payload))
    except (tarfile.TarError, OSError) as error:
        raise QualificationError(f"{path}: invalid source tar: {error}") from error
    _require(root_node, str(path), "archive contains no governed source files")

    def tree_id(node: dict[bytes, Any]) -> bytes:
        entries: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            if type(value) is dict:
                mode = b"40000"
                identifier = tree_id(value)
                sort_name = name + b"/"
            else:
                mode, identifier = value
                sort_name = name
            entries.append((sort_name, mode + b" " + name + b"\0" + identifier))
        payload = b"".join(
            entry for _, entry in sorted(entries, key=lambda item: item[0])
        )
        return object_id(b"tree", payload)

    return tree_id(root_node).hex()


def validate_candidate_archive_record(value: Any) -> dict[str, Any]:
    """Validate a manifest-covered source archive bound to both source cuts."""

    record = _strict_object(
        value,
        "candidate-archive",
        {
            "archive",
            "archive_tree",
            "extraction_root",
            "final_source",
            "guest_archive_path",
            "guest_id",
            "schema",
            "starting_source",
        },
    )
    _require(
        record["schema"] == CANDIDATE_ARCHIVE_SCHEMA,
        "candidate-archive.schema",
        "unknown schema",
    )
    guest_id = _validate_id(record["guest_id"], "candidate-archive.guest_id")
    _require(
        guest_id in {guest[0] for guest in GUESTS},
        "candidate-archive.guest_id",
        "unknown frozen guest",
    )
    archive = _validate_artifact_reference(
        record["archive"], "candidate-archive.archive"
    )
    _require(
        archive["length"] > 0, "candidate-archive.archive.length", "must be positive"
    )
    _validate_git_id(record["archive_tree"], "candidate-archive.archive_tree")
    _require(
        record["extraction_root"] == GOVERNED_SOURCE_CWD,
        "candidate-archive.extraction_root",
        "must name the governed source build root",
    )
    _require(
        record["guest_archive_path"] == GUEST_CANDIDATE_ARCHIVE_PATH,
        "candidate-archive.guest_archive_path",
        "must name the fixed guest archive path",
    )
    _validate_source_cut(record["starting_source"], "candidate-archive.starting_source")
    _validate_source_cut(record["final_source"], "candidate-archive.final_source")
    return record


def _validate_receipt_matrix(value: Any) -> list[str]:
    cells = _strict_list(value, "receipt.matrix")
    _require(
        len(cells) == len(GUESTS),
        "receipt.matrix",
        "must contain the exact four guest cells",
    )
    all_results: list[str] = []
    seen_guests: set[str] = set()
    for cell_index, (raw_cell, expected_guest) in enumerate(
        zip(cells, GUESTS, strict=True)
    ):
        location = f"receipt.matrix[{cell_index}]"
        cell = _strict_object(
            raw_cell,
            location,
            {
                "architecture",
                "cases",
                "distribution",
                "guest_evidence",
                "guest_id",
                "image",
                "observed",
                "release",
                "snapshots",
            },
        )
        guest_id = _validate_id(cell["guest_id"], f"{location}.guest_id")
        _require(guest_id not in seen_guests, f"{location}.guest_id", "duplicate guest")
        seen_guests.add(guest_id)
        expected_id, expected_distribution, expected_release, expected_architecture = (
            expected_guest
        )
        _require(
            guest_id == expected_id,
            f"{location}.guest_id",
            "guest order or id differs from frozen matrix",
        )
        expected_fields = {
            "architecture": expected_architecture,
            "distribution": expected_distribution,
            "release": expected_release,
        }
        for field, expected in expected_fields.items():
            _require(
                cell[field] == expected,
                f"{location}.{field}",
                "differs from frozen matrix",
            )
        image = cell["image"]
        if image is not None:
            image = _strict_object(
                image,
                f"{location}.image",
                {"bytes", "provenance", "source", "source_digest"},
            )
            _validate_external_identity(image["bytes"], f"{location}.image.bytes")
            _validate_receipt_identity(
                image["provenance"], f"{location}.image.provenance"
            )
            _require(
                image["provenance"]["path"].startswith("mandatory/image_provenance/"),
                f"{location}.image.provenance.path",
                "must reside below the image-provenance evidence role",
            )
            _require(
                bool(_strict_string(image["source"], f"{location}.image.source")),
                f"{location}.image.source",
                "must not be empty",
            )
            source_digest = _strict_string(
                image["source_digest"], f"{location}.image.source_digest"
            )
            _require(
                SOURCE_DIGEST_RE.fullmatch(source_digest) is not None,
                f"{location}.image.source_digest",
                "invalid source digest",
            )
        observed = cell["observed"]
        if observed is not None:
            observed = _strict_object(
                observed,
                f"{location}.observed",
                {
                    "active_lsms",
                    "architecture",
                    "cgroup",
                    "distribution",
                    "filesystem",
                    "kernel",
                    "landlock_abi",
                    "release",
                    "systemd",
                },
            )
            for field in observed:
                _strict_string(observed[field], f"{location}.observed.{field}")
            for field, expected in expected_fields.items():
                _require(
                    observed[field] == expected,
                    f"{location}.observed.{field}",
                    "observed guest differs from the frozen cell",
                )
            _require(
                observed["landlock_abi"].isdigit(),
                f"{location}.observed.landlock_abi",
                "must be a decimal ABI number",
            )
        for field in ("guest_evidence", "snapshots"):
            references = _strict_list(cell[field], f"{location}.{field}")
            for index, reference in enumerate(references):
                _validate_receipt_identity(reference, f"{location}.{field}[{index}]")
        cases = _strict_list(cell["cases"], f"{location}.cases")
        _require(
            len(cases) == len(CASE_FAMILIES),
            f"{location}.cases",
            "must contain every frozen case",
        )
        seen_cases: set[str] = set()
        for case_index, (raw_case, expected_family) in enumerate(
            zip(cases, CASE_FAMILIES, strict=True)
        ):
            case_location = f"{location}.cases[{case_index}]"
            case = _strict_object(
                raw_case,
                case_location,
                {"evidence", "family", "result", "summary"},
            )
            family = _validate_id(case["family"], f"{case_location}.family")
            _require(
                family not in seen_cases, f"{case_location}.family", "duplicate case"
            )
            seen_cases.add(family)
            _require(
                family == expected_family,
                f"{case_location}.family",
                "case order or id differs from frozen matrix",
            )
            result = _strict_string(case["result"], f"{case_location}.result")
            _require(
                result in CASE_RESULTS, f"{case_location}.result", "invalid case result"
            )
            all_results.append(result)
            _require(
                bool(_strict_string(case["summary"], f"{case_location}.summary")),
                f"{case_location}.summary",
                "must not be empty",
            )
            evidence = _strict_list(case["evidence"], f"{case_location}.evidence")
            if result != "not_run":
                _require(
                    evidence,
                    f"{case_location}.evidence",
                    "executed or bounded case requires evidence",
                )
            for evidence_index, reference in enumerate(evidence):
                _validate_receipt_identity(
                    reference, f"{case_location}.evidence[{evidence_index}]"
                )
    return all_results


def _nonempty_string(value: Any, location: str) -> str:
    text = _strict_string(value, location)
    _require(bool(text.strip()), location, "must not be empty")
    return text


def validate_claim_contract(value: Any) -> dict[str, Any]:
    """Validate the checked-in frozen claim copied into an evidence bundle."""

    claim = _strict_object(
        value,
        "claim-contract",
        {
            "authority_use",
            "blockers",
            "claim_layers",
            "exclusions",
            "reconstructs_standing",
            "schema",
            "verdict",
        },
    )
    _require(
        claim["schema"] == "ag.clean-host-package-qualification-claim/v1",
        "claim-contract.schema",
        "unknown schema",
    )
    _require(
        claim["authority_use"] == AUTHORITY_USE, "claim-contract", "wrong authority use"
    )
    _require(claim["reconstructs_standing"] is False, "claim-contract", "must be false")
    _require(claim["verdict"] == "not_run", "claim-contract.verdict", "must be not_run")
    _require(
        claim["blockers"] == list(KNOWN_BLOCKERS),
        "claim-contract.blockers",
        "wrong blockers",
    )
    _require(
        claim["exclusions"] == list(CLAIM_EXCLUSIONS),
        "claim-contract.exclusions",
        "wrong exclusions",
    )
    layers = _strict_list(claim["claim_layers"], "claim-contract.claim_layers")
    _require(
        len(layers) == len(CLAIM_LAYERS),
        "claim-contract.claim_layers",
        "wrong layer count",
    )
    for index, (raw_layer, expected) in enumerate(
        zip(layers, CLAIM_LAYERS, strict=True)
    ):
        location = f"claim-contract.claim_layers[{index}]"
        layer = _strict_object(raw_layer, location, {"id", "required", "status"})
        _require(layer["id"] == expected[0], f"{location}.id", "wrong layer")
        _require(
            layer["required"] is expected[1],
            f"{location}.required",
            "wrong requirement",
        )
        _require(
            layer["status"] in ("not_run", "blocked"),
            f"{location}.status",
            "invalid starting status",
        )
    return claim


def _validate_claim(value: Any) -> list[str]:
    claim = _strict_object(
        value,
        "receipt.claim",
        {"blockers", "evidence", "exclusions", "layers"},
    )
    evidence = _validate_receipt_identity(claim["evidence"], "receipt.claim.evidence")
    _require(
        evidence["path"] == "inputs/claim.v1.json",
        "receipt.claim.evidence.path",
        "must bind the copied frozen claim",
    )
    blockers = _strict_list(claim["blockers"], "receipt.claim.blockers")
    _require(
        blockers == list(KNOWN_BLOCKERS),
        "receipt.claim.blockers",
        "must carry the exact frozen blockers",
    )
    exclusions = _strict_list(claim["exclusions"], "receipt.claim.exclusions")
    _require(
        exclusions == list(CLAIM_EXCLUSIONS),
        "receipt.claim.exclusions",
        "must carry the exact frozen exclusions",
    )
    layers = _strict_list(claim["layers"], "receipt.claim.layers")
    _require(
        len(layers) == len(CLAIM_LAYERS),
        "receipt.claim.layers",
        "must carry every frozen claim layer",
    )
    statuses: list[str] = []
    for index, (raw_layer, expected) in enumerate(
        zip(layers, CLAIM_LAYERS, strict=True)
    ):
        location = f"receipt.claim.layers[{index}]"
        layer = _strict_object(raw_layer, location, {"id", "required", "status"})
        _require(layer["id"] == expected[0], f"{location}.id", "wrong layer")
        _require(
            layer["required"] is expected[1],
            f"{location}.required",
            "wrong requirement bit",
        )
        status = _strict_string(layer["status"], f"{location}.status")
        _require(
            status in CLAIM_LAYER_RESULTS,
            f"{location}.status",
            "invalid layer result",
        )
        statuses.append(status)
    return statuses


def _validate_mandatory_evidence(value: Any) -> dict[str, list[dict[str, Any]]]:
    evidence = _strict_object(
        value,
        "receipt.mandatory_evidence",
        set(MANDATORY_EVIDENCE_CATEGORIES),
    )
    for category in MANDATORY_EVIDENCE_CATEGORIES:
        references = _strict_list(
            evidence[category], f"receipt.mandatory_evidence.{category}"
        )
        for index, reference in enumerate(references):
            validated = _validate_receipt_identity(
                reference,
                f"receipt.mandatory_evidence.{category}[{index}]",
            )
            _require(
                validated["path"].startswith(f"mandatory/{category}/"),
                f"receipt.mandatory_evidence.{category}[{index}].path",
                "must reside below its exact evidence-role directory",
            )
    return evidence


def _validate_case_references(value: Any, location: str) -> list[str]:
    references = _strict_list(value, location)
    valid = {f"{guest[0]}/{family}" for guest in GUESTS for family in CASE_FAMILIES}
    seen: set[str] = set()
    for index, reference in enumerate(references):
        reference = _strict_string(reference, f"{location}[{index}]")
        _require(reference in valid, f"{location}[{index}]", "unknown matrix case")
        _require(reference not in seen, f"{location}[{index}]", "duplicate case")
        seen.add(reference)
    return references


def validate_final_receipt(value: Any) -> dict[str, Any]:
    """Validate a final receipt without accepting the inert template schema."""

    receipt = _strict_object(
        value,
        "receipt",
        {
            "authority_use",
            "candidate",
            "claim",
            "controller_host",
            "defects",
            "dependency_inventory",
            "evidence_manifest",
            "harness",
            "mandatory_evidence",
            "matrix",
            "package_digest_history",
            "receipt_inventory",
            "reconstructs_standing",
            "repairs",
            "residual_gates",
            "schema",
            "phase1",
            "support_boundary",
            "verdict",
        },
    )
    _require(receipt["schema"] == RECEIPT_SCHEMA, "receipt.schema", "unknown schema")
    _require(
        receipt["authority_use"] == AUTHORITY_USE,
        "receipt.authority_use",
        "must be evidence_only",
    )
    _require(
        receipt["reconstructs_standing"] is False,
        "receipt.reconstructs_standing",
        "must be false",
    )
    candidate = _strict_object(
        receipt["candidate"], "receipt.candidate", {"final", "starting"}
    )
    _validate_source_cut(candidate["starting"], "receipt.candidate.starting")
    _validate_source_cut(candidate["final"], "receipt.candidate.final")
    _require(
        candidate["starting"]["worktree"] == "clean",
        "receipt.candidate.starting.worktree",
        "must be clean",
    )
    _require(
        candidate["final"]["worktree"] == "clean",
        "receipt.candidate.final.worktree",
        "must be clean",
    )
    claim_statuses = _validate_claim(receipt["claim"])
    phase1 = _validate_receipt_identity(receipt["phase1"], "receipt.phase1")
    _require(
        phase1["path"] == "inputs/phase1-starting-candidate.v1.json",
        "receipt.phase1.path",
        "must bind the copied canonical Phase 1 record",
    )
    mandatory_evidence = _validate_mandatory_evidence(receipt["mandatory_evidence"])
    controller_host = _strict_object(
        receipt["controller_host"],
        "receipt.controller_host",
        {"architecture", "distribution", "evidence", "hypervisor", "kernel"},
    )
    for field in ("architecture", "distribution", "hypervisor", "kernel"):
        _strict_string(controller_host[field], f"receipt.controller_host.{field}")
    controller_evidence = _strict_list(
        controller_host["evidence"], "receipt.controller_host.evidence"
    )
    _require(
        controller_evidence, "receipt.controller_host.evidence", "must not be empty"
    )
    for index, reference in enumerate(controller_evidence):
        _validate_receipt_identity(
            reference, f"receipt.controller_host.evidence[{index}]"
        )
    manifest = _validate_receipt_identity(
        receipt["evidence_manifest"], "receipt.evidence_manifest"
    )
    _require(
        manifest["path"] == "manifest.v1.json",
        "receipt.evidence_manifest.path",
        "must name root manifest",
    )
    harness = _strict_object(
        receipt["harness"],
        "receipt.harness",
        {
            "commit",
            "evidence",
            "publisher_evidence",
            "tree",
            "vm_fixture_evidence",
        },
    )
    _validate_git_id(harness["commit"], "receipt.harness.commit")
    _validate_git_id(harness["tree"], "receipt.harness.tree")
    _validate_receipt_identity(harness["evidence"], "receipt.harness.evidence")
    _validate_receipt_identity(
        harness["publisher_evidence"], "receipt.harness.publisher_evidence"
    )
    _validate_receipt_identity(
        harness["vm_fixture_evidence"], "receipt.harness.vm_fixture_evidence"
    )
    results = _validate_receipt_matrix(receipt["matrix"])
    package_history = _strict_list(
        receipt["package_digest_history"], "receipt.package_digest_history"
    )
    generations: set[int] = set()
    generation_records: dict[int, dict[str, Any]] = {}
    for index, raw_generation in enumerate(package_history):
        location = f"receipt.package_digest_history[{index}]"
        generation = _strict_object(
            raw_generation,
            location,
            {"artifacts", "generation", "reason", "source_commit", "source_tree"},
        )
        generation_number = _strict_int(
            generation["generation"], f"{location}.generation"
        )
        _require(
            generation_number > 0 and generation_number not in generations,
            f"{location}.generation",
            "must be unique and positive",
        )
        generations.add(generation_number)
        _nonempty_string(generation["reason"], f"{location}.reason")
        _validate_git_id(generation["source_commit"], f"{location}.source_commit")
        _validate_git_id(generation["source_tree"], f"{location}.source_tree")
        artifacts = _strict_list(generation["artifacts"], f"{location}.artifacts")
        _require(artifacts, f"{location}.artifacts", "must not be empty")
        for artifact_index, artifact in enumerate(artifacts):
            artifact_location = f"{location}.artifacts[{artifact_index}]"
            package = _strict_object(
                artifact,
                artifact_location,
                {"architecture", "identity", "kind", "name", "version"},
            )
            for field in ("kind", "name", "version"):
                _nonempty_string(package[field], f"{artifact_location}.{field}")
            _require(
                package["architecture"] in ("amd64", "arm64"),
                f"{artifact_location}.architecture",
                "must be a supported package architecture",
            )
            _validate_receipt_identity(
                package["identity"], f"{artifact_location}.identity"
            )
            _require(
                package["identity"]["path"].startswith(
                    f"packages/generation-{generation_number}/"
                ),
                f"{artifact_location}.identity.path",
                "must reside below its exact package-generation directory",
            )
        generation_records[generation_number] = generation
    if generations:
        _require(
            generations == set(range(1, len(generations) + 1)),
            "receipt.package_digest_history",
            "generations must be contiguous",
        )
        final_generation = generation_records[max(generations)]
        _require(
            final_generation["source_commit"] == candidate["final"]["commit"],
            "receipt.package_digest_history",
            "final package generation is from a different commit",
        )
        _require(
            final_generation["source_tree"] == candidate["final"]["tree"],
            "receipt.package_digest_history",
            "final package generation is from a different tree",
        )
    defects = _strict_list(receipt["defects"], "receipt.defects")
    defect_ids: set[str] = set()
    for index, raw_defect in enumerate(defects):
        location = f"receipt.defects[{index}]"
        defect = _strict_object(
            raw_defect,
            location,
            {"case_refs", "classification", "evidence", "id", "summary"},
        )
        defect_id = _validate_id(defect["id"], f"{location}.id")
        _require(defect_id not in defect_ids, f"{location}.id", "duplicate defect")
        defect_ids.add(defect_id)
        _require(
            defect["classification"] in DEFECT_CLASSES,
            f"{location}.classification",
            "invalid defect class",
        )
        _nonempty_string(defect["summary"], f"{location}.summary")
        _validate_case_references(defect["case_refs"], f"{location}.case_refs")
        evidence = _strict_list(defect["evidence"], f"{location}.evidence")
        _require(evidence, f"{location}.evidence", "must not be empty")
        for evidence_index, reference in enumerate(evidence):
            _validate_receipt_identity(
                reference, f"{location}.evidence[{evidence_index}]"
            )

    repairs = _strict_list(receipt["repairs"], "receipt.repairs")
    repair_ids: set[str] = set()
    repaired_defects: set[str] = set()
    for index, raw_repair in enumerate(repairs):
        location = f"receipt.repairs[{index}]"
        repair = _strict_object(
            raw_repair,
            location,
            {
                "after_generation",
                "before_generation",
                "classification",
                "defect_id",
                "evidence",
                "id",
                "summary",
            },
        )
        repair_id = _validate_id(repair["id"], f"{location}.id")
        _require(repair_id not in repair_ids, f"{location}.id", "duplicate repair")
        repair_ids.add(repair_id)
        defect_id = _validate_id(repair["defect_id"], f"{location}.defect_id")
        _require(
            defect_id in defect_ids or defect_id in KNOWN_BLOCKERS,
            f"{location}.defect_id",
            "does not name a recorded or frozen defect",
        )
        repaired_defects.add(defect_id)
        _require(
            repair["classification"] in DEFECT_CLASSES,
            f"{location}.classification",
            "invalid repair class",
        )
        _nonempty_string(repair["summary"], f"{location}.summary")
        evidence = _strict_list(repair["evidence"], f"{location}.evidence")
        _require(evidence, f"{location}.evidence", "must not be empty")
        for evidence_index, reference in enumerate(evidence):
            _validate_receipt_identity(
                reference, f"{location}.evidence[{evidence_index}]"
            )
        before = repair["before_generation"]
        after = repair["after_generation"]
        _require(
            before is None or (type(before) is int and before in generation_records),
            f"{location}.before_generation",
            "must be null or an existing package generation",
        )
        _require(
            after is None or (type(after) is int and after in generation_records),
            f"{location}.after_generation",
            "must be null or an existing package generation",
        )
        if before is not None and after is not None:
            _require(
                after == before + 1,
                location,
                "repair generations must be adjacent",
            )

    residual = _strict_list(receipt["residual_gates"], "receipt.residual_gates")
    residual_ids: set[str] = set()
    residual_case_refs: set[str] = set()
    for index, raw_gate in enumerate(residual):
        location = f"receipt.residual_gates[{index}]"
        gate = _strict_object(
            raw_gate,
            location,
            {
                "case_refs",
                "classification",
                "evidence",
                "id",
                "repair_surface",
                "summary",
            },
        )
        gate_id = _validate_id(gate["id"], f"{location}.id")
        _require(gate_id not in residual_ids, f"{location}.id", "duplicate gate")
        residual_ids.add(gate_id)
        _require(
            gate["classification"] in DEFECT_CLASSES,
            f"{location}.classification",
            "invalid residual-gate class",
        )
        _nonempty_string(gate["summary"], f"{location}.summary")
        _nonempty_string(gate["repair_surface"], f"{location}.repair_surface")
        case_refs = _validate_case_references(
            gate["case_refs"], f"{location}.case_refs"
        )
        residual_case_refs.update(case_refs)
        _require(
            case_refs or gate_id in KNOWN_BLOCKERS,
            f"{location}.case_refs",
            "must name an affected case or frozen blocker",
        )
        evidence = _strict_list(gate["evidence"], f"{location}.evidence")
        _require(evidence, f"{location}.evidence", "must not be empty")
        for evidence_index, reference in enumerate(evidence):
            _validate_receipt_identity(
                reference, f"{location}.evidence[{evidence_index}]"
            )

    dependencies = _strict_list(
        receipt["dependency_inventory"], "receipt.dependency_inventory"
    )
    _require(dependencies, "receipt.dependency_inventory", "must not be empty")
    dependency_ids: set[str] = set()
    dependency_classes: list[str] = []
    for index, item in enumerate(dependencies):
        location = f"receipt.dependency_inventory[{index}]"
        dependency = _strict_object(
            item, location, {"classification", "evidence", "id", "requirement"}
        )
        dependency_id = _validate_id(dependency["id"], f"{location}.id")
        _require(
            dependency_id not in dependency_ids,
            f"{location}.id",
            "duplicate dependency",
        )
        dependency_ids.add(dependency_id)
        classification = _strict_string(
            dependency["classification"], f"{location}.classification"
        )
        _require(
            classification in DEPENDENCY_CLASSES,
            f"{location}.classification",
            "invalid dependency class",
        )
        dependency_classes.append(classification)
        _nonempty_string(dependency["requirement"], f"{location}.requirement")
        refs = _strict_list(dependency["evidence"], f"{location}.evidence")
        _require(refs, f"{location}.evidence", "must not be empty")
        for evidence_index, reference in enumerate(refs):
            _validate_receipt_identity(
                reference, f"{location}.evidence[{evidence_index}]"
            )
    inventory = _strict_list(receipt["receipt_inventory"], "receipt.receipt_inventory")
    for index, reference in enumerate(inventory):
        _validate_receipt_identity(reference, f"receipt.receipt_inventory[{index}]")

    case_results_by_ref = {
        f"{cell['guest_id']}/{case['family']}": case["result"]
        for cell in receipt["matrix"]
        for case in cell["cases"]
    }
    for case_ref in residual_case_refs:
        _require(
            case_results_by_ref[case_ref] != "pass",
            "receipt.residual_gates.case_refs",
            f"residual gate points at a passing case: {case_ref}",
        )

    support_boundary = receipt["support_boundary"]
    if support_boundary is not None:
        support_boundary = _strict_object(
            support_boundary,
            "receipt.support_boundary",
            {
                "documented_predicate",
                "evidence",
                "guest_id",
                "observed_contradiction",
            },
        )
        boundary_guest = _validate_id(
            support_boundary["guest_id"], "receipt.support_boundary.guest_id"
        )
        _require(
            boundary_guest in {guest[0] for guest in GUESTS},
            "receipt.support_boundary.guest_id",
            "unknown guest",
        )
        _nonempty_string(
            support_boundary["documented_predicate"],
            "receipt.support_boundary.documented_predicate",
        )
        _nonempty_string(
            support_boundary["observed_contradiction"],
            "receipt.support_boundary.observed_contradiction",
        )
        boundary_evidence = _strict_list(
            support_boundary["evidence"], "receipt.support_boundary.evidence"
        )
        _require(
            boundary_evidence,
            "receipt.support_boundary.evidence",
            "must not be empty",
        )
        for index, reference in enumerate(boundary_evidence):
            _validate_receipt_identity(
                reference, f"receipt.support_boundary.evidence[{index}]"
            )

    verdict = _strict_string(receipt["verdict"], "receipt.verdict")
    _require(verdict in FINAL_VERDICTS, "receipt.verdict", "invalid final verdict")
    _require(
        verdict == "BLOCKED",
        "receipt.verdict",
        "this frozen claim is blocked-only while shipped_stranger_workflow has no production ingress; a success or support-boundary verdict requires a new claim schema",
    )
    _require(
        claim_statuses[2] == "blocked",
        "receipt.claim.layers[2].status",
        "shipped_stranger_workflow remains frozen blocked in this campaign",
    )
    _require(
        "unsupported" not in results,
        "receipt.matrix",
        "all four frozen cells are supported; this blocked-only campaign cannot emit an unsupported case",
    )
    _require(
        "production_artifact_admission_ingress_absent" in residual_ids,
        "receipt.residual_gates",
        "the frozen production-ingress blocker must remain residual",
    )
    _require(
        "production_artifact_admission_ingress_absent" not in repaired_defects,
        "receipt.repairs",
        "the frozen claim contains no shipped-ingress gate capable of closing this blocker",
    )
    all_pass = bool(results) and all(result == "pass" for result in results)
    unaccounted_blockers = set(KNOWN_BLOCKERS) - repaired_defects - residual_ids
    _require(
        not unaccounted_blockers,
        "receipt.claim.blockers",
        f"frozen blockers are neither repaired nor residual: {', '.join(sorted(unaccounted_blockers))}",
    )
    if verdict == "QUALIFIED":
        _require(all_pass, "receipt.verdict", "QUALIFIED requires every case to pass")
        _require(
            not repairs, "receipt.verdict", "QUALIFIED cannot contain candidate repairs"
        )
        _require(
            not residual, "receipt.verdict", "QUALIFIED cannot retain residual gates"
        )
        _require(
            bool(package_history),
            "receipt.verdict",
            "QUALIFIED requires a package generation",
        )
        _require(
            candidate["starting"] == candidate["final"],
            "receipt.candidate",
            "QUALIFIED requires the unchanged starting candidate",
        )
    elif verdict == "REQUALIFIED":
        _require(all_pass, "receipt.verdict", "REQUALIFIED requires every case to pass")
        _require(bool(repairs), "receipt.verdict", "REQUALIFIED requires a repair")
        _require(
            not residual, "receipt.verdict", "REQUALIFIED cannot retain residual gates"
        )
        _require(
            len(package_history) >= 2,
            "receipt.verdict",
            "REQUALIFIED requires package history",
        )
        for index, repair in enumerate(repairs):
            before = repair["before_generation"]
            after = repair["after_generation"]
            _require(
                before is not None and after is not None,
                f"receipt.repairs[{index}]",
                "REQUALIFIED repairs require before and after package generations",
            )
            before_digests = {
                artifact["identity"]["sha256"]
                for artifact in generation_records[before]["artifacts"]
                if artifact["kind"] == "deb"
            }
            after_digests = {
                artifact["identity"]["sha256"]
                for artifact in generation_records[after]["artifacts"]
                if artifact["kind"] == "deb"
            }
            _require(
                before_digests and after_digests and before_digests != after_digests,
                f"receipt.repairs[{index}]",
                "repair did not change the candidate package digests",
            )
    elif verdict == "BLOCKED":
        _require(bool(residual), "receipt.verdict", "BLOCKED requires a residual gate")
        _require(
            not all_pass or any(status != "pass" for status in claim_statuses),
            "receipt.verdict",
            "BLOCKED requires an incomplete matrix or claim layer",
        )
        _require(
            claim_statuses == ["blocked", "not_run", "blocked"],
            "receipt.claim.layers",
            "the bounded clean-build stop blocks package lifecycle, leaves live activation not run, and preserves the shipped-workflow blocker",
        )
        _require(
            not package_history,
            "receipt.package_digest_history",
            "a stop at candidate package generation cannot claim a package artifact",
        )
        terminal_ref = f"{GUESTS[0][0]}/{CASE_FAMILIES[0]}"
        _require(
            case_results_by_ref[terminal_ref] in ("fail", "blocked"),
            "receipt.matrix[0].cases[0].result",
            "the current campaign receipt must stop at the first clean-build gate",
        )
        _require(
            all(
                result == "not_run"
                for case_ref, result in case_results_by_ref.items()
                if case_ref != terminal_ref
            ),
            "receipt.matrix",
            "no later matrix case may execute after the bounded first-gate stop",
        )
        terminal_defects = [
            defect for defect in defects if terminal_ref in defect["case_refs"]
        ]
        _require(
            terminal_defects,
            "receipt.defects",
            "the first-gate stop requires an exact classified defect",
        )
        clean_build_gate = next(
            (
                gate
                for gate in residual
                if gate["id"] == "clean_offline_source_build_absent"
            ),
            None,
        )
        _require(
            clean_build_gate is not None
            and clean_build_gate["case_refs"] == [terminal_ref],
            "receipt.residual_gates",
            "the frozen clean-build blocker must bind the exact terminal matrix case",
        )
    else:
        _require(
            any(result == "unsupported" for result in results),
            "receipt.verdict",
            "UNSUPPORTED requires an unsupported case",
        )
        _require(
            bool(residual),
            "receipt.verdict",
            "UNSUPPORTED requires the documented boundary",
        )
        _require(
            support_boundary is not None,
            "receipt.support_boundary",
            "UNSUPPORTED requires a typed documented boundary",
        )
        _require(
            all(result in ("pass", "not_run", "unsupported") for result in results),
            "receipt.verdict",
            "UNSUPPORTED cannot conceal a failed or blocked supported case",
        )
        boundary_cell = next(
            cell
            for cell in receipt["matrix"]
            if cell["guest_id"] == support_boundary["guest_id"]
        )
        _require(
            boundary_cell["image"] is not None
            and boundary_cell["observed"] is not None,
            "receipt.support_boundary",
            "UNSUPPORTED requires observed image and guest facts",
        )
        _require(
            any(case["result"] == "unsupported" for case in boundary_cell["cases"]),
            "receipt.support_boundary.guest_id",
            "named guest has no unsupported case",
        )
    if verdict != "UNSUPPORTED":
        _require(
            support_boundary is None,
            "receipt.support_boundary",
            "is allowed only for UNSUPPORTED",
        )
    if verdict in ("QUALIFIED", "REQUALIFIED"):
        _require(
            all(status == "pass" for status in claim_statuses),
            "receipt.claim.layers",
            "qualification requires every required claim layer to pass",
        )
        _require(
            "undeclared_ambient_dependency" not in dependency_classes,
            "receipt.dependency_inventory",
            "an undeclared ambient dependency vetoes qualification",
        )
        for category in MANDATORY_EVIDENCE_CATEGORIES:
            _require(
                mandatory_evidence[category],
                f"receipt.mandatory_evidence.{category}",
                "qualification requires this evidence role",
            )
        final_generation = generation_records[max(generations)]
        final_debs = {
            artifact["architecture"]
            for artifact in final_generation["artifacts"]
            if artifact["kind"] == "deb" and artifact["name"] == "agent-governor-ng"
        }
        _require(
            final_debs == {"amd64", "arm64"},
            "receipt.package_digest_history",
            "final candidate requires exact amd64 and arm64 deb artifacts",
        )
        for cell_index, cell in enumerate(receipt["matrix"]):
            location = f"receipt.matrix[{cell_index}]"
            _require(
                cell["image"] is not None,
                f"{location}.image",
                "passing cell requires a pinned image",
            )
            _require(
                cell["observed"] is not None,
                f"{location}.observed",
                "passing cell requires observed guest facts",
            )
            _require(
                cell["guest_evidence"],
                f"{location}.guest_evidence",
                "passing cell requires guest facts",
            )
            _require(
                cell["snapshots"],
                f"{location}.snapshots",
                "passing cell requires snapshot boundaries",
            )
            observed = cell["observed"]
            _require(
                int(observed["landlock_abi"]) >= 3,
                f"{location}.observed.landlock_abi",
                "supported passing guest requires Landlock ABI >= 3",
            )
            systemd_match = re.match(r"([0-9]+)", observed["systemd"])
            _require(
                systemd_match is not None and int(systemd_match.group(1)) >= 252,
                f"{location}.observed.systemd",
                "supported passing guest requires systemd >= 252",
            )
            kernel_match = re.match(r"([0-9]+)\.([0-9]+)", observed["kernel"])
            _require(
                kernel_match is not None
                and (int(kernel_match.group(1)), int(kernel_match.group(2))) >= (6, 1),
                f"{location}.observed.kernel",
                "supported passing guest requires Linux >= 6.1",
            )
            for case_index, case in enumerate(cell["cases"]):
                _require(
                    case["evidence"],
                    f"{location}.cases[{case_index}].evidence",
                    "passing case requires evidence",
                )
    return receipt


def _collect_artifact_references(value: Any) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    if type(value) is dict:
        if set(value) == {"length", "path", "sha256"}:
            references.append(value)
        else:
            for nested in value.values():
                references.extend(_collect_artifact_references(nested))
    elif type(value) is list:
        for nested in value:
            references.extend(_collect_artifact_references(nested))
    return references


def _verify_reference(
    reference: dict[str, Any],
    manifest_entries: dict[str, dict[str, Any]],
    location: str,
) -> None:
    path = reference["path"]
    _require(
        path not in EXCLUDED_ROOT_PATHS,
        location,
        "must refer to manifest-covered evidence",
    )
    _require(path in manifest_entries, location, "does not name a manifest entry")
    enrolled = manifest_entries[path]
    _require(
        reference["sha256"] == enrolled["sha256"],
        location,
        "digest differs from manifest",
    )
    _require(
        reference["length"] == enrolled["length"],
        location,
        "length differs from manifest",
    )


def validate_verification_result(value: Any) -> dict[str, Any]:
    """Validate the exact post-seal verification marker shape."""

    result = _strict_object(
        value,
        "verification-result",
        {"manifest", "receipt", "schema", "valid", "verdict"},
    )
    _require(
        result["schema"] == VERIFICATION_SCHEMA,
        "verification-result.schema",
        "unknown schema",
    )
    _require(result["valid"] is True, "verification-result.valid", "must be true")
    manifest = _validate_receipt_identity(
        result["manifest"], "verification-result.manifest"
    )
    _require(
        manifest["path"] == "manifest.v1.json",
        "verification-result.manifest.path",
        "must name root manifest",
    )
    if result["receipt"] is None:
        _require(
            result["verdict"] is None,
            "verification-result.verdict",
            "must be null without receipt",
        )
    else:
        receipt = _validate_receipt_identity(
            result["receipt"], "verification-result.receipt"
        )
        _require(
            receipt["path"] == "receipt.v1.json",
            "verification-result.receipt.path",
            "must name root receipt",
        )
        verdict = _strict_string(result["verdict"], "verification-result.verdict")
        _require(
            verdict in FINAL_VERDICTS,
            "verification-result.verdict",
            "invalid final verdict",
        )
    return result


def _command_path_identity(path: str) -> tuple[str, str, str]:
    """Derive the only admitted guest/case/id identity from a command path."""

    parts = PurePosixPath(path).parts
    _require(
        len(parts) == 6
        and parts[0] == "guests"
        and parts[2] == "cases"
        and parts[4] == "commands",
        path,
        "command record is outside the initialized guest/case layout",
    )
    suffix = ".command.v1.json"
    _require(parts[5].endswith(suffix), path, "invalid command-record suffix")
    command_id = parts[5][: -len(suffix)]
    guest_id = _validate_id(parts[1], f"{path}.guest_id")
    case_family = _validate_id(parts[3], f"{path}.case_family")
    _validate_id(command_id, f"{path}.command_id")
    _require(guest_id in {guest[0] for guest in GUESTS}, path, "unknown guest")
    _require(case_family in CASE_FAMILIES, path, "unknown case family")
    return guest_id, case_family, command_id


def _typed_records_from_references(
    root: Path,
    references: list[dict[str, Any]],
    schemas: set[str],
    location: str,
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    records: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for index, reference in enumerate(references):
        if not reference["path"].endswith(".json"):
            continue
        value = load_canonical_json(root / reference["path"])
        schema = value.get("schema") if type(value) is dict else None
        if schema not in schemas:
            continue
        _require(
            schema not in records,
            f"{location}[{index}]",
            f"duplicate typed record for {schema}",
        )
        records[schema] = (value, reference)
    return records


def _successful_command(command: dict[str, Any], location: str) -> None:
    _require(
        command["matched_expectation"]
        and command["expected_outcome"] == {"kind": "exit_code", "value": 0}
        and command["outcome"]
        == {
            "exit_code": 0,
            "launch_error": None,
            "signal": None,
            "timed_out": False,
        },
        location,
        "must be one successful exact command",
    )


def _require_command_before(
    first: tuple[str, dict[str, Any]], second: tuple[str, dict[str, Any]]
) -> None:
    first_path, first_command = first
    second_path, second_command = second
    _require(
        first_command["ended_boottime_ns"] <= second_command["started_boottime_ns"],
        f"{first_path} -> {second_path}",
        "command evidence is not ordered at the controller boot-time boundary",
    )


def _terminal_command_by_id(
    command_records: dict[str, dict[str, Any]], command_id: str
) -> tuple[str, dict[str, Any]]:
    prefix = f"guests/{GUESTS[0][0]}/cases/{CASE_FAMILIES[0]}/commands/"
    matches = [
        (path, command)
        for path, command in command_records.items()
        if path.startswith(prefix) and command["command_id"] == command_id
    ]
    _require(
        len(matches) == 1,
        f"terminal command {command_id}",
        "requires exactly one terminal-case command record",
    )
    return matches[0]


def _absolute_argument_path(value: str, location: str) -> Path:
    path = Path(value)
    _require(path.is_absolute(), location, "must be absolute")
    return path


def _verify_first_gate_vm_chain(
    root: Path,
    receipt: dict[str, Any],
    manifest_entries: dict[str, dict[str, Any]],
    command_records: dict[str, dict[str, Any]],
    image_artifact: dict[str, Any],
    snapshot_artifact: dict[str, Any],
    archive_record: dict[str, Any],
) -> None:
    """Require one ordered real-VM chain for the bounded first build veto."""

    commands = {
        command_id: _terminal_command_by_id(command_records, command_id)
        for command_id in FIRST_GATE_COMMAND_IDS
    }
    for command_id in (
        "fixture-render-nocloud",
        "nocloud-iso-create",
        "vm-overlay-create",
        "vm-launch",
        "fixture-ssh-readiness",
        "guest-apt-update",
        "guest-build-dependency-install",
        "candidate-archive-transfer",
        "guest-archive-sha256",
        "extract-candidate-archive",
        "source-tree-init",
        "source-tree-add",
        "source-tree-write",
        "guest-facts",
        "vm-shutdown",
        "vm-exit-wait",
        "snapshot-convert",
        "snapshot-check",
        "snapshot-info",
    ):
        _successful_command(commands[command_id][1], commands[command_id][0])

    base_image_path = root / image_artifact["path"]
    overlay_path_text = commands["vm-overlay-create"][1]["argv"][-1]
    overlay_path = _absolute_argument_path(
        overlay_path_text, "vm-overlay-create overlay"
    )
    _require(
        not overlay_path.is_relative_to(root),
        "vm-overlay-create overlay",
        "mutable VM overlay must remain outside the sealed evidence root",
    )
    _require(
        commands["vm-overlay-create"][1]["argv"]
        == [
            "/usr/bin/qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(base_image_path),
            str(overlay_path),
        ],
        commands["vm-overlay-create"][0],
        "is not the exact fresh overlay creation command",
    )
    _require(
        commands["vm-overlay-create"][1]["observed_inputs"][0]["sha256"]
        == image_artifact["sha256"],
        commands["vm-overlay-create"][0],
        "did not observe the sealed base-image bytes",
    )

    launch_path, launch = commands["vm-launch"]
    launch_argv = launch["argv"]
    _require(len(launch_argv) == 33, launch_path, "QEMU argv length is not exact")
    fixed_launch = {
        0: "/usr/bin/qemu-system-x86_64",
        1: "-name",
        2: "ag-ng-debian-12-amd64",
        3: "-uuid",
        5: "-machine",
        6: "q35,accel=kvm",
        7: "-cpu",
        8: "host",
        9: "-smp",
        10: "4",
        11: "-m",
        12: "8192",
        13: "-display",
        14: "none",
        15: "-serial",
        17: "-monitor",
        18: "none",
        19: "-no-reboot",
        20: "-daemonize",
        21: "-pidfile",
        23: "-qmp",
        25: "-drive",
        27: "-drive",
        29: "-netdev",
        31: "-device",
        32: "virtio-net-pci,netdev=net0",
    }
    _require(
        all(launch_argv[index] == value for index, value in fixed_launch.items()),
        launch_path,
        "does not use the frozen daemonized KVM launch envelope",
    )
    _require(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            launch_argv[4],
        )
        is not None,
        launch_path,
        "QEMU UUID is malformed",
    )
    _require(
        launch_argv[16].startswith("file:"), launch_path, "serial log is not a file"
    )
    serial_path = _absolute_argument_path(
        launch_argv[16].removeprefix("file:"), f"{launch_path}.serial"
    )
    pid_path = _absolute_argument_path(launch_argv[22], f"{launch_path}.pidfile")
    qmp_argument = launch_argv[24]
    _require(
        qmp_argument.startswith("unix:")
        and qmp_argument.endswith(",server=on,wait=off"),
        launch_path,
        "QMP endpoint is not exact",
    )
    qmp_path = _absolute_argument_path(
        qmp_argument.removeprefix("unix:").removesuffix(",server=on,wait=off"),
        f"{launch_path}.qmp",
    )
    _require(
        launch_argv[26] == f"if=virtio,format=qcow2,file={overlay_path},cache=none",
        launch_path,
        "QEMU did not boot the freshly created overlay",
    )
    nocloud_prefix = "if=virtio,format=raw,readonly=on,file="
    _require(
        launch_argv[28].startswith(nocloud_prefix),
        launch_path,
        "QEMU NoCloud drive is not immutable",
    )
    nocloud_path = _absolute_argument_path(
        launch_argv[28].removeprefix(nocloud_prefix), f"{launch_path}.nocloud"
    )
    net_match = re.fullmatch(
        r"user,id=net0,hostfwd=tcp:127\.0\.0\.1:([0-9]+)-:22", launch_argv[30]
    )
    _require(net_match is not None, launch_path, "SSH forwarding is not exact")
    forwarded_port = int(net_match.group(1))
    _require(1 <= forwarded_port <= 65535, launch_path, "SSH port is invalid")
    for evidence_path, location in (
        (serial_path, "serial log"),
        (pid_path, "QEMU pidfile"),
        (nocloud_path, "NoCloud image"),
    ):
        try:
            relative = evidence_path.relative_to(root).as_posix()
        except ValueError as error:
            raise QualificationError(
                f"{location}: is outside the evidence root"
            ) from error
        _require(
            relative in manifest_entries,
            location,
            "is not manifest-covered",
        )
    _require(
        launch["observed_inputs"][0]["requested_path"] == str(nocloud_path),
        launch_path,
        "did not observe the immutable NoCloud bytes",
    )
    _require(
        not qmp_path.is_relative_to(root),
        launch_path,
        "live QMP socket must remain outside the evidence tree",
    )

    render_path, render = commands["fixture-render-nocloud"]
    seed_root = root / "mandatory/hypervisor_and_host/nocloud"
    public_key_path = root / "mandatory/hypervisor_and_host/fixture.pub"
    expected_render_argv = [
        "/usr/bin/python3",
        str(root / "inputs/vm_fixture.py"),
        "render-nocloud",
        "--output-dir",
        str(seed_root),
        "--instance-id",
        "agq-debian-12-amd64",
        "--hostname",
        "agq-debian-12-amd64",
        "--username",
        "agqual",
        "--authorized-key-file",
        str(public_key_path),
    ]
    _require(
        render["argv"] == expected_render_argv,
        render_path,
        "NoCloud renderer argv is not exact",
    )
    _require(
        len(render["observed_inputs"]) == 2
        and render["observed_inputs"][1]["requested_path"] == str(public_key_path),
        render_path,
        "NoCloud renderer did not observe the sealed public key",
    )
    fixture_path = seed_root / "fixture.v1.json"
    fixture = _strict_object(
        load_canonical_json(fixture_path),
        "NoCloud fixture",
        {
            "authorized_key",
            "files",
            "hostname",
            "instance_id",
            "private_key_copied",
            "schema",
            "username",
        },
    )
    _require(
        fixture["schema"] == "ag.clean-host-nocloud-fixture/v1"
        and fixture["instance_id"] == "agq-debian-12-amd64"
        and fixture["hostname"] == "agq-debian-12-amd64"
        and fixture["username"] == "agqual"
        and fixture["private_key_copied"] is False,
        "NoCloud fixture",
        "identity or private-key boundary is wrong",
    )
    public_key_fields = public_key_path.read_bytes().strip().split()
    _require(
        len(public_key_fields) >= 2,
        "NoCloud public key",
        "does not contain an OpenSSH type and payload",
    )
    normalized_public_key = b" ".join(public_key_fields[:2]) + b"\n"
    try:
        normalized_public_key_text = normalized_public_key.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise QualificationError("NoCloud public key: must be ASCII") from error

    def byte_identity(payload: bytes) -> dict[str, Any]:
        return {
            "length": len(payload),
            "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        }

    _require(
        fixture["authorized_key"] == byte_identity(normalized_public_key),
        "NoCloud fixture.authorized_key",
        "does not identify the admitted public key",
    )
    meta_data = (
        'instance-id: "agq-debian-12-amd64"\nlocal-hostname: "agq-debian-12-amd64"\n'
    ).encode()
    user_data = (
        "#cloud-config\n"
        "disable_root: true\n"
        "growpart:\n"
        '  devices: ["/"]\n'
        "  ignore_growroot_disabled: false\n"
        '  mode: "auto"\n'
        'hostname: "agq-debian-12-amd64"\n'
        "package_update: false\n"
        "package_upgrade: false\n"
        "preserve_hostname: false\n"
        "resize_rootfs: true\n"
        "ssh_pwauth: false\n"
        "users:\n"
        '  - name: "agqual"\n'
        '    groups: ["sudo"]\n'
        "    lock_passwd: true\n"
        '    shell: "/bin/bash"\n'
        '    sudo: ["ALL=(ALL) NOPASSWD:ALL"]\n'
        "    ssh_authorized_keys:\n"
        f"      - {json.dumps(normalized_public_key_text)}\n"
    ).encode()
    _require(
        (seed_root / "meta-data").read_bytes() == meta_data
        and (seed_root / "user-data").read_bytes() == user_data
        and fixture["files"]
        == {
            "meta-data": byte_identity(meta_data),
            "user-data": byte_identity(user_data),
        }
        and (root / render["stdout"]["path"]).read_bytes() == fixture_path.read_bytes(),
        "NoCloud fixture",
        "rendered seed bytes or renderer stdout differ",
    )
    iso_path, iso_command = commands["nocloud-iso-create"]
    _require(
        iso_command["argv"]
        == [
            "/usr/bin/xorriso",
            "-as",
            "mkisofs",
            "-output",
            str(nocloud_path),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            str(seed_root / "user-data"),
            str(seed_root / "meta-data"),
        ],
        iso_path,
        "NoCloud ISO producer argv is not exact",
    )
    _require(
        [item["requested_path"] for item in iso_command["observed_inputs"]]
        == [str(seed_root / "user-data"), str(seed_root / "meta-data")],
        iso_path,
        "NoCloud ISO producer did not observe both exact seed inputs",
    )

    readiness_path, readiness = commands["fixture-ssh-readiness"]
    _require(
        readiness["argv"].count("--output") == 1,
        readiness_path,
        "readiness command requires one output",
    )
    readiness_output_index = readiness["argv"].index("--output") + 1
    _require(
        readiness_output_index < len(readiness["argv"]),
        readiness_path,
        "readiness output path is missing",
    )
    readiness_record_path = Path(readiness["argv"][readiness_output_index])
    try:
        readiness_relative = readiness_record_path.relative_to(root).as_posix()
    except ValueError as error:
        raise QualificationError(
            f"{readiness_path}: readiness output is outside the evidence root"
        ) from error
    _require(
        readiness_relative in manifest_entries,
        readiness_path,
        "readiness output is not manifest-covered",
    )
    readiness_record = _strict_object(
        load_canonical_json(readiness_record_path),
        "SSH readiness record",
        {
            "attempts",
            "deadline_overrun_ns",
            "duration_ms",
            "finished_utc",
            "identity_file",
            "known_hosts",
            "poll_interval_ms",
            "remote_argv",
            "rendered_remote_command",
            "result",
            "schema",
            "started_utc",
            "target",
            "timeout_seconds",
        },
    )
    _require(
        readiness_record["schema"] == "ag.clean-host-ssh-readiness/v1"
        and readiness_record["result"] == "ready"
        and readiness_record["target"]
        == {"host": "127.0.0.1", "port": forwarded_port, "username": "agqual"}
        and readiness_record["timeout_seconds"] == 110
        and readiness_record["poll_interval_ms"] == 250
        and readiness_record["deadline_overrun_ns"] == 0
        and readiness_record["remote_argv"] == ["/usr/bin/true"]
        and readiness_record["rendered_remote_command"] == "/usr/bin/true",
        readiness_path,
        "typed readiness boundary differs from the fixed VM probe",
    )
    identity_file = readiness_record["identity_file"]
    known_hosts = readiness_record["known_hosts"]
    _require(
        type(identity_file) is dict
        and type(known_hosts) is dict
        and type(identity_file.get("path")) is str
        and type(known_hosts.get("path")) is str,
        readiness_path,
        "readiness does not bind identity and known-host files",
    )
    expected_readiness_argv = [
        "/usr/bin/python3",
        str(root / "inputs/vm_fixture.py"),
        "wait-ssh",
        "--output",
        str(readiness_record_path),
        "--host",
        "127.0.0.1",
        "--port",
        str(forwarded_port),
        "--username",
        "agqual",
        "--identity-file",
        identity_file["path"],
        "--known-hosts-file",
        known_hosts["path"],
        "--ssh-executable",
        "/usr/bin/ssh",
        "--timeout-seconds",
        "110",
        "--poll-interval-ms",
        "250",
        "--connect-timeout-ms",
        "1000",
        "--ssh-attempt-timeout-seconds",
        "10",
        "--",
        "/usr/bin/true",
    ]
    _require(
        readiness["argv"] == expected_readiness_argv
        and len(readiness["observed_inputs"]) == 2
        and readiness["observed_inputs"][1]["requested_path"] == identity_file["path"],
        readiness_path,
        "readiness producer argv or observed identity is not exact",
    )
    attempts = readiness_record["attempts"]
    expected_probe_argv = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=1",
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
        f"UserKnownHostsFile={known_hosts['path']}",
        "-i",
        identity_file["path"],
        "-p",
        str(forwarded_port),
        "agqual@127.0.0.1",
        "/usr/bin/true",
    ]
    _require(
        type(attempts) is list
        and bool(attempts)
        and type(attempts[-1]) is dict
        and type(attempts[-1].get("tcp")) is dict
        and attempts[-1]["tcp"].get("outcome") == "connected"
        and type(attempts[-1].get("ssh")) is dict
        and attempts[-1]["ssh"].get("outcome") == "exit"
        and attempts[-1]["ssh"].get("exit_code") == 0
        and attempts[-1]["ssh"].get("argv") == expected_probe_argv
        and type(attempts[-1]["ssh"].get("executable")) is dict
        and attempts[-1]["ssh"]["executable"].get("path") == "/usr/bin/ssh",
        readiness_path,
        "readiness has no successful pinned-SSH attempt",
    )

    transfer_path, transfer = commands["candidate-archive-transfer"]
    archive_path = root / archive_record["archive"]["path"]
    measurement_path, measurement = commands["guest-archive-sha256"]
    target_index = _exact_ssh_prefix_end(measurement["argv"])
    _require(target_index is not None, measurement_path, "invalid SSH prefix")
    ssh_prefix = measurement["argv"][: target_index + 1]
    identity_path = ssh_prefix[ssh_prefix.index("-i") + 1]
    known_hosts_argument = next(
        item for item in ssh_prefix if item.startswith("UserKnownHostsFile=")
    )
    known_hosts_path = known_hosts_argument.split("=", 1)[1]
    port = ssh_prefix[ssh_prefix.index("-p") + 1]
    for command_id, tail in (
        ("guest-apt-update", SSH_APT_UPDATE_TAIL),
        ("guest-build-dependency-install", SSH_BUILD_DEPENDENCY_INSTALL_TAIL),
    ):
        command_path, command = commands[command_id]
        _require(
            is_exact_ssh_tail(command["argv"], tail),
            command_path,
            "package-manager preparation argv is not exact",
        )
    scp_prefix = [
        "/usr/bin/scp",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        known_hosts_argument,
        "-i",
        identity_path,
        "-P",
        port,
        str(archive_path),
        f"{SSH_BUILD_TARGET}:{GUEST_CANDIDATE_ARCHIVE_PATH}",
    ]
    _require(transfer["argv"] == scp_prefix, transfer_path, "SCP argv is not exact")
    _require(
        transfer["observed_inputs"][:2] == measurement["observed_inputs"]
        and transfer["observed_inputs"][2]["sha256"]
        == archive_record["archive"]["sha256"],
        transfer_path,
        "SCP did not bind the readiness SSH inputs and sealed source archive",
    )
    _require(
        readiness_record["identity_file"]["path"] == identity_path
        and readiness_record["known_hosts"]["path"] == known_hosts_path,
        readiness_path,
        "readiness inputs differ from the fixed SSH/SCP boundary",
    )
    for command_path, command in command_records.items():
        if command["argv"][0] != "/usr/bin/ssh":
            continue
        command_target = _exact_ssh_prefix_end(command["argv"])
        _require(
            command_target is not None
            and command["argv"][: command_target + 1] == ssh_prefix
            and command["observed_inputs"] == measurement["observed_inputs"],
            command_path,
            "terminal SSH command does not reuse the measured readiness boundary",
        )
        _require_command_before(
            commands["fixture-ssh-readiness"], (command_path, command)
        )
        _require_command_before((command_path, command), commands["vm-shutdown"])

    for command_id, tail in (
        ("terminal-build-refusal", SSH_BUILD_REMOTE_TAILS[0]),
        ("terminal-dpkg-build-refusal", SSH_BUILD_REMOTE_TAILS[1]),
    ):
        command_path, command = commands[command_id]
        _require(
            is_exact_ssh_tail(command["argv"], tail),
            command_path,
            "build command id does not name its exact governed tail",
        )
    check_path, check_command = commands["terminal-build-refusal"]
    package_path, package_command = commands["terminal-dpkg-build-refusal"]
    try:
        check_stderr = (root / check_command["stderr"]["path"]).read_text(
            encoding="utf-8", errors="strict"
        )
        package_stderr = (root / package_command["stderr"]["path"]).read_text(
            encoding="utf-8", errors="strict"
        )
    except UnicodeDecodeError as error:
        raise QualificationError("package-build stderr: must be UTF-8") from error
    _require(
        check_stderr.strip() == EXPECTED_BUILD_DEPENDENCY_REFUSAL,
        f"{check_path}.stderr",
        "does not isolate the exact cargo/rustc version shortfall",
    )
    unmet_lines = [
        line.strip()
        for line in package_stderr.splitlines()
        if "Unmet build dependencies:" in line
    ]
    _require(
        unmet_lines == [EXPECTED_BUILD_DEPENDENCY_REFUSAL]
        and "build dependencies/conflicts unsatisfied; aborting" in package_stderr,
        f"{package_path}.stderr",
        "does not isolate the same exact cargo/rustc version shortfall",
    )

    shutdown_path, shutdown = commands["vm-shutdown"]
    _require(
        shutdown["argv"].count("--output") == 1,
        shutdown_path,
        "QMP command requires one output",
    )
    qmp_output_index = shutdown["argv"].index("--output") + 1
    _require(
        qmp_output_index < len(shutdown["argv"]),
        shutdown_path,
        "QMP output path is missing",
    )
    expected_shutdown_argv = [
        "/usr/bin/python3",
        str(root / "inputs/vm_fixture.py"),
        "qmp",
        "--output",
        shutdown["argv"][qmp_output_index],
        "--socket",
        str(qmp_path),
        "--operation",
        "quit",
        "--timeout-seconds",
        "10",
    ]
    _require(
        shutdown["argv"] == expected_shutdown_argv,
        shutdown_path,
        "QMP quit argv is not exact",
    )
    qmp_output_path = _absolute_argument_path(
        shutdown["argv"][qmp_output_index], f"{shutdown_path}.output"
    )
    try:
        qmp_relative = qmp_output_path.relative_to(root).as_posix()
    except ValueError as error:
        raise QualificationError(
            f"{shutdown_path}: QMP output is outside the evidence root"
        ) from error
    _require(
        qmp_relative in manifest_entries,
        shutdown_path,
        "QMP output is not manifest-covered",
    )
    qmp_record = _strict_object(
        load_canonical_json(qmp_output_path),
        "QMP quit record",
        {
            "duration_ms",
            "finished_utc",
            "operation",
            "outcome",
            "response",
            "schema",
            "socket",
            "started_utc",
            "timeout_seconds",
            "transcript",
        },
    )
    _require(
        qmp_record.get("schema") == "ag.clean-host-qmp-operation/v1"
        and qmp_record.get("operation") == "quit"
        and qmp_record.get("outcome") == "accepted"
        and qmp_record.get("socket") == str(qmp_path),
        shutdown_path,
        "QMP output does not attest accepted quit",
    )
    _require(
        (root / shutdown["stdout"]["path"]).read_bytes()
        == qmp_output_path.read_bytes(),
        shutdown_path,
        "QMP command stdout differs from its typed output",
    )
    qmp_sends = [
        item.get("message")
        for item in qmp_record.get("transcript", [])
        if type(item) is dict and item.get("direction") == "send"
    ]
    _require(
        qmp_sends
        == [
            {"execute": "qmp_capabilities", "id": "ag-ng-capabilities"},
            {"execute": "quit", "id": "ag-ng-command"},
        ],
        shutdown_path,
        "QMP transcript does not contain the exact negotiated quit request",
    )
    _require(
        (
            qmp_record["response"] == {"id": "ag-ng-command", "return": {}}
            or qmp_record["response"]
            == {"accepted_without_reply": "peer_closed_after_quit_request"}
        ),
        shutdown_path,
        "QMP quit response is not an admitted success form",
    )
    hypervisor_paths = {
        ref["path"] for ref in receipt["mandatory_evidence"]["hypervisor_and_host"]
    }
    _require(
        {
            qmp_relative,
            serial_path.relative_to(root).as_posix(),
            pid_path.relative_to(root).as_posix(),
            nocloud_path.relative_to(root).as_posix(),
            readiness_record_path.relative_to(root).as_posix(),
            public_key_path.relative_to(root).as_posix(),
            fixture_path.relative_to(root).as_posix(),
            (seed_root / "meta-data").relative_to(root).as_posix(),
            (seed_root / "user-data").relative_to(root).as_posix(),
        }
        <= hypervisor_paths,
        "receipt.mandatory_evidence.hypervisor_and_host",
        "omits part of the VM launch/readiness/shutdown evidence",
    )
    try:
        pid_text = pid_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise QualificationError(
            f"QEMU pidfile: cannot read ASCII PID: {error}"
        ) from error
    _require(pid_text.isdigit() and int(pid_text) > 1, "QEMU pidfile", "is invalid")
    wait_path, wait_command = commands["vm-exit-wait"]
    _require(
        wait_command["argv"]
        == [
            "/usr/bin/tail",
            f"--pid={pid_text}",
            "--follow=name",
            "--sleep-interval=0.1",
            "/dev/null",
        ],
        wait_path,
        "does not wait for the launched QEMU process",
    )

    snapshot_path = root / snapshot_artifact["path"]
    _require(snapshot_artifact["length"] > 0, "snapshot artifact", "must be nonempty")
    convert_path, convert = commands["snapshot-convert"]
    _require(
        convert["argv"]
        == [
            "/usr/bin/qemu-img",
            "convert",
            "-f",
            "qcow2",
            "-O",
            "qcow2",
            str(overlay_path),
            str(snapshot_path),
        ],
        convert_path,
        "is not the exact standalone snapshot conversion",
    )
    for command_id, exact_argv in (
        (
            "snapshot-check",
            ["/usr/bin/qemu-img", "check", "--output=json", str(snapshot_path)],
        ),
        (
            "snapshot-info",
            [
                "/usr/bin/qemu-img",
                "info",
                "--output=json",
                "--backing-chain",
                str(snapshot_path),
            ],
        ),
    ):
        command_path, command = commands[command_id]
        _require(
            command["argv"] == exact_argv, command_path, "qemu-img argv is not exact"
        )
        _require(
            command["observed_inputs"][0]["sha256"] == snapshot_artifact["sha256"],
            command_path,
            "did not observe the sealed snapshot bytes",
        )
    info_path, info_command = commands["snapshot-info"]
    try:
        info = json.loads((root / info_command["stdout"]["path"]).read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(
            f"{info_path}.stdout: invalid qemu-img JSON: {error}"
        ) from error
    _require(
        type(info) is list
        and len(info) == 1
        and type(info[0]) is dict
        and info[0].get("format") == "qcow2"
        and type(info[0].get("virtual-size")) is int
        and info[0]["virtual-size"] > 0
        and "backing-filename" not in info[0]
        and "full-backing-filename" not in info[0],
        f"{info_path}.stdout",
        "does not describe one standalone qcow2 image",
    )
    check_path, check_command = commands["snapshot-check"]
    try:
        check = json.loads((root / check_command["stdout"]["path"]).read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(
            f"{check_path}.stdout: invalid qemu-img JSON: {error}"
        ) from error
    _require(
        type(check) is dict
        and check.get("check-errors") == 0
        and check.get("corruptions") in (None, 0)
        and check.get("leaks") in (None, 0),
        f"{check_path}.stdout",
        "qemu-img check did not report a clean snapshot",
    )

    ordered = [
        commands["fixture-render-nocloud"],
        commands["nocloud-iso-create"],
        commands["vm-overlay-create"],
        commands["vm-launch"],
        commands["fixture-ssh-readiness"],
        commands["guest-apt-update"],
        commands["guest-build-dependency-install"],
        commands["candidate-archive-transfer"],
        commands["guest-archive-sha256"],
        commands["extract-candidate-archive"],
        commands["source-tree-init"],
        commands["source-tree-add"],
        commands["source-tree-write"],
        commands["guest-facts"],
        commands["terminal-build-refusal"],
        commands["terminal-dpkg-build-refusal"],
        commands["vm-shutdown"],
        commands["vm-exit-wait"],
        commands["snapshot-convert"],
        commands["snapshot-check"],
        commands["snapshot-info"],
    ]
    for first, second in zip(ordered, ordered[1:]):
        _require_command_before(first, second)


def _verify_blocked_typed_evidence(
    root: Path,
    receipt: dict[str, Any],
    manifest_entries: dict[str, dict[str, Any]],
    command_records: dict[str, dict[str, Any]],
    build_commands: list[tuple[str, dict[str, Any]]],
) -> None:
    """Bind the first-gate assertions to exact typed, sealed evidence."""

    terminal = receipt["matrix"][0]
    image = terminal["image"]
    _require(image is not None, "receipt.matrix[0].image", "must be present")
    provenance = validate_image_provenance_record(
        load_canonical_json(root / image["provenance"]["path"])
    )
    _require(
        provenance
        == {
            "artifact": provenance["artifact"],
            "bytes": image["bytes"],
            "guest_id": GUESTS[0][0],
            "schema": IMAGE_PROVENANCE_SCHEMA,
            "source": image["source"],
            "source_digest": image["source_digest"],
        },
        "receipt.matrix[0].image",
        "differs from its typed image-provenance record",
    )
    _verify_reference(
        provenance["artifact"], manifest_entries, "image-provenance.artifact"
    )
    _require(
        {
            "length": provenance["artifact"]["length"],
            "sha256": provenance["artifact"]["sha256"],
        }
        == image["bytes"],
        "image-provenance.artifact",
        "differs from the receipt image identity",
    )
    source_algorithm = provenance["source_digest"].split(":", 1)[0]
    source_digest, source_length = digest_regular_file_algorithm(
        root / provenance["artifact"]["path"], source_algorithm
    )
    _require(
        source_digest == provenance["source_digest"]
        and source_length == provenance["artifact"]["length"],
        "image-provenance.source_digest",
        "does not measure the manifest-covered VM image artifact",
    )
    image_provenance_paths = {
        reference["path"]
        for reference in receipt["mandatory_evidence"]["image_provenance"]
    }
    _require(
        {image["provenance"]["path"], provenance["artifact"]["path"]}
        <= image_provenance_paths,
        "receipt.mandatory_evidence.image_provenance",
        "does not contain the exact typed image record",
    )

    guest_records = _typed_records_from_references(
        root,
        terminal["guest_evidence"],
        {GUEST_FACTS_BINDING_SCHEMA, CANDIDATE_ARCHIVE_SCHEMA},
        "receipt.matrix[0].guest_evidence",
    )
    _require(
        set(guest_records) == {GUEST_FACTS_BINDING_SCHEMA, CANDIDATE_ARCHIVE_SCHEMA},
        "receipt.matrix[0].guest_evidence",
        "must contain exactly one typed guest-facts and candidate-archive record",
    )
    facts_value, facts_ref = guest_records[GUEST_FACTS_BINDING_SCHEMA]
    facts = validate_guest_facts_binding_record(facts_value)
    _require(
        facts["guest_id"] == GUESTS[0][0] and facts["observed"] == terminal["observed"],
        "receipt.matrix[0].observed",
        "differs from the typed guest-facts record",
    )
    _verify_reference(
        facts["observation"], manifest_entries, "guest-facts-binding.observation"
    )
    direct_probe = validate_guest_facts_record(
        load_canonical_json(root / facts["observation"]["path"])
    )
    _require(
        direct_probe["guest_id"] == facts["guest_id"]
        and direct_probe["observed"] == facts["observed"],
        "guest-facts-binding.observation",
        "differs from the bound direct guest-probe output",
    )
    facts_commands = [
        (path, command)
        for path, command in command_records.items()
        if command["stdout"] == facts["observation"]
        and is_exact_ssh_tail(command["argv"], SSH_GUEST_FACTS_TAIL)
        and command["matched_expectation"]
        and command["expected_outcome"] == {"kind": "exit_code", "value": 0}
        and command["outcome"]["exit_code"] == 0
    ]
    _require(
        len(facts_commands) == 1,
        "guest-facts-binding.observation",
        "requires exactly one successful fixed guest-probe command",
    )
    observed = facts["observed"]
    _require(
        int(observed["landlock_abi"]) >= 3
        and "landlock" in {item.strip() for item in observed["active_lsms"].split(",")},
        "guest-facts.observed",
        "supported clean guest requires active Landlock ABI >= 3",
    )
    systemd_match = re.match(r"([0-9]+)", observed["systemd"])
    _require(
        systemd_match is not None and int(systemd_match.group(1)) >= 252,
        "guest-facts.observed.systemd",
        "supported clean guest requires systemd >= 252",
    )
    kernel_match = re.match(r"([0-9]+)\.([0-9]+)", observed["kernel"])
    _require(
        kernel_match is not None
        and (int(kernel_match.group(1)), int(kernel_match.group(2))) >= (6, 1),
        "guest-facts.observed.kernel",
        "supported clean guest requires Linux >= 6.1",
    )
    _require(
        observed["cgroup"].startswith("unified-v2:/"),
        "guest-facts.observed.cgroup",
        "supported clean guest requires the direct probe's unified-v2 path",
    )
    filesystem = observed["filesystem"]
    _require(
        filesystem.startswith("ext4 mount_options=")
        and " source=" in filesystem
        and " super_options=" in filesystem,
        "guest-facts.observed.filesystem",
        "the bounded storage variant requires the direct probe's ext4 root facts",
    )

    archive_value, archive_record_ref = guest_records[CANDIDATE_ARCHIVE_SCHEMA]
    archive = validate_candidate_archive_record(archive_value)
    _require(
        archive["guest_id"] == GUESTS[0][0]
        and archive["starting_source"] == receipt["candidate"]["starting"]
        and archive["final_source"] == receipt["candidate"]["final"],
        "candidate-archive",
        "does not bind the exact starting and final source identities",
    )
    _verify_reference(archive["archive"], manifest_entries, "candidate-archive.archive")
    _require(
        archive["archive"]["path"].startswith("mandatory/test_results/"),
        "candidate-archive.archive.path",
        "must remain in the typed test-results evidence role",
    )
    object_format = "sha1" if len(archive["final_source"]["tree"]) == 40 else "sha256"
    recomputed_tree = candidate_archive_git_tree(
        root / archive["archive"]["path"], object_format
    )
    _require(
        archive["archive_tree"] == recomputed_tree == archive["final_source"]["tree"],
        "candidate-archive.archive_tree",
        "archive contents do not reconstruct the exact final Git tree",
    )
    measurement_commands = [
        (path, command)
        for path, command in command_records.items()
        if is_exact_ssh_archive_measurement_command(command["argv"])
        and command["matched_expectation"]
        and command["expected_outcome"] == {"kind": "exit_code", "value": 0}
        and command["outcome"]["exit_code"] == 0
    ]
    _require(
        len(measurement_commands) == 1,
        "candidate-archive",
        "requires exactly one successful fixed guest archive measurement",
    )
    measurement_path, measurement = measurement_commands[0]
    measurement_target = _exact_ssh_prefix_end(measurement["argv"])
    _require(measurement_target is not None, measurement_path, "invalid SSH prefix")
    measurement_prefix = measurement["argv"][: measurement_target + 1]
    for build_path, build in build_commands:
        build_target = _exact_ssh_prefix_end(build["argv"])
        _require(
            build_target is not None
            and build["argv"][: build_target + 1] == measurement_prefix,
            build_path,
            "build and guest archive measurement use different SSH boundaries",
        )
    facts_path, facts_command = facts_commands[0]
    facts_target = _exact_ssh_prefix_end(facts_command["argv"])
    _require(
        facts_target is not None
        and facts_command["argv"][: facts_target + 1] == measurement_prefix,
        facts_path,
        "guest facts and package build use different SSH boundaries",
    )
    expected_stdout = (
        archive["archive"]["sha256"].removeprefix("sha256:")
        + "  "
        + archive["guest_archive_path"]
        + "\n"
    ).encode("ascii")
    observed_stdout = (root / measurement["stdout"]["path"]).read_bytes()
    _require(
        observed_stdout == expected_stdout,
        f"{measurement_path}.stdout",
        "guest archive digest differs from the sealed candidate archive",
    )
    source_commands: dict[tuple[str, ...], tuple[str, dict[str, Any]]] = {}
    for tail in (SSH_ARCHIVE_EXTRACTION_TAIL, *SSH_SOURCE_TREE_TAILS):
        matches = [
            (path, command)
            for path, command in command_records.items()
            if is_exact_ssh_tail(command["argv"], tail)
            and command["matched_expectation"]
            and command["expected_outcome"] == {"kind": "exit_code", "value": 0}
            and command["outcome"]["exit_code"] == 0
        ]
        _require(
            len(matches) == 1,
            "candidate-archive",
            f"requires exactly one successful source operation: {' '.join(tail)}",
        )
        source_commands[tuple(tail)] = matches[0]
    for tail, (source_path, source_command) in source_commands.items():
        source_target = _exact_ssh_prefix_end(source_command["argv"])
        _require(
            source_target is not None
            and source_command["argv"][: source_target + 1] == measurement_prefix,
            source_path,
            "source operation and package build use different SSH boundaries",
        )
    tree_path, tree_command = source_commands[SSH_SOURCE_TREE_TAILS[-1]]
    _require(
        (root / tree_command["stdout"]["path"]).read_bytes()
        == (archive["final_source"]["tree"] + "\n").encode("ascii"),
        f"{tree_path}.stdout",
        "extracted build directory differs from the exact candidate Git tree",
    )
    test_result_paths = {
        reference["path"] for reference in receipt["mandatory_evidence"]["test_results"]
    }
    _require(
        {facts_ref["path"], archive_record_ref["path"]} <= test_result_paths,
        "receipt.mandatory_evidence.test_results",
        "must contain the exact guest-facts and candidate-archive records",
    )

    _require(
        len(terminal["snapshots"]) == 1,
        "receipt.matrix[0].snapshots",
        "must contain exactly one typed preserved failure boundary",
    )
    snapshot_ref = terminal["snapshots"][0]
    snapshot = validate_snapshot_boundary_record(
        load_canonical_json(root / snapshot_ref["path"])
    )
    _require(
        snapshot["guest_id"] == GUESTS[0][0]
        and snapshot["image_sha256"] == image["bytes"]["sha256"]
        and snapshot["starting_source"] == receipt["candidate"]["starting"]
        and snapshot["final_source"] == receipt["candidate"]["final"],
        "snapshot-boundary",
        "does not bind the terminal image and exact source identities",
    )
    _verify_reference(
        snapshot["artifact"], manifest_entries, "snapshot-boundary.artifact"
    )
    snapshot_paths = {
        reference["path"]
        for reference in receipt["mandatory_evidence"]["snapshot_boundaries"]
    }
    _require(
        {snapshot_ref["path"], snapshot["artifact"]["path"]} <= snapshot_paths,
        "receipt.mandatory_evidence.snapshot_boundaries",
        "does not contain the exact typed snapshot record",
    )
    _verify_first_gate_vm_chain(
        root,
        receipt,
        manifest_entries,
        command_records,
        provenance["artifact"],
        snapshot["artifact"],
        archive,
    )


def verify_bundle(
    root: Path,
    require_receipt: bool = True,
    receipt_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute manifest coverage and an on-disk or pre-publication receipt."""

    root = root.resolve(strict=True)
    manifest_path = root / "manifest.v1.json"
    manifest = validate_manifest(load_canonical_json(manifest_path))
    verify_manifest_coverage(root, manifest)
    controller_plan = _load_controller_plan(root)
    for guest_id in controller_plan["guest_ids"]:
        for case_family in controller_plan["case_ids"]:
            case_plan_path = (
                root / "guests" / guest_id / "cases" / case_family / "case-plan.v1.json"
            )
            case_plan = _strict_object(
                load_canonical_json(case_plan_path),
                str(case_plan_path),
                {
                    "case_family",
                    "guest_id",
                    "per_case_deadline_seconds",
                    "per_command_deadline_seconds",
                    "schema",
                },
            )
            _require(
                case_plan
                == {
                    "case_family": case_family,
                    "guest_id": guest_id,
                    "per_case_deadline_seconds": PER_CASE_DEADLINE_SECONDS,
                    "per_command_deadline_seconds": PER_COMMAND_DEADLINE_SECONDS,
                    "schema": CONTROLLER_SCHEMA,
                },
                str(case_plan_path),
                "differs from the frozen controller plan",
            )
    manifest_digest, manifest_length = digest_regular_file(manifest_path)
    manifest_entries = {entry["path"]: entry for entry in manifest["entries"]}
    copied_harness = manifest_entries.get("inputs/bundle.py")
    _require(
        copied_harness is not None,
        "inputs/bundle.py",
        "executing controller is absent from the evidence seal",
    )
    executing_harness_digest, executing_harness_length = digest_regular_file(
        Path(__file__).resolve(strict=True)
    )
    _require(
        executing_harness_digest == copied_harness["sha256"]
        and executing_harness_length == copied_harness["length"],
        "executing bundle.py",
        "differs from the sealed copied controller bytes",
    )
    receipt_path = root / "receipt.v1.json"
    receipt_digest: str | None = None
    receipt_length: int | None = None
    verdict: str | None = None
    command_assignments: dict[str, tuple[str, str, str]] | None = None
    if receipt_candidate is not None:
        try:
            receipt_path.lstat()
        except FileNotFoundError:
            pass
        else:
            _error(str(receipt_path), "cannot preflight while a receipt node exists")
        receipt = validate_final_receipt(copy.deepcopy(receipt_candidate))
        receipt_payload = canonical_json_bytes(receipt)
        receipt_digest = f"sha256:{hashlib.sha256(receipt_payload).hexdigest()}"
        receipt_length = len(receipt_payload)
    elif receipt_path.exists():
        receipt = validate_final_receipt(load_canonical_json(receipt_path))
        receipt_digest, receipt_length = digest_regular_file(receipt_path)
    else:
        receipt = None
    if receipt is not None:
        binding = receipt["evidence_manifest"]
        _require(
            binding["sha256"] == manifest_digest,
            "receipt.evidence_manifest.sha256",
            "manifest binding mismatch",
        )
        _require(
            binding["length"] == manifest_length,
            "receipt.evidence_manifest.length",
            "manifest binding mismatch",
        )
        verdict = receipt["verdict"]
        references = _collect_artifact_references(receipt)
        _require(
            sum(reference["path"] == "manifest.v1.json" for reference in references)
            == 1,
            "receipt.evidence_manifest",
            "manifest may be referenced only by its dedicated binding",
        )
        for index, reference in enumerate(references):
            if reference["path"] == "manifest.v1.json":
                continue
            _verify_reference(
                reference, manifest_entries, f"receipt artifact reference {index}"
            )

        claim_contract = validate_claim_contract(
            load_canonical_json(root / receipt["claim"]["evidence"]["path"])
        )
        phase1_record = validate_phase1_record(
            load_canonical_json(root / receipt["phase1"]["path"])
        )
        host_contract_path = root / "inputs/phase1-host-contract.v1.json"
        validate_phase1_host_contract(load_canonical_json(host_contract_path))
        host_digest, host_length = digest_regular_file(host_contract_path)
        _require(
            host_digest == phase1_record["host_contract"]["sha256"]
            and host_length == phase1_record["host_contract"]["length"],
            "inputs/phase1-host-contract.v1.json",
            "differs from the Phase 1 host-contract reference",
        )
        for index, reference in enumerate(phase1_record["contract_inputs"]):
            copied_path = root / "inputs/phase1-contract" / reference["path"]
            copied_digest, copied_length = digest_regular_file(copied_path)
            _require(
                copied_digest == reference["sha256"]
                and copied_length == reference["length"],
                f"phase1.contract_inputs[{index}]",
                "copied starting-candidate bytes differ from Phase 1",
            )
        for source_path, copied_path in (
            (
                "qualification/clean-host/claim.v1.json",
                root / "inputs/claim.v1.json",
            ),
            ("qualification/clean-host/matrix.toml", root / "matrix.toml"),
        ):
            reference = next(
                item
                for item in phase1_record["contract_inputs"]
                if item["path"] == source_path
            )
            copied_digest, copied_length = digest_regular_file(copied_path)
            _require(
                copied_digest == reference["sha256"]
                and copied_length == reference["length"],
                str(copied_path),
                "differs from the frozen Phase 1 contract input",
            )
        candidate_identity = validate_candidate_identity(
            load_canonical_json(root / "inputs/candidate-identity.v1.json")
        )
        _require(
            receipt["candidate"]["starting"] == phase1_record["source"],
            "receipt.candidate.starting",
            "does not match the bound Phase 1 source cut",
        )
        _require(
            receipt["candidate"]["final"] == candidate_identity["source"],
            "receipt.candidate.final",
            "does not match the source cut measured at bundle initialization",
        )
        _require(
            candidate_identity["source"]["worktree"] == "clean",
            "candidate-identity.source.worktree",
            "the executed candidate must come from a clean worktree",
        )
        _require(
            candidate_identity["harness"]["matches_head"],
            "candidate-identity.harness.matches_head",
            "the executing harness bytes are not the bytes in the candidate commit",
        )
        _require(
            candidate_identity["publisher"]["matches_head"],
            "candidate-identity.publisher.matches_head",
            "the receipt publisher bytes are not the bytes in the candidate commit",
        )
        _require(
            candidate_identity["vm_fixture"]["matches_head"],
            "candidate-identity.vm_fixture.matches_head",
            "the VM fixture bytes are not the bytes in the candidate commit",
        )
        harness_path = root / "inputs/bundle.py"
        harness_digest, _ = digest_regular_file(harness_path)
        _require(
            harness_digest == candidate_identity["harness"]["working_sha256"],
            "inputs/bundle.py",
            "differs from the measured controller bytes",
        )
        publisher_path = root / "inputs/blocked_receipt.py"
        publisher_digest, _ = digest_regular_file(publisher_path)
        _require(
            publisher_digest == candidate_identity["publisher"]["working_sha256"],
            "inputs/blocked_receipt.py",
            "differs from the measured receipt-publisher bytes",
        )
        vm_fixture_path = root / "inputs/vm_fixture.py"
        vm_fixture_digest, _ = digest_regular_file(vm_fixture_path)
        _require(
            vm_fixture_digest == candidate_identity["vm_fixture"]["working_sha256"],
            "inputs/vm_fixture.py",
            "differs from the measured VM-fixture bytes",
        )
        _require(
            receipt["harness"]["commit"] == receipt["candidate"]["final"]["commit"]
            and receipt["harness"]["tree"] == receipt["candidate"]["final"]["tree"],
            "receipt.harness",
            "harness commit/tree must be the executed final candidate",
        )
        _require(
            receipt["harness"]["evidence"] == artifact_reference(root, harness_path),
            "receipt.harness.evidence",
            "must bind the copied controller bytes",
        )
        _require(
            receipt["harness"]["publisher_evidence"]
            == artifact_reference(root, publisher_path),
            "receipt.harness.publisher_evidence",
            "must bind the copied receipt-publisher bytes",
        )
        _require(
            receipt["harness"]["vm_fixture_evidence"]
            == artifact_reference(root, vm_fixture_path),
            "receipt.harness.vm_fixture_evidence",
            "must bind the copied VM-fixture bytes",
        )
        phase1_dependencies = phase1_record["dependency_inventory"]
        _require(
            len(receipt["dependency_inventory"]) == len(phase1_dependencies),
            "receipt.dependency_inventory",
            "must preserve every Phase 1 dependency",
        )
        for index, (final_dependency, starting_dependency) in enumerate(
            zip(
                receipt["dependency_inventory"],
                phase1_dependencies,
                strict=True,
            )
        ):
            _require(
                final_dependency["id"] == starting_dependency["id"]
                and final_dependency["classification"]
                == starting_dependency["classification"]
                and final_dependency["requirement"]
                == starting_dependency["requirement"],
                f"receipt.dependency_inventory[{index}]",
                "Phase 1 dependency identity, classification, or requirement changed",
            )
        _require(
            receipt["claim"]["blockers"] == claim_contract["blockers"]
            and receipt["claim"]["exclusions"] == claim_contract["exclusions"],
            "receipt.claim",
            "does not match the bound frozen claim",
        )

        command_assignments = {}
        for cell in receipt["matrix"]:
            for case in cell["cases"]:
                for reference in case["evidence"]:
                    path = reference["path"]
                    if not path.endswith(".command.v1.json"):
                        continue
                    _require(
                        path not in command_assignments,
                        "receipt.matrix.cases.evidence",
                        f"command record assigned more than once: {path}",
                    )
                    command_assignments[path] = (
                        cell["guest_id"],
                        case["family"],
                        case["result"],
                    )
        command_paths = {
            path for path in manifest_entries if path.endswith(".command.v1.json")
        }
        _require(
            command_paths == set(command_assignments),
            "receipt.matrix.cases.evidence",
            "every command record must be assigned exactly once to its matrix case",
        )
    else:
        _require(not require_receipt, str(receipt_path), "missing final receipt")
    files = _walk_bundle(root)
    case_durations: dict[tuple[str, str], int] = {}
    command_paths = {
        path for path in manifest_entries if path.endswith(".command.v1.json")
    }
    expected_command_files: set[str] = set()
    expected_case_clock_files: set[str] = set()
    actual_command_files = {path for path in manifest_entries if "/commands/" in path}
    actual_case_clock_files = {
        path for path in manifest_entries if path.endswith("/case-wall-clock.v1.json")
    }
    command_records: dict[str, dict[str, Any]] = {}
    for command_path in sorted(
        command_paths,
        key=os.fsencode,
    ):
        command_record = validate_command_record(
            load_canonical_json(files[command_path])
        )
        command_records[command_path] = command_record
        for input_index, observed_input in enumerate(command_record["observed_inputs"]):
            resolved_input = Path(observed_input["resolved_path"])
            try:
                relative_input = resolved_input.relative_to(root).as_posix()
            except ValueError:
                continue
            _require(
                relative_input in manifest_entries,
                f"{command_path}.observed_inputs[{input_index}]",
                "bundle-local observed input is not manifest-covered",
            )
            input_entry = manifest_entries[relative_input]
            _require(
                observed_input["sha256"] == input_entry["sha256"]
                and observed_input["length"] == input_entry["length"],
                f"{command_path}.observed_inputs[{input_index}]",
                "bundle-local input bytes differ from the sealed evidence",
            )
        guest_id, case_family, command_id = _command_path_identity(command_path)
        _require(
            command_record["guest_id"] == guest_id,
            f"{command_path}.guest_id",
            "differs from command path",
        )
        _require(
            command_record["case_family"] == case_family,
            f"{command_path}.case_family",
            "differs from command path",
        )
        _require(
            command_record["command_id"] == command_id,
            f"{command_path}.command_id",
            "differs from command path",
        )
        expected_case_clock_path = (
            PurePosixPath(command_path).parent.parent / "case-wall-clock.v1.json"
        ).as_posix()
        _require(
            command_record["case_wall_clock"]["path"] == expected_case_clock_path,
            f"{command_path}.case_wall_clock.path",
            "differs from the exact case clock path",
        )
        _verify_reference(
            command_record["case_wall_clock"],
            manifest_entries,
            f"{command_path}.case_wall_clock",
        )
        case_clock = _validate_case_clock(
            load_canonical_json(files[expected_case_clock_path]),
            guest_id,
            case_family,
        )
        _require(
            case_clock["started_boottime_ns"]
            <= command_record["started_boottime_ns"]
            <= command_record["ended_boottime_ns"]
            <= case_clock["deadline_boottime_ns"],
            f"{command_path}.case_wall_clock",
            "command lies outside the real 1800-second case boundary",
        )
        expected_case_clock_files.add(expected_case_clock_path)
        if command_assignments is not None:
            _require(
                command_assignments[command_path][:2] == (guest_id, case_family),
                "receipt.matrix.cases.evidence",
                f"command assigned to the wrong guest or case: {command_path}",
            )
            if command_assignments[command_path][2] == "pass":
                _require(
                    command_record["matched_expectation"],
                    f"{command_path}.matched_expectation",
                    "a passing case contains a command with an unexpected outcome",
                )
        duration_key = (guest_id, case_family)
        case_durations[duration_key] = (
            case_durations.get(duration_key, 0) + command_record["duration_ms"]
        )
        for stream in ("stdout", "stderr"):
            expected_stream_path = (
                PurePosixPath(command_path).parent / f"{command_id}.{stream}"
            ).as_posix()
            _require(
                command_record[stream]["path"] == expected_stream_path,
                f"{command_path}.{stream}.path",
                "differs from the command's exact stream path",
            )
            _verify_reference(
                command_record[stream],
                manifest_entries,
                f"{command_path}.{stream}",
            )
            expected_command_files.add(expected_stream_path)
        expected_command_files.add(command_path)
    _require(
        actual_command_files == expected_command_files,
        "commands",
        "orphan, missing, or unrecognized command evidence is present",
    )
    _require(
        actual_case_clock_files == expected_case_clock_files,
        "case wall clocks",
        "orphan or missing case wall-clock evidence is present",
    )
    if command_assignments is not None:
        _require(
            all(result != "not_run" for _, _, result in command_assignments.values()),
            "receipt.matrix.cases.evidence",
            "a not-run case cannot contain an executed command",
        )
        assigned_cases = {
            (guest_id, case_family)
            for guest_id, case_family, result in command_assignments.values()
            if result == "pass"
        }
        passing_cases = {
            (cell["guest_id"], case["family"])
            for cell in receipt["matrix"]
            for case in cell["cases"]
            if case["result"] == "pass"
        }
        _require(
            assigned_cases == passing_cases,
            "receipt.matrix.cases.evidence",
            "every passing case must contain at least one exact command record",
        )
        if verdict == "BLOCKED":
            terminal_guest = GUESTS[0][0]
            terminal_family = CASE_FAMILIES[0]
            terminal_paths = [
                path
                for path, assignment in command_assignments.items()
                if assignment[:2] == (terminal_guest, terminal_family)
            ]
            _require(
                terminal_paths,
                "receipt.matrix[0].cases[0].evidence",
                "the bounded build stop requires exact command evidence",
            )
            unexpected_build_commands = [
                (path, command_records[path])
                for path in terminal_paths
                if not command_records[path]["matched_expectation"]
            ]
            _require(
                len(unexpected_build_commands) == 2,
                "receipt.matrix[0].cases[0].evidence",
                "requires exactly the two governed package-build refusals",
            )
            observed_refusals: set[tuple[str, ...]] = set()
            for command_path, command_record in unexpected_build_commands:
                _require(
                    command_record["executable"]["requested_path"] == "/usr/bin/ssh"
                    and is_exact_ssh_build_command(command_record["argv"])
                    and command_record["expected_outcome"]
                    == {"kind": "exit_code", "value": 0},
                    command_path,
                    "an unexpected command is not an admitted exact build gate",
                )
                target_index = command_record["argv"].index(SSH_BUILD_TARGET)
                remote_tail = tuple(command_record["argv"][target_index + 1 :])
                expected_exit = 1 if remote_tail == SSH_BUILD_REMOTE_TAILS[0] else 3
                _require(
                    command_record["outcome"]["exit_code"] == expected_exit,
                    command_path,
                    f"exact build gate must refuse with exit {expected_exit}",
                )
                observed_refusals.add(remote_tail)
            _require(
                observed_refusals == set(SSH_BUILD_REMOTE_TAILS),
                "receipt.matrix[0].cases[0].evidence",
                "must contain checkbuilddeps exit 1 and dpkg-buildpackage exit 3",
            )
            readiness_records: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for reference in receipt["mandatory_evidence"]["hypervisor_and_host"]:
                evidence_path = root / reference["path"]
                if not evidence_path.name.endswith(".json"):
                    continue
                candidate_record = load_canonical_json(evidence_path)
                if (
                    type(candidate_record) is dict
                    and candidate_record.get("schema")
                    == "ag.clean-host-ssh-readiness/v1"
                ):
                    readiness_records.append((candidate_record, reference))
            _require(
                len(readiness_records) == 1,
                "receipt.mandatory_evidence.hypervisor_and_host",
                "must contain exactly one typed SSH readiness record",
            )
            readiness_record, readiness_reference = readiness_records[0]
            _require(
                readiness_record.get("result") == "ready"
                and type(readiness_record.get("target")) is dict
                and type(readiness_record.get("identity_file")) is dict
                and type(readiness_record.get("known_hosts")) is dict,
                "SSH readiness record",
                "does not bind a ready peer, identity, and accepted host key",
            )
            readiness_path = root / readiness_reference["path"]
            readiness_producers = []
            expected_fixture_path = root / "inputs/vm_fixture.py"
            for command_path, command_record in command_records.items():
                if command_path not in terminal_paths:
                    continue
                argv = command_record["argv"]
                if not (
                    len(argv) >= 3
                    and argv[:3]
                    == [
                        "/usr/bin/python3",
                        str(expected_fixture_path),
                        "wait-ssh",
                    ]
                    and argv.count("--output") == 1
                ):
                    continue
                output_index = argv.index("--output") + 1
                if output_index >= len(argv) or argv[output_index] != str(
                    readiness_path
                ):
                    continue
                observed_by_path = {
                    item["resolved_path"]: item
                    for item in command_record["observed_inputs"]
                }
                fixture_input = observed_by_path.get(str(expected_fixture_path))
                if (
                    command_record["matched_expectation"]
                    and command_record["expected_outcome"]
                    == {"kind": "exit_code", "value": 0}
                    and command_record["outcome"]["exit_code"] == 0
                    and len(command_record["observed_inputs"]) == 2
                    and fixture_input is not None
                    and (root / command_record["stdout"]["path"]).read_bytes()
                    == readiness_path.read_bytes()
                ):
                    readiness_producers.append(command_path)
            _require(
                len(readiness_producers) == 1,
                "SSH readiness record",
                "requires exactly one successful copied VM-fixture producer command",
            )
            for command_path, command_record in unexpected_build_commands:
                argv = command_record["argv"]
                for required_argument in (
                    "BatchMode=yes",
                    "GlobalKnownHostsFile=/dev/null",
                    "IdentitiesOnly=yes",
                    "KbdInteractiveAuthentication=no",
                    "PasswordAuthentication=no",
                    "PreferredAuthentications=publickey",
                    "StrictHostKeyChecking=yes",
                    "agqual@127.0.0.1",
                ):
                    _require(
                        required_argument in argv,
                        f"{command_path}.argv",
                        f"missing fixed SSH boundary argument: {required_argument}",
                    )
                _require(
                    "-F" in argv
                    and argv[argv.index("-F") + 1 : argv.index("-F") + 2]
                    == ["/dev/null"],
                    f"{command_path}.argv",
                    "must disable ambient SSH configuration",
                )
                _require(
                    "-i" in argv
                    and len(argv[argv.index("-i") + 1 : argv.index("-i") + 2]) == 1
                    and Path(argv[argv.index("-i") + 1]).is_absolute(),
                    f"{command_path}.argv",
                    "must bind one absolute SSH identity path",
                )
                identity_path = Path(argv[argv.index("-i") + 1])
                observed_input_by_path = {
                    item["requested_path"]: item
                    for item in command_record["observed_inputs"]
                }
                _require(
                    str(identity_path) in observed_input_by_path,
                    f"{command_path}.observed_inputs",
                    "does not measure the SSH identity used by the build",
                )
                observed_identity = observed_input_by_path[str(identity_path)]
                _require(
                    not Path(observed_identity["resolved_path"]).is_relative_to(root),
                    f"{command_path}.argv",
                    "private SSH identity material must remain outside the evidence bundle",
                )
                _require(
                    "-p" in argv
                    and len(argv[argv.index("-p") + 1 : argv.index("-p") + 2]) == 1
                    and argv[argv.index("-p") + 1].isdigit(),
                    f"{command_path}.argv",
                    "must bind one numeric forwarded SSH port",
                )
                known_hosts_options = [
                    argument
                    for argument in argv
                    if argument.startswith("UserKnownHostsFile=")
                ]
                _require(
                    len(known_hosts_options) == 1,
                    f"{command_path}.argv",
                    "must bind one run-local known-hosts file",
                )
                known_hosts_path = Path(known_hosts_options[0].split("=", 1)[1])
                try:
                    known_hosts_relative = (
                        known_hosts_path.resolve(strict=True)
                        .relative_to(root)
                        .as_posix()
                    )
                except (OSError, ValueError) as error:
                    raise QualificationError(
                        f"{command_path}.argv: known-hosts file is outside the sealed bundle"
                    ) from error
                _require(
                    known_hosts_relative in manifest_entries,
                    f"{command_path}.argv",
                    "known-hosts file is not manifest-covered",
                )
                known_hosts_entry = manifest_entries[known_hosts_relative]
                readiness_known_hosts = readiness_record["known_hosts"]
                readiness_identity = readiness_record["identity_file"]
                readiness_target = readiness_record["target"]
                _require(
                    readiness_known_hosts.get("path") == str(known_hosts_path)
                    and readiness_known_hosts.get("sha256")
                    == known_hosts_entry["sha256"]
                    and readiness_known_hosts.get("length")
                    == known_hosts_entry["length"],
                    f"{command_path}.argv",
                    "known-hosts bytes differ from the accepted readiness peer",
                )
                _require(
                    readiness_identity.get("path") == str(identity_path)
                    and readiness_identity.get("sha256") == observed_identity["sha256"]
                    and readiness_identity.get("length") == observed_identity["length"],
                    f"{command_path}.argv",
                    "build SSH identity bytes differ from readiness",
                )
                _require(
                    readiness_target
                    == {
                        "host": "127.0.0.1",
                        "port": int(argv[argv.index("-p") + 1]),
                        "username": "agqual",
                    },
                    f"{command_path}.argv",
                    "build SSH target differs from readiness",
                )
            terminal_case = receipt["matrix"][0]["cases"][0]
            terminal_case_paths = {
                reference["path"] for reference in terminal_case["evidence"]
            }
            _require(
                any(
                    path in terminal_case_paths for path, _ in unexpected_build_commands
                ),
                "receipt.matrix[0].cases[0].evidence",
                "does not bind the unexpected terminal build command",
            )
            unexpected_paths = {path for path, _ in unexpected_build_commands}
            clean_build_residual = next(
                gate
                for gate in receipt["residual_gates"]
                if gate["id"] == "clean_offline_source_build_absent"
            )
            _require(
                unexpected_paths
                & {reference["path"] for reference in clean_build_residual["evidence"]},
                "receipt.residual_gates.clean_offline_source_build_absent.evidence",
                "must bind the unexpected clean-build command",
            )
            _require(
                any(
                    unexpected_paths
                    & {reference["path"] for reference in defect["evidence"]}
                    for defect in receipt["defects"]
                    if f"{terminal_guest}/{terminal_family}" in defect["case_refs"]
                ),
                "receipt.defects",
                "the exact terminal defect must bind the unexpected clean-build command",
            )
            terminal_cell = receipt["matrix"][0]
            _require(
                terminal_cell["image"] is not None
                and terminal_cell["observed"] is not None
                and terminal_cell["guest_evidence"]
                and terminal_cell["snapshots"],
                "receipt.matrix[0]",
                "the failed clean-host gate requires pinned image, guest, and snapshot evidence",
            )
            _verify_blocked_typed_evidence(
                root,
                receipt,
                manifest_entries,
                command_records,
                unexpected_build_commands,
            )
            for category in (
                "command_ledger",
                "hypervisor_and_host",
                "image_provenance",
                "snapshot_boundaries",
                "test_results",
            ):
                _require(
                    receipt["mandatory_evidence"][category],
                    f"receipt.mandatory_evidence.{category}",
                    "the executed clean-build gate requires this evidence role",
                )
    for (guest_id, case_family), duration_ms in case_durations.items():
        _require(
            duration_ms <= PER_CASE_DEADLINE_SECONDS * 1000,
            f"{guest_id}.{case_family}.duration_ms",
            "exceeds frozen case deadline",
        )
    result = {
        "manifest": {
            "length": manifest_length,
            "path": "manifest.v1.json",
            "sha256": manifest_digest,
        },
        "receipt": None
        if receipt_digest is None
        else {
            "length": receipt_length,
            "path": "receipt.v1.json",
            "sha256": receipt_digest,
        },
        "schema": VERIFICATION_SCHEMA,
        "valid": True,
        "verdict": verdict,
    }
    result_path = root / "verification-result.v1.json"
    if result_path.exists():
        existing = validate_verification_result(load_canonical_json(result_path))
        _require(
            existing == result,
            str(result_path),
            "stale or contradictory verification marker",
        )
    return result


def _git_output(repository: Path, arguments: Sequence[str]) -> bytes:
    try:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        ).stdout
    except subprocess.CalledProcessError as error:
        raise QualificationError(
            f"git {' '.join(arguments)} failed: {error.stderr.decode('utf-8', 'replace').strip()}"
        ) from error


def candidate_preflight(
    repository: Path, rejected_artifacts: Sequence[Path]
) -> dict[str, Any]:
    """Capture an exact source cut and explicitly reject stale package files."""

    repository = repository.resolve(strict=True)
    commit = _git_output(repository, ("rev-parse", "HEAD")).decode("ascii").strip()
    tree = _git_output(repository, ("rev-parse", "HEAD^{tree}")).decode("ascii").strip()
    branch = (
        _git_output(repository, ("rev-parse", "--abbrev-ref", "HEAD"))
        .decode("utf-8")
        .strip()
    )
    status = _git_output(
        repository, ("status", "--porcelain=v1", "-z", "--untracked-files=all")
    )
    rejected: list[dict[str, Any]] = []
    for path in rejected_artifacts:
        absolute = path.resolve(strict=True)
        digest, length = digest_regular_file(absolute)
        rejected.append(
            {
                "length": length,
                "path": str(absolute),
                "reason": "artifact is not cryptographically bound to the recorded candidate commit and tree",
                "sha256": digest,
                "status": "rejected",
            }
        )
    xattr_evidence: str
    try:
        os.getxattr("/usr/bin/git", "security.capability")
    except OSError as error:
        xattr_evidence = f"os.getxattr(/usr/bin/git,security.capability) errno={error.errno} ({error.strerror})"
    else:
        xattr_evidence = "security.capability is present on /usr/bin/git"
    try:
        dev_null = os.lstat("/dev/null")
        dev_null_evidence = f"uid={dev_null.st_uid} gid={dev_null.st_gid} mode={stat.S_IMODE(dev_null.st_mode):04o}"
    except OSError as error:
        dev_null_evidence = f"lstat failed errno={error.errno} ({error.strerror})"
    proc_paths = (
        "/proc/self/exe",
        "/proc/self/status",
        "/proc/self/cgroup",
        "/proc/self/mountinfo",
    )
    proc_evidence = ", ".join(
        f"{path}:readable={os.access(path, os.R_OK)}" for path in proc_paths
    )
    dependencies = [
        {
            "classification": "declared_package_dependency",
            "consumers": ["candidate_package_build"],
            "evidence": "debian/control declares debhelper-compat (= 13), bubblewrap, cargo (>= 1.94.0), git (>= 1:2.39.0), python3, and rustc (>= 1.94.0)",
            "id": "source_build_packages",
            "requirement": "candidate source-package construction has the complete declared Build-Depends on a separately pinned builder",
        },
        {
            "classification": "explicitly_documented_operator_prerequisite",
            "consumers": ["candidate_package_build"],
            "evidence": "docs/clean-host-activation-qualification.md records that debian/rules requires locked offline Cargo resolution while no vendored source set or Debian crate-source closure is enrolled",
            "id": "offline_cargo_source_closure",
            "requirement": "the pinned builder has an enrolled Cargo dependency closure sufficient for cargo --locked --offline",
        },
        {
            "classification": "explicitly_documented_operator_prerequisite",
            "consumers": ["qualification_controller"],
            "evidence": "the frozen harness executes standard-library Python plus fixed Git, QEMU/KVM, qemu-img, xorriso, OpenSSH, SCP, and coreutils paths",
            "id": "qualification_controller_toolchain",
            "requirement": "the qualification controller provides Python 3.11 or newer, Git, QEMU/KVM, qemu-img, xorriso, OpenSSH client and SCP, and coreutils at the fixed paths recorded by the harness",
        },
        {
            "classification": "explicitly_documented_operator_prerequisite",
            "consumers": ["candidate_package_build", "clean_guest_bootstrap"],
            "evidence": "the frozen first gate uses NoCloud boot, sshd, sudo, apt-get, Python, tar, sha256sum, Git, dpkg-checkbuilddeps, and dpkg-buildpackage before a candidate package exists",
            "id": "clean_guest_bootstrap_tooling",
            "requirement": "the pinned clean image supplies functional NoCloud initialization, SSH server, sudo, configured distribution package repositories, apt and dpkg tools, Python 3, tar, coreutils, and Git without a repository checkout or development-machine state",
        },
        {
            "classification": "undeclared_ambient_dependency",
            "consumers": ["managed_pointer_genesis", "activation", "worker_launch"],
            "evidence": dev_null_evidence,
            "id": AMBIENT_DEPENDENCIES[0],
            "requirement": "/dev/null is a root-owned character device with exact approved mode and stable descriptor semantics",
        },
        {
            "classification": "undeclared_ambient_dependency",
            "consumers": ["managed_pointer_genesis", "activation", "agctl_doctor"],
            "evidence": xattr_evidence,
            "id": AMBIENT_DEPENDENCIES[1],
            "requirement": "security.capability can be queried on pinned /usr/bin/git and an absent value is reported as ENODATA",
        },
        {
            "classification": "undeclared_ambient_dependency",
            "consumers": ["systemd_unit_start", "activation", "worker_launch"],
            "evidence": f"os.memfd_create={hasattr(os, 'memfd_create')}; /proc/self/fd={Path('/proc/self/fd').is_dir()}; execution not qualified by Phase 1",
            "id": AMBIENT_DEPENDENCIES[2],
            "requirement": "sealed executable memfds remain executable through /proc/self/fd under the service sandbox",
        },
        {
            "classification": "undeclared_ambient_dependency",
            "consumers": [
                "systemd_unit_start",
                "activation",
                "agctl_doctor",
                "restart_reconstruction",
            ],
            "evidence": proc_evidence,
            "id": AMBIENT_DEPENDENCIES[3],
            "requirement": "/proc/self/exe, status, cgroup, and mountinfo are readable through the effective service sandbox",
        },
    ]
    migration_receipt = (
        repository / "migration/receipts/ag-kernel-authority-replacement.v1.json"
    )
    migration_digest, migration_length = digest_regular_file(migration_receipt)
    narrative_receipts: list[dict[str, Any]] = []
    for (
        path,
        expected_length,
        expected_digest,
        narrative_status,
    ) in PHASE1_NARRATIVE_RECEIPTS:
        payload = _git_output(repository, ("show", path))
        observed_digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        _require(
            len(payload) == expected_length and observed_digest == expected_digest,
            f"phase1.receipt_inventory[{path}]",
            "historical narrative bytes differ from the frozen identity",
        )
        narrative_receipts.append(
            {
                "digest": expected_digest,
                "kind": "narrative_qualification_only",
                "length": expected_length,
                "path": path,
                "schema": "none",
                "status": narrative_status,
            }
        )
    receipt_template = repository / "qualification/clean-host/receipt.template.v1.json"
    template_digest, template_length = digest_regular_file(receipt_template)
    os_release = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    distribution = next(
        (
            line.removeprefix("PRETTY_NAME=").strip('"')
            for line in os_release.splitlines()
            if line.startswith("PRETTY_NAME=")
        ),
        "unknown",
    )
    record = {
        "authority_use": AUTHORITY_USE,
        "candidate_artifacts": {"accepted": [], "rejected": rejected},
        "contract_inputs": [
            artifact_reference(repository, repository / path)
            for path in PHASE1_CONTRACT_INPUT_PATHS
        ],
        "dependency_inventory": dependencies,
        "host_contract": artifact_reference(
            repository,
            repository / "qualification/clean-host/phase1-host-contract.v1.json",
        ),
        "host_capability_summary": {
            "active_lsms": Path("/sys/kernel/security/lsm")
            .read_text(encoding="utf-8", errors="replace")
            .strip()
            if Path("/sys/kernel/security/lsm").is_file()
            else "unavailable",
            "architecture": os.uname().machine,
            "cgroup": "cgroup-v2"
            if Path("/sys/fs/cgroup/cgroup.controllers").exists()
            else "not-cgroup-v2",
            "distribution": distribution,
            "filesystem": "record separately from /proc/self/mountinfo before VM use",
            "hypervisor_tools": [
                str(path)
                for path in (
                    Path("/usr/bin/qemu-system-x86_64"),
                    Path("/usr/bin/virsh"),
                )
                if path.is_file()
            ],
            "kernel": os.uname().release,
            "notes": "controller-host capability presence is not clean-guest qualification",
            "systemd": "record separately from systemd --version before VM use",
        },
        "known_blockers": list(KNOWN_BLOCKERS),
        "receipt_inventory": [
            {
                "digest": migration_digest,
                "kind": "material_migration_test_receipt",
                "length": migration_length,
                "path": "migration/receipts/ag-kernel-authority-replacement.v1.json",
                "schema": "ag.migration-test-receipt/v1",
                "status": "passed",
            },
            {
                "digest": None,
                "kind": "absent_package_systemd_receipt",
                "length": None,
                "path": "qualification/receipts/clean-host/",
                "schema": "ag.clean-host-package-qualification-receipt/v1",
                "status": "no_material_receipt",
            },
            *narrative_receipts,
            {
                "digest": template_digest,
                "kind": "inert_template_not_receipt",
                "length": template_length,
                "path": "qualification/clean-host/receipt.template.v1.json",
                "schema": "ag.clean-host-package-qualification-receipt-template/v1",
                "status": "not_run",
            },
        ],
        "recorded_at": _timestamp(),
        "reconstructs_standing": False,
        "schema": PHASE1_SCHEMA,
        "source": {
            "branch": branch,
            "commit": commit,
            "status_porcelain_sha256": f"sha256:{hashlib.sha256(status).hexdigest()}",
            "tree": tree,
            "worktree": "clean" if not status else "dirty",
        },
    }
    validate_phase1_record(record)
    return record


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    initialize = subparsers.add_parser("init", help="initialise one evidence bundle")
    initialize.add_argument("root", type=Path)
    initialize.add_argument(
        "--matrix", type=Path, default=Path(__file__).resolve().parent / "matrix.toml"
    )

    record = subparsers.add_parser("record", help="execute and record exact argv")
    record.add_argument("--root", required=True, type=Path)
    record.add_argument("--guest", required=True)
    record.add_argument("--case", required=True, dest="case_family")
    record.add_argument("--command-id", required=True)
    record.add_argument("--cwd", required=True, type=Path)
    record.add_argument("--env", action="append", default=[])
    record.add_argument("--timeout-seconds", type=int)
    expectation = record.add_mutually_exclusive_group()
    expectation.add_argument("--expect-exit-code", type=int)
    expectation.add_argument("--expect-signal", type=int)
    expectation.add_argument("--expect-timeout", action="store_true")
    expectation.add_argument("--expect-launch-error", action="store_true")
    record.add_argument("argv", nargs=argparse.REMAINDER)

    seal = subparsers.add_parser("seal", help="seal all pre-result evidence")
    seal.add_argument("root", type=Path)

    verify = subparsers.add_parser("verify", help="recompute seal and receipt binding")
    verify.add_argument("root", type=Path)
    verify.add_argument("--allow-missing-receipt", action="store_true")
    verify.add_argument("--write-result", action="store_true")

    receipt = subparsers.add_parser(
        "validate-receipt", help="validate canonical final receipt"
    )
    receipt.add_argument("path", type=Path)

    phase1 = subparsers.add_parser(
        "candidate-preflight", help="record the exact starting source cut"
    )
    phase1.add_argument("repository", type=Path)
    phase1.add_argument("--reject-artifact", action="append", default=[], type=Path)
    phase1.add_argument("--output", type=Path)

    validate_phase1 = subparsers.add_parser(
        "validate-phase1", help="validate a canonical Phase 1 record"
    )
    validate_phase1.add_argument("path", type=Path)
    validate_host_contract = subparsers.add_parser(
        "validate-host-contract", help="validate the frozen supported-host contract"
    )
    validate_host_contract.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            initialize_bundle(arguments.root, arguments.matrix)
            print(f"initialised clean-host evidence bundle at {arguments.root}")
        elif arguments.command == "record":
            command_argv = list(arguments.argv)
            if command_argv and command_argv[0] == "--":
                command_argv.pop(0)
            environment = _parse_environment(arguments.env)
            if arguments.expect_signal is not None:
                expected_outcome = {
                    "kind": "signal",
                    "value": arguments.expect_signal,
                }
            elif arguments.expect_timeout:
                expected_outcome = {"kind": "timeout", "value": None}
            elif arguments.expect_launch_error:
                expected_outcome = {"kind": "launch_error", "value": None}
            else:
                expected_outcome = {
                    "kind": "exit_code",
                    "value": 0
                    if arguments.expect_exit_code is None
                    else arguments.expect_exit_code,
                }
            record_command(
                arguments.root,
                arguments.guest,
                arguments.case_family,
                arguments.command_id,
                command_argv,
                arguments.cwd,
                environment,
                arguments.timeout_seconds,
                expected_outcome,
            )
            print("command evidence recorded")
        elif arguments.command == "seal":
            print(
                canonical_json_bytes(seal_bundle(arguments.root)).decode("utf-8"),
                end="",
            )
        elif arguments.command == "verify":
            result = verify_bundle(
                arguments.root, require_receipt=not arguments.allow_missing_receipt
            )
            if arguments.write_result:
                write_new_canonical_json(
                    arguments.root / "verification-result.v1.json", result
                )
            print(canonical_json_bytes(result).decode("utf-8"), end="")
        elif arguments.command == "validate-receipt":
            validate_final_receipt(load_canonical_json(arguments.path))
            print("clean-host final receipt valid")
        elif arguments.command == "candidate-preflight":
            record = candidate_preflight(
                arguments.repository, arguments.reject_artifact
            )
            if arguments.output is None:
                print(canonical_json_bytes(record).decode("utf-8"), end="")
            else:
                write_new_canonical_json(arguments.output, record)
        elif arguments.command == "validate-phase1":
            validate_phase1_record(load_canonical_json(arguments.path))
            print("clean-host Phase 1 candidate record valid")
        elif arguments.command == "validate-host-contract":
            validate_phase1_host_contract(load_canonical_json(arguments.path))
            print("clean-host Phase 1 host contract valid")
        else:  # pragma: no cover - argparse closes this branch
            parser.error("unknown command")
    except (QualificationError, OSError) as error:
        print(f"clean-host evidence error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
