#!/usr/bin/python3
"""Publish the bounded first-gate BLOCKED clean-host receipt.

The campaign metadata is evidence: it must be canonical JSON below the sealed
bundle root and covered by the evidence manifest.  All identities that can be
derived from the bundle are deliberately not accepted from the metadata.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn, Sequence


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("clean_host_bundle", HERE / "bundle.py")
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


METADATA_SCHEMA = "ag.clean-host-blocked-receipt-metadata/v1"
DEFAULT_METADATA_PATH = "inputs/blocked-receipt-metadata.v1.json"
TERMINAL_GUEST = BUNDLE.GUESTS[0][0]
TERMINAL_FAMILY = BUNDLE.CASE_FAMILIES[0]
TERMINAL_CASE_REF = f"{TERMINAL_GUEST}/{TERMINAL_FAMILY}"
PRIMARY_DEFECT_ID = "debian-12-bookworm-rust-toolchain-version-shortfall"
GUEST_FACTS_PATH = "mandatory/test_results/guest-facts.v1.json"
CANDIDATE_ARCHIVE_RECORD_PATH = "mandatory/test_results/candidate-archive.v1.json"
IMAGE_PROVENANCE_PATH = "mandatory/image_provenance/image.v1.json"
SNAPSHOT_BOUNDARY_PATH = "mandatory/snapshot_boundaries/snapshot.v1.json"


def _error(location: str, message: str) -> NoReturn:
    raise BUNDLE.QualificationError(f"{location}: {message}")


def _require(condition: bool, location: str, message: str) -> None:
    if not condition:
        _error(location, message)


def _object(
    value: Any,
    location: str,
    required: set[str],
    optional: set[str] = frozenset(),
) -> dict[str, Any]:
    _require(type(value) is dict, location, "must be an object")
    missing = required - set(value)
    extra = set(value) - required - optional
    _require(not missing, location, f"missing fields: {', '.join(sorted(missing))}")
    _require(not extra, location, f"unknown fields: {', '.join(sorted(extra))}")
    return value


def _text(value: Any, location: str) -> str:
    _require(
        type(value) is str and bool(value.strip()),
        location,
        "must be a nonempty string",
    )
    return value


def _path(value: Any, location: str) -> str:
    return BUNDLE._validate_relative_path(_text(value, location), location)


def _paths(value: Any, location: str) -> list[str]:
    _require(type(value) is list, location, "must be an array")
    result = [_path(item, f"{location}[{index}]") for index, item in enumerate(value)]
    _require(len(result) == len(set(result)), location, "must not contain duplicates")
    return sorted(result, key=os.fsencode)


def _metadata(value: Any) -> dict[str, Any]:
    metadata = _object(
        value,
        "metadata",
        {
            "authority_use",
            "controller_host",
            "mandatory_evidence_paths",
            "schema",
            "terminal_guest_evidence_paths",
            "terminal_image",
            "terminal_observed",
            "terminal_snapshot_paths",
        },
        {
            "additional_defects",
            "additional_residual_gates",
            "repairs",
            "receipt_inventory_paths",
        },
    )
    _require(metadata["schema"] == METADATA_SCHEMA, "metadata.schema", "unknown schema")
    _require(
        metadata["authority_use"] == BUNDLE.AUTHORITY_USE,
        "metadata.authority_use",
        "must be evidence_only",
    )
    host = _object(
        metadata["controller_host"],
        "metadata.controller_host",
        {"architecture", "distribution", "evidence_paths", "hypervisor", "kernel"},
    )
    for field in ("architecture", "distribution", "hypervisor", "kernel"):
        _text(host[field], f"metadata.controller_host.{field}")
    _require(
        bool(_paths(host["evidence_paths"], "metadata.controller_host.evidence_paths")),
        "metadata.controller_host.evidence_paths",
        "must not be empty",
    )
    image = _object(
        metadata["terminal_image"],
        "metadata.terminal_image",
        {"bytes", "provenance_path", "source", "source_digest"},
    )
    identity = _object(
        image["bytes"], "metadata.terminal_image.bytes", {"length", "sha256"}
    )
    _require(
        type(identity["length"]) is int and identity["length"] > 0,
        "metadata.terminal_image.bytes.length",
        "must be a positive integer",
    )
    BUNDLE._validate_sha256(identity["sha256"], "metadata.terminal_image.bytes.sha256")
    _path(image["provenance_path"], "metadata.terminal_image.provenance_path")
    _text(image["source"], "metadata.terminal_image.source")
    _require(
        BUNDLE.SOURCE_DIGEST_RE.fullmatch(
            _text(image["source_digest"], "metadata.terminal_image.source_digest")
        )
        is not None,
        "metadata.terminal_image.source_digest",
        "invalid source digest",
    )
    observed = _object(
        metadata["terminal_observed"],
        "metadata.terminal_observed",
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
    for field, setting in observed.items():
        _text(setting, f"metadata.terminal_observed.{field}")
    _require(
        (observed["distribution"], observed["release"], observed["architecture"])
        == ("debian", "12", "amd64"),
        "metadata.terminal_observed",
        "must describe the frozen Debian 12 amd64 terminal guest",
    )
    _require(
        observed["landlock_abi"].isdigit(),
        "metadata.terminal_observed.landlock_abi",
        "must be a decimal ABI number",
    )
    _paths(
        metadata["terminal_guest_evidence_paths"],
        "metadata.terminal_guest_evidence_paths",
    )
    _paths(metadata["terminal_snapshot_paths"], "metadata.terminal_snapshot_paths")
    mandatory = _object(
        metadata["mandatory_evidence_paths"],
        "metadata.mandatory_evidence_paths",
        set(BUNDLE.MANDATORY_EVIDENCE_CATEGORIES),
    )
    for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
        for path in _paths(
            mandatory[category], f"metadata.mandatory_evidence_paths.{category}"
        ):
            _require(
                path.startswith(f"mandatory/{category}/"),
                f"metadata.mandatory_evidence_paths.{category}",
                "path is outside its exact mandatory evidence role",
            )
    for field in ("additional_defects", "additional_residual_gates", "repairs"):
        _require(
            type(metadata.get(field, [])) is list,
            f"metadata.{field}",
            "must be an array",
        )
    _paths(
        metadata.get("receipt_inventory_paths", []), "metadata.receipt_inventory_paths"
    )
    return metadata


def _reference(
    entries: dict[str, dict[str, Any]], path: str, location: str
) -> dict[str, Any]:
    normalized = _path(path, location)
    _require(normalized in entries, location, "does not name manifest-covered evidence")
    return copy.deepcopy(entries[normalized])


def _references(
    entries: dict[str, dict[str, Any]], paths: list[str], location: str
) -> list[dict[str, Any]]:
    return [
        _reference(entries, path, f"{location}[{index}]")
        for index, path in enumerate(_paths(paths, location))
    ]


def _typed_records(
    entries: dict[str, dict[str, Any]],
    records: list[Any],
    location: str,
    fields: set[str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(records):
        item_location = f"{location}[{index}]"
        item = _object(raw, item_location, fields)
        converted = dict(item)
        converted["evidence"] = _references(
            entries, item["evidence_paths"], f"{item_location}.evidence_paths"
        )
        del converted["evidence_paths"]
        result.append(converted)
    return sorted(
        result, key=lambda item: os.fsencode(_text(item["id"], f"{location}.id"))
    )


def _require_copied_tool_bytes(root: Path) -> None:
    for executing, copied_name in (
        (Path(BUNDLE.__file__).resolve(strict=True), "bundle.py"),
        (Path(__file__).resolve(strict=True), "blocked_receipt.py"),
    ):
        executing_digest, executing_length = BUNDLE.digest_regular_file(executing)
        copied = root / "inputs" / copied_name
        copied_digest, copied_length = BUNDLE.digest_regular_file(copied)
        _require(
            (executing_digest, executing_length) == (copied_digest, copied_length),
            f"executing {copied_name}",
            "differs from the copied campaign tool bytes",
        )


def prepare_typed_evidence(
    root: Path,
    archive_path: str,
    guest_facts_observation_path: str,
    image_artifact_path: str,
    snapshot_artifact_path: str,
    snapshot_id: str,
    metadata_path: str = DEFAULT_METADATA_PATH,
) -> None:
    """Render the four fixed typed records before the evidence seal."""

    root = root.resolve(strict=True)
    for sealed in BUNDLE.EXCLUDED_ROOT_PATHS:
        try:
            (root / sealed).lstat()
        except FileNotFoundError:
            pass
        else:
            _error(sealed, "typed evidence must be rendered before sealing")
    _require_copied_tool_bytes(root)
    metadata_relative = _path(metadata_path, "metadata path")
    metadata = _metadata(BUNDLE.load_canonical_json(root / metadata_relative))
    archive_relative = _path(archive_path, "archive path")
    _require(
        archive_relative.startswith("mandatory/test_results/"),
        "archive path",
        "must reside below mandatory/test_results",
    )
    guest_facts_relative = _path(
        guest_facts_observation_path, "guest facts observation path"
    )
    terminal_command_prefix = (
        f"guests/{TERMINAL_GUEST}/cases/{TERMINAL_FAMILY}/commands/"
    )
    _require(
        guest_facts_relative.startswith(terminal_command_prefix)
        and guest_facts_relative.endswith(".stdout"),
        "guest facts observation path",
        "must name one terminal-case command stdout",
    )
    image_artifact_relative = _path(image_artifact_path, "image artifact path")
    _require(
        image_artifact_relative.startswith("mandatory/image_provenance/")
        and image_artifact_relative != IMAGE_PROVENANCE_PATH,
        "image artifact path",
        "must name a non-record file below mandatory/image_provenance",
    )
    snapshot_artifact_relative = _path(snapshot_artifact_path, "snapshot artifact path")
    _require(
        snapshot_artifact_relative.startswith("mandatory/snapshot_boundaries/")
        and snapshot_artifact_relative != SNAPSHOT_BOUNDARY_PATH,
        "snapshot artifact path",
        "must name a non-record file below mandatory/snapshot_boundaries",
    )
    BUNDLE._validate_id(snapshot_id, "snapshot id")
    phase1 = BUNDLE.validate_phase1_record(
        BUNDLE.load_canonical_json(root / "inputs/phase1-starting-candidate.v1.json")
    )
    candidate = BUNDLE.validate_candidate_identity(
        BUNDLE.load_canonical_json(root / "inputs/candidate-identity.v1.json")
    )
    required_paths = {
        "terminal_guest_evidence_paths": {
            GUEST_FACTS_PATH,
            CANDIDATE_ARCHIVE_RECORD_PATH,
        },
        "terminal_snapshot_paths": {SNAPSHOT_BOUNDARY_PATH},
    }
    for field, expected in required_paths.items():
        _require(
            set(metadata[field]) == expected,
            f"metadata.{field}",
            f"must name the exact typed paths: {', '.join(sorted(expected))}",
        )
    _require(
        metadata["terminal_image"]["provenance_path"] == IMAGE_PROVENANCE_PATH,
        "metadata.terminal_image.provenance_path",
        "must name the fixed typed image-provenance path",
    )
    mandatory_required = {
        "image_provenance": {IMAGE_PROVENANCE_PATH, image_artifact_relative},
        "snapshot_boundaries": {SNAPSHOT_BOUNDARY_PATH, snapshot_artifact_relative},
        "test_results": {
            GUEST_FACTS_PATH,
            CANDIDATE_ARCHIVE_RECORD_PATH,
            archive_relative,
        },
    }
    for category, expected in mandatory_required.items():
        _require(
            expected <= set(metadata["mandatory_evidence_paths"][category]),
            f"metadata.mandatory_evidence_paths.{category}",
            "omits a fixed typed evidence record",
        )
    image = metadata["terminal_image"]
    image_artifact = BUNDLE.artifact_reference(root, root / image_artifact_relative)
    _require(
        image["bytes"]
        == {
            "length": image_artifact["length"],
            "sha256": image_artifact["sha256"],
        },
        "metadata.terminal_image.bytes",
        "differs from the manifest-destined image artifact",
    )
    source_algorithm = image["source_digest"].split(":", 1)[0]
    measured_source_digest, measured_image_length = (
        BUNDLE.digest_regular_file_algorithm(
            root / image_artifact_relative, source_algorithm
        )
    )
    _require(
        measured_source_digest == image["source_digest"]
        and measured_image_length == image_artifact["length"],
        "metadata.terminal_image.source_digest",
        "differs from the manifest-destined image artifact",
    )
    snapshot_artifact = BUNDLE.artifact_reference(
        root, root / snapshot_artifact_relative
    )
    guest_probe = BUNDLE.validate_guest_facts_record(
        BUNDLE.load_canonical_json(root / guest_facts_relative)
    )
    _require(
        guest_probe["guest_id"] == TERMINAL_GUEST
        and guest_probe["observed"] == metadata["terminal_observed"],
        "metadata.terminal_observed",
        "differs from the direct guest-probe output",
    )
    starting_source = copy.deepcopy(phase1["source"])
    final_source = copy.deepcopy(candidate["source"])
    object_format = "sha1" if len(final_source["tree"]) == 40 else "sha256"
    archive_tree = BUNDLE.candidate_archive_git_tree(
        root / archive_relative, object_format
    )
    _require(
        archive_tree == final_source["tree"],
        "candidate archive",
        "recomputed Git tree differs from the final candidate source tree",
    )
    records = {
        GUEST_FACTS_PATH: {
            "guest_id": TERMINAL_GUEST,
            "observation": BUNDLE.artifact_reference(root, root / guest_facts_relative),
            "observed": copy.deepcopy(guest_probe["observed"]),
            "schema": BUNDLE.GUEST_FACTS_BINDING_SCHEMA,
        },
        IMAGE_PROVENANCE_PATH: {
            "artifact": image_artifact,
            "bytes": copy.deepcopy(image["bytes"]),
            "guest_id": TERMINAL_GUEST,
            "schema": BUNDLE.IMAGE_PROVENANCE_SCHEMA,
            "source": image["source"],
            "source_digest": image["source_digest"],
        },
        SNAPSHOT_BOUNDARY_PATH: {
            "artifact": snapshot_artifact,
            "boundary": "preserved_first_gate_failure",
            "final_source": final_source,
            "guest_id": TERMINAL_GUEST,
            "image_sha256": image["bytes"]["sha256"],
            "schema": BUNDLE.SNAPSHOT_BOUNDARY_SCHEMA,
            "snapshot_id": snapshot_id,
            "starting_source": starting_source,
        },
        CANDIDATE_ARCHIVE_RECORD_PATH: {
            "archive": BUNDLE.artifact_reference(root, root / archive_relative),
            "archive_tree": archive_tree,
            "extraction_root": BUNDLE.GOVERNED_SOURCE_CWD,
            "final_source": final_source,
            "guest_archive_path": BUNDLE.GUEST_CANDIDATE_ARCHIVE_PATH,
            "guest_id": TERMINAL_GUEST,
            "schema": BUNDLE.CANDIDATE_ARCHIVE_SCHEMA,
            "starting_source": starting_source,
        },
    }
    BUNDLE.validate_guest_facts_binding_record(records[GUEST_FACTS_PATH])
    BUNDLE.validate_image_provenance_record(records[IMAGE_PROVENANCE_PATH])
    BUNDLE.validate_snapshot_boundary_record(records[SNAPSHOT_BOUNDARY_PATH])
    BUNDLE.validate_candidate_archive_record(records[CANDIDATE_ARCHIVE_RECORD_PATH])
    destinations = [root / path for path in records]
    for destination in destinations:
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            _error(str(destination), "typed record already exists")
    created: list[Path] = []
    try:
        for relative, record in records.items():
            destination = root / relative
            BUNDLE.write_new_canonical_json(destination, record)
            created.append(destination)
    except BaseException:
        for destination in reversed(created):
            try:
                destination.unlink()
                BUNDLE._fsync_directory(destination.parent)
            except OSError:
                pass
        raise


def build_blocked_receipt(
    root: Path, metadata_path: str = DEFAULT_METADATA_PATH
) -> dict[str, Any]:
    """Build, but do not publish, the deterministic first-gate receipt."""

    root = root.resolve(strict=True)
    for excluded in ("receipt.v1.json", "verification-result.v1.json"):
        try:
            (root / excluded).lstat()
        except FileNotFoundError:
            pass
        else:
            _error(excluded, "must not exist before receipt publication")
    preflight = BUNDLE.verify_bundle(root, require_receipt=False)
    manifest = BUNDLE.validate_manifest(
        BUNDLE.load_canonical_json(root / "manifest.v1.json")
    )
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    metadata_ref = _reference(entries, metadata_path, "metadata path")
    metadata = _metadata(BUNDLE.load_canonical_json(root / metadata_ref["path"]))

    phase1_ref = _reference(
        entries, "inputs/phase1-starting-candidate.v1.json", "phase1"
    )
    phase1 = BUNDLE.validate_phase1_record(
        BUNDLE.load_canonical_json(root / phase1_ref["path"])
    )
    candidate_ref = _reference(
        entries, "inputs/candidate-identity.v1.json", "candidate identity"
    )
    candidate = BUNDLE.validate_candidate_identity(
        BUNDLE.load_canonical_json(root / candidate_ref["path"])
    )
    claim_ref = _reference(entries, "inputs/claim.v1.json", "claim")
    claim = BUNDLE.validate_claim_contract(
        BUNDLE.load_canonical_json(root / claim_ref["path"])
    )
    harness_ref = _reference(entries, "inputs/bundle.py", "harness")
    publisher_ref = _reference(
        entries, "inputs/blocked_receipt.py", "receipt publisher"
    )
    vm_fixture_ref = _reference(entries, "inputs/vm_fixture.py", "VM fixture")
    executing_publisher_digest, executing_publisher_length = BUNDLE.digest_regular_file(
        Path(__file__).resolve(strict=True)
    )
    _require(
        executing_publisher_digest == publisher_ref["sha256"]
        and executing_publisher_length == publisher_ref["length"],
        "executing blocked_receipt.py",
        "differs from the sealed copied publisher bytes",
    )

    command_paths = sorted(
        (path for path in entries if path.endswith(".command.v1.json")), key=os.fsencode
    )
    prefix = f"guests/{TERMINAL_GUEST}/cases/{TERMINAL_FAMILY}/commands/"
    _require(
        bool(command_paths),
        "terminal commands",
        "no terminal command record is present",
    )
    _require(
        all(path.startswith(prefix) for path in command_paths),
        "terminal commands",
        "a command exists outside the bounded first-gate case",
    )
    command_refs = [copy.deepcopy(entries[path]) for path in command_paths]
    refusal_refs: list[dict[str, Any]] = []
    observed_refusals: set[tuple[str, ...]] = set()
    for path in command_paths:
        command = BUNDLE.validate_command_record(
            BUNDLE.load_canonical_json(root / path)
        )
        if command["matched_expectation"]:
            continue
        _require(
            command["executable"]["requested_path"] == "/usr/bin/ssh"
            and BUNDLE.is_exact_ssh_build_command(command["argv"])
            and command["expected_outcome"] == {"kind": "exit_code", "value": 0},
            path,
            "unexpected outcome is not an admitted exact package-build gate",
        )
        target_index = command["argv"].index(BUNDLE.SSH_BUILD_TARGET)
        remote_tail = tuple(command["argv"][target_index + 1 :])
        expected_exit = 1 if remote_tail == BUNDLE.SSH_BUILD_REMOTE_TAILS[0] else 3
        _require(
            command["outcome"]["exit_code"] == expected_exit,
            path,
            f"exact build gate must refuse with exit {expected_exit}",
        )
        observed_refusals.add(remote_tail)
        refusal_refs.append(copy.deepcopy(entries[path]))
    _require(
        len(refusal_refs) == 2
        and observed_refusals == set(BUNDLE.SSH_BUILD_REMOTE_TAILS),
        "terminal commands",
        "requires exactly checkbuilddeps exit 1 and dpkg-buildpackage exit 3",
    )

    def refs(field: str) -> list[dict[str, Any]]:
        return _references(entries, metadata[field], f"metadata.{field}")

    mandatory = {
        category: _references(
            entries,
            metadata["mandatory_evidence_paths"][category],
            f"metadata.mandatory_evidence_paths.{category}",
        )
        for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES
    }
    matrix: list[dict[str, Any]] = []
    for guest_id, distribution, release, architecture in BUNDLE.GUESTS:
        terminal = guest_id == TERMINAL_GUEST
        cases = [
            {
                "evidence": command_refs
                if terminal and family == TERMINAL_FAMILY
                else [],
                "family": family,
                "result": "blocked"
                if terminal and family == TERMINAL_FAMILY
                else "not_run",
                "summary": (
                    "clean Debian 12 candidate package build refused at the first frozen gate"
                    if terminal and family == TERMINAL_FAMILY
                    else "not executed after the bounded first-gate stop"
                ),
            }
            for family in BUNDLE.CASE_FAMILIES
        ]
        image = metadata["terminal_image"]
        matrix.append(
            {
                "architecture": architecture,
                "cases": cases,
                "distribution": distribution,
                "guest_evidence": refs("terminal_guest_evidence_paths")
                if terminal
                else [],
                "guest_id": guest_id,
                "image": {
                    "bytes": copy.deepcopy(image["bytes"]),
                    "provenance": _reference(
                        entries,
                        image["provenance_path"],
                        "metadata.terminal_image.provenance_path",
                    ),
                    "source": image["source"],
                    "source_digest": image["source_digest"],
                }
                if terminal
                else None,
                "observed": copy.deepcopy(metadata["terminal_observed"])
                if terminal
                else None,
                "release": release,
                "snapshots": refs("terminal_snapshot_paths") if terminal else [],
            }
        )

    dependency_inventory = [
        {
            "classification": item["classification"],
            "evidence": [phase1_ref],
            "id": item["id"],
            "requirement": item["requirement"],
        }
        for item in phase1["dependency_inventory"]
    ]
    defects = [
        {
            "case_refs": [TERMINAL_CASE_REF],
            "classification": "package_metadata_or_maintainer_scripts",
            "evidence": refusal_refs,
            "id": PRIMARY_DEFECT_ID,
            "summary": "Debian 12 satisfies every other declared build dependency but cannot satisfy cargo >= 1.94.0 or rustc >= 1.94.0",
        }
    ]
    defects.extend(
        _typed_records(
            entries,
            metadata.get("additional_defects", []),
            "metadata.additional_defects",
            {"case_refs", "classification", "evidence_paths", "id", "summary"},
        )
    )
    repairs = _typed_records(
        entries,
        metadata.get("repairs", []),
        "metadata.repairs",
        {
            "after_generation",
            "before_generation",
            "classification",
            "defect_id",
            "evidence_paths",
            "id",
            "summary",
        },
    )
    residual_gates = []
    for blocker in BUNDLE.KNOWN_BLOCKERS:
        terminal = blocker == "clean_offline_source_build_absent"
        residual_gates.append(
            {
                "case_refs": [TERMINAL_CASE_REF] if terminal else [],
                "classification": "package_metadata_or_maintainer_scripts"
                if terminal
                else "operator_tooling",
                "evidence": refusal_refs if terminal else [claim_ref],
                "id": blocker,
                "repair_surface": (
                    "provide and enroll the separately pinned offline Cargo/Rust 1.94 builder closure for Debian 12"
                    if terminal
                    else f"close the frozen {blocker} gate without weakening the claim"
                ),
                "summary": f"frozen blocker remains open: {blocker}",
            }
        )
    residual_gates.extend(
        _typed_records(
            entries,
            metadata.get("additional_residual_gates", []),
            "metadata.additional_residual_gates",
            {
                "case_refs",
                "classification",
                "evidence_paths",
                "id",
                "repair_surface",
                "summary",
            },
        )
    )
    controller = metadata["controller_host"]
    receipt = {
        "authority_use": BUNDLE.AUTHORITY_USE,
        "candidate": {
            "final": copy.deepcopy(candidate["source"]),
            "starting": copy.deepcopy(phase1["source"]),
        },
        "claim": {
            "blockers": copy.deepcopy(claim["blockers"]),
            "evidence": claim_ref,
            "exclusions": copy.deepcopy(claim["exclusions"]),
            "layers": [
                {"id": "package_lifecycle", "required": True, "status": "blocked"},
                {
                    "id": "live_effectd_activation",
                    "required": True,
                    "status": "not_run",
                },
                {
                    "id": "shipped_stranger_workflow",
                    "required": True,
                    "status": "blocked",
                },
            ],
        },
        "controller_host": {
            "architecture": controller["architecture"],
            "distribution": controller["distribution"],
            "evidence": _references(
                entries,
                controller["evidence_paths"],
                "metadata.controller_host.evidence_paths",
            ),
            "hypervisor": controller["hypervisor"],
            "kernel": controller["kernel"],
        },
        "defects": defects,
        "dependency_inventory": dependency_inventory,
        "evidence_manifest": copy.deepcopy(preflight["manifest"]),
        "harness": {
            "commit": candidate["source"]["commit"],
            "evidence": harness_ref,
            "publisher_evidence": publisher_ref,
            "tree": candidate["source"]["tree"],
            "vm_fixture_evidence": vm_fixture_ref,
        },
        "mandatory_evidence": mandatory,
        "matrix": matrix,
        "package_digest_history": [],
        "phase1": phase1_ref,
        "receipt_inventory": _references(
            entries,
            metadata.get("receipt_inventory_paths", []),
            "metadata.receipt_inventory_paths",
        ),
        "reconstructs_standing": False,
        "repairs": repairs,
        "residual_gates": residual_gates,
        "schema": BUNDLE.RECEIPT_SCHEMA,
        "support_boundary": None,
        "verdict": "BLOCKED",
    }
    BUNDLE.validate_final_receipt(receipt)
    return receipt


def _remove_owned_receipt(path: Path, identity: tuple[int, int]) -> None:
    """Remove only the exact receipt inode created by this publication attempt."""

    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    _require(
        (current.st_dev, current.st_ino) == identity,
        str(path),
        "changed after exclusive creation; refusing to remove a foreign node",
    )
    path.unlink()
    BUNDLE._fsync_directory(path.parent)


def _publish_receipt_bytes(path: Path, payload: bytes) -> tuple[int, int]:
    """Publish complete bytes atomically without replacing an existing receipt."""

    staging_directory = path.parent.parent
    _require(
        staging_directory.stat().st_dev == path.parent.stat().st_dev,
        str(staging_directory),
        "receipt staging directory must share the evidence filesystem",
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.parent.name}.{path.name}.",
        suffix=".tmp",
        dir=staging_directory,
    )
    temporary_path = Path(temporary_name)
    identity: tuple[int, int] | None = None
    linked = False
    try:
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("receipt write made no progress")
            offset += written
        os.fsync(descriptor)
        closing_descriptor = descriptor
        descriptor = -1
        os.close(closing_descriptor)
        os.link(temporary_path, path, follow_symlinks=False)
        linked = True
        published = path.lstat()
        _require(
            (published.st_dev, published.st_ino) == identity,
            str(path),
            "published receipt does not identify the completed temporary inode",
        )
        BUNDLE._fsync_directory(path.parent)
        _remove_owned_receipt(temporary_path, identity)
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if linked and identity is not None:
            _remove_owned_receipt(path, identity)
        if identity is not None:
            _remove_owned_receipt(temporary_path, identity)
        else:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            BUNDLE._fsync_directory(temporary_path.parent)
        raise
    assert identity is not None
    return identity


def publish_blocked_receipt(
    root: Path, metadata_path: str = DEFAULT_METADATA_PATH
) -> dict[str, Any]:
    """Publish ``receipt.v1.json`` with O_EXCL, then fully reopen the bundle."""

    root = root.resolve(strict=True)
    receipt = build_blocked_receipt(root, metadata_path)
    BUNDLE.verify_bundle(root, require_receipt=True, receipt_candidate=receipt)

    receipt_path = root / "receipt.v1.json"
    try:
        identity = _publish_receipt_bytes(
            receipt_path, BUNDLE.canonical_json_bytes(receipt)
        )
    except FileExistsError as error:
        raise BUNDLE.QualificationError("receipt.v1.json: already exists") from error
    try:
        BUNDLE.verify_bundle(root, require_receipt=True)
    except BaseException:
        _remove_owned_receipt(receipt_path, identity)
        raise
    return receipt


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--metadata", default=DEFAULT_METADATA_PATH)
    parser.add_argument("--prepare-evidence", action="store_true")
    parser.add_argument("--archive")
    parser.add_argument("--guest-facts-observation")
    parser.add_argument("--image-artifact")
    parser.add_argument("--snapshot-artifact")
    parser.add_argument("--snapshot-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.prepare_evidence:
            _require(arguments.archive is not None, "--archive", "is required")
            _require(
                arguments.guest_facts_observation is not None,
                "--guest-facts-observation",
                "is required",
            )
            _require(
                arguments.image_artifact is not None,
                "--image-artifact",
                "is required",
            )
            _require(
                arguments.snapshot_artifact is not None,
                "--snapshot-artifact",
                "is required",
            )
            _require(
                arguments.snapshot_id is not None,
                "--snapshot-id",
                "is required",
            )
            prepare_typed_evidence(
                arguments.root,
                arguments.archive,
                arguments.guest_facts_observation,
                arguments.image_artifact,
                arguments.snapshot_artifact,
                arguments.snapshot_id,
                arguments.metadata,
            )
        else:
            _require(
                arguments.archive is None
                and arguments.guest_facts_observation is None
                and arguments.image_artifact is None
                and arguments.snapshot_artifact is None
                and arguments.snapshot_id is None,
                "arguments",
                "preparation arguments require --prepare-evidence",
            )
            publish_blocked_receipt(arguments.root, arguments.metadata)
    except (BUNDLE.QualificationError, OSError) as error:
        print(f"blocked-receipt: {error}", file=sys.stderr)
        return 2
    if arguments.prepare_evidence:
        print(f"rendered typed evidence below {arguments.root / 'mandatory'}")
    else:
        print(f"published BLOCKED receipt at {arguments.root / 'receipt.v1.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
