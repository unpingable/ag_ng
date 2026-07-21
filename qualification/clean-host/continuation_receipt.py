#!/usr/bin/python3
"""Publish and reopen the Debian 12 amd64 clean-host continuation receipt.

This module deliberately leaves the frozen ``receipt/v1`` BLOCKED claim
untouched.  It reuses the frozen controller's command records, case clocks,
and evidence manifest while applying a new, narrower continuation claim.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Sequence


# Initialization measures the invoking worktree.  Prevent the dynamic import
# below from creating an untracked ``__pycache__`` before that measurement.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("clean_host_bundle", HERE / "bundle.py")
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


CLAIM_SCHEMA = "ag.clean-host-package-qualification-continuation-claim/v1"
RECEIPT_SCHEMA = "ag.clean-host-package-qualification-continuation-receipt/v1"
METADATA_SCHEMA = "ag.clean-host-package-qualification-continuation-metadata/v1"
BUILD_RECORD_SCHEMA = "ag.clean-host-package-build/v1"
IDENTITY_SCHEMA = "ag.clean-host-continuation-tool-identity/v1"
DEFAULT_METADATA_PATH = "inputs/continuation-receipt-metadata.v1.json"
SCOPED_GUEST = BUNDLE.GUESTS[0]
SCOPED_GUEST_ID = SCOPED_GUEST[0]
UNQUALIFIED_GUESTS = BUNDLE.GUESTS[1:]
VERDICTS = frozenset(("REQUALIFIED", "BLOCKED"))
LAYER_IDS = ("package_lifecycle", "live_effectd_activation")
LAYER_RESULTS = frozenset(("pass", "blocked", "not_run"))
PACKAGE_LAYER_CASES = frozenset(
    (
        "package_build_and_payload",
        "fresh_install_and_reboot",
        "remove_reinstall_reconstruct",
        "identical_bytes_packaging_upgrade",
        "changed_build_safe_refusal",
    )
)
ACTIVATION_LAYER_CASES = frozenset(BUNDLE.CASE_FAMILIES) - PACKAGE_LAYER_CASES
PREDECESSOR_RUN_ID = "20260720-debian12-amd64-9a5f140"
PREDECESSOR_SOURCE = {
    "commit": "9a5f14006cdc342d1625204a08f19d00adf7e660",
    "tree": "0aa4f4c871957c57e47b97e9c5a0f7fcb8860de8",
}
PREDECESSOR_IDENTITIES = {
    "evidence_locator": {
        "length": 1977,
        "sha256": "sha256:5cbe4a813896d1816d172834fac3b31514b340aaf3b19764f4960489de32ee35",
    },
    "manifest": {
        "length": 42719,
        "sha256": "sha256:3625ffd2b4796aecd5d78093a25f6ba9adfa5df563d2cc78154b1ab80c325efe",
    },
    "receipt": {
        "length": 45454,
        "sha256": "sha256:a1d57540fe1cfc58fc6b82a92aa15fc24d9f6399855acb07944c8d4727aaeacf",
    },
    "verification_result": {
        "length": 364,
        "sha256": "sha256:f1e636cac592891b5b0beb9992a444c4402da40e82b84185b9999851260ba3a5",
    },
}
PREDECESSOR_BUNDLE_PATHS = {
    "evidence_locator": "inputs/predecessor/evidence-locator.v1.json",
    "manifest": "inputs/predecessor/manifest.v1.json",
    "receipt": "inputs/predecessor/receipt.v1.json",
    "verification_result": "inputs/predecessor/verification-result.v1.json",
}
SOURCE_INPUT_PATHS = (
    "Cargo.lock",
    "Cargo.toml",
    "debian/control",
    "debian/rules",
)


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
    _require(type(value) is str and bool(value.strip()), location, "must be nonempty")
    return value


def _string_list(value: Any, location: str) -> list[str]:
    _require(type(value) is list, location, "must be an array")
    result = [_text(item, f"{location}[{index}]") for index, item in enumerate(value)]
    _require(len(result) == len(set(result)), location, "contains duplicates")
    return result


def _path(value: Any, location: str) -> str:
    return BUNDLE._validate_relative_path(_text(value, location), location)


def _paths(value: Any, location: str) -> list[str]:
    result = [_path(item, f"{location}[{index}]") for index, item in enumerate(
        value if type(value) is list else _error(location, "must be an array")
    )]
    _require(len(result) == len(set(result)), location, "contains duplicates")
    return result


def _reference(
    entries: dict[str, dict[str, Any]], path: str, location: str
) -> dict[str, Any]:
    normalized = _path(path, location)
    _require(normalized in entries, location, "does not name manifest-covered evidence")
    return copy.deepcopy(entries[normalized])


def _references(
    entries: dict[str, dict[str, Any]], paths: Any, location: str
) -> list[dict[str, Any]]:
    return [
        _reference(entries, path, f"{location}[{index}]")
        for index, path in enumerate(_paths(paths, location))
    ]


def validate_claim(value: Any) -> dict[str, Any]:
    claim = _object(
        value,
        "continuation-claim",
        {
            "authority_use",
            "case_families",
            "claim_layers",
            "exclusions",
            "predecessor",
            "qualified_guest",
            "reconstructs_standing",
            "schema",
            "unqualified_guests",
            "verdicts",
        },
    )
    _require(claim["schema"] == CLAIM_SCHEMA, "continuation-claim.schema", "wrong schema")
    _require(
        claim["authority_use"] == BUNDLE.AUTHORITY_USE,
        "continuation-claim.authority_use",
        "must be evidence_only",
    )
    _require(
        claim["reconstructs_standing"] is False,
        "continuation-claim.reconstructs_standing",
        "must be false",
    )
    _require(
        claim["case_families"] == list(BUNDLE.CASE_FAMILIES),
        "continuation-claim.case_families",
        "must retain all frozen case families in order",
    )
    expected_layers = [{"id": layer, "required": True} for layer in LAYER_IDS]
    _require(
        claim["claim_layers"] == expected_layers,
        "continuation-claim.claim_layers",
        "wrong scoped claim layers",
    )
    expected_guest = {
        "architecture": SCOPED_GUEST[3],
        "distribution": SCOPED_GUEST[1],
        "id": SCOPED_GUEST[0],
        "release": SCOPED_GUEST[2],
    }
    _require(
        claim["qualified_guest"] == expected_guest,
        "continuation-claim.qualified_guest",
        "must be exactly Debian 12 amd64",
    )
    expected_unqualified = [
        {
            "architecture": guest[3],
            "disposition": "not_run_not_claimed",
            "distribution": guest[1],
            "id": guest[0],
            "release": guest[2],
        }
        for guest in UNQUALIFIED_GUESTS
    ]
    _require(
        claim["unqualified_guests"] == expected_unqualified,
        "continuation-claim.unqualified_guests",
        "must preserve the other three frozen cells as unqualified",
    )
    _require(claim["verdicts"] == ["REQUALIFIED", "BLOCKED"], "continuation-claim.verdicts", "wrong verdict domain")
    _require(
        "shipped_stranger_submit_ratify_workflow" in claim["exclusions"]
        and "compiler_closure_and_byte_reproducibility" in claim["exclusions"],
        "continuation-claim.exclusions",
        "must preserve both explicit continuation exclusions",
    )
    predecessor = _object(
        claim["predecessor"],
        "continuation-claim.predecessor",
        {
            "candidate",
            "evidence_locator",
            "manifest",
            "receipt",
            "run_id",
            "verification_result",
            "verdict",
        },
    )
    _require(predecessor["run_id"] == PREDECESSOR_RUN_ID, "continuation-claim.predecessor.run_id", "wrong predecessor")
    _require(predecessor["candidate"] == PREDECESSOR_SOURCE, "continuation-claim.predecessor.candidate", "wrong predecessor source")
    _require(predecessor["verdict"] == "BLOCKED", "continuation-claim.predecessor.verdict", "must be BLOCKED")
    for name, identity in PREDECESSOR_IDENTITIES.items():
        _require(predecessor[name] == identity, f"continuation-claim.predecessor.{name}", "wrong immutable identity")
    return claim


def _repository_root() -> Path:
    return HERE.parents[1]


def initialize_bundle(root: Path, matrix_path: Path | None = None) -> None:
    """Initialise the frozen layout, then add continuation-only bound inputs."""

    source_matrix = HERE / "matrix.toml" if matrix_path is None else matrix_path
    BUNDLE.initialize_bundle(root, source_matrix)
    root = root.resolve(strict=True)
    repository = _repository_root()
    claim_path = HERE / "continuation-claim.v1.json"
    validate_claim(BUNDLE.load_canonical_json(claim_path))
    additions: list[tuple[Path, Path]] = [
        (claim_path, root / "inputs/continuation-claim.v1.json"),
        (Path(__file__).resolve(strict=True), root / "inputs/continuation_receipt.py"),
    ]
    predecessor_root = (
        repository
        / "qualification/receipts/clean-host"
        / PREDECESSOR_RUN_ID
    )
    additions.extend(
        (
            predecessor_root / source_name,
            root / PREDECESSOR_BUNDLE_PATHS[key],
        )
        for key, source_name in (
            ("evidence_locator", "evidence-locator.v1.json"),
            ("manifest", "manifest.v1.json"),
            ("receipt", "receipt.v1.json"),
            ("verification_result", "verification-result.v1.json"),
        )
    )
    additions.extend(
        (repository / relative, root / "inputs/build-source" / relative)
        for relative in SOURCE_INPUT_PATHS
    )
    for source, destination in additions:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        BUNDLE.write_new_bytes(destination, source.read_bytes())
    candidate = BUNDLE.validate_candidate_identity(
        BUNDLE.load_canonical_json(root / "inputs/candidate-identity.v1.json")
    )
    payload = Path(__file__).resolve(strict=True).read_bytes()
    tracked: bytes | None
    try:
        tracked = BUNDLE._git_output(
            repository,
            ("show", f"{candidate['source']['commit']}:qualification/clean-host/continuation_receipt.py"),
        )
    except BUNDLE.QualificationError:
        tracked = None
    identity = {
        "matches_head": tracked == payload,
        "path": "qualification/clean-host/continuation_receipt.py",
        "schema": IDENTITY_SCHEMA,
        "source": copy.deepcopy(candidate["source"]),
        "tracked_sha256": None if tracked is None else f"sha256:{hashlib.sha256(tracked).hexdigest()}",
        "working_sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
    }
    BUNDLE.write_new_canonical_json(root / "inputs/continuation-identity.v1.json", identity)


def _validate_identity(value: Any, location: str) -> dict[str, Any]:
    return BUNDLE._validate_receipt_identity(value, location)


def _validate_source(value: Any, location: str) -> dict[str, Any]:
    source = BUNDLE._validate_source_cut(value, location)
    _require(source["worktree"] == "clean", f"{location}.worktree", "must be clean")
    return source


def validate_build_record(value: Any) -> dict[str, Any]:
    record = _object(
        value,
        "package-build",
        {
            "build_command",
            "cargo_home",
            "cargo_lock",
            "cargo_version_verbose",
            "environment",
            "native_tools",
            "network_access",
            "output",
            "output_preexisting",
            "package_control_evidence",
            "runtime_dependencies",
            "rustc_version_verbose",
            "schema",
            "source",
            "target_directory",
            "target_triple",
        },
    )
    _require(record["schema"] == BUILD_RECORD_SCHEMA, "package-build.schema", "wrong schema")
    _validate_source(record["source"], "package-build.source")
    for field in (
        "build_command",
        "cargo_lock",
        "cargo_version_verbose",
        "output",
        "package_control_evidence",
        "rustc_version_verbose",
    ):
        _validate_identity(record[field], f"package-build.{field}")
    _require(
        record["build_command"]["path"].startswith(
            f"guests/{SCOPED_GUEST_ID}/cases/package_build_and_payload/commands/"
        )
        and record["build_command"]["path"].endswith(".command.v1.json"),
        "package-build.build_command.path",
        "must name a scoped package-build command",
    )
    _require(
        record["cargo_lock"]["path"] == "inputs/build-source/Cargo.lock",
        "package-build.cargo_lock.path",
        "must bind the copied candidate Cargo.lock",
    )
    _require(
        record["output"]["path"].startswith("packages/generation-"),
        "package-build.output.path",
        "must reside below a package generation",
    )
    _require(record["output_preexisting"] is False, "package-build.output_preexisting", "stale output is inadmissible")
    _require(record["target_triple"] == "x86_64-unknown-linux-gnu", "package-build.target_triple", "wrong target")
    _require(record["network_access"] in ("available", "unavailable"), "package-build.network_access", "invalid state")
    for field in ("cargo_home", "target_directory"):
        boundary = _object(record[field], f"package-build.{field}", {"path", "strategy"})
        _text(boundary["path"], f"package-build.{field}.path")
        _text(boundary["strategy"], f"package-build.{field}.strategy")
    environment = record["environment"]
    _require(type(environment) is list, "package-build.environment", "must be an array")
    names: list[str] = []
    for index, raw in enumerate(environment):
        item = _object(raw, f"package-build.environment[{index}]", {"name", "value"})
        name = _text(item["name"], f"package-build.environment[{index}].name")
        _require(BUNDLE.ENV_NAME_RE.fullmatch(name) is not None, f"package-build.environment[{index}].name", "invalid environment name")
        _require(type(item["value"]) is str, f"package-build.environment[{index}].value", "must be a string")
        names.append(name)
    _require(names == sorted(set(names)), "package-build.environment", "must be uniquely name-sorted")
    tools = record["native_tools"]
    _require(type(tools) is list and bool(tools), "package-build.native_tools", "must be nonempty")
    tool_names: list[str] = []
    for index, raw in enumerate(tools):
        tool = _object(raw, f"package-build.native_tools[{index}]", {"name", "version_evidence"})
        tool_names.append(_text(tool["name"], f"package-build.native_tools[{index}].name"))
        _validate_identity(tool["version_evidence"], f"package-build.native_tools[{index}].version_evidence")
    _require(tool_names == sorted(set(tool_names)), "package-build.native_tools", "must be uniquely name-sorted")
    dependencies = _string_list(record["runtime_dependencies"], "package-build.runtime_dependencies")
    normalized = {re.split(r"[ (]", dependency, maxsplit=1)[0] for dependency in dependencies}
    _require("cargo" not in normalized and "rustc" not in normalized, "package-build.runtime_dependencies", "Rust and Cargo must not be runtime dependencies")
    return record


def _validate_case(value: Any, location: str, expected_family: str) -> dict[str, Any]:
    case = _object(value, location, {"evidence", "family", "result", "summary"})
    _require(case["family"] == expected_family, f"{location}.family", "wrong case order")
    _require(case["result"] in BUNDLE.CASE_RESULTS, f"{location}.result", "invalid result")
    _text(case["summary"], f"{location}.summary")
    _require(type(case["evidence"]) is list, f"{location}.evidence", "must be an array")
    for index, reference in enumerate(case["evidence"]):
        _validate_identity(reference, f"{location}.evidence[{index}]")
    if case["result"] != "not_run":
        _require(bool(case["evidence"]), f"{location}.evidence", "executed case requires evidence")
    else:
        _require(not case["evidence"], f"{location}.evidence", "not-run case must be empty")
    return case


def _validate_matrix(value: Any) -> tuple[list[str], dict[str, str]]:
    _require(type(value) is list and len(value) == len(BUNDLE.GUESTS), "receipt.matrix", "must retain four cells")
    scoped_results: list[str] = []
    results_by_ref: dict[str, str] = {}
    for cell_index, (raw_cell, guest) in enumerate(zip(value, BUNDLE.GUESTS, strict=True)):
        location = f"receipt.matrix[{cell_index}]"
        cell = _object(
            raw_cell,
            location,
            {"architecture", "cases", "distribution", "guest_evidence", "guest_id", "image", "observed", "release", "snapshots"},
        )
        expected = {"guest_id": guest[0], "distribution": guest[1], "release": guest[2], "architecture": guest[3]}
        for field, setting in expected.items():
            _require(cell[field] == setting, f"{location}.{field}", "differs from frozen cell")
        cases = cell["cases"]
        _require(type(cases) is list and len(cases) == len(BUNDLE.CASE_FAMILIES), f"{location}.cases", "must retain all cases")
        for case_index, family in enumerate(BUNDLE.CASE_FAMILIES):
            case = _validate_case(cases[case_index], f"{location}.cases[{case_index}]", family)
            results_by_ref[f"{guest[0]}/{family}"] = case["result"]
            if cell_index == 0:
                _require(case["result"] != "unsupported", f"{location}.cases[{case_index}].result", "supported scoped guest cannot be unsupported")
                scoped_results.append(case["result"])
            else:
                _require(case["result"] == "not_run", f"{location}.cases[{case_index}].result", "unqualified cell must remain not_run")
        for field in ("guest_evidence", "snapshots"):
            _require(type(cell[field]) is list, f"{location}.{field}", "must be an array")
            for index, reference in enumerate(cell[field]):
                _validate_identity(reference, f"{location}.{field}[{index}]")
        if cell_index:
            _require(cell["image"] is None and cell["observed"] is None and not cell["guest_evidence"] and not cell["snapshots"], location, "unqualified cell must contain no execution evidence")
        else:
            runtime_executed = any(
                case["result"] != "not_run" for case in cases[1:]
            )
            execution_identity_present = (
                cell["image"] is not None
                or cell["observed"] is not None
                or bool(cell["guest_evidence"])
                or bool(cell["snapshots"])
            )
            _require(
                not runtime_executed
                or (
                    cell["image"] is not None
                    and cell["observed"] is not None
                    and bool(cell["guest_evidence"])
                    and bool(cell["snapshots"])
                ),
                location,
                "executed runtime cases require image, facts, and snapshot evidence",
            )
            _require(
                not execution_identity_present
                or (
                    cell["image"] is not None
                    and cell["observed"] is not None
                    and bool(cell["guest_evidence"])
                    and bool(cell["snapshots"])
                ),
                location,
                "partial guest execution identity is forbidden",
            )
            if not execution_identity_present:
                continue
            image = _object(cell["image"], f"{location}.image", {"bytes", "provenance", "source", "source_digest"})
            BUNDLE._validate_external_identity(image["bytes"], f"{location}.image.bytes")
            _validate_identity(image["provenance"], f"{location}.image.provenance")
            _text(image["source"], f"{location}.image.source")
            _text(image["source_digest"], f"{location}.image.source_digest")
            observed = _object(cell["observed"], f"{location}.observed", {"active_lsms", "architecture", "cgroup", "distribution", "filesystem", "kernel", "landlock_abi", "release", "systemd"})
            for field, setting in expected.items():
                if field != "guest_id":
                    _require(observed[field] == setting, f"{location}.observed.{field}", "wrong observed guest")
            _require(observed["landlock_abi"].isdigit() and int(observed["landlock_abi"]) >= 3, f"{location}.observed.landlock_abi", "requires Landlock ABI >= 3")
            systemd = re.match(r"[0-9]+", observed["systemd"])
            kernel = re.match(r"([0-9]+)\.([0-9]+)", observed["kernel"])
            _require(systemd is not None and int(systemd.group()) >= 252, f"{location}.observed.systemd", "requires systemd >= 252")
            _require(kernel is not None and tuple(map(int, kernel.groups())) >= (6, 1), f"{location}.observed.kernel", "requires Linux >= 6.1")
    return scoped_results, results_by_ref


def _validate_case_refs(value: Any, location: str) -> list[str]:
    refs = _string_list(value, location)
    admitted = {f"{SCOPED_GUEST_ID}/{family}" for family in BUNDLE.CASE_FAMILIES}
    _require(set(refs) <= admitted, location, "must refer only to scoped cases")
    return refs


def _validate_findings(value: Any, location: str, kind: str) -> list[dict[str, Any]]:
    _require(type(value) is list, location, "must be an array")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_location = f"{location}[{index}]"
        if kind == "defect":
            fields = {"case_refs", "classification", "evidence", "id", "summary"}
        elif kind == "repair":
            fields = {"after_generation", "before_generation", "classification", "defect_id", "evidence", "id", "summary"}
        else:
            fields = {"case_refs", "classification", "evidence", "id", "repair_surface", "summary"}
        item = _object(raw, item_location, fields)
        item_id = BUNDLE._validate_id(item["id"], f"{item_location}.id")
        _require(item_id not in seen, f"{item_location}.id", "duplicate id")
        seen.add(item_id)
        _require(item["classification"] in BUNDLE.DEFECT_CLASSES, f"{item_location}.classification", "invalid class")
        _text(item["summary"], f"{item_location}.summary")
        evidence = item["evidence"]
        _require(type(evidence) is list and bool(evidence), f"{item_location}.evidence", "must be nonempty")
        for evidence_index, reference in enumerate(evidence):
            _validate_identity(reference, f"{item_location}.evidence[{evidence_index}]")
        if kind in ("defect", "residual"):
            _validate_case_refs(item["case_refs"], f"{item_location}.case_refs")
        if kind == "repair":
            BUNDLE._validate_id(item["defect_id"], f"{item_location}.defect_id")
            for field in ("before_generation", "after_generation"):
                setting = item[field]
                _require(setting is None or (type(setting) is int and setting > 0), f"{item_location}.{field}", "must be null or positive")
        if kind == "residual":
            _text(item["repair_surface"], f"{item_location}.repair_surface")
        result.append(item)
    return result


def _validate_package_history(
    value: Any, candidate: dict[str, Any]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    _require(type(value) is list, "receipt.package_digest_history", "must be an array")
    generations: dict[int, dict[str, Any]] = {}
    main_debs: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        location = f"receipt.package_digest_history[{index}]"
        generation = _object(raw, location, {"artifacts", "generation", "reason", "source_commit", "source_tree"})
        number = generation["generation"]
        _require(type(number) is int and number > 0 and number not in generations, f"{location}.generation", "must be a unique positive integer")
        _text(generation["reason"], f"{location}.reason")
        BUNDLE._validate_git_id(generation["source_commit"], f"{location}.source_commit")
        BUNDLE._validate_git_id(generation["source_tree"], f"{location}.source_tree")
        artifacts = generation["artifacts"]
        _require(type(artifacts) is list and bool(artifacts), f"{location}.artifacts", "must be nonempty")
        for artifact_index, raw_artifact in enumerate(artifacts):
            artifact_location = f"{location}.artifacts[{artifact_index}]"
            artifact = _object(raw_artifact, artifact_location, {"architecture", "identity", "kind", "name", "version"})
            _require(artifact["architecture"] == "amd64", f"{artifact_location}.architecture", "continuation admits only amd64 artifacts")
            for field in ("kind", "name", "version"):
                _text(artifact[field], f"{artifact_location}.{field}")
            _validate_identity(artifact["identity"], f"{artifact_location}.identity")
            _require(artifact["identity"]["path"].startswith(f"packages/generation-{number}/"), f"{artifact_location}.identity.path", "wrong generation directory")
            if artifact["kind"] == "deb" and artifact["name"] == "agent-governor-ng":
                main_debs.append(artifact)
        generations[number] = generation
    _require(set(generations) == set(range(1, len(generations) + 1)), "receipt.package_digest_history", "generations must be contiguous")
    if generations:
        final = generations[max(generations)]
        _require(final["source_commit"] == candidate["commit"] and final["source_tree"] == candidate["tree"], "receipt.package_digest_history", "final generation must bind the candidate")
    return generations, main_debs


def _validate_predecessor_shape(value: Any) -> dict[str, Any]:
    predecessor = _object(
        value,
        "receipt.predecessor",
        {"candidate", "evidence_locator", "manifest", "receipt", "run_id", "verification_result", "verdict"},
    )
    _require(predecessor["run_id"] == PREDECESSOR_RUN_ID, "receipt.predecessor.run_id", "wrong predecessor")
    _require(predecessor["candidate"] == PREDECESSOR_SOURCE, "receipt.predecessor.candidate", "wrong predecessor candidate")
    _require(predecessor["verdict"] == "BLOCKED", "receipt.predecessor.verdict", "must be BLOCKED")
    for key, path in PREDECESSOR_BUNDLE_PATHS.items():
        reference = _validate_identity(predecessor[key], f"receipt.predecessor.{key}")
        _require(reference["path"] == path, f"receipt.predecessor.{key}.path", "wrong copied predecessor path")
        _require({"length": reference["length"], "sha256": reference["sha256"]} == PREDECESSOR_IDENTITIES[key], f"receipt.predecessor.{key}", "wrong immutable predecessor identity")
    return predecessor


def validate_receipt(value: Any) -> dict[str, Any]:
    receipt = _object(
        value,
        "receipt",
        {
            "authority_use",
            "build",
            "candidate",
            "claim",
            "controller_host",
            "defects",
            "evidence_manifest",
            "harness",
            "mandatory_evidence",
            "matrix",
            "package_digest_history",
            "predecessor",
            "reconstructs_standing",
            "repairs",
            "residual_gates",
            "schema",
            "unqualified_scope",
            "verdict",
        },
    )
    _require(receipt["schema"] == RECEIPT_SCHEMA, "receipt.schema", "wrong schema")
    _require(receipt["authority_use"] == BUNDLE.AUTHORITY_USE, "receipt.authority_use", "must be evidence_only")
    _require(receipt["reconstructs_standing"] is False, "receipt.reconstructs_standing", "must be false")
    verdict = _text(receipt["verdict"], "receipt.verdict")
    _require(verdict in VERDICTS, "receipt.verdict", "invalid continuation verdict")
    candidate = _validate_source(receipt["candidate"], "receipt.candidate")
    manifest = _validate_identity(receipt["evidence_manifest"], "receipt.evidence_manifest")
    _require(manifest["path"] == "manifest.v1.json", "receipt.evidence_manifest.path", "must bind root manifest")
    claim = _object(receipt["claim"], "receipt.claim", {"evidence", "exclusions", "layers"})
    claim_evidence = _validate_identity(claim["evidence"], "receipt.claim.evidence")
    _require(claim_evidence["path"] == "inputs/continuation-claim.v1.json", "receipt.claim.evidence.path", "must bind continuation claim")
    _require(type(claim["exclusions"]) is list and bool(claim["exclusions"]), "receipt.claim.exclusions", "must be nonempty")
    layers = claim["layers"]
    _require(type(layers) is list and len(layers) == len(LAYER_IDS), "receipt.claim.layers", "wrong layer count")
    layer_statuses: dict[str, str] = {}
    for index, layer_id in enumerate(LAYER_IDS):
        layer = _object(layers[index], f"receipt.claim.layers[{index}]", {"id", "required", "status"})
        _require(layer["id"] == layer_id and layer["required"] is True, f"receipt.claim.layers[{index}]", "wrong layer")
        _require(layer["status"] in LAYER_RESULTS, f"receipt.claim.layers[{index}].status", "wrong status")
        layer_statuses[layer_id] = layer["status"]
    _validate_predecessor_shape(receipt["predecessor"])
    harness = _object(receipt["harness"], "receipt.harness", {"commit", "controller", "publisher", "tree", "vm_fixture"})
    _require(harness["commit"] == candidate["commit"] and harness["tree"] == candidate["tree"], "receipt.harness", "must bind candidate source")
    for field, expected_path in (
        ("controller", "inputs/bundle.py"),
        ("publisher", "inputs/continuation_receipt.py"),
        ("vm_fixture", "inputs/vm_fixture.py"),
    ):
        reference = _validate_identity(harness[field], f"receipt.harness.{field}")
        _require(reference["path"] == expected_path, f"receipt.harness.{field}.path", "wrong tool path")
    host = _object(receipt["controller_host"], "receipt.controller_host", {"architecture", "distribution", "evidence", "hypervisor", "kernel"})
    for field in ("architecture", "distribution", "hypervisor", "kernel"):
        _text(host[field], f"receipt.controller_host.{field}")
    _require(type(host["evidence"]) is list and bool(host["evidence"]), "receipt.controller_host.evidence", "must be nonempty")
    for index, reference in enumerate(host["evidence"]):
        _validate_identity(reference, f"receipt.controller_host.evidence[{index}]")
    mandatory = _object(receipt["mandatory_evidence"], "receipt.mandatory_evidence", set(BUNDLE.MANDATORY_EVIDENCE_CATEGORIES))
    for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
        _require(type(mandatory[category]) is list, f"receipt.mandatory_evidence.{category}", "must be an array")
        for index, reference in enumerate(mandatory[category]):
            validated = _validate_identity(reference, f"receipt.mandatory_evidence.{category}[{index}]")
            _require(validated["path"].startswith(f"mandatory/{category}/"), f"receipt.mandatory_evidence.{category}[{index}].path", "wrong evidence role")
    scoped_results, results_by_ref = _validate_matrix(receipt["matrix"])
    expected_unqualified = [
        {"disposition": "not_run_not_claimed", "guest_id": guest[0]}
        for guest in UNQUALIFIED_GUESTS
    ]
    _require(receipt["unqualified_scope"] == expected_unqualified, "receipt.unqualified_scope", "must explicitly retain the three unqualified cells")
    generations, main_debs = _validate_package_history(receipt["package_digest_history"], candidate)
    build = receipt["build"]
    if build is not None:
        build = _validate_identity(build, "receipt.build")
        _require(build["path"].startswith("mandatory/test_results/") and build["path"].endswith(".json"), "receipt.build.path", "must name a typed test-result record")
    defects = _validate_findings(receipt["defects"], "receipt.defects", "defect")
    repairs = _validate_findings(receipt["repairs"], "receipt.repairs", "repair")
    residual = _validate_findings(receipt["residual_gates"], "receipt.residual_gates", "residual")
    defect_ids = {defect["id"] for defect in defects}
    for index, repair in enumerate(repairs):
        _require(repair["defect_id"] in defect_ids or repair["defect_id"] == "clean_offline_source_build_absent", f"receipt.repairs[{index}].defect_id", "unknown defect")
        for field in ("before_generation", "after_generation"):
            generation = repair[field]
            _require(generation is None or generation in generations, f"receipt.repairs[{index}].{field}", "unknown generation")
    for index, gate in enumerate(residual):
        for case_ref in gate["case_refs"]:
            _require(results_by_ref[case_ref] != "pass", f"receipt.residual_gates[{index}].case_refs", "cannot point at passing case")
    package_status = layer_statuses["package_lifecycle"]
    activation_status = layer_statuses["live_effectd_activation"]
    results_by_family = dict(zip(BUNDLE.CASE_FAMILIES, scoped_results, strict=True))
    for status, families, layer_id in (
        (package_status, PACKAGE_LAYER_CASES, "package_lifecycle"),
        (activation_status, ACTIVATION_LAYER_CASES, "live_effectd_activation"),
    ):
        if status == "pass":
            _require(all(results_by_family[family] == "pass" for family in families), f"receipt.claim.layers.{layer_id}", "pass requires every mapped case to pass")
    if verdict == "REQUALIFIED":
        _require(all(result == "pass" for result in scoped_results), "receipt.verdict", "REQUALIFIED requires all scoped cases to pass")
        _require(all(status == "pass" for status in layer_statuses.values()), "receipt.claim.layers", "REQUALIFIED requires both layers to pass")
        _require(build is not None, "receipt.build", "REQUALIFIED requires build evidence")
        _require(bool(generations), "receipt.package_digest_history", "REQUALIFIED requires a package generation")
        final_generation = max(generations)
        final_debs = [
            artifact
            for artifact in generations[final_generation]["artifacts"]
            if artifact["kind"] == "deb" and artifact["name"] == "agent-governor-ng"
        ]
        _require(len(final_debs) == 1, "receipt.package_digest_history", "final generation requires exactly one amd64 agent-governor-ng deb")
        _require(not residual, "receipt.residual_gates", "REQUALIFIED cannot retain an in-scope residual gate")
        for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
            _require(bool(mandatory[category]), f"receipt.mandatory_evidence.{category}", "REQUALIFIED requires this role")
    else:
        terminal_indices = [index for index, result in enumerate(scoped_results) if result in ("fail", "blocked")]
        _require(bool(terminal_indices), "receipt.matrix[0]", "BLOCKED requires an exact failed or blocked case")
        terminal = terminal_indices[0]
        _require(all(result == "pass" for result in scoped_results[:terminal]), "receipt.matrix[0]", "cases before the terminal obstruction must pass")
        _require(all(result == "not_run" for result in scoped_results[terminal + 1 :]), "receipt.matrix[0]", "cases after the terminal obstruction must remain not_run")
        terminal_ref = f"{SCOPED_GUEST_ID}/{BUNDLE.CASE_FAMILIES[terminal]}"
        _require(any(terminal_ref in defect["case_refs"] for defect in defects), "receipt.defects", "BLOCKED requires a defect bound to the terminal case")
        _require(any(terminal_ref in gate["case_refs"] for gate in residual), "receipt.residual_gates", "BLOCKED requires a residual gate bound to the terminal case")
    return receipt


def _metadata(value: Any) -> dict[str, Any]:
    metadata = _object(
        value,
        "metadata",
        {
            "authority_use",
            "build_record_path",
            "claim_layers",
            "controller_host",
            "defects",
            "mandatory_evidence_paths",
            "package_digest_history",
            "repairs",
            "residual_gates",
            "schema",
            "scoped_guest",
            "verdict",
        },
    )
    _require(metadata["schema"] == METADATA_SCHEMA, "metadata.schema", "wrong schema")
    _require(metadata["authority_use"] == BUNDLE.AUTHORITY_USE, "metadata.authority_use", "must be evidence_only")
    _require(metadata["verdict"] in VERDICTS, "metadata.verdict", "invalid verdict")
    layers = metadata["claim_layers"]
    _require(type(layers) is list and len(layers) == len(LAYER_IDS), "metadata.claim_layers", "wrong layer count")
    for index, layer_id in enumerate(LAYER_IDS):
        layer = _object(layers[index], f"metadata.claim_layers[{index}]", {"id", "required", "status"})
        _require(layer["id"] == layer_id and layer["required"] is True and layer["status"] in LAYER_RESULTS, f"metadata.claim_layers[{index}]", "invalid layer")
    build_path = metadata["build_record_path"]
    _require(build_path is None or type(build_path) is str, "metadata.build_record_path", "must be null or path")
    if build_path is not None:
        _path(build_path, "metadata.build_record_path")
    host = _object(metadata["controller_host"], "metadata.controller_host", {"architecture", "distribution", "evidence_paths", "hypervisor", "kernel"})
    for field in ("architecture", "distribution", "hypervisor", "kernel"):
        _text(host[field], f"metadata.controller_host.{field}")
    _require(bool(_paths(host["evidence_paths"], "metadata.controller_host.evidence_paths")), "metadata.controller_host.evidence_paths", "must be nonempty")
    mandatory = _object(metadata["mandatory_evidence_paths"], "metadata.mandatory_evidence_paths", set(BUNDLE.MANDATORY_EVIDENCE_CATEGORIES))
    for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
        for path in _paths(mandatory[category], f"metadata.mandatory_evidence_paths.{category}"):
            _require(path.startswith(f"mandatory/{category}/"), f"metadata.mandatory_evidence_paths.{category}", "wrong role path")
    scoped = _object(metadata["scoped_guest"], "metadata.scoped_guest", {"cases", "guest_evidence_paths", "image", "observed", "snapshot_paths"})
    cases = scoped["cases"]
    _require(type(cases) is list and len(cases) == len(BUNDLE.CASE_FAMILIES), "metadata.scoped_guest.cases", "must contain all cases")
    for index, family in enumerate(BUNDLE.CASE_FAMILIES):
        case = _object(cases[index], f"metadata.scoped_guest.cases[{index}]", {"evidence_paths", "family", "result", "summary"})
        _require(case["family"] == family and case["result"] in BUNDLE.CASE_RESULTS, f"metadata.scoped_guest.cases[{index}]", "invalid case")
        _text(case["summary"], f"metadata.scoped_guest.cases[{index}].summary")
        _paths(case["evidence_paths"], f"metadata.scoped_guest.cases[{index}].evidence_paths")
    for field in ("guest_evidence_paths", "snapshot_paths"):
        _paths(scoped[field], f"metadata.scoped_guest.{field}")
    image = scoped["image"]
    if image is not None:
        image = _object(image, "metadata.scoped_guest.image", {"bytes", "provenance_path", "source", "source_digest"})
        BUNDLE._validate_external_identity(image["bytes"], "metadata.scoped_guest.image.bytes")
        _path(image["provenance_path"], "metadata.scoped_guest.image.provenance_path")
        _text(image["source"], "metadata.scoped_guest.image.source")
        _text(image["source_digest"], "metadata.scoped_guest.image.source_digest")
    _require(scoped["observed"] is None or type(scoped["observed"]) is dict, "metadata.scoped_guest.observed", "must be null or object")
    _require(type(metadata["package_digest_history"]) is list, "metadata.package_digest_history", "must be an array")
    for index, generation in enumerate(metadata["package_digest_history"]):
        location = f"metadata.package_digest_history[{index}]"
        generation = _object(generation, location, {"artifacts", "generation", "reason", "source_commit", "source_tree"})
        _require(type(generation["artifacts"]) is list and bool(generation["artifacts"]), f"{location}.artifacts", "must be nonempty")
        for artifact_index, artifact in enumerate(generation["artifacts"]):
            artifact = _object(artifact, f"{location}.artifacts[{artifact_index}]", {"architecture", "kind", "name", "path", "version"})
            _path(artifact["path"], f"{location}.artifacts[{artifact_index}].path")
    for field, kind in (("defects", "defect"), ("repairs", "repair"), ("residual_gates", "residual")):
        records = metadata[field]
        _require(type(records) is list, f"metadata.{field}", "must be an array")
        for index, record in enumerate(records):
            if kind == "defect":
                fields = {"case_refs", "classification", "evidence_paths", "id", "summary"}
            elif kind == "repair":
                fields = {"after_generation", "before_generation", "classification", "defect_id", "evidence_paths", "id", "summary"}
            else:
                fields = {"case_refs", "classification", "evidence_paths", "id", "repair_surface", "summary"}
            item = _object(record, f"metadata.{field}[{index}]", fields)
            _paths(item["evidence_paths"], f"metadata.{field}[{index}].evidence_paths")
    return metadata


def _finding_references(
    entries: dict[str, dict[str, Any]], records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for index, raw in enumerate(records):
        item = copy.deepcopy(raw)
        item["evidence"] = _references(
            entries,
            item.pop("evidence_paths"),
            f"metadata.findings[{index}].evidence_paths",
        )
        converted.append(item)
    return converted


def build_receipt(root: Path, metadata_path: str = DEFAULT_METADATA_PATH) -> dict[str, Any]:
    """Build, but do not publish, one deterministic continuation receipt."""

    root = root.resolve(strict=True)
    _require(not (root / "receipt.v1.json").exists(), "receipt.v1.json", "already exists")
    BUNDLE.verify_bundle(root, require_receipt=False)
    manifest = BUNDLE.validate_manifest(BUNDLE.load_canonical_json(root / "manifest.v1.json"))
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    metadata_ref = _reference(entries, metadata_path, "metadata path")
    metadata = _metadata(BUNDLE.load_canonical_json(root / metadata_ref["path"]))
    claim_ref = _reference(entries, "inputs/continuation-claim.v1.json", "continuation claim")
    claim = validate_claim(BUNDLE.load_canonical_json(root / claim_ref["path"]))
    candidate_ref = _reference(entries, "inputs/candidate-identity.v1.json", "candidate identity")
    candidate_identity = BUNDLE.validate_candidate_identity(BUNDLE.load_canonical_json(root / candidate_ref["path"]))
    candidate = copy.deepcopy(candidate_identity["source"])
    _require(candidate["worktree"] == "clean", "candidate.worktree", "must be clean")
    continuation_identity_ref = _reference(entries, "inputs/continuation-identity.v1.json", "continuation identity")
    continuation_identity = BUNDLE.load_canonical_json(root / continuation_identity_ref["path"])
    _require(continuation_identity.get("schema") == IDENTITY_SCHEMA and continuation_identity.get("matches_head") is True and continuation_identity.get("source") == candidate, "continuation identity", "publisher must be committed in the exact clean candidate")

    def refs(paths: Any, location: str) -> list[dict[str, Any]]:
        return _references(entries, paths, location)

    scoped = metadata["scoped_guest"]
    scoped_cases = [
        {
            "evidence": refs(case["evidence_paths"], f"metadata.scoped_guest.cases[{index}].evidence_paths"),
            "family": case["family"],
            "result": case["result"],
            "summary": case["summary"],
        }
        for index, case in enumerate(scoped["cases"])
    ]
    image_metadata = scoped["image"]
    scoped_cell = {
        "architecture": SCOPED_GUEST[3],
        "cases": scoped_cases,
        "distribution": SCOPED_GUEST[1],
        "guest_evidence": refs(scoped["guest_evidence_paths"], "metadata.scoped_guest.guest_evidence_paths"),
        "guest_id": SCOPED_GUEST_ID,
        "image": None if image_metadata is None else {
            "bytes": copy.deepcopy(image_metadata["bytes"]),
            "provenance": _reference(entries, image_metadata["provenance_path"], "metadata.scoped_guest.image.provenance_path"),
            "source": image_metadata["source"],
            "source_digest": image_metadata["source_digest"],
        },
        "observed": copy.deepcopy(scoped["observed"]),
        "release": SCOPED_GUEST[2],
        "snapshots": refs(scoped["snapshot_paths"], "metadata.scoped_guest.snapshot_paths"),
    }
    matrix = [scoped_cell]
    for guest in UNQUALIFIED_GUESTS:
        matrix.append(
            {
                "architecture": guest[3],
                "cases": [
                    {"evidence": [], "family": family, "result": "not_run", "summary": "outside the exact Debian 12 amd64 continuation scope"}
                    for family in BUNDLE.CASE_FAMILIES
                ],
                "distribution": guest[1],
                "guest_evidence": [],
                "guest_id": guest[0],
                "image": None,
                "observed": None,
                "release": guest[2],
                "snapshots": [],
            }
        )
    package_history = []
    for generation in metadata["package_digest_history"]:
        converted = copy.deepcopy(generation)
        converted["artifacts"] = [
            {
                "architecture": artifact["architecture"],
                "identity": _reference(entries, artifact["path"], "metadata.package_digest_history.artifact.path"),
                "kind": artifact["kind"],
                "name": artifact["name"],
                "version": artifact["version"],
            }
            for artifact in generation["artifacts"]
        ]
        package_history.append(converted)
    mandatory = {
        category: refs(metadata["mandatory_evidence_paths"][category], f"metadata.mandatory_evidence_paths.{category}")
        for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES
    }
    predecessor = {
        "candidate": copy.deepcopy(PREDECESSOR_SOURCE),
        "run_id": PREDECESSOR_RUN_ID,
        "verdict": "BLOCKED",
    }
    predecessor.update(
        {
            key: _reference(entries, path, f"predecessor.{key}")
            for key, path in PREDECESSOR_BUNDLE_PATHS.items()
        }
    )
    host = metadata["controller_host"]
    manifest_digest, manifest_length = BUNDLE.digest_regular_file(root / "manifest.v1.json")
    receipt = {
        "authority_use": BUNDLE.AUTHORITY_USE,
        "build": None if metadata["build_record_path"] is None else _reference(entries, metadata["build_record_path"], "metadata.build_record_path"),
        "candidate": candidate,
        "claim": {
            "evidence": claim_ref,
            "exclusions": copy.deepcopy(claim["exclusions"]),
            "layers": copy.deepcopy(metadata["claim_layers"]),
        },
        "controller_host": {
            "architecture": host["architecture"],
            "distribution": host["distribution"],
            "evidence": refs(host["evidence_paths"], "metadata.controller_host.evidence_paths"),
            "hypervisor": host["hypervisor"],
            "kernel": host["kernel"],
        },
        "defects": _finding_references(entries, metadata["defects"]),
        "evidence_manifest": {"length": manifest_length, "path": "manifest.v1.json", "sha256": manifest_digest},
        "harness": {
            "commit": candidate["commit"],
            "controller": _reference(entries, "inputs/bundle.py", "controller"),
            "publisher": _reference(entries, "inputs/continuation_receipt.py", "publisher"),
            "tree": candidate["tree"],
            "vm_fixture": _reference(entries, "inputs/vm_fixture.py", "vm fixture"),
        },
        "mandatory_evidence": mandatory,
        "matrix": matrix,
        "package_digest_history": package_history,
        "predecessor": predecessor,
        "reconstructs_standing": False,
        "repairs": _finding_references(entries, metadata["repairs"]),
        "residual_gates": _finding_references(entries, metadata["residual_gates"]),
        "schema": RECEIPT_SCHEMA,
        "unqualified_scope": [
            {"disposition": "not_run_not_claimed", "guest_id": guest[0]}
            for guest in UNQUALIFIED_GUESTS
        ],
        "verdict": metadata["verdict"],
    }
    validate_receipt(receipt)
    verify_bundle(root, receipt_candidate=receipt)
    return receipt


def _verify_predecessor(root: Path, predecessor: dict[str, Any]) -> None:
    receipt_path = root / predecessor["receipt"]["path"]
    manifest_path = root / predecessor["manifest"]["path"]
    result_path = root / predecessor["verification_result"]["path"]
    locator_path = root / predecessor["evidence_locator"]["path"]
    prior_receipt = BUNDLE.validate_final_receipt(BUNDLE.load_canonical_json(receipt_path))
    prior_manifest = BUNDLE.validate_manifest(BUNDLE.load_canonical_json(manifest_path))
    prior_result = BUNDLE.validate_verification_result(BUNDLE.load_canonical_json(result_path))
    locator = _object(
        BUNDLE.load_canonical_json(locator_path),
        "predecessor locator",
        {"authority_use", "candidate", "raw_bundle", "reopen", "run_id", "schema", "tracked_copies", "verdict"},
    )
    _require(prior_receipt["verdict"] == "BLOCKED", "predecessor receipt", "must be BLOCKED")
    _require(prior_receipt["candidate"]["final"]["commit"] == PREDECESSOR_SOURCE["commit"] and prior_receipt["candidate"]["final"]["tree"] == PREDECESSOR_SOURCE["tree"], "predecessor receipt candidate", "wrong source")
    _require(prior_result["valid"] is True and prior_result["verdict"] == "BLOCKED", "predecessor verification", "must be a valid BLOCKED result")
    _require(
        {"length": prior_result["receipt"]["length"], "sha256": prior_result["receipt"]["sha256"]} == PREDECESSOR_IDENTITIES["receipt"]
        and {"length": prior_result["manifest"]["length"], "sha256": prior_result["manifest"]["sha256"]} == PREDECESSOR_IDENTITIES["manifest"],
        "predecessor verification",
        "does not bind the copied prior receipt and manifest",
    )
    _require(locator["schema"] == "ag.clean-host-qualification-evidence-locator/v1" and locator["authority_use"] == BUNDLE.AUTHORITY_USE and locator["run_id"] == PREDECESSOR_RUN_ID and locator["verdict"] == "BLOCKED", "predecessor locator", "wrong locator identity")
    _require(locator["candidate"] == PREDECESSOR_SOURCE, "predecessor locator.candidate", "wrong source")
    raw = locator["raw_bundle"]
    for key in ("manifest", "receipt", "verification_result"):
        _require({"length": raw[key]["length"], "sha256": raw[key]["sha256"]} == PREDECESSOR_IDENTITIES[key], f"predecessor locator.raw_bundle.{key}", "wrong identity")
    tracked = {
        PurePosixPath(item["path"]).name: {"length": item["length"], "sha256": item["sha256"]}
        for item in locator["tracked_copies"]
    }
    _require(tracked == {
        "manifest.v1.json": PREDECESSOR_IDENTITIES["manifest"],
        "receipt.v1.json": PREDECESSOR_IDENTITIES["receipt"],
        "verification-result.v1.json": PREDECESSOR_IDENTITIES["verification_result"],
    }, "predecessor locator.tracked_copies", "wrong tracked identity set")
    _require(len(prior_manifest["entries"]) > 0, "predecessor manifest.entries", "must not be empty")
    first = prior_receipt["matrix"][0]["cases"]
    _require(first[0]["result"] == "blocked", "predecessor receipt.matrix[0].cases[0]", "must preserve first-gate block")
    _require(all(case["result"] == "not_run" for case in first[1:]), "predecessor receipt.matrix[0]", "later cases must remain not_run")
    for cell in prior_receipt["matrix"][1:]:
        _require(all(case["result"] == "not_run" for case in cell["cases"]), "predecessor receipt.matrix", "other cells must remain not_run")


def _verify_build_record(
    root: Path,
    receipt: dict[str, Any],
    manifest_entries: dict[str, dict[str, Any]],
) -> None:
    if receipt["build"] is None:
        return
    record = validate_build_record(BUNDLE.load_canonical_json(root / receipt["build"]["path"]))
    _require(record["source"] == receipt["candidate"], "package-build.source", "must bind receipt candidate")
    for index, reference in enumerate(BUNDLE._collect_artifact_references(record)):
        BUNDLE._verify_reference(reference, manifest_entries, f"package-build reference {index}")
    final_generation = max(item["generation"] for item in receipt["package_digest_history"])
    final_debs = [
        artifact
        for generation in receipt["package_digest_history"]
        if generation["generation"] == final_generation
        for artifact in generation["artifacts"]
        if artifact["kind"] == "deb" and artifact["name"] == "agent-governor-ng"
    ]
    _require(len(final_debs) == 1 and record["output"] == final_debs[0]["identity"], "package-build.output", "must be the exact final candidate deb")
    cargo_lock = root / record["cargo_lock"]["path"]
    source_lock = root / "inputs/build-source/Cargo.lock"
    _require(cargo_lock.read_bytes() == source_lock.read_bytes(), "package-build.cargo_lock", "differs from copied source lock")


def _verify_commands(
    root: Path,
    receipt: dict[str, Any],
    manifest_entries: dict[str, dict[str, Any]],
) -> None:
    assignments: dict[str, tuple[str, str, str]] = {}
    for cell in receipt["matrix"]:
        for case in cell["cases"]:
            for reference in case["evidence"]:
                path = reference["path"]
                if not path.endswith(".command.v1.json"):
                    continue
                _require(path not in assignments, "receipt.matrix.cases.evidence", f"duplicate command assignment: {path}")
                assignments[path] = (cell["guest_id"], case["family"], case["result"])
    command_paths = {path for path in manifest_entries if path.endswith(".command.v1.json")}
    _require(command_paths == set(assignments), "receipt.matrix.cases.evidence", "every command must be assigned exactly once")
    expected_command_files: set[str] = set()
    expected_clock_files: set[str] = set()
    actual_command_files = {path for path in manifest_entries if "/commands/" in path}
    actual_clock_files = {path for path in manifest_entries if path.endswith("/case-wall-clock.v1.json")}
    commands_by_case: dict[tuple[str, str], list[dict[str, Any]]] = {}
    duration_by_case: dict[tuple[str, str], int] = {}
    for path in sorted(command_paths, key=os.fsencode):
        record = BUNDLE.validate_command_record(BUNDLE.load_canonical_json(root / path))
        guest_id, family, command_id = BUNDLE._command_path_identity(path)
        _require((record["guest_id"], record["case_family"], record["command_id"]) == (guest_id, family, command_id), path, "record identity differs from path")
        _require(guest_id == SCOPED_GUEST_ID, path, "command exists outside continuation scope")
        _require(assignments[path][:2] == (guest_id, family), path, "assigned to wrong case")
        if assignments[path][2] == "pass":
            _require(record["matched_expectation"], f"{path}.matched_expectation", "passing case contains unexpected command outcome")
        for index, observed in enumerate(record["observed_inputs"]):
            resolved = Path(observed["resolved_path"])
            try:
                relative = resolved.relative_to(root).as_posix()
            except ValueError:
                continue
            _require(relative in manifest_entries, f"{path}.observed_inputs[{index}]", "bundle-local input is not sealed")
            enrolled = manifest_entries[relative]
            _require(observed["sha256"] == enrolled["sha256"] and observed["length"] == enrolled["length"], f"{path}.observed_inputs[{index}]", "input identity differs from seal")
        clock_path = (PurePosixPath(path).parent.parent / "case-wall-clock.v1.json").as_posix()
        _require(record["case_wall_clock"]["path"] == clock_path, f"{path}.case_wall_clock.path", "wrong clock")
        BUNDLE._verify_reference(record["case_wall_clock"], manifest_entries, f"{path}.case_wall_clock")
        clock = BUNDLE._validate_case_clock(BUNDLE.load_canonical_json(root / clock_path), guest_id, family)
        _require(clock["started_boottime_ns"] <= record["started_boottime_ns"] <= record["ended_boottime_ns"] <= clock["deadline_boottime_ns"], f"{path}.case_wall_clock", "command lies outside case boundary")
        expected_clock_files.add(clock_path)
        for stream in ("stdout", "stderr"):
            stream_path = (PurePosixPath(path).parent / f"{command_id}.{stream}").as_posix()
            _require(record[stream]["path"] == stream_path, f"{path}.{stream}.path", "wrong stream")
            BUNDLE._verify_reference(record[stream], manifest_entries, f"{path}.{stream}")
            expected_command_files.add(stream_path)
        expected_command_files.add(path)
        key = (guest_id, family)
        commands_by_case.setdefault(key, []).append(record)
        duration_by_case[key] = duration_by_case.get(key, 0) + record["duration_ms"]
    _require(actual_command_files == expected_command_files, "commands", "orphan, missing, or unrecognized command evidence")
    _require(actual_clock_files == expected_clock_files, "case clocks", "orphan or missing case clock")
    for family, case in zip(BUNDLE.CASE_FAMILIES, receipt["matrix"][0]["cases"], strict=True):
        records = commands_by_case.get((SCOPED_GUEST_ID, family), [])
        if case["result"] == "pass":
            _require(bool(records), f"receipt.matrix[0].{family}", "passing case requires a command record")
        elif case["result"] in ("blocked", "fail"):
            _require(bool(records) and any(not record["matched_expectation"] for record in records), f"receipt.matrix[0].{family}", "terminal obstruction requires an unexpected command outcome")
    for key, duration in duration_by_case.items():
        _require(duration <= BUNDLE.PER_CASE_DEADLINE_SECONDS * 1000, f"{key[0]}.{key[1]}.duration", "exceeds case deadline")


def verify_bundle(
    root: Path,
    receipt_candidate: dict[str, Any] | None = None,
    require_receipt: bool = True,
) -> dict[str, Any]:
    """Recompute the continuation seal, predecessor, receipt, and commands."""

    root = root.resolve(strict=True)
    manifest = BUNDLE.validate_manifest(BUNDLE.load_canonical_json(root / "manifest.v1.json"))
    BUNDLE.verify_manifest_coverage(root, manifest)
    plan = BUNDLE._load_controller_plan(root)
    for guest_id in plan["guest_ids"]:
        for family in plan["case_ids"]:
            path = root / "guests" / guest_id / "cases" / family / "case-plan.v1.json"
            expected = {
                "case_family": family,
                "guest_id": guest_id,
                "per_case_deadline_seconds": BUNDLE.PER_CASE_DEADLINE_SECONDS,
                "per_command_deadline_seconds": BUNDLE.PER_COMMAND_DEADLINE_SECONDS,
                "schema": BUNDLE.CONTROLLER_SCHEMA,
            }
            _require(BUNDLE.load_canonical_json(path) == expected, str(path), "wrong case plan")
    entries = {entry["path"]: entry for entry in manifest["entries"]}
    for tool_path in ("inputs/bundle.py", "inputs/continuation_receipt.py"):
        _require(tool_path in entries, tool_path, "executing tool is absent from seal")
    executing_bundle = BUNDLE.digest_regular_file(Path(BUNDLE.__file__).resolve(strict=True))
    executing_publisher = BUNDLE.digest_regular_file(Path(__file__).resolve(strict=True))
    for path, identity in (("inputs/bundle.py", executing_bundle), ("inputs/continuation_receipt.py", executing_publisher)):
        _require(entries[path]["sha256"] == identity[0] and entries[path]["length"] == identity[1], path, "executing bytes differ from sealed copy")
    receipt_path = root / "receipt.v1.json"
    if receipt_candidate is None:
        if not receipt_path.exists():
            _require(not require_receipt, str(receipt_path), "missing continuation receipt")
            return {
                "manifest": BUNDLE.artifact_reference(root, root / "manifest.v1.json"),
                "receipt": None,
                "schema": BUNDLE.VERIFICATION_SCHEMA,
                "valid": True,
                "verdict": None,
            }
        receipt = validate_receipt(BUNDLE.load_canonical_json(receipt_path))
        receipt_identity = BUNDLE.artifact_reference(root, receipt_path)
    else:
        _require(not receipt_path.exists(), str(receipt_path), "cannot preflight over an existing receipt")
        receipt = validate_receipt(copy.deepcopy(receipt_candidate))
        payload = BUNDLE.canonical_json_bytes(receipt)
        receipt_identity = {"length": len(payload), "path": "receipt.v1.json", "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}"}
    manifest_identity = BUNDLE.artifact_reference(root, root / "manifest.v1.json")
    _require(receipt["evidence_manifest"] == manifest_identity, "receipt.evidence_manifest", "manifest binding mismatch")
    for index, reference in enumerate(BUNDLE._collect_artifact_references(receipt)):
        if reference["path"] == "manifest.v1.json":
            continue
        BUNDLE._verify_reference(reference, entries, f"receipt reference {index}")
    claim = validate_claim(BUNDLE.load_canonical_json(root / receipt["claim"]["evidence"]["path"]))
    _require(receipt["claim"]["exclusions"] == claim["exclusions"], "receipt.claim.exclusions", "differs from claim")
    candidate_identity = BUNDLE.validate_candidate_identity(BUNDLE.load_canonical_json(root / "inputs/candidate-identity.v1.json"))
    _require(candidate_identity["source"] == receipt["candidate"] and candidate_identity["source"]["worktree"] == "clean", "receipt.candidate", "differs from clean initialization identity")
    _require(candidate_identity["harness"]["matches_head"] and candidate_identity["vm_fixture"]["matches_head"], "candidate identity", "controller or VM fixture differs from candidate commit")
    continuation_identity = BUNDLE.load_canonical_json(root / "inputs/continuation-identity.v1.json")
    _require(continuation_identity.get("schema") == IDENTITY_SCHEMA and continuation_identity.get("matches_head") is True and continuation_identity.get("source") == receipt["candidate"], "continuation identity", "publisher differs from candidate commit")
    _verify_predecessor(root, receipt["predecessor"])
    _verify_build_record(root, receipt, entries)
    _verify_commands(root, receipt, entries)
    return {
        "manifest": manifest_identity,
        "receipt": receipt_identity,
        "schema": BUNDLE.VERIFICATION_SCHEMA,
        "valid": True,
        "verdict": receipt["verdict"],
    }


def publish_receipt(root: Path, metadata_path: str = DEFAULT_METADATA_PATH) -> dict[str, Any]:
    root = root.resolve(strict=True)
    receipt = build_receipt(root, metadata_path)
    BUNDLE.write_new_bytes(root / "receipt.v1.json", BUNDLE.canonical_json_bytes(receipt))
    return verify_bundle(root)


def _write_verification_result(root: Path, result: dict[str, Any]) -> None:
    path = root / "verification-result.v1.json"
    if path.exists():
        _require(BUNDLE.load_canonical_json(path) == result, str(path), "stale or contradictory result")
    else:
        BUNDLE.write_new_canonical_json(path, result)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init", help="initialise a continuation evidence bundle")
    init.add_argument("root", type=Path)
    init.add_argument("--matrix", type=Path)
    publish = subparsers.add_parser("publish", help="publish the sealed continuation receipt")
    publish.add_argument("root", type=Path)
    publish.add_argument("--metadata", default=DEFAULT_METADATA_PATH)
    verify = subparsers.add_parser("verify", help="recompute the continuation receipt and seal")
    verify.add_argument("root", type=Path)
    verify.add_argument("--allow-missing-receipt", action="store_true")
    verify.add_argument("--write-result", action="store_true")
    receipt = subparsers.add_parser("validate-receipt", help="validate canonical continuation receipt shape")
    receipt.add_argument("path", type=Path)
    build = subparsers.add_parser("validate-build-record", help="validate one typed build record")
    build.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            initialize_bundle(arguments.root, arguments.matrix)
            print(f"initialised continuation evidence bundle at {arguments.root}")
        elif arguments.command == "publish":
            result = publish_receipt(arguments.root, arguments.metadata)
            print(BUNDLE.canonical_json_bytes(result).decode("utf-8"), end="")
        elif arguments.command == "verify":
            result = verify_bundle(arguments.root, require_receipt=not arguments.allow_missing_receipt)
            if arguments.write_result:
                _write_verification_result(arguments.root.resolve(strict=True), result)
            print(BUNDLE.canonical_json_bytes(result).decode("utf-8"), end="")
        elif arguments.command == "validate-receipt":
            validate_receipt(BUNDLE.load_canonical_json(arguments.path))
            print("continuation receipt is structurally valid")
        else:
            validate_build_record(BUNDLE.load_canonical_json(arguments.path))
            print("package build record is structurally valid")
    except BUNDLE.QualificationError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
