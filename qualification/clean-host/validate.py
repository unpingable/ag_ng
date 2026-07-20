#!/usr/bin/python3
"""Validate the checked-in clean-host qualification contract.

This validator is deliberately rootless and uses only the Python standard
library.  It validates the source claim, matrix, and receipt *template*.  The
template has a schema distinct from a completed receipt so it cannot be
promoted by changing only its verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn


CLAIM_SCHEMA = "ag.clean-host-package-qualification-claim/v1"
MATRIX_SCHEMA = "ag.clean-host-package-qualification-matrix/v1"
RECEIPT_TEMPLATE_SCHEMA = (
    "ag.clean-host-package-qualification-receipt-template/v1"
)
RECEIPT_SCHEMA = "ag.clean-host-package-qualification-receipt/v1"

AUTHORITY_USE = "evidence_only"
BLOCKERS = (
    "clean_offline_source_build_absent",
    "production_artifact_admission_ingress_absent",
    "expanded_system_call_filter_live_attestation_absent",
    "offline_store_upgrade_activation_absent",
)
EXCLUSIONS = (
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
LAYER_IDS = (
    "package_lifecycle",
    "live_effectd_activation",
    "shipped_stranger_workflow",
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
    {
        "id": "debian-12-amd64",
        "distribution": "debian",
        "release": "12",
        "architecture": "amd64",
    },
    {
        "id": "debian-12-arm64",
        "distribution": "debian",
        "release": "12",
        "architecture": "arm64",
    },
    {
        "id": "ubuntu-24.04-amd64",
        "distribution": "ubuntu",
        "release": "24.04",
        "architecture": "amd64",
    },
    {
        "id": "ubuntu-24.04-arm64",
        "distribution": "ubuntu",
        "release": "24.04",
        "architecture": "arm64",
    },
)

RESULTS = frozenset(("pass", "fail", "blocked", "not_run"))
VERDICTS = frozenset(("qualified", "failed", "blocked", "not_run"))
SHA256_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ContractError(ValueError):
    """The source qualification contract is malformed or inconsistent."""


def _error(location: str, message: str) -> NoReturn:
    raise ContractError(f"{location}: {message}")


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


def _ordered_exact_strings(
    value: Any, location: str, expected: tuple[str, ...]
) -> list[str]:
    items = _strict_list(value, location)
    for index, item in enumerate(items):
        _strict_string(item, f"{location}[{index}]")
    _require(items == list(expected), location, "does not match the frozen v1 list")
    return items


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(token: str) -> NoReturn:
    raise ContractError(f"JSON contains non-finite number {token!r}")


def load_canonical_json(path: Path) -> Any:
    """Load an exact canonical JSON document terminated by one LF."""

    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(f"{path}: is not UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, ContractError) as error:
        raise ContractError(f"{path}: invalid strict JSON: {error}") from error
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    _require(raw == canonical, str(path), "must be canonical JSON plus exactly one LF")
    return value


def load_matrix(path: Path) -> Any:
    """Load the qualification matrix as strict UTF-8 TOML."""

    raw = path.read_bytes()
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ContractError(f"{path}: invalid UTF-8 TOML: {error}") from error


def _validate_layer_list(value: Any, location: str) -> list[dict[str, Any]]:
    layers = _strict_list(value, location)
    _require(len(layers) == len(LAYER_IDS), location, "must contain exactly three layers")
    seen: list[str] = []
    for index, layer_value in enumerate(layers):
        layer_location = f"{location}[{index}]"
        layer = _strict_object(
            layer_value, layer_location, {"id", "required", "status"}
        )
        layer_id = _strict_string(layer["id"], f"{layer_location}.id")
        _require(layer_id in LAYER_IDS, f"{layer_location}.id", "unknown layer id")
        _require(
            _strict_bool(layer["required"], f"{layer_location}.required"),
            f"{layer_location}.required",
            "all v1 layers are mandatory",
        )
        status = _strict_string(layer["status"], f"{layer_location}.status")
        _require(status in RESULTS, f"{layer_location}.status", "unknown result enum")
        seen.append(layer_id)
    _require(seen == list(LAYER_IDS), location, "layers must be complete and ordered")
    shipped = layers[LAYER_IDS.index("shipped_stranger_workflow")]
    _require(
        shipped["status"] == "blocked",
        f"{location}[2].status",
        "must remain blocked while production admission ingress is absent",
    )
    return layers


def _expected_verdict(
    layer_results: list[str], case_results: list[str], blockers: list[str]
) -> str:
    results = layer_results + case_results
    if "fail" in results:
        return "failed"
    if "not_run" in results:
        return "not_run"
    if "blocked" in results or blockers:
        return "blocked"
    return "qualified"


def validate_claim(value: Any) -> dict[str, Any]:
    """Validate the frozen v1 claim and its current verdict."""

    claim = _strict_object(
        value,
        "claim",
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
    _require(claim["schema"] == CLAIM_SCHEMA, "claim.schema", "unknown schema")
    _require(
        claim["authority_use"] == AUTHORITY_USE,
        "claim.authority_use",
        "must be evidence_only",
    )
    blockers = _ordered_exact_strings(claim["blockers"], "claim.blockers", BLOCKERS)
    _ordered_exact_strings(claim["exclusions"], "claim.exclusions", EXCLUSIONS)
    _require(
        _strict_bool(claim["reconstructs_standing"], "claim.reconstructs_standing")
        is False,
        "claim.reconstructs_standing",
        "qualification evidence must not reconstruct standing",
    )
    layers = _validate_layer_list(claim["claim_layers"], "claim.claim_layers")
    verdict = _strict_string(claim["verdict"], "claim.verdict")
    _require(verdict in VERDICTS, "claim.verdict", "unknown verdict enum")
    expected = _expected_verdict(
        [layer["status"] for layer in layers], [], blockers
    )
    _require(verdict == expected, "claim.verdict", f"must be {expected!r}")
    return claim


def validate_matrix(value: Any) -> dict[str, Any]:
    """Validate the exact four-cell guest and case-family matrix."""

    matrix = _strict_object(
        value,
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
    _ordered_exact_strings(
        matrix["mandatory_case_families"],
        "matrix.mandatory_case_families",
        CASE_FAMILIES,
    )
    _require(
        matrix["mandatory_enrollment_reload"]
        == "systemctl daemon-reload before effective-unit comparison and first start",
        "matrix.mandatory_enrollment_reload",
        "does not match the v1 reload gate",
    )
    _require(
        _strict_int(
            matrix["per_command_deadline_seconds"],
            "matrix.per_command_deadline_seconds",
        )
        == 120,
        "matrix.per_command_deadline_seconds",
        "must be 120",
    )
    _require(
        _strict_int(
            matrix["per_case_deadline_seconds"], "matrix.per_case_deadline_seconds"
        )
        == 1800,
        "matrix.per_case_deadline_seconds",
        "must be 1800",
    )
    guests = _strict_list(matrix["guests"], "matrix.guests")
    _require(len(guests) == len(GUESTS), "matrix.guests", "must contain exactly four guests")
    for index, (guest_value, expected) in enumerate(zip(guests, GUESTS, strict=True)):
        location = f"matrix.guests[{index}]"
        guest = _strict_object(
            guest_value,
            location,
            {"architecture", "distribution", "id", "image_digest", "release"},
        )
        for key, expected_value in expected.items():
            _require(guest[key] == expected_value, f"{location}.{key}", "unexpected guest cell")
        image_digest = _strict_string(guest["image_digest"], f"{location}.image_digest")
        _require(
            image_digest == "UNENROLLED" or SHA256_IMAGE.fullmatch(image_digest) is not None,
            f"{location}.image_digest",
            "must be UNENROLLED or a lowercase sha256 digest",
        )
    return matrix


def _validate_receipt_cases(value: Any, matrix: dict[str, Any]) -> list[str]:
    cells = _strict_list(value, "receipt-template.cases")
    guests = matrix["guests"]
    _require(
        len(cells) == len(guests),
        "receipt-template.cases",
        "must contain exactly one case cell per guest",
    )
    results: list[str] = []
    for index, (cell_value, guest) in enumerate(zip(cells, guests, strict=True)):
        location = f"receipt-template.cases[{index}]"
        cell = _strict_object(cell_value, location, {"guest_id", "results"})
        _require(
            cell["guest_id"] == guest["id"],
            f"{location}.guest_id",
            "must match the guest matrix order",
        )
        result_map = _strict_object(
            cell["results"], f"{location}.results", set(CASE_FAMILIES)
        )
        for family in CASE_FAMILIES:
            result = _strict_string(
                result_map[family], f"{location}.results.{family}"
            )
            _require(
                result in RESULTS,
                f"{location}.results.{family}",
                "unknown result enum",
            )
            results.append(result)
    return results


def validate_receipt_template(
    value: Any, claim: dict[str, Any], matrix: dict[str, Any]
) -> dict[str, Any]:
    """Validate the inert template; this function never accepts a final receipt."""

    receipt = _strict_object(
        value,
        "receipt-template",
        {
            "authority_use",
            "blockers",
            "cases",
            "claim",
            "exclusions",
            "fixtures",
            "harness",
            "matrix",
            "packages",
            "reconstructs_standing",
            "schema",
            "source",
            "target_schema",
            "template_only",
            "verdict",
        },
    )
    _require(
        receipt["schema"] == RECEIPT_TEMPLATE_SCHEMA,
        "receipt-template.schema",
        "must use the non-promotable template schema",
    )
    _require(
        receipt["target_schema"] == RECEIPT_SCHEMA,
        "receipt-template.target_schema",
        "unknown target receipt schema",
    )
    _require(
        _strict_bool(receipt["template_only"], "receipt-template.template_only"),
        "receipt-template.template_only",
        "must be true",
    )
    _require(
        receipt["authority_use"] == claim["authority_use"] == AUTHORITY_USE,
        "receipt-template.authority_use",
        "must carry the claim authority-use boundary",
    )
    _require(
        receipt["blockers"] == claim["blockers"],
        "receipt-template.blockers",
        "must exactly carry the claim blockers",
    )
    _require(
        receipt["exclusions"] == claim["exclusions"],
        "receipt-template.exclusions",
        "must exactly carry the claim exclusions",
    )
    _require(
        _strict_bool(
            receipt["reconstructs_standing"],
            "receipt-template.reconstructs_standing",
        )
        is False,
        "receipt-template.reconstructs_standing",
        "qualification evidence must not reconstruct standing",
    )

    receipt_claim = _strict_object(
        receipt["claim"], "receipt-template.claim", {"layers", "schema"}
    )
    _require(
        receipt_claim["schema"] == CLAIM_SCHEMA,
        "receipt-template.claim.schema",
        "must bind the v1 claim schema",
    )
    receipt_layers = _validate_layer_list(
        receipt_claim["layers"], "receipt-template.claim.layers"
    )
    _require(
        receipt_layers == claim["claim_layers"],
        "receipt-template.claim.layers",
        "the inert template must copy the current claim-layer states",
    )

    receipt_matrix = _strict_list(receipt["matrix"], "receipt-template.matrix")
    _require(
        receipt_matrix == matrix["guests"],
        "receipt-template.matrix",
        "must exactly carry all four guest cells",
    )
    case_results = _validate_receipt_cases(receipt["cases"], matrix)
    _require(
        all(result == "not_run" for result in case_results),
        "receipt-template.cases",
        "a source template may contain only not_run results",
    )

    for field in ("fixtures", "packages"):
        _require(
            _strict_list(receipt[field], f"receipt-template.{field}") == [],
            f"receipt-template.{field}",
            "must remain empty in the source template",
        )
    for field in ("harness", "source"):
        _require(
            _strict_object(receipt[field], f"receipt-template.{field}", set()) == {},
            f"receipt-template.{field}",
            "must remain empty in the source template",
        )

    verdict = _strict_string(receipt["verdict"], "receipt-template.verdict")
    _require(verdict in VERDICTS, "receipt-template.verdict", "unknown verdict enum")
    expected = _expected_verdict(
        [layer["status"] for layer in receipt_layers],
        case_results,
        receipt["blockers"],
    )
    _require(verdict == expected, "receipt-template.verdict", f"must be {expected!r}")
    _require(
        verdict != "qualified",
        "receipt-template.verdict",
        "shipped_stranger_workflow is blocked",
    )
    return receipt


def validate_contract(directory: Path) -> None:
    """Validate all three source contract artifacts in ``directory``."""

    claim = validate_claim(load_canonical_json(directory / "claim.v1.json"))
    matrix = validate_matrix(load_matrix(directory / "matrix.toml"))
    validate_receipt_template(
        load_canonical_json(directory / "receipt.template.v1.json"), claim, matrix
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="clean-host contract directory (default: directory containing this script)",
    )
    arguments = parser.parse_args(argv)
    try:
        validate_contract(arguments.directory)
    except (ContractError, OSError) as error:
        print(f"clean-host qualification contract invalid: {error}", file=sys.stderr)
        return 1
    print("clean-host qualification contract valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
