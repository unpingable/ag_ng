#!/usr/bin/env python3
"""Run the ordinary AG/Docket governed-repair wire conformance gate.

AG owns the canonical producer contract. Docket is its consequence-bearing
consumer. This gate verifies the pinned cross-repository corpus and then runs
the producer and consumer serializer/validator tests that give that corpus
operational meaning.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--docket-root",
        type=Path,
        required=True,
        help="path to the canonical Docket runtime repository",
    )
    parser.add_argument(
        "--ag-target-dir",
        type=Path,
        help="optional external Cargo target directory for AG",
    )
    parser.add_argument(
        "--docket-target-dir",
        type=Path,
        help="optional external Cargo target directory for Docket",
    )
    return parser.parse_args()


def run(command: list[str], *, cwd: Path, target_dir: Path | None = None) -> None:
    environment = os.environ.copy()
    if target_dir is not None:
        environment["CARGO_TARGET_DIR"] = str(target_dir.resolve())
    rendered = " ".join(command)
    print(f"governed-repair-r3-contract-gate: cwd={cwd} command={rendered}")
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def run_rust_contract_tests(
    command: list[str],
    *,
    expected_tests: tuple[str, ...],
    cwd: Path,
    target_dir: Path | None = None,
) -> None:
    """Prove the named conformance tests still exist, then execute them.

    Cargo treats an empty test filter as success.  The ordinary gate must fail
    if a producer or consumer conformance module is renamed or removed, so a
    successful test process alone is not enough.
    """

    environment = os.environ.copy()
    if target_dir is not None:
        environment["CARGO_TARGET_DIR"] = str(target_dir.resolve())
    list_command = [*command, "--", "--list"]
    print(
        "governed-repair-r3-contract-gate: "
        f"cwd={cwd} command={' '.join(list_command)}"
    )
    listed = subprocess.run(
        list_command,
        cwd=cwd,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    print(listed.stdout, end="")
    if listed.stderr:
        print(listed.stderr, end="", file=sys.stderr)
    observed_tests = tuple(
        sorted(
            line.removesuffix(": test")
            for line in listed.stdout.splitlines()
            if line.endswith(": test")
        )
    )
    if observed_tests != tuple(sorted(expected_tests)):
        missing = sorted(set(expected_tests) - set(observed_tests))
        unexpected = sorted(set(observed_tests) - set(expected_tests))
        raise SystemExit(
            "governed-repair conformance test census drifted; "
            f"missing={missing}; unexpected={unexpected}"
        )
    run([*command, "--", "--test-threads=1"], cwd=cwd, target_dir=target_dir)


def main() -> int:
    args = parse_args()
    ag_root = Path(__file__).resolve().parents[1]
    docket_root = args.docket_root.resolve()
    if not (docket_root / "Cargo.toml").is_file():
        raise SystemExit(f"Docket root has no Cargo.toml: {docket_root}")

    run(
        [
            sys.executable,
            "scripts/verify_governed_repair_r2_contract.py",
            "--docket-root",
            str(docket_root),
        ],
        cwd=ag_root,
    )
    run_rust_contract_tests(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "ag-campaign",
            "--test",
            "governed_repair_wire_contract",
        ],
        expected_tests=(
            "canonical_contract_and_label_corpus_have_pinned_exact_bytes",
            "manifest_closes_the_complete_conformance_corpus",
            "ag_scope_identity_matches_the_shared_corpus",
            "ag_validator_accepts_and_refuses_the_shared_label_corpus",
            "mutable_ref_words_are_resource_only_exclusions",
        ),
        cwd=ag_root,
        target_dir=args.ag_target_dir,
    )
    run_rust_contract_tests(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "ag-app",
            "governed_wire_conformance_tests",
        ],
        expected_tests=(
            "governed_ports::governed_wire_conformance_tests::actual_ag_records_round_trip_and_reproduce_all_corpus_identities",
            "governed_ports::governed_wire_conformance_tests::every_closed_acceptance_and_reconciliation_variant_round_trips",
            "governed_ports::governed_wire_conformance_tests::both_governed_result_families_reproduce_requirement_checkpoint_and_seal",
            "governed_ports::governed_wire_conformance_tests::hostile_optional_unknown_integer_and_identity_mutations_refuse_at_the_boundary",
        ),
        cwd=ag_root,
        target_dir=args.ag_target_dir,
    )
    run_rust_contract_tests(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "gwr-local",
            "governed_wire_conformance_tests",
        ],
        expected_tests=(
            "governed_loop::governed_wire_conformance_tests::actual_docket_intake_records_reproduce_all_positive_identities",
            "governed_loop::governed_wire_conformance_tests::actual_docket_closed_response_and_reconciliation_variants_round_trip",
            "governed_loop::governed_wire_conformance_tests::actual_docket_result_validator_reproduces_both_governed_families",
            "governed_loop::governed_wire_conformance_tests::hostile_optional_unknown_integer_and_identity_mutations_refuse_in_docket",
        ),
        cwd=docket_root,
        target_dir=args.docket_target_dir,
    )
    print(
        json.dumps(
            {
                "gate": "canonical_governed_repair_r3_contract_conformance",
                "producer_owner": "AG",
                "consumer": "Docket",
                "qualification_status": "not_assessed",
                "status": "pass",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
