from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "continuation_receipt", HERE / "continuation_receipt.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTINUATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTINUATION)
BUNDLE = CONTINUATION.BUNDLE


class ContinuationReceiptTests(unittest.TestCase):
    def assert_refuses(self, function) -> None:
        with self.assertRaises(BUNDLE.QualificationError):
            function()

    @staticmethod
    def reference(path: str) -> dict:
        return {"length": 1, "path": path, "sha256": "sha256:" + "1" * 64}

    def source(self) -> dict:
        return {
            "branch": "main",
            "commit": "2" * 40,
            "status_porcelain_sha256": BUNDLE.EMPTY_SHA256,
            "tree": "3" * 40,
            "worktree": "clean",
        }

    def receipt(self) -> dict:
        evidence = self.reference(
            "guests/debian-12-amd64/cases/package_build_and_payload/commands/test.command.v1.json"
        )
        cases = [
            {
                "evidence": [copy.deepcopy(evidence)],
                "family": family,
                "result": "pass",
                "summary": "scoped case passed",
            }
            for family in BUNDLE.CASE_FAMILIES
        ]
        scoped = {
            "architecture": "amd64",
            "cases": cases,
            "distribution": "debian",
            "guest_evidence": [self.reference("mandatory/test_results/guest.json")],
            "guest_id": "debian-12-amd64",
            "image": {
                "bytes": {"length": 1, "sha256": "sha256:" + "4" * 64},
                "provenance": self.reference("mandatory/image_provenance/image.json"),
                "source": "sealed Debian fixture",
                "source_digest": "sha256:" + "4" * 64,
            },
            "observed": {
                "active_lsms": "landlock",
                "architecture": "amd64",
                "cgroup": "unified-v2",
                "distribution": "debian",
                "filesystem": "ext4",
                "kernel": "6.12.0",
                "landlock_abi": "6",
                "release": "12",
                "systemd": "252",
            },
            "release": "12",
            "snapshots": [self.reference("mandatory/snapshot_boundaries/snapshot.json")],
        }
        matrix = [scoped]
        for guest in BUNDLE.GUESTS[1:]:
            matrix.append(
                {
                    "architecture": guest[3],
                    "cases": [
                        {
                            "evidence": [],
                            "family": family,
                            "result": "not_run",
                            "summary": "outside continuation scope",
                        }
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
        predecessor = {
            "candidate": copy.deepcopy(CONTINUATION.PREDECESSOR_SOURCE),
            "run_id": CONTINUATION.PREDECESSOR_RUN_ID,
            "verdict": "BLOCKED",
        }
        predecessor.update(
            {
                key: {
                    "length": CONTINUATION.PREDECESSOR_IDENTITIES[key]["length"],
                    "path": path,
                    "sha256": CONTINUATION.PREDECESSOR_IDENTITIES[key]["sha256"],
                }
                for key, path in CONTINUATION.PREDECESSOR_BUNDLE_PATHS.items()
            }
        )
        mandatory = {
            category: [self.reference(f"mandatory/{category}/evidence")]
            for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES
        }
        source = self.source()
        package = self.reference(
            "packages/generation-1/agent-governor-ng_0.1.0-1_amd64.deb"
        )
        claim = CONTINUATION.validate_claim(
            BUNDLE.load_canonical_json(HERE / "continuation-claim.v1.json")
        )
        return {
            "authority_use": BUNDLE.AUTHORITY_USE,
            "build": self.reference("mandatory/test_results/build.v1.json"),
            "candidate": source,
            "claim": {
                "evidence": self.reference("inputs/continuation-claim.v1.json"),
                "exclusions": copy.deepcopy(claim["exclusions"]),
                "layers": [
                    {"id": layer, "required": True, "status": "pass"}
                    for layer in CONTINUATION.LAYER_IDS
                ],
            },
            "controller_host": {
                "architecture": "amd64",
                "distribution": "test",
                "evidence": [self.reference("mandatory/hypervisor_and_host/host")],
                "hypervisor": "qemu",
                "kernel": "6.8",
            },
            "defects": [],
            "evidence_manifest": self.reference("manifest.v1.json"),
            "harness": {
                "commit": source["commit"],
                "controller": self.reference("inputs/bundle.py"),
                "publisher": self.reference("inputs/continuation_receipt.py"),
                "tree": source["tree"],
                "vm_fixture": self.reference("inputs/vm_fixture.py"),
            },
            "mandatory_evidence": mandatory,
            "matrix": matrix,
            "package_digest_history": [
                {
                    "artifacts": [
                        {
                            "architecture": "amd64",
                            "identity": package,
                            "kind": "deb",
                            "name": "agent-governor-ng",
                            "version": "0.1.0-1",
                        }
                    ],
                    "generation": 1,
                    "reason": "first admissible continuation package",
                    "source_commit": source["commit"],
                    "source_tree": source["tree"],
                }
            ],
            "predecessor": predecessor,
            "reconstructs_standing": False,
            "repairs": [],
            "residual_gates": [],
            "schema": CONTINUATION.RECEIPT_SCHEMA,
            "unqualified_scope": [
                {"disposition": "not_run_not_claimed", "guest_id": guest[0]}
                for guest in BUNDLE.GUESTS[1:]
            ],
            "verdict": "REQUALIFIED",
        }

    def test_claim_and_one_package_requalified_receipt_validate(self) -> None:
        CONTINUATION.validate_claim(
            BUNDLE.load_canonical_json(HERE / "continuation-claim.v1.json")
        )
        CONTINUATION.validate_receipt(self.receipt())

    def test_unqualified_cell_cannot_execute_or_carry_evidence(self) -> None:
        for mutation in ("result", "image"):
            with self.subTest(mutation=mutation):
                receipt = self.receipt()
                if mutation == "result":
                    receipt["matrix"][1]["cases"][0].update(
                        {"result": "pass", "evidence": [self.reference("mandatory/test_results/x")]}
                    )
                else:
                    receipt["matrix"][1]["guest_evidence"] = [
                        self.reference("mandatory/test_results/x")
                    ]
                self.assert_refuses(lambda: CONTINUATION.validate_receipt(receipt))

    def test_requalified_requires_every_scoped_case(self) -> None:
        receipt = self.receipt()
        receipt["matrix"][0]["cases"][-1].update(
            {"result": "not_run", "evidence": []}
        )
        self.assert_refuses(lambda: CONTINUATION.validate_receipt(receipt))

    def test_later_bounded_blocked_receipt_validates(self) -> None:
        receipt = self.receipt()
        terminal = 2
        for index, case in enumerate(receipt["matrix"][0]["cases"]):
            if index == terminal:
                case["result"] = "blocked"
            elif index > terminal:
                case.update({"result": "not_run", "evidence": []})
        terminal_ref = "debian-12-amd64/genesis_measure_enroll_verify"
        finding_evidence = [self.reference("mandatory/test_results/failure")]
        receipt["claim"]["layers"] = [
            {"id": "package_lifecycle", "required": True, "status": "blocked"},
            {"id": "live_effectd_activation", "required": True, "status": "blocked"},
        ]
        receipt["defects"] = [
            {
                "case_refs": [terminal_ref],
                "classification": "runtime_implementation",
                "evidence": finding_evidence,
                "id": "exact-runtime-defect",
                "summary": "bounded exact defect",
            }
        ]
        receipt["residual_gates"] = [
            {
                "case_refs": [terminal_ref],
                "classification": "runtime_implementation",
                "evidence": finding_evidence,
                "id": "exact-runtime-gate",
                "repair_surface": "repair only the demonstrated path",
                "summary": "bounded exact obstruction",
            }
        ]
        receipt["verdict"] = "BLOCKED"
        CONTINUATION.validate_receipt(receipt)

    def test_predecessor_identity_is_exact(self) -> None:
        receipt = self.receipt()
        receipt["predecessor"]["receipt"]["sha256"] = "sha256:" + "0" * 64
        self.assert_refuses(lambda: CONTINUATION.validate_receipt(receipt))

    def test_build_record_refuses_rust_runtime_dependency(self) -> None:
        reference = self.reference("mandatory/test_results/evidence")
        record = {
            "build_command": self.reference(
                "guests/debian-12-amd64/cases/package_build_and_payload/commands/build.command.v1.json"
            ),
            "cargo_home": {"path": "/tmp/cargo", "strategy": "deliberate cache"},
            "cargo_lock": self.reference("inputs/build-source/Cargo.lock"),
            "cargo_version_verbose": reference,
            "environment": [],
            "native_tools": [{"name": "cc", "version_evidence": reference}],
            "network_access": "available",
            "output": self.reference(
                "packages/generation-1/agent-governor-ng_0.1.0-1_amd64.deb"
            ),
            "output_preexisting": False,
            "package_control_evidence": reference,
            "runtime_dependencies": ["systemd (>= 252)", "rustc"],
            "rustc_version_verbose": reference,
            "schema": CONTINUATION.BUILD_RECORD_SCHEMA,
            "source": self.source(),
            "target_directory": {"path": "/tmp/target", "strategy": "initially absent"},
            "target_triple": "x86_64-unknown-linux-gnu",
        }
        self.assert_refuses(lambda: CONTINUATION.validate_build_record(record))

    def test_initializer_copies_predecessor_and_manifest_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            CONTINUATION.initialize_bundle(root)
            for path in CONTINUATION.PREDECESSOR_BUNDLE_PATHS.values():
                self.assertTrue((root / path).is_file())
            BUNDLE.seal_bundle(root)
            (root / "unmanifested").write_bytes(b"extra")
            manifest = BUNDLE.load_canonical_json(root / "manifest.v1.json")
            self.assert_refuses(lambda: BUNDLE.verify_manifest_coverage(root, manifest))

    def test_cli_import_does_not_create_bytecode_before_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy2(HERE / "continuation_receipt.py", root)
            shutil.copy2(HERE / "bundle.py", root)
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            completed = subprocess.run(
                [sys.executable, str(root / "continuation_receipt.py"), "--help"],
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse((root / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
