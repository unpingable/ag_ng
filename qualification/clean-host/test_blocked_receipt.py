#!/usr/bin/python3
"""Tests for the deterministic first-gate receipt publisher."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLE = _load("blocked_receipt_test_bundle", "bundle.py")
PUBLISHER = _load("blocked_receipt_under_test", "blocked_receipt.py")
BASE_TESTS = _load("blocked_receipt_base_tests", "test_bundle.py")


class BlockedReceiptPublisherTests(unittest.TestCase):
    def fixture(
        self, temporary: str, *, terminal_command: bool = True
    ) -> tuple[Path, dict]:
        helper = BASE_TESTS.CleanHostBundleTests()
        root = helper.initialized_bundle(temporary)
        if terminal_command:
            helper.write_terminal_build_fixture(root)
        image_record = BUNDLE.load_canonical_json(
            root / "mandatory/image_provenance/image.v1.json"
        )
        mandatory = {
            category: (
                [
                    "mandatory/image_provenance/image.v1.json"
                    if category == "image_provenance"
                    else "mandatory/snapshot_boundaries/snapshot.v1.json"
                    if category == "snapshot_boundaries"
                    else f"mandatory/{category}/evidence.txt"
                ]
                if category
                in {
                    "command_ledger",
                    "hypervisor_and_host",
                    "image_provenance",
                    "snapshot_boundaries",
                    "test_results",
                }
                else []
            )
            for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES
        }
        mandatory["test_results"] = [
            "mandatory/test_results/candidate-source.tar",
            "mandatory/test_results/guest-facts.v1.json",
            "mandatory/test_results/candidate-archive.v1.json",
        ]
        mandatory["image_provenance"] = [
            "mandatory/image_provenance/base-image.qcow2",
            "mandatory/image_provenance/image.v1.json",
        ]
        mandatory["snapshot_boundaries"] = [
            "mandatory/snapshot_boundaries/failure.qcow2",
            "mandatory/snapshot_boundaries/snapshot.v1.json",
        ]
        mandatory["hypervisor_and_host"] = [
            "mandatory/hypervisor_and_host/fixture.pub",
            "mandatory/hypervisor_and_host/nocloud/fixture.v1.json",
            "mandatory/hypervisor_and_host/nocloud/meta-data",
            "mandatory/hypervisor_and_host/nocloud/user-data",
            "mandatory/hypervisor_and_host/nocloud.iso",
            "mandatory/hypervisor_and_host/qemu.pid",
            "mandatory/hypervisor_and_host/qmp-quit.v1.json",
            "mandatory/hypervisor_and_host/serial.log",
            "mandatory/hypervisor_and_host/ssh-readiness.v1.json",
        ]
        metadata = {
            "authority_use": "evidence_only",
            "controller_host": {
                "architecture": "amd64",
                "distribution": "Debian 12 controller",
                "evidence_paths": [
                    "mandatory/hypervisor_and_host/ssh-readiness.v1.json"
                ],
                "hypervisor": "QEMU/KVM test fixture",
                "kernel": "6.8.0-test",
            },
            "mandatory_evidence_paths": mandatory,
            "schema": PUBLISHER.METADATA_SCHEMA,
            "terminal_guest_evidence_paths": [
                "mandatory/test_results/guest-facts.v1.json",
                "mandatory/test_results/candidate-archive.v1.json",
            ],
            "terminal_image": {
                "bytes": copy.deepcopy(image_record["bytes"]),
                "provenance_path": "mandatory/image_provenance/image.v1.json",
                "source": "https://example.invalid/test-image",
                "source_digest": image_record["source_digest"],
            },
            "terminal_observed": {
                "active_lsms": "capability,landlock",
                "architecture": "amd64",
                "cgroup": "unified cgroup v2",
                "distribution": "debian",
                "filesystem": "ext4",
                "kernel": "6.1.0-test",
                "landlock_abi": "3",
                "release": "12",
                "systemd": "252",
            },
            "terminal_snapshot_paths": [
                "mandatory/snapshot_boundaries/snapshot.v1.json"
            ],
        }
        metadata_path = root / PUBLISHER.DEFAULT_METADATA_PATH
        BUNDLE.write_new_canonical_json(metadata_path, metadata)
        return root, metadata

    def test_publishes_and_reopens_exact_blocked_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            BUNDLE.seal_bundle(root)
            receipt = PUBLISHER.publish_blocked_receipt(root)
            self.assertEqual(receipt["verdict"], "BLOCKED")
            self.assertEqual(receipt["matrix"][0]["cases"][0]["result"], "blocked")
            command_paths = {
                entry["path"]
                for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                    "entries"
                ]
                if entry["path"].endswith(".command.v1.json")
            }
            self.assertEqual(
                command_paths,
                {
                    reference["path"]
                    for reference in receipt["matrix"][0]["cases"][0]["evidence"]
                },
            )
            self.assertTrue(BUNDLE.verify_bundle(root)["valid"])

    def test_rejects_metadata_reference_outside_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            metadata["controller_host"]["evidence_paths"] = [
                "mandatory/hypervisor_and_host/absent.txt"
            ]
            path.write_bytes(BUNDLE.canonical_json_bytes(metadata))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_rejects_missing_real_ssh_dpkg_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary, terminal_command=False)
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)

    def test_rejects_dpkg_name_that_is_not_the_exact_remote_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            record_path = (
                root
                / "guests/debian-12-amd64/cases/package_build_and_payload/commands"
                / "terminal-build-refusal.command.v1.json"
            )
            record = BUNDLE.load_canonical_json(record_path)
            record["argv"][-1:] = ["/usr/bin/false", "/usr/bin/dpkg-checkbuilddeps"]
            record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_exact_buildpackage_tail_is_admitted_without_dependency_bypass(
        self,
    ) -> None:
        argv = [
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
            "UserKnownHostsFile=/tmp/known-hosts",
            "-i",
            "/tmp/identity",
            "-p",
            "2222",
            BUNDLE.SSH_BUILD_TARGET,
        ]
        argv.extend(BUNDLE.SSH_BUILD_REMOTE_TAILS[1])
        self.assertTrue(BUNDLE.is_exact_ssh_build_command(argv))
        self.assertNotIn("--no-check-builddeps", argv)
        self.assertFalse(BUNDLE.is_exact_ssh_build_command([*argv, "--verbose"]))
        self.assertFalse(
            BUNDLE.is_exact_ssh_build_command(
                ["/usr/bin/ssh", "-o", "Hostname=elsewhere", *argv[1:]]
            )
        )

    def test_rejects_wrong_build_exit_and_any_other_unmatched_command(self) -> None:
        mutations = (
            ("terminal-dpkg-build-refusal", 1),
            ("guest-archive-sha256", 1),
        )
        for command_id, exit_code in mutations:
            with self.subTest(command_id=command_id):
                with tempfile.TemporaryDirectory() as temporary:
                    root, _ = self.fixture(temporary)
                    path = (
                        root
                        / "guests/debian-12-amd64/cases/package_build_and_payload/commands"
                        / f"{command_id}.command.v1.json"
                    )
                    record = BUNDLE.load_canonical_json(path)
                    record["outcome"]["exit_code"] = exit_code
                    record["matched_expectation"] = False
                    path.write_bytes(BUNDLE.canonical_json_bytes(record))
                    BUNDLE.seal_bundle(root)
                    with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                        PUBLISHER.publish_blocked_receipt(root)
                    self.assertFalse((root / "receipt.v1.json").exists())

    def test_guest_archive_digest_must_equal_sealed_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            commands = (
                root / "guests/debian-12-amd64/cases/package_build_and_payload/commands"
            )
            stdout_path = commands / "guest-archive-sha256.stdout"
            stdout_path.write_bytes(b"0" * 64 + b"  /home/agqual/wrong.tar\n")
            record_path = commands / "guest-archive-sha256.command.v1.json"
            record = BUNDLE.load_canonical_json(record_path)
            record["stdout"] = BUNDLE.artifact_reference(root, stdout_path)
            record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_rejects_any_command_outside_terminal_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[1][0],
                BUNDLE.CASE_FAMILIES[0],
                "unexpected-later-command",
                ["/usr/bin/true"],
                Path("/"),
                {},
                120,
                {"kind": "exit_code", "value": 0},
            )
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)

    def test_receipt_publication_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            BUNDLE.seal_bundle(root)
            PUBLISHER.publish_blocked_receipt(root)
            original = (root / "receipt.v1.json").read_bytes()
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertEqual((root / "receipt.v1.json").read_bytes(), original)

    def test_failed_full_prepublication_reopen_leaves_no_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            metadata["mandatory_evidence_paths"]["hypervisor_and_host"] = [
                "mandatory/hypervisor_and_host/evidence.txt"
            ]
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            path.write_bytes(BUNDLE.canonical_json_bytes(metadata))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_postpublication_reopen_failure_cleans_exact_new_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            BUNDLE.seal_bundle(root)
            real_verify = PUBLISHER.BUNDLE.verify_bundle

            def fail_only_after_publication(
                evidence_root, require_receipt=True, receipt_candidate=None
            ):
                if (
                    receipt_candidate is None
                    and (Path(evidence_root) / "receipt.v1.json").exists()
                ):
                    raise PUBLISHER.BUNDLE.QualificationError(
                        "injected post-publication reopen failure"
                    )
                return real_verify(
                    evidence_root,
                    require_receipt=require_receipt,
                    receipt_candidate=receipt_candidate,
                )

            PUBLISHER.BUNDLE.verify_bundle = fail_only_after_publication
            try:
                with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                    PUBLISHER.publish_blocked_receipt(root)
            finally:
                PUBLISHER.BUNDLE.verify_bundle = real_verify
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_partial_receipt_write_removes_exact_created_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            BUNDLE.seal_bundle(root)
            real_write = PUBLISHER.os.write
            calls = 0

            def fail_after_partial_write(descriptor, payload):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(descriptor, payload[:17])
                raise OSError("injected partial receipt write")

            PUBLISHER.os.write = fail_after_partial_write
            try:
                with self.assertRaises(OSError):
                    PUBLISHER.publish_blocked_receipt(root)
            finally:
                PUBLISHER.os.write = real_write
            self.assertFalse((root / "receipt.v1.json").exists())
            self.assertEqual(
                list(root.parent.glob(f".{root.name}.receipt.v1.json.*.tmp")), []
            )

    def test_receipt_staging_fstat_and_close_failures_leave_no_visible_result(
        self,
    ) -> None:
        for operation in ("fstat", "close"):
            with self.subTest(operation=operation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "bundle"
                    root.mkdir()
                    receipt_path = root / "receipt.v1.json"
                    original = getattr(PUBLISHER.os, operation)

                    if operation == "fstat":

                        def injected(descriptor):
                            raise OSError("injected fstat failure")

                    else:

                        def injected(descriptor):
                            original(descriptor)
                            raise OSError("injected close failure")

                    setattr(PUBLISHER.os, operation, injected)
                    try:
                        with self.assertRaises(OSError):
                            PUBLISHER._publish_receipt_bytes(
                                receipt_path, b"complete\n"
                            )
                    finally:
                        setattr(PUBLISHER.os, operation, original)
                    self.assertFalse(receipt_path.exists())
                    self.assertEqual(
                        list(root.parent.glob(f".{root.name}.receipt.v1.json.*.tmp")),
                        [],
                    )

    def test_prepare_evidence_renders_all_typed_records_from_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            for relative in (
                PUBLISHER.GUEST_FACTS_PATH,
                PUBLISHER.CANDIDATE_ARCHIVE_RECORD_PATH,
                PUBLISHER.IMAGE_PROVENANCE_PATH,
                PUBLISHER.SNAPSHOT_BOUNDARY_PATH,
            ):
                (root / relative).unlink()
            PUBLISHER.prepare_typed_evidence(
                root,
                "mandatory/test_results/candidate-source.tar",
                "guests/debian-12-amd64/cases/package_build_and_payload/commands/guest-facts.stdout",
                "mandatory/image_provenance/base-image.qcow2",
                "mandatory/snapshot_boundaries/failure.qcow2",
                "rendered-pristine-build",
            )
            phase1 = BUNDLE.load_canonical_json(
                root / "inputs/phase1-starting-candidate.v1.json"
            )
            candidate = BUNDLE.load_canonical_json(
                root / "inputs/candidate-identity.v1.json"
            )
            archive = BUNDLE.load_canonical_json(
                root / PUBLISHER.CANDIDATE_ARCHIVE_RECORD_PATH
            )
            snapshot = BUNDLE.load_canonical_json(
                root / PUBLISHER.SNAPSHOT_BOUNDARY_PATH
            )
            self.assertEqual(archive["starting_source"], phase1["source"])
            self.assertEqual(archive["final_source"], candidate["source"])
            self.assertEqual(snapshot["starting_source"], phase1["source"])
            self.assertEqual(snapshot["final_source"], candidate["source"])
            for relative in (
                PUBLISHER.GUEST_FACTS_PATH,
                PUBLISHER.CANDIDATE_ARCHIVE_RECORD_PATH,
                PUBLISHER.IMAGE_PROVENANCE_PATH,
                PUBLISHER.SNAPSHOT_BOUNDARY_PATH,
            ):
                self.assertTrue((root / relative).is_file())

    def test_typed_guest_facts_must_equal_receipt_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            path = root / "mandatory/test_results/guest-facts.v1.json"
            record = BUNDLE.load_canonical_json(path)
            record["observed"]["kernel"] = "6.2.0-contradictory"
            path.write_bytes(BUNDLE.canonical_json_bytes(record))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_typed_image_provenance_must_equal_receipt_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            metadata["terminal_image"]["bytes"]["sha256"] = "sha256:" + "3" * 64
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            path.write_bytes(BUNDLE.canonical_json_bytes(metadata))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_typed_snapshot_must_bind_image_and_source_cuts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            path = root / "mandatory/snapshot_boundaries/snapshot.v1.json"
            record = BUNDLE.load_canonical_json(path)
            record["image_sha256"] = "sha256:" + "4" * 64
            path.write_bytes(BUNDLE.canonical_json_bytes(record))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_typed_candidate_archive_must_bind_both_source_cuts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.fixture(temporary)
            path = root / "mandatory/test_results/candidate-archive.v1.json"
            record = BUNDLE.load_canonical_json(path)
            record["final_source"]["tree"] = "0" * 40
            path.write_bytes(BUNDLE.canonical_json_bytes(record))
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)
            self.assertFalse((root / "receipt.v1.json").exists())

    def test_executing_bundle_and_publisher_must_equal_sealed_copies(self) -> None:
        for copied_name in ("bundle.py", "blocked_receipt.py"):
            with self.subTest(copied_name=copied_name):
                with tempfile.TemporaryDirectory() as temporary:
                    root, _ = self.fixture(temporary)
                    path = root / "inputs" / copied_name
                    path.write_bytes(path.read_bytes() + b"# substituted after init\n")
                    BUNDLE.seal_bundle(root)
                    with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                        PUBLISHER.publish_blocked_receipt(root)
                    self.assertFalse((root / "receipt.v1.json").exists())

    def test_optional_defect_repair_and_inventory_are_typed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            metadata["additional_defects"] = [
                {
                    "case_refs": [],
                    "classification": "documented_host_prerequisites",
                    "evidence_paths": [PUBLISHER.DEFAULT_METADATA_PATH],
                    "id": "ambient-prerequisites-were-undeclared",
                    "summary": "the original host contract omitted four runtime prerequisites",
                }
            ]
            metadata["repairs"] = [
                {
                    "after_generation": None,
                    "before_generation": None,
                    "classification": "documented_host_prerequisites",
                    "defect_id": "ambient-prerequisites-were-undeclared",
                    "evidence_paths": [PUBLISHER.DEFAULT_METADATA_PATH],
                    "id": "declare-ambient-prerequisites",
                    "summary": "the candidate documentation now declares the prerequisites",
                }
            ]
            metadata["receipt_inventory_paths"] = [
                "inputs/phase1-starting-candidate.v1.json"
            ]
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            path.write_bytes(BUNDLE.canonical_json_bytes(metadata))
            BUNDLE.seal_bundle(root)
            receipt = PUBLISHER.publish_blocked_receipt(root)
            self.assertEqual(len(receipt["defects"]), 2)
            self.assertEqual(len(receipt["repairs"]), 1)
            self.assertEqual(len(receipt["receipt_inventory"]), 1)

    def test_optional_agctl_doctor_deadline_residual_gate_is_typed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            metadata["additional_residual_gates"] = [
                {
                    "case_refs": ["debian-12-amd64/hostile_systemd_and_process"],
                    "classification": "runtime_implementation",
                    "evidence_paths": [PUBLISHER.DEFAULT_METADATA_PATH],
                    "id": "agctl_doctor_subprocess_deadline_absent",
                    "repair_surface": (
                        "give every agctl doctor subprocess a bounded deadline "
                        "and typed timeout refusal"
                    ),
                    "summary": (
                        "agctl doctor still invokes subprocesses without a "
                        "bounded deadline"
                    ),
                }
            ]
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            path.write_bytes(BUNDLE.canonical_json_bytes(metadata))
            BUNDLE.seal_bundle(root)

            receipt = PUBLISHER.publish_blocked_receipt(root)
            gate = next(
                item
                for item in receipt["residual_gates"]
                if item["id"] == "agctl_doctor_subprocess_deadline_absent"
            )
            self.assertEqual(gate["classification"], "runtime_implementation")
            self.assertEqual(
                gate["case_refs"],
                ["debian-12-amd64/hostile_systemd_and_process"],
            )
            self.assertEqual(
                [reference["path"] for reference in gate["evidence"]],
                [PUBLISHER.DEFAULT_METADATA_PATH],
            )
            self.assertNotIn("evidence_paths", gate)

    def test_rejects_noncanonical_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, metadata = self.fixture(temporary)
            path = root / PUBLISHER.DEFAULT_METADATA_PATH
            path.write_text(str(copy.deepcopy(metadata)), encoding="utf-8")
            BUNDLE.seal_bundle(root)
            with self.assertRaises(PUBLISHER.BUNDLE.QualificationError):
                PUBLISHER.publish_blocked_receipt(root)


if __name__ == "__main__":
    unittest.main()
