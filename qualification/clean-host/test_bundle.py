#!/usr/bin/python3
"""Hostile tests for the clean-host evidence controller and seal."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("clean_host_bundle", HERE / "bundle.py")
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


EMPTY_SHA256 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class CleanHostBundleTests(unittest.TestCase):
    def assert_qualification_error(self, callback) -> None:
        with self.assertRaises(BUNDLE.QualificationError):
            callback()

    def test_build_bootstrap_includes_debian_implicit_build_essential(self) -> None:
        self.assertEqual(
            BUNDLE.SSH_BUILD_DEPENDENCY_INSTALL_TAIL,
            (
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
            ),
        )

    def initialized_bundle(self, temporary: str) -> Path:
        root = Path(temporary) / "bundle"
        BUNDLE.initialize_bundle(root, HERE / "matrix.toml")
        phase1 = BUNDLE.load_canonical_json(
            root / "inputs" / "phase1-starting-candidate.v1.json"
        )
        candidate_identity_path = root / "inputs" / "candidate-identity.v1.json"
        candidate_identity = BUNDLE.load_canonical_json(candidate_identity_path)
        harness_digest, _ = BUNDLE.digest_regular_file(root / "inputs" / "bundle.py")
        publisher_digest, _ = BUNDLE.digest_regular_file(
            root / "inputs" / "blocked_receipt.py"
        )
        vm_fixture_digest, _ = BUNDLE.digest_regular_file(
            root / "inputs" / "vm_fixture.py"
        )
        self.assertEqual(
            (root / "inputs" / "vm_fixture.py").read_bytes(),
            (HERE / "vm_fixture.py").read_bytes(),
        )
        self.assertEqual(
            (root / "inputs" / "blocked_receipt.py").read_bytes(),
            (HERE / "blocked_receipt.py").read_bytes(),
        )
        candidate_identity["source"] = copy.deepcopy(phase1["source"])
        candidate_identity["harness"].update(
            {
                "matches_head": True,
                "tracked_sha256": harness_digest,
                "working_sha256": harness_digest,
            }
        )
        candidate_identity["publisher"].update(
            {
                "matches_head": True,
                "tracked_sha256": publisher_digest,
                "working_sha256": publisher_digest,
            }
        )
        candidate_identity["vm_fixture"].update(
            {
                "matches_head": True,
                "tracked_sha256": vm_fixture_digest,
                "working_sha256": vm_fixture_digest,
            }
        )
        archive_path = root / "mandatory" / "test_results" / "candidate-source.tar"
        archive_payload = b"synthetic candidate source archive\n"
        with tarfile.open(
            archive_path, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            prefix = Path(BUNDLE.GOVERNED_SOURCE_CWD).name
            directory = tarfile.TarInfo(f"{prefix}/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = 0
            archive.addfile(directory)
            member = tarfile.TarInfo(f"{prefix}/README.test")
            member.mode = 0o644
            member.mtime = 0
            member.size = len(archive_payload)
            archive.addfile(member, io.BytesIO(archive_payload))
        archive_tree = BUNDLE.candidate_archive_git_tree(archive_path, "sha1")
        candidate_identity["source"]["tree"] = archive_tree
        candidate_identity_path.write_bytes(
            BUNDLE.canonical_json_bytes(candidate_identity)
        )
        for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
            evidence_root = root / "mandatory" / category
            (evidence_root / "evidence.txt").write_text(
                f"test evidence role: {category}\n", encoding="utf-8"
            )
        observed = {
            "active_lsms": "capability,landlock",
            "architecture": "amd64",
            "cgroup": "unified-v2:/user.slice/user-1000.slice/session-1.scope",
            "distribution": "debian",
            "filesystem": (
                "ext4 mount_options=rw,relatime source=/dev/vda1 "
                "super_options=rw,errors=remount-ro"
            ),
            "kernel": "6.1.0-test",
            "landlock_abi": "3",
            "release": "12",
            "systemd": "252",
        }
        guest_probe_path = (
            root
            / "guests"
            / BUNDLE.GUESTS[0][0]
            / "cases"
            / BUNDLE.CASE_FAMILIES[0]
            / "commands"
            / "guest-facts.stdout"
        )
        BUNDLE.write_new_canonical_json(
            guest_probe_path,
            {
                "guest_id": BUNDLE.GUESTS[0][0],
                "observed": observed,
                "schema": BUNDLE.GUEST_FACTS_SCHEMA,
            },
        )
        BUNDLE.write_new_canonical_json(
            root / "mandatory" / "test_results" / "guest-facts.v1.json",
            {
                "guest_id": BUNDLE.GUESTS[0][0],
                "observation": BUNDLE.artifact_reference(root, guest_probe_path),
                "observed": observed,
                "schema": BUNDLE.GUEST_FACTS_BINDING_SCHEMA,
            },
        )
        BUNDLE.write_new_canonical_json(
            root / "mandatory" / "test_results" / "candidate-archive.v1.json",
            {
                "archive": BUNDLE.artifact_reference(root, archive_path),
                "archive_tree": archive_tree,
                "extraction_root": BUNDLE.GOVERNED_SOURCE_CWD,
                "final_source": copy.deepcopy(candidate_identity["source"]),
                "guest_archive_path": BUNDLE.GUEST_CANDIDATE_ARCHIVE_PATH,
                "guest_id": BUNDLE.GUESTS[0][0],
                "schema": BUNDLE.CANDIDATE_ARCHIVE_SCHEMA,
                "starting_source": copy.deepcopy(phase1["source"]),
            },
        )
        image_artifact_path = (
            root / "mandatory" / "image_provenance" / "base-image.qcow2"
        )
        image_artifact_path.write_bytes(b"synthetic VM image artifact\n")
        image_artifact = BUNDLE.artifact_reference(root, image_artifact_path)
        image_identity = {
            "length": image_artifact["length"],
            "sha256": image_artifact["sha256"],
        }
        BUNDLE.write_new_canonical_json(
            root / "mandatory" / "image_provenance" / "image.v1.json",
            {
                "artifact": image_artifact,
                "bytes": image_identity,
                "guest_id": BUNDLE.GUESTS[0][0],
                "schema": BUNDLE.IMAGE_PROVENANCE_SCHEMA,
                "source": "https://example.invalid/test-image",
                "source_digest": image_artifact["sha256"],
            },
        )
        snapshot_artifact_path = (
            root / "mandatory" / "snapshot_boundaries" / "failure.qcow2"
        )
        snapshot_artifact_path.write_bytes(b"synthetic preserved snapshot\n")
        BUNDLE.write_new_canonical_json(
            root / "mandatory" / "snapshot_boundaries" / "snapshot.v1.json",
            {
                "artifact": BUNDLE.artifact_reference(root, snapshot_artifact_path),
                "boundary": "preserved_first_gate_failure",
                "final_source": copy.deepcopy(candidate_identity["source"]),
                "guest_id": BUNDLE.GUESTS[0][0],
                "image_sha256": image_identity["sha256"],
                "schema": BUNDLE.SNAPSHOT_BOUNDARY_SCHEMA,
                "snapshot_id": "test-pristine-build",
                "starting_source": copy.deepcopy(phase1["source"]),
            },
        )
        hypervisor_root = root / "mandatory" / "hypervisor_and_host"
        public_key = b"ssh-ed25519 AAAATESTFIXTUREKEY\n"
        (hypervisor_root / "fixture.pub").write_bytes(public_key)
        seed_root = hypervisor_root / "nocloud"
        seed_root.mkdir()
        meta_data = (
            'instance-id: "agq-debian-12-amd64"\n'
            'local-hostname: "agq-debian-12-amd64"\n'
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
            '      - "ssh-ed25519 AAAATESTFIXTUREKEY"\n'
        ).encode()
        (seed_root / "meta-data").write_bytes(meta_data)
        (seed_root / "user-data").write_bytes(user_data)

        def bytes_identity(payload: bytes) -> dict:
            return {
                "length": len(payload),
                "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }

        BUNDLE.write_new_canonical_json(
            seed_root / "fixture.v1.json",
            {
                "authorized_key": bytes_identity(public_key),
                "files": {
                    "meta-data": bytes_identity(meta_data),
                    "user-data": bytes_identity(user_data),
                },
                "hostname": "agq-debian-12-amd64",
                "instance_id": "agq-debian-12-amd64",
                "private_key_copied": False,
                "schema": "ag.clean-host-nocloud-fixture/v1",
                "username": "agqual",
            },
        )
        (hypervisor_root / "nocloud.iso").write_bytes(b"synthetic NoCloud image\n")
        (hypervisor_root / "serial.log").write_bytes(b"synthetic serial log\n")
        (hypervisor_root / "qemu.pid").write_bytes(b"4242\n")
        BUNDLE.write_new_canonical_json(
            hypervisor_root / "qmp-quit.v1.json",
            {
                "duration_ms": 1,
                "finished_utc": "2026-07-20T00:00:00.001000Z",
                "operation": "quit",
                "outcome": "accepted",
                "response": {"id": "ag-ng-command", "return": {}},
                "schema": "ag.clean-host-qmp-operation/v1",
                "socket": str(root.parent / "vm-work/qmp.sock"),
                "started_utc": "2026-07-20T00:00:00.000000Z",
                "timeout_seconds": 10,
                "transcript": [
                    {"direction": "receive", "message": {"QMP": {}}},
                    {
                        "direction": "send",
                        "message": {
                            "execute": "qmp_capabilities",
                            "id": "ag-ng-capabilities",
                        },
                    },
                    {
                        "direction": "receive",
                        "message": {"id": "ag-ng-capabilities", "return": {}},
                    },
                    {
                        "direction": "send",
                        "message": {"execute": "quit", "id": "ag-ng-command"},
                    },
                    {
                        "direction": "receive",
                        "message": {"id": "ag-ng-command", "return": {}},
                    },
                ],
            },
        )
        for generation in (1, 2):
            package_root = root / "packages" / f"generation-{generation}"
            package_root.mkdir(parents=True)
            for architecture in ("amd64", "arm64"):
                (
                    package_root / f"agent-governor-ng_0.1.0-1_{architecture}.deb"
                ).write_bytes(
                    f"test {architecture} package generation {generation}\n".encode()
                )
        return root

    def write_terminal_build_fixture(self, root: Path) -> str:
        commands_root = (
            root
            / "guests"
            / BUNDLE.GUESTS[0][0]
            / "cases"
            / BUNDLE.CASE_FAMILIES[0]
            / "commands"
        )
        command_id = "terminal-build-refusal"
        record_path = commands_root / f"{command_id}.command.v1.json"
        if record_path.exists():
            self.write_terminal_supporting_commands(
                root, commands_root, BUNDLE.load_canonical_json(record_path)
            )
            return record_path.relative_to(root).as_posix()
        case_clock, case_clock_path = BUNDLE._load_or_start_case_clock(
            commands_root.parent,
            BUNDLE.GUESTS[0][0],
            BUNDLE.CASE_FAMILIES[0],
        )
        stdout_path = commands_root / f"{command_id}.stdout"
        stderr_path = commands_root / f"{command_id}.stderr"
        stdout_path.write_bytes(b"")
        stderr_path.write_bytes(
            (BUNDLE.EXPECTED_BUILD_DEPENDENCY_REFUSAL + "\n").encode()
        )
        known_hosts_path = root / "mandatory" / "hypervisor_and_host" / "known_hosts"
        if not known_hosts_path.exists():
            known_hosts_path.write_bytes(b"[127.0.0.1]:2222 test-host-key\n")
        known_hosts_digest, known_hosts_length = BUNDLE.digest_regular_file(
            known_hosts_path
        )
        identity_path = root.parent / "test-identity"
        if not identity_path.exists():
            identity_path.write_bytes(b"test-private-identity-not-in-evidence\n")
        identity_measurement = BUNDLE._input_file_identity(str(identity_path))
        readiness_path = (
            root / "mandatory" / "hypervisor_and_host" / "ssh-readiness.v1.json"
        )
        if not readiness_path.exists():
            readiness_ssh_argv = [
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
                f"UserKnownHostsFile={known_hosts_path}",
                "-i",
                str(identity_path),
                "-p",
                "2222",
                "agqual@127.0.0.1",
                "/usr/bin/true",
            ]
            ssh_digest, ssh_length = BUNDLE.digest_regular_file(
                Path("/usr/bin/ssh").resolve(strict=True)
            )
            BUNDLE.write_new_canonical_json(
                readiness_path,
                {
                    "attempts": [
                        {
                            "attempt": 1,
                            "offset_ms": 0,
                            "ssh": {
                                "argv": readiness_ssh_argv,
                                "duration_ms": 1,
                                "executable": {
                                    "length": ssh_length,
                                    "path": "/usr/bin/ssh",
                                    "sha256": ssh_digest,
                                },
                                "exit_code": 0,
                                "outcome": "exit",
                                "stderr": {
                                    "base64": "",
                                    "length": 0,
                                    "sha256": EMPTY_SHA256,
                                },
                                "stdout": {
                                    "base64": "",
                                    "length": 0,
                                    "sha256": EMPTY_SHA256,
                                },
                            },
                            "tcp": {
                                "duration_ms": 1,
                                "errno": None,
                                "outcome": "connected",
                            },
                        }
                    ],
                    "deadline_overrun_ns": 0,
                    "duration_ms": 2,
                    "finished_utc": "2026-07-20T00:00:00.002000Z",
                    "identity_file": {
                        "length": identity_measurement["length"],
                        "path": str(identity_path),
                        "sha256": identity_measurement["sha256"],
                    },
                    "known_hosts": {
                        "length": known_hosts_length,
                        "path": str(known_hosts_path),
                        "sha256": known_hosts_digest,
                    },
                    "poll_interval_ms": 250,
                    "remote_argv": ["/usr/bin/true"],
                    "rendered_remote_command": "/usr/bin/true",
                    "result": "ready",
                    "schema": "ag.clean-host-ssh-readiness/v1",
                    "started_utc": "2026-07-20T00:00:00.000000Z",
                    "target": {
                        "host": "127.0.0.1",
                        "port": 2222,
                        "username": "agqual",
                    },
                    "timeout_seconds": 110,
                },
            )
        descriptor = os.open("/usr/bin/ssh", os.O_RDONLY | os.O_CLOEXEC)
        try:
            executable = BUNDLE._executable_identity(descriptor, "/usr/bin/ssh")
        finally:
            os.close(descriptor)
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
            f"UserKnownHostsFile={known_hosts_path}",
            "-i",
            str(identity_path),
            "-p",
            "2222",
            "agqual@127.0.0.1",
            "/usr/bin/env",
            "--chdir=/home/agqual/agent-governor-ng-0.1.0",
            "LC_ALL=C",
            "/usr/bin/dpkg-checkbuilddeps",
        ]
        record = {
            "argv": argv,
            "case_family": BUNDLE.CASE_FAMILIES[0],
            "case_wall_clock": BUNDLE.artifact_reference(root, case_clock_path),
            "command_id": command_id,
            "cwd": str(root),
            "duration_ms": 1,
            "ended_at": "2026-07-20T00:00:00.001000Z",
            "ended_boottime_ns": case_clock["started_boottime_ns"] + 1_000_000,
            "environment": {},
            "executable": executable,
            "expected_outcome": {"kind": "exit_code", "value": 0},
            "guest_id": BUNDLE.GUESTS[0][0],
            "matched_expectation": False,
            "observed_inputs": [
                identity_measurement,
                BUNDLE._input_file_identity(str(known_hosts_path)),
            ],
            "outcome": {
                "exit_code": 1,
                "launch_error": None,
                "signal": None,
                "timed_out": False,
            },
            "schema": BUNDLE.COMMAND_SCHEMA,
            "started_at": "2026-07-20T00:00:00.000000Z",
            "started_boottime_ns": case_clock["started_boottime_ns"],
            "stderr": BUNDLE.artifact_reference(root, stderr_path),
            "stdout": BUNDLE.artifact_reference(root, stdout_path),
            "timeout_seconds": 120,
        }
        BUNDLE.validate_command_record(record)
        BUNDLE.write_new_canonical_json(record_path, record)
        self.write_terminal_supporting_commands(root, commands_root, record)
        return record_path.relative_to(root).as_posix()

    def write_terminal_supporting_commands(
        self, root: Path, commands_root: Path, build_record: dict
    ) -> None:
        target_index = build_record["argv"].index(BUNDLE.SSH_BUILD_TARGET)
        ssh_prefix = build_record["argv"][: target_index + 1]
        known_hosts_argument = next(
            argument
            for argument in ssh_prefix
            if argument.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = known_hosts_argument.split("=", 1)[1]
        identity_path = ssh_prefix[ssh_prefix.index("-i") + 1]
        port = ssh_prefix[ssh_prefix.index("-p") + 1]
        archive_path = root / "mandatory" / "test_results" / "candidate-source.tar"
        archive_digest, _ = BUNDLE.digest_regular_file(archive_path)
        guest_facts = BUNDLE.load_canonical_json(
            root / "mandatory" / "test_results" / "guest-facts.v1.json"
        )
        specifications = (
            (
                "terminal-dpkg-build-refusal",
                list(BUNDLE.SSH_BUILD_REMOTE_TAILS[1]),
                3,
                False,
                b"",
                (
                    BUNDLE.EXPECTED_BUILD_DEPENDENCY_REFUSAL
                    + "\ndpkg-buildpackage: warning: build dependencies/conflicts "
                    "unsatisfied; aborting\n"
                ).encode(),
            ),
            (
                "guest-apt-update",
                list(BUNDLE.SSH_APT_UPDATE_TAIL),
                0,
                True,
                b"",
                b"",
            ),
            (
                "guest-build-dependency-install",
                list(BUNDLE.SSH_BUILD_DEPENDENCY_INSTALL_TAIL),
                0,
                True,
                b"",
                b"",
            ),
            (
                "guest-archive-sha256",
                list(BUNDLE.SSH_ARCHIVE_MEASUREMENT_TAIL),
                0,
                True,
                (
                    archive_digest.removeprefix("sha256:")
                    + "  "
                    + BUNDLE.GUEST_CANDIDATE_ARCHIVE_PATH
                    + "\n"
                ).encode("ascii"),
                b"",
            ),
            (
                "extract-candidate-archive",
                list(BUNDLE.SSH_ARCHIVE_EXTRACTION_TAIL),
                0,
                True,
                b"",
                b"",
            ),
            (
                "source-tree-init",
                list(BUNDLE.SSH_SOURCE_TREE_TAILS[0]),
                0,
                True,
                b"",
                b"",
            ),
            (
                "source-tree-add",
                list(BUNDLE.SSH_SOURCE_TREE_TAILS[1]),
                0,
                True,
                b"",
                b"",
            ),
            (
                "source-tree-write",
                list(BUNDLE.SSH_SOURCE_TREE_TAILS[2]),
                0,
                True,
                b"",
                b"",
            ),
            (
                "guest-facts",
                list(BUNDLE.SSH_GUEST_FACTS_TAIL),
                0,
                True,
                BUNDLE.canonical_json_bytes(
                    {
                        "guest_id": guest_facts["guest_id"],
                        "observed": guest_facts["observed"],
                        "schema": BUNDLE.GUEST_FACTS_SCHEMA,
                    }
                ),
                b"",
            ),
        )
        for command_id, tail, exit_code, matched, stdout, stderr in specifications:
            record_path = commands_root / f"{command_id}.command.v1.json"
            if record_path.exists():
                continue
            stdout_path = commands_root / f"{command_id}.stdout"
            stderr_path = commands_root / f"{command_id}.stderr"
            if command_id == "source-tree-write":
                candidate = BUNDLE.load_canonical_json(
                    root / "inputs" / "candidate-identity.v1.json"
                )
                stdout = (candidate["source"]["tree"] + "\n").encode("ascii")
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            record = copy.deepcopy(build_record)
            record.update(
                {
                    "argv": [*ssh_prefix, *tail],
                    "command_id": command_id,
                    "matched_expectation": matched,
                    "outcome": {
                        "exit_code": exit_code,
                        "launch_error": None,
                        "signal": None,
                        "timed_out": False,
                    },
                    "stderr": BUNDLE.artifact_reference(root, stderr_path),
                    "stdout": BUNDLE.artifact_reference(root, stdout_path),
                }
            )
            BUNDLE.validate_command_record(record)
            BUNDLE.write_new_canonical_json(record_path, record)
        readiness_command_id = "fixture-ssh-readiness"
        readiness_record_path = (
            commands_root / f"{readiness_command_id}.command.v1.json"
        )
        if not readiness_record_path.exists():
            readiness_path = (
                root / "mandatory/hypervisor_and_host/ssh-readiness.v1.json"
            )
            stdout_path = commands_root / f"{readiness_command_id}.stdout"
            stderr_path = commands_root / f"{readiness_command_id}.stderr"
            stdout_path.write_bytes(readiness_path.read_bytes())
            stderr_path.write_bytes(b"")
            descriptor = os.open("/usr/bin/python3", os.O_RDONLY | os.O_CLOEXEC)
            try:
                executable = BUNDLE._executable_identity(descriptor, "/usr/bin/python3")
            finally:
                os.close(descriptor)
            fixture_path = root / "inputs/vm_fixture.py"
            readiness_command = copy.deepcopy(build_record)
            readiness_argv = [
                "/usr/bin/python3",
                str(fixture_path),
                "wait-ssh",
                "--output",
                str(readiness_path),
                "--host",
                "127.0.0.1",
                "--port",
                "2222",
                "--username",
                "agqual",
                "--identity-file",
                str(identity_path),
                "--known-hosts-file",
                str(known_hosts_path),
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
            readiness_command.update(
                {
                    "argv": readiness_argv,
                    "command_id": readiness_command_id,
                    "executable": executable,
                    "matched_expectation": True,
                    "observed_inputs": [
                        BUNDLE._input_file_identity(path)
                        for path in BUNDLE._declared_input_paths(readiness_argv)
                    ],
                    "outcome": {
                        "exit_code": 0,
                        "launch_error": None,
                        "signal": None,
                        "timed_out": False,
                    },
                    "stderr": BUNDLE.artifact_reference(root, stderr_path),
                    "stdout": BUNDLE.artifact_reference(root, stdout_path),
                }
            )
            BUNDLE.validate_command_record(readiness_command)
            BUNDLE.write_new_canonical_json(readiness_record_path, readiness_command)

        work_root = root.parent / "vm-work"
        work_root.mkdir(exist_ok=True)
        overlay_path = work_root / "overlay.qcow2"
        if not overlay_path.exists():
            overlay_path.write_bytes(b"synthetic mutable overlay\n")
        qmp_path = work_root / "qmp.sock"
        image_path = root / "mandatory/image_provenance/base-image.qcow2"
        snapshot_path = root / "mandatory/snapshot_boundaries/failure.qcow2"
        hypervisor_root = root / "mandatory/hypervisor_and_host"
        nocloud_path = hypervisor_root / "nocloud.iso"
        serial_path = hypervisor_root / "serial.log"
        pid_path = hypervisor_root / "qemu.pid"
        qmp_output_path = hypervisor_root / "qmp-quit.v1.json"
        fixture_path = root / "inputs/vm_fixture.py"

        def synthetic_executable(requested_path: str) -> dict:
            descriptor = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
            try:
                identity = BUNDLE._executable_identity(descriptor, requested_path)
            finally:
                os.close(descriptor)
            return identity

        def write_synthetic_command(
            command_id: str,
            argv: list[str],
            *,
            stdout: bytes = b"",
            stderr: bytes = b"",
        ) -> None:
            record_path = commands_root / f"{command_id}.command.v1.json"
            if record_path.exists():
                return
            stdout_path = commands_root / f"{command_id}.stdout"
            stderr_path = commands_root / f"{command_id}.stderr"
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            record = copy.deepcopy(build_record)
            record.update(
                {
                    "argv": argv,
                    "command_id": command_id,
                    "executable": synthetic_executable(argv[0]),
                    "expected_outcome": {"kind": "exit_code", "value": 0},
                    "matched_expectation": True,
                    "observed_inputs": [
                        BUNDLE._input_file_identity(path)
                        for path in BUNDLE._declared_input_paths(argv)
                    ],
                    "outcome": {
                        "exit_code": 0,
                        "launch_error": None,
                        "signal": None,
                        "timed_out": False,
                    },
                    "stderr": BUNDLE.artifact_reference(root, stderr_path),
                    "stdout": BUNDLE.artifact_reference(root, stdout_path),
                }
            )
            BUNDLE.validate_command_record(record)
            BUNDLE.write_new_canonical_json(record_path, record)

        seed_root = hypervisor_root / "nocloud"
        public_key_path = hypervisor_root / "fixture.pub"
        render_argv = [
            "/usr/bin/python3",
            str(fixture_path),
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
        write_synthetic_command(
            "fixture-render-nocloud",
            render_argv,
            stdout=(seed_root / "fixture.v1.json").read_bytes(),
        )
        write_synthetic_command(
            "nocloud-iso-create",
            [
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
        )
        write_synthetic_command(
            "vm-overlay-create",
            [
                "/usr/bin/qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(image_path),
                str(overlay_path),
            ],
        )
        write_synthetic_command(
            "vm-launch",
            [
                "/usr/bin/qemu-system-x86_64",
                "-name",
                "ag-ng-debian-12-amd64",
                "-uuid",
                "12345678-1234-4234-9234-123456789abc",
                "-machine",
                "q35,accel=kvm",
                "-cpu",
                "host",
                "-smp",
                "4",
                "-m",
                "8192",
                "-display",
                "none",
                "-serial",
                f"file:{serial_path}",
                "-monitor",
                "none",
                "-no-reboot",
                "-daemonize",
                "-pidfile",
                str(pid_path),
                "-qmp",
                f"unix:{qmp_path},server=on,wait=off",
                "-drive",
                f"if=virtio,format=qcow2,file={overlay_path},cache=none",
                "-drive",
                f"if=virtio,format=raw,readonly=on,file={nocloud_path}",
                "-netdev",
                f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
                "-device",
                "virtio-net-pci,netdev=net0",
            ],
        )
        scp_argv = [
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
            f"{BUNDLE.SSH_BUILD_TARGET}:{BUNDLE.GUEST_CANDIDATE_ARCHIVE_PATH}",
        ]
        write_synthetic_command("candidate-archive-transfer", scp_argv)
        write_synthetic_command(
            "vm-shutdown",
            [
                "/usr/bin/python3",
                str(fixture_path),
                "qmp",
                "--output",
                str(qmp_output_path),
                "--socket",
                str(qmp_path),
                "--operation",
                "quit",
                "--timeout-seconds",
                "10",
            ],
            stdout=qmp_output_path.read_bytes(),
        )
        write_synthetic_command(
            "vm-exit-wait",
            [
                "/usr/bin/tail",
                "--pid=4242",
                "--follow=name",
                "--sleep-interval=0.1",
                "/dev/null",
            ],
        )
        write_synthetic_command(
            "snapshot-convert",
            [
                "/usr/bin/qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "qcow2",
                str(overlay_path),
                str(snapshot_path),
            ],
        )
        write_synthetic_command(
            "snapshot-check",
            [
                "/usr/bin/qemu-img",
                "check",
                "--output=json",
                str(snapshot_path),
            ],
            stdout=b'{"check-errors":0}\n',
        )
        write_synthetic_command(
            "snapshot-info",
            [
                "/usr/bin/qemu-img",
                "info",
                "--output=json",
                "--backing-chain",
                str(snapshot_path),
            ],
            stdout=(
                b'[{"actual-size":28,"filename":"failure.qcow2",'
                b'"format":"qcow2","virtual-size":1048576}]\n'
            ),
        )

        case_clock = BUNDLE.load_canonical_json(
            commands_root.parent / "case-wall-clock.v1.json"
        )
        for sequence, command_id in enumerate(BUNDLE.FIRST_GATE_COMMAND_IDS, start=1):
            record_path = commands_root / f"{command_id}.command.v1.json"
            record = BUNDLE.load_canonical_json(record_path)
            started = case_clock["started_boottime_ns"] + sequence * 10_000_000
            record["started_boottime_ns"] = started
            record["ended_boottime_ns"] = started + 1_000_000
            record["duration_ms"] = 1
            BUNDLE.validate_command_record(record)
            record_path.write_bytes(BUNDLE.canonical_json_bytes(record))

    def blocked_receipt(
        self,
        root: Path,
        manifest_reference: dict,
        *,
        command_references: list[dict] | None = None,
    ) -> dict:
        plan_reference = BUNDLE.artifact_reference(
            root, root / "controller-plan.v1.json"
        )
        phase1_record = BUNDLE.load_canonical_json(
            root / "inputs" / "phase1-starting-candidate.v1.json"
        )
        source = copy.deepcopy(phase1_record["source"])
        final_source = copy.deepcopy(
            BUNDLE.load_canonical_json(root / "inputs" / "candidate-identity.v1.json")[
                "source"
            ]
        )
        command_references = [] if command_references is None else command_references
        terminal_evidence = command_references or [plan_reference]
        matrix = []
        for guest_id, distribution, release, architecture in BUNDLE.GUESTS:
            executed_cell = guest_id == BUNDLE.GUESTS[0][0]
            cases = []
            for family in BUNDLE.CASE_FAMILIES:
                terminal = executed_cell and family == BUNDLE.CASE_FAMILIES[0]
                cases.append(
                    {
                        "evidence": terminal_evidence if terminal else [],
                        "family": family,
                        "result": "blocked" if terminal else "not_run",
                        "summary": "clean candidate package generation refused"
                        if terminal
                        else "not executed after the bounded first-gate stop",
                    }
                )
            guest_facts_path = (
                root / "mandatory" / "test_results" / "guest-facts.v1.json"
            )
            archive_record_path = (
                root / "mandatory" / "test_results" / "candidate-archive.v1.json"
            )
            guest_references = [
                BUNDLE.artifact_reference(root, guest_facts_path),
                BUNDLE.artifact_reference(root, archive_record_path),
            ]
            image_reference = BUNDLE.artifact_reference(
                root, root / "mandatory" / "image_provenance" / "image.v1.json"
            )
            snapshot_reference = BUNDLE.artifact_reference(
                root,
                root / "mandatory" / "snapshot_boundaries" / "snapshot.v1.json",
            )
            image_record = BUNDLE.load_canonical_json(root / image_reference["path"])
            guest_facts = BUNDLE.load_canonical_json(guest_facts_path)
            matrix.append(
                {
                    "architecture": architecture,
                    "cases": cases,
                    "distribution": distribution,
                    "guest_evidence": guest_references if executed_cell else [],
                    "guest_id": guest_id,
                    "image": {
                        "bytes": copy.deepcopy(image_record["bytes"]),
                        "provenance": image_reference,
                        "source": image_record["source"],
                        "source_digest": image_record["source_digest"],
                    }
                    if executed_cell
                    else None,
                    "observed": copy.deepcopy(guest_facts["observed"])
                    if executed_cell
                    else None,
                    "release": release,
                    "snapshots": [snapshot_reference] if executed_cell else [],
                }
            )
        claim_reference = BUNDLE.artifact_reference(root, root / "inputs/claim.v1.json")
        phase1_reference = BUNDLE.artifact_reference(
            root, root / "inputs/phase1-starting-candidate.v1.json"
        )
        terminal_ref = f"{BUNDLE.GUESTS[0][0]}/{BUNDLE.CASE_FAMILIES[0]}"
        residual_gates = [
            {
                "case_refs": [terminal_ref]
                if blocker == "clean_offline_source_build_absent"
                else [],
                "classification": "package_metadata_or_maintainer_scripts"
                if blocker == "clean_offline_source_build_absent"
                else "operator_tooling",
                "evidence": terminal_evidence
                if blocker == "clean_offline_source_build_absent"
                else [plan_reference],
                "id": blocker,
                "repair_surface": f"close the frozen {blocker} gate",
                "summary": f"frozen blocker remains open: {blocker}",
            }
            for blocker in BUNDLE.KNOWN_BLOCKERS
        ]
        dependency_inventory = [
            {
                "classification": dependency["classification"],
                "evidence": [plan_reference],
                "id": dependency["id"],
                "requirement": dependency["requirement"],
            }
            for dependency in phase1_record["dependency_inventory"]
        ]
        mandatory_evidence = {}
        required_categories = {
            "command_ledger",
            "hypervisor_and_host",
            "image_provenance",
            "snapshot_boundaries",
            "test_results",
        }
        for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES:
            references = []
            if category in required_categories:
                references.append(
                    BUNDLE.artifact_reference(
                        root, root / "mandatory" / category / "evidence.txt"
                    )
                )
            if category == "hypervisor_and_host":
                for name in (
                    "fixture.pub",
                    "nocloud/fixture.v1.json",
                    "nocloud/meta-data",
                    "nocloud/user-data",
                    "nocloud.iso",
                    "qemu.pid",
                    "qmp-quit.v1.json",
                    "serial.log",
                    "ssh-readiness.v1.json",
                ):
                    path = root / "mandatory" / "hypervisor_and_host" / name
                    if path.exists():
                        references.append(BUNDLE.artifact_reference(root, path))
            elif category == "image_provenance":
                for name in ("base-image.qcow2", "image.v1.json"):
                    references.append(
                        BUNDLE.artifact_reference(
                            root, root / "mandatory" / category / name
                        )
                    )
            elif category == "snapshot_boundaries":
                for name in ("failure.qcow2", "snapshot.v1.json"):
                    references.append(
                        BUNDLE.artifact_reference(
                            root, root / "mandatory" / category / name
                        )
                    )
            elif category == "test_results":
                for name in (
                    "candidate-source.tar",
                    "guest-facts.v1.json",
                    "candidate-archive.v1.json",
                ):
                    references.append(
                        BUNDLE.artifact_reference(
                            root, root / "mandatory" / category / name
                        )
                    )
            mandatory_evidence[category] = references
        return {
            "authority_use": "evidence_only",
            "candidate": {"final": final_source, "starting": source},
            "claim": {
                "blockers": list(BUNDLE.KNOWN_BLOCKERS),
                "evidence": claim_reference,
                "exclusions": list(BUNDLE.CLAIM_EXCLUSIONS),
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
                "architecture": "amd64",
                "distribution": "test-host",
                "evidence": [plan_reference],
                "hypervisor": "test-hypervisor",
                "kernel": "test-kernel",
            },
            "defects": [
                {
                    "case_refs": [terminal_ref],
                    "classification": "package_metadata_or_maintainer_scripts",
                    "evidence": terminal_evidence,
                    "id": "bookworm-rust-build-dependency-unavailable",
                    "summary": "the supported archive cannot satisfy the declared Rust build versions",
                }
            ],
            "dependency_inventory": dependency_inventory,
            "evidence_manifest": manifest_reference,
            "harness": {
                "commit": final_source["commit"],
                "evidence": BUNDLE.artifact_reference(
                    root, root / "inputs" / "bundle.py"
                ),
                "publisher_evidence": BUNDLE.artifact_reference(
                    root, root / "inputs" / "blocked_receipt.py"
                ),
                "tree": final_source["tree"],
                "vm_fixture_evidence": BUNDLE.artifact_reference(
                    root, root / "inputs" / "vm_fixture.py"
                ),
            },
            "mandatory_evidence": mandatory_evidence,
            "matrix": matrix,
            "package_digest_history": [],
            "receipt_inventory": [],
            "reconstructs_standing": False,
            "repairs": [],
            "residual_gates": residual_gates,
            "schema": BUNDLE.RECEIPT_SCHEMA,
            "phase1": phase1_reference,
            "support_boundary": None,
            "verdict": "BLOCKED",
        }

    def seal_and_receipt(self, root: Path) -> dict:
        self.write_terminal_build_fixture(root)
        manifest_reference = BUNDLE.seal_bundle(root)
        command_references = [
            entry
            for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                "entries"
            ]
            if entry["path"].endswith(".command.v1.json")
        ]
        receipt = self.blocked_receipt(
            root,
            manifest_reference,
            command_references=command_references,
        )
        BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
        return receipt

    def qualified_receipt(self, root: Path, manifest_reference: dict) -> dict:
        receipt = self.blocked_receipt(root, manifest_reference)
        plan_reference = BUNDLE.artifact_reference(
            root, root / "controller-plan.v1.json"
        )
        for layer in receipt["claim"]["layers"]:
            layer["status"] = "pass"
        mandatory = {
            category: [
                BUNDLE.artifact_reference(
                    root, root / "mandatory" / category / "evidence.txt"
                )
            ]
            for category in BUNDLE.MANDATORY_EVIDENCE_CATEGORIES
        }
        receipt["mandatory_evidence"] = mandatory
        image_provenance = mandatory["image_provenance"][0]
        for cell in receipt["matrix"]:
            cell["image"] = {
                "bytes": {
                    "length": image_provenance["length"],
                    "sha256": image_provenance["sha256"],
                },
                "provenance": image_provenance,
                "source": "https://example.invalid/pinned-test-image",
                "source_digest": image_provenance["sha256"],
            }
            cell["observed"] = {
                "active_lsms": "landlock",
                "architecture": cell["architecture"],
                "cgroup": "v2",
                "distribution": cell["distribution"],
                "filesystem": "ext4",
                "kernel": "6.1.0-test",
                "landlock_abi": "3",
                "release": cell["release"],
                "systemd": "252",
            }
            cell["guest_evidence"] = [mandatory["test_results"][0]]
            cell["snapshots"] = [mandatory["snapshot_boundaries"][0]]
            for case in cell["cases"]:
                case["result"] = "pass"
                case["evidence"] = [plan_reference]
                case["summary"] = "synthetic passing case for validator tests"
        package_artifacts = []
        for architecture in ("amd64", "arm64"):
            package_artifacts.append(
                {
                    "architecture": architecture,
                    "identity": BUNDLE.artifact_reference(
                        root,
                        root
                        / "packages"
                        / "generation-1"
                        / f"agent-governor-ng_0.1.0-1_{architecture}.deb",
                    ),
                    "kind": "deb",
                    "name": "agent-governor-ng",
                    "version": "0.1.0-1",
                }
            )
        receipt["package_digest_history"] = [
            {
                "artifacts": package_artifacts,
                "generation": 1,
                "reason": "initial candidate",
                "source_commit": receipt["candidate"]["final"]["commit"],
                "source_tree": receipt["candidate"]["final"]["tree"],
            }
        ]
        receipt["residual_gates"] = []
        receipt["verdict"] = "QUALIFIED"
        return receipt

    def test_initialization_creates_every_guest_case_and_frozen_deadlines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            plan = BUNDLE.load_canonical_json(root / "controller-plan.v1.json")
            self.assertEqual(plan["guest_ids"], [guest[0] for guest in BUNDLE.GUESTS])
            self.assertEqual(plan["case_ids"], list(BUNDLE.CASE_FAMILIES))
            self.assertEqual(plan["per_command_deadline_seconds"], 120)
            self.assertEqual(plan["per_case_deadline_seconds"], 1800)
            for guest in BUNDLE.GUESTS:
                for family in BUNDLE.CASE_FAMILIES:
                    self.assertTrue(
                        (
                            root
                            / "guests"
                            / guest[0]
                            / "cases"
                            / family
                            / "case-plan.v1.json"
                        ).is_file()
                    )

    def test_matrix_and_controller_plan_cannot_expand_frozen_deadlines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            matrix_path = temporary_root / "matrix.toml"
            matrix_path.write_text(
                (HERE / "matrix.toml")
                .read_text(encoding="utf-8")
                .replace(
                    "per_command_deadline_seconds = 120",
                    "per_command_deadline_seconds = 121",
                ),
                encoding="utf-8",
            )
            self.assert_qualification_error(
                lambda: BUNDLE.initialize_bundle(
                    temporary_root / "bad-bundle", matrix_path
                )
            )

            root = self.initialized_bundle(temporary)
            plan_path = root / "controller-plan.v1.json"
            plan = BUNDLE.load_canonical_json(plan_path)
            plan["per_command_deadline_seconds"] = 121
            plan_path.write_bytes(BUNDLE.canonical_json_bytes(plan))
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "expanded",
                    ["/usr/bin/true"],
                    root,
                    {},
                    1,
                )
            )

    def test_case_wall_clock_counts_idle_gaps_and_stops_late_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "first",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            clock_path = (
                root
                / "guests"
                / BUNDLE.GUESTS[0][0]
                / "cases"
                / BUNDLE.CASE_FAMILIES[0]
                / "case-wall-clock.v1.json"
            )
            clock = BUNDLE.load_canonical_json(clock_path)
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            clock["started_boottime_ns"] = now - 1_801_000_000_000
            clock["deadline_boottime_ns"] = (
                clock["started_boottime_ns"] + 1_800_000_000_000
            )
            clock_path.write_bytes(BUNDLE.canonical_json_bytes(clock))
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "late",
                    ["/usr/bin/true"],
                    root,
                    {},
                    1,
                )
            )

    def test_command_record_uses_exact_argv_environment_and_stream_refs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "exact-command",
                [
                    "/usr/bin/python3",
                    "-c",
                    "import os,sys;print(os.environ['VISIBLE']);sys.stderr.write('err\\n')",
                ],
                root,
                {"VISIBLE": "yes"},
                10,
            )
            self.assertEqual(record["argv"][0], "/usr/bin/python3")
            self.assertEqual(record["environment"], {"VISIBLE": "yes"})
            self.assertEqual(record["outcome"]["exit_code"], 0)
            self.assertEqual((root / record["stdout"]["path"]).read_bytes(), b"yes\n")
            self.assertEqual((root / record["stderr"]["path"]).read_bytes(), b"err\n")
            BUNDLE.validate_command_record(record)

    def test_command_record_binds_argv_to_measured_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "executable-binding",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            record["argv"][0] = "/usr/bin/false"
            self.assert_qualification_error(
                lambda: BUNDLE.validate_command_record(record)
            )

    def test_copied_python_tool_is_measured_and_required_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            fixture_path = root / "inputs/vm_fixture.py"
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "measured-fixture",
                ["/usr/bin/python3", str(fixture_path), "--help"],
                root,
                {},
                10,
            )
            self.assertEqual(len(record["observed_inputs"]), 1)
            self.assertEqual(
                record["observed_inputs"][0]["requested_path"], str(fixture_path)
            )
            missing = copy.deepcopy(record)
            missing["observed_inputs"] = []
            self.assert_qualification_error(
                lambda: BUNDLE.validate_command_record(missing)
            )
            duplicate = copy.deepcopy(record)
            duplicate["observed_inputs"].append(
                copy.deepcopy(duplicate["observed_inputs"][0])
            )
            self.assert_qualification_error(
                lambda: BUNDLE.validate_command_record(duplicate)
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            alias_parent = root / "alias/inputs"
            alias_parent.mkdir(parents=True)
            alias = alias_parent / "vm_fixture.py"
            alias.symlink_to(root / "inputs/vm_fixture.py")
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "aliased-fixture",
                    ["/usr/bin/python3", str(alias), "--help"],
                    root,
                    {},
                    10,
                )
            )
            command_root = (
                root
                / "guests"
                / BUNDLE.GUESTS[0][0]
                / "cases"
                / BUNDLE.CASE_FAMILIES[0]
                / "commands"
            )
            self.assertFalse((command_root / "aliased-fixture.stdout").exists())
            self.assertFalse(
                (command_root / "aliased-fixture.command.v1.json").exists()
            )

    def test_command_timeout_is_terminal_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "timeout",
                ["/usr/bin/python3", "-c", "import time;time.sleep(5)"],
                root,
                {},
                1,
            )
            self.assertTrue(record["outcome"]["timed_out"])
            self.assertEqual(record["outcome"]["signal"], 9)
            self.assertIsNone(record["outcome"]["exit_code"])

    def test_command_requires_absolute_executable_and_unique_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "relative",
                    ["true"],
                    root,
                    {},
                    1,
                )
            )

    def test_paired_stream_reservation_failure_does_not_poison_command_id(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            commands = (
                root
                / "guests"
                / BUNDLE.GUESTS[0][0]
                / "cases"
                / BUNDLE.CASE_FAMILIES[0]
                / "commands"
            )
            stdout_path = commands / "paired-reservation.stdout"
            stderr_path = commands / "paired-reservation.stderr"
            real_open = os.open

            def fail_stderr(path, flags, mode=0o777, *, dir_fd=None):
                if Path(path) == stderr_path and flags & os.O_EXCL:
                    raise PermissionError("synthetic stderr reservation failure")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(BUNDLE.os, "open", side_effect=fail_stderr):
                with self.assertRaises(PermissionError):
                    BUNDLE.record_command(
                        root,
                        BUNDLE.GUESTS[0][0],
                        BUNDLE.CASE_FAMILIES[0],
                        "paired-reservation",
                        ["/usr/bin/true"],
                        root,
                        {},
                        1,
                    )
            self.assertFalse(stdout_path.exists())
            self.assertFalse(stderr_path.exists())
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "paired-reservation",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            self.assertTrue(record["matched_expectation"])
            BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "once",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "once",
                    ["/usr/bin/true"],
                    root,
                    {},
                    1,
                )
            )

    def test_valid_seal_and_blocked_receipt_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            self.seal_and_receipt(root)
            result = BUNDLE.verify_bundle(root)
            self.assertTrue(result["valid"])
            self.assertEqual(result["verdict"], "BLOCKED")

    def test_blocked_receipt_requires_real_ordered_vm_snapshot_chain(self) -> None:
        command_root_suffix = Path(
            "guests/debian-12-amd64/cases/package_build_and_payload/commands"
        )

        def seal_existing(root: Path) -> None:
            manifest_reference = BUNDLE.seal_bundle(root)
            receipt = self.blocked_receipt(
                root,
                manifest_reference,
                command_references=[
                    entry
                    for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                        "entries"
                    ]
                    if entry["path"].endswith(".command.v1.json")
                ],
            )
            BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)

        with self.subTest(mutation="missing-launch"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                for suffix in ("command.v1.json", "stdout", "stderr"):
                    (commands / f"vm-launch.{suffix}").unlink()
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="empty-snapshot"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                snapshot_path = root / "mandatory/snapshot_boundaries/failure.qcow2"
                snapshot_path.write_bytes(b"")
                snapshot_record_path = (
                    root / "mandatory/snapshot_boundaries/snapshot.v1.json"
                )
                snapshot_record = BUNDLE.load_canonical_json(snapshot_record_path)
                snapshot_record["artifact"] = BUNDLE.artifact_reference(
                    root, snapshot_path
                )
                snapshot_record_path.write_bytes(
                    BUNDLE.canonical_json_bytes(snapshot_record)
                )
                for command_id in ("snapshot-check", "snapshot-info"):
                    record_path = commands / f"{command_id}.command.v1.json"
                    record = BUNDLE.load_canonical_json(record_path)
                    record["observed_inputs"] = [
                        BUNDLE._input_file_identity(str(snapshot_path))
                    ]
                    record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="unordered-source-measurement"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                extract_path = commands / "extract-candidate-archive.command.v1.json"
                tree_path = commands / "source-tree-init.command.v1.json"
                extract = BUNDLE.load_canonical_json(extract_path)
                tree = BUNDLE.load_canonical_json(tree_path)
                tree["started_boottime_ns"] = extract["started_boottime_ns"] - 2_000_000
                tree["ended_boottime_ns"] = extract["started_boottime_ns"] - 1_000_000
                tree_path.write_bytes(BUNDLE.canonical_json_bytes(tree))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="ssh-input-drift"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                record_path = (
                    root / command_root_suffix / "source-tree-add.command.v1.json"
                )
                record = BUNDLE.load_canonical_json(record_path)
                record["observed_inputs"][0]["sha256"] = "sha256:" + "a" * 64
                record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="non-utf8-build-diagnostic"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                stderr_path = commands / "terminal-build-refusal.stderr"
                stderr_path.write_bytes(b"\xff\n")
                record_path = commands / "terminal-build-refusal.command.v1.json"
                record = BUNDLE.load_canonical_json(record_path)
                record["stderr"] = BUNDLE.artifact_reference(root, stderr_path)
                record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="non-ascii-nocloud-key"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                public_key_path = root / "mandatory/hypervisor_and_host/fixture.pub"
                public_key = b"ssh-ed25519 \xff\n"
                public_key_path.write_bytes(public_key)
                fixture_path = (
                    root / "mandatory/hypervisor_and_host/nocloud/fixture.v1.json"
                )
                fixture = BUNDLE.load_canonical_json(fixture_path)
                fixture["authorized_key"] = {
                    "length": len(public_key),
                    "sha256": "sha256:" + hashlib.sha256(public_key).hexdigest(),
                }
                fixture_path.write_bytes(BUNDLE.canonical_json_bytes(fixture))
                render_path = commands / "fixture-render-nocloud.command.v1.json"
                render = BUNDLE.load_canonical_json(render_path)
                render["observed_inputs"][1] = BUNDLE._input_file_identity(
                    str(public_key_path)
                )
                render_stdout = commands / "fixture-render-nocloud.stdout"
                render_stdout.write_bytes(fixture_path.read_bytes())
                render["stdout"] = BUNDLE.artifact_reference(root, render_stdout)
                render_path.write_bytes(BUNDLE.canonical_json_bytes(render))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with self.subTest(mutation="snapshot-backing-file"):
            with tempfile.TemporaryDirectory() as temporary:
                root = self.initialized_bundle(temporary)
                self.write_terminal_build_fixture(root)
                commands = root / command_root_suffix
                stdout_path = commands / "snapshot-info.stdout"
                stdout_path.write_bytes(
                    b'[{"backing-filename":"base.qcow2","format":"qcow2",'
                    b'"virtual-size":1048576}]\n'
                )
                record_path = commands / "snapshot-info.command.v1.json"
                record = BUNDLE.load_canonical_json(record_path)
                record["stdout"] = BUNDLE.artifact_reference(root, stdout_path)
                record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
                seal_existing(root)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_verifier_rejects_dpkg_name_outside_exact_remote_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            command_path = root / self.write_terminal_build_fixture(root)
            command = BUNDLE.load_canonical_json(command_path)
            command["argv"][-1:] = [
                "/usr/bin/false",
                "/usr/bin/dpkg-checkbuilddeps",
            ]
            command_path.write_bytes(BUNDLE.canonical_json_bytes(command))
            manifest_reference = BUNDLE.seal_bundle(root)
            command_references = [
                entry
                for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                    "entries"
                ]
                if entry["path"].endswith(".command.v1.json")
            ]
            receipt = self.blocked_receipt(
                root,
                manifest_reference,
                command_references=command_references,
            )
            BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_verifier_binds_executing_controller_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            BUNDLE.seal_bundle(root)
            substituted = Path(temporary) / "substitute-bundle.py"
            substituted.write_bytes(Path(BUNDLE.__file__).read_bytes() + b"# changed\n")
            original = BUNDLE.__file__
            BUNDLE.__file__ = str(substituted)
            try:
                self.assert_qualification_error(
                    lambda: BUNDLE.verify_bundle(root, require_receipt=False)
                )
            finally:
                BUNDLE.__file__ = original

    def test_verifier_requires_exact_campaign_tool_evidence_bindings(self) -> None:
        for field in ("publisher_evidence", "vm_fixture_evidence"):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temporary:
                    root = self.initialized_bundle(temporary)
                    self.write_terminal_build_fixture(root)
                    manifest_reference = BUNDLE.seal_bundle(root)
                    command_references = [
                        entry
                        for entry in BUNDLE.load_canonical_json(
                            root / "manifest.v1.json"
                        )["entries"]
                        if entry["path"].endswith(".command.v1.json")
                    ]
                    receipt = self.blocked_receipt(
                        root,
                        manifest_reference,
                        command_references=command_references,
                    )
                    receipt["harness"][field] = receipt["harness"]["evidence"]
                    BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
                    self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_seal_refuses_preexisting_post_seal_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            (root / "receipt.v1.json").write_bytes(b"premature\n")
            self.assert_qualification_error(lambda: BUNDLE.seal_bundle(root))

    def test_record_refuses_after_seal_before_executing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            BUNDLE.seal_bundle(root)
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "post-seal",
                    ["/usr/bin/true"],
                    root,
                    {},
                    1,
                )
            )

    def test_manifest_exclusions_are_exact_root_paths_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            nested = root / "nested"
            nested.mkdir()
            (nested / "receipt.v1.json").write_bytes(b"nested evidence\n")
            BUNDLE.seal_bundle(root)
            manifest = BUNDLE.load_canonical_json(root / "manifest.v1.json")
            self.assertIn(
                "nested/receipt.v1.json",
                {entry["path"] for entry in manifest["entries"]},
            )
            hostile = copy.deepcopy(manifest)
            hostile["excluded_root_paths"] = [
                "manifest.v1.json",
                "receipt.v1.json",
                "*/verification-result.v1.json",
            ]
            self.assert_qualification_error(lambda: BUNDLE.validate_manifest(hostile))

    def test_manifest_rejects_traversal_duplicate_and_unsorted_paths(self) -> None:
        base = {
            "algorithm": "sha256",
            "entries": [
                {"length": 0, "path": "a", "sha256": EMPTY_SHA256},
            ],
            "excluded_root_paths": list(BUNDLE.EXCLUDED_ROOT_PATHS),
            "root": ".",
            "schema": BUNDLE.MANIFEST_SCHEMA,
        }
        for path in ("../a", "/a", "a//b", "a/./b", ".", "a\\b"):
            with self.subTest(path=path):
                hostile = copy.deepcopy(base)
                hostile["entries"][0]["path"] = path
                self.assert_qualification_error(
                    lambda: BUNDLE.validate_manifest(hostile)
                )
        duplicate = copy.deepcopy(base)
        duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
        self.assert_qualification_error(lambda: BUNDLE.validate_manifest(duplicate))
        unsorted = copy.deepcopy(base)
        unsorted["entries"] = [
            {"length": 0, "path": "z", "sha256": EMPTY_SHA256},
            {"length": 0, "path": "a", "sha256": EMPTY_SHA256},
        ]
        self.assert_qualification_error(lambda: BUNDLE.validate_manifest(unsorted))

    def test_seal_rejects_symlink_and_nonregular_node(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            os.symlink("controller-plan.v1.json", root / "alias")
            self.assert_qualification_error(lambda: BUNDLE.seal_bundle(root))
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            os.mkfifo(root / "fifo")
            self.assert_qualification_error(lambda: BUNDLE.seal_bundle(root))

    def test_seal_rejects_same_device_exact_bind_mountpoint(self) -> None:
        parsed = BUNDLE._parse_mountinfo_exact_mountpoints(
            b"42 1 0:1 / /tmp/evidence\\040root rw - ext4 /dev/test rw\n"
        )
        self.assertEqual(parsed, {Path("/tmp/evidence root")})

        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            nested = root / "nested"
            nested.mkdir()
            (nested / "evidence.txt").write_bytes(b"same-device bind contents\n")
            original = BUNDLE._mountinfo_exact_mountpoints
            BUNDLE._mountinfo_exact_mountpoints = lambda: {
                root.resolve(),
                nested.resolve(),
            }
            try:
                self.assert_qualification_error(lambda: BUNDLE.seal_bundle(root))
            finally:
                BUNDLE._mountinfo_exact_mountpoints = original

    def test_manifest_final_pass_rejects_change_after_first_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            target = root / "a-race.txt"
            target.write_bytes(b"before\n")
            BUNDLE.seal_bundle(root)

            original = BUNDLE._digest_bundle_relative
            changed = False

            def racing_digest(bundle_root: Path, relative: str) -> tuple[str, int]:
                nonlocal changed
                result = original(bundle_root, relative)
                if relative == "a-race.txt" and not changed:
                    target.write_bytes(b"after\n")
                    changed = True
                return result

            BUNDLE._digest_bundle_relative = racing_digest
            try:
                self.assert_qualification_error(
                    lambda: BUNDLE.verify_bundle(root, require_receipt=False)
                )
            finally:
                BUNDLE._digest_bundle_relative = original
            self.assertTrue(changed)

    def test_verifier_rejects_extra_missing_renamed_and_tampered_evidence(self) -> None:
        mutations = ("extra", "missing", "renamed", "tampered")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.initialized_bundle(temporary)
                evidence = root / "evidence.txt"
                evidence.write_bytes(b"original\n")
                BUNDLE.seal_bundle(root)
                if mutation == "extra":
                    (root / "extra.txt").write_bytes(b"extra\n")
                elif mutation == "missing":
                    evidence.unlink()
                elif mutation == "renamed":
                    evidence.rename(root / "renamed.txt")
                else:
                    evidence.write_bytes(b"mutated\n")
                self.assert_qualification_error(
                    lambda: BUNDLE.verify_bundle(root, require_receipt=False)
                )

    def test_duplicate_json_keys_and_noncanonical_manifest_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_bytes(b'{"schema":"a","schema":"b"}\n')
            self.assert_qualification_error(lambda: BUNDLE.load_canonical_json(path))
            path.write_bytes(b'{ "schema": "a" }\n')
            self.assert_qualification_error(lambda: BUNDLE.load_canonical_json(path))

    def test_receipt_manifest_digest_and_length_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            receipt = self.seal_and_receipt(root)
            receipt["evidence_manifest"]["sha256"] = "sha256:" + "0" * 64
            (root / "receipt.v1.json").write_bytes(BUNDLE.canonical_json_bytes(receipt))
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_command_record_must_be_assigned_to_its_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "recorded",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            receipt = self.seal_and_receipt(root)
            self.assertTrue(BUNDLE.verify_bundle(root)["valid"])
            (root / "receipt.v1.json").unlink()
            command_path = str(
                Path(record["stdout"]["path"]).with_name("recorded.command.v1.json")
            )
            command_reference = next(
                entry
                for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                    "entries"
                ]
                if entry["path"] == command_path
            )
            receipt["matrix"][0]["cases"][0]["evidence"] = [
                reference
                for reference in receipt["matrix"][0]["cases"][0]["evidence"]
                if reference != command_reference
            ]
            BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_command_record_cannot_move_or_cross_case_and_case_time_is_frozen(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "attributed",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            command_path = record["stdout"]["path"].removesuffix(".stdout")
            command_path += ".command.v1.json"
            manifest_reference = BUNDLE.seal_bundle(root)
            command_reference = next(
                entry
                for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                    "entries"
                ]
                if entry["path"] == command_path
            )
            receipt = self.blocked_receipt(root, manifest_reference)
            receipt["matrix"][0]["cases"][1]["evidence"] = [command_reference]
            BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "duration",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            record_path = root / record["stdout"]["path"].replace(
                ".stdout", ".command.v1.json"
            )
            record["duration_ms"] = BUNDLE.PER_CASE_DEADLINE_SECONDS * 1000 + 1
            record_path.write_bytes(BUNDLE.canonical_json_bytes(record))
            self.seal_and_receipt(root)
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_command_stream_reference_must_match_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            record = BUNDLE.record_command(
                root,
                BUNDLE.GUESTS[0][0],
                BUNDLE.CASE_FAMILIES[0],
                "recorded",
                ["/usr/bin/true"],
                root,
                {},
                1,
            )
            command_path = str(
                Path(record["stdout"]["path"]).with_name("recorded.command.v1.json")
            )
            self.seal_and_receipt(root)
            record_path = root / command_path
            hostile = BUNDLE.load_canonical_json(record_path)
            hostile["stdout"]["sha256"] = "sha256:" + "0" * 64
            record_path.write_bytes(BUNDLE.canonical_json_bytes(hostile))
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_passing_case_requires_each_command_to_match_its_expected_outcome(
        self,
    ) -> None:
        for expected in (None, {"kind": "exit_code", "value": 1}):
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.initialized_bundle(temporary)
                record = BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "expected-refusal",
                    ["/usr/bin/false"],
                    root,
                    {},
                    1,
                    expected,
                )
                command_path = record["stdout"]["path"].replace(
                    ".stdout", ".command.v1.json"
                )
                manifest_reference = BUNDLE.seal_bundle(root)
                command_reference = next(
                    entry
                    for entry in BUNDLE.load_canonical_json(root / "manifest.v1.json")[
                        "entries"
                    ]
                    if entry["path"] == command_path
                )
                receipt = self.blocked_receipt(root, manifest_reference)
                case = receipt["matrix"][0]["cases"][0]
                case.update(
                    {
                        "evidence": [command_reference],
                        "result": "pass",
                        "summary": "typed refusal matched the exact expected exit",
                    }
                )
                receipt["residual_gates"][-1]["case_refs"] = [
                    f"{BUNDLE.GUESTS[0][0]}/{BUNDLE.CASE_FAMILIES[1]}"
                ]
                BUNDLE.write_new_canonical_json(root / "receipt.v1.json", receipt)
                self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_orphan_command_stream_and_symlinked_command_root_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            commands = (
                root
                / "guests"
                / BUNDLE.GUESTS[0][0]
                / "cases"
                / BUNDLE.CASE_FAMILIES[0]
                / "commands"
            )
            (commands / "orphan.stdout").write_bytes(b"orphan\n")
            self.seal_and_receipt(root)
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            commands = (
                root
                / "guests"
                / BUNDLE.GUESTS[0][0]
                / "cases"
                / BUNDLE.CASE_FAMILIES[0]
                / "commands"
            )
            external = Path(temporary) / "external"
            external.mkdir()
            for command_artifact in commands.iterdir():
                command_artifact.unlink()
            commands.rmdir()
            commands.symlink_to(external, target_is_directory=True)
            self.assert_qualification_error(
                lambda: BUNDLE.record_command(
                    root,
                    BUNDLE.GUESTS[0][0],
                    BUNDLE.CASE_FAMILIES[0],
                    "escape",
                    ["/usr/bin/true"],
                    root,
                    {},
                    1,
                )
            )
            self.assertEqual(list(external.iterdir()), [])

    def test_final_receipt_accepts_only_exact_uppercase_verdict_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            manifest_reference = BUNDLE.seal_bundle(root)
            blocked = self.blocked_receipt(root, manifest_reference)
            BUNDLE.validate_final_receipt(blocked)
            for invalid in ("blocked", "qualified", "failed", "FAILED", "not_run"):
                with self.subTest(verdict=invalid):
                    hostile = copy.deepcopy(blocked)
                    hostile["verdict"] = invalid
                    self.assert_qualification_error(
                        lambda: BUNDLE.validate_final_receipt(hostile)
                    )

    def test_qualified_and_requalified_verdict_derivation_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            manifest_reference = BUNDLE.seal_bundle(root)
            qualified = self.qualified_receipt(root, manifest_reference)
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(qualified)
            )
            requalified = copy.deepcopy(qualified)
            requalified["verdict"] = "REQUALIFIED"
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(requalified)
            )

    def test_unsupported_requires_explicit_case_and_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            manifest_reference = BUNDLE.seal_bundle(root)
            receipt = self.blocked_receipt(root, manifest_reference)
            receipt["verdict"] = "UNSUPPORTED"
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(receipt)
            )
            receipt["matrix"][0]["cases"][0]["result"] = "unsupported"
            plan_reference = receipt["harness"]["evidence"]
            receipt["matrix"][0]["cases"][0]["evidence"] = [plan_reference]
            receipt["matrix"][0]["cases"][0]["summary"] = (
                "documented support predicate is contradicted"
            )
            image_provenance = BUNDLE.artifact_reference(
                root, root / "mandatory" / "image_provenance" / "evidence.txt"
            )
            receipt["matrix"][0]["image"] = {
                "bytes": {
                    "length": image_provenance["length"],
                    "sha256": image_provenance["sha256"],
                },
                "provenance": image_provenance,
                "source": "https://example.invalid/unsupported-image",
                "source_digest": image_provenance["sha256"],
            }
            receipt["matrix"][0]["observed"] = {
                "active_lsms": "none",
                "architecture": "amd64",
                "cgroup": "v2",
                "distribution": "debian",
                "filesystem": "ext4",
                "kernel": "5.10.0-test",
                "landlock_abi": "0",
                "release": "12",
                "systemd": "247",
            }
            receipt["support_boundary"] = {
                "documented_predicate": "Linux 6.1 and systemd 252 are required",
                "evidence": [plan_reference],
                "guest_id": "debian-12-amd64",
                "observed_contradiction": "guest reported Linux 5.10 and systemd 247",
            }
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(receipt)
            )

    def test_receipt_requires_every_guest_and_case_in_frozen_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            receipt = self.blocked_receipt(root, BUNDLE.seal_bundle(root))
            missing_guest = copy.deepcopy(receipt)
            missing_guest["matrix"].pop()
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(missing_guest)
            )
            missing_case = copy.deepcopy(receipt)
            missing_case["matrix"][0]["cases"].pop()
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(missing_case)
            )
            reordered = copy.deepcopy(receipt)
            reordered["matrix"][0]["cases"][0], reordered["matrix"][0]["cases"][1] = (
                reordered["matrix"][0]["cases"][1],
                reordered["matrix"][0]["cases"][0],
            )
            self.assert_qualification_error(
                lambda: BUNDLE.validate_final_receipt(reordered)
            )

    def test_inert_template_cannot_validate_as_final_receipt(self) -> None:
        template = BUNDLE.load_canonical_json(HERE / "receipt.template.v1.json")
        self.assert_qualification_error(lambda: BUNDLE.validate_final_receipt(template))

    def test_stale_verification_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.initialized_bundle(temporary)
            self.seal_and_receipt(root)
            result = BUNDLE.verify_bundle(root)
            hostile = copy.deepcopy(result)
            hostile["receipt"]["sha256"] = "sha256:" + "0" * 64
            BUNDLE.write_new_canonical_json(
                root / "verification-result.v1.json", hostile
            )
            self.assert_qualification_error(lambda: BUNDLE.verify_bundle(root))

    def test_checked_in_phase1_record_is_canonical_and_complete(self) -> None:
        record = BUNDLE.load_canonical_json(HERE / "phase1-starting-candidate.v1.json")
        BUNDLE.validate_phase1_record(record)
        host_contract = BUNDLE.load_canonical_json(
            HERE / "phase1-host-contract.v1.json"
        )
        BUNDLE.validate_phase1_host_contract(host_contract)
        self.assertEqual(
            [
                command["stdout_path"]
                for command in host_contract["activation_and_readiness_commands"]
            ],
            ["/etc/agent-governor/genesis-measurement.json"] + [None] * 7,
        )
        host_digest, host_length = BUNDLE.digest_regular_file(
            HERE / "phase1-host-contract.v1.json"
        )
        self.assertEqual(
            record["host_contract"],
            {
                "length": host_length,
                "path": "qualification/clean-host/phase1-host-contract.v1.json",
                "sha256": host_digest,
            },
        )
        self.assertEqual(
            [item["path"] for item in record["contract_inputs"]],
            list(BUNDLE.PHASE1_CONTRACT_INPUT_PATHS),
        )
        ambient = [
            dependency["id"]
            for dependency in record["dependency_inventory"]
            if dependency["classification"] == "undeclared_ambient_dependency"
        ]
        self.assertEqual(ambient, list(BUNDLE.AMBIENT_DEPENDENCIES))
        dependency_classes = {
            dependency["id"]: dependency["classification"]
            for dependency in record["dependency_inventory"]
        }
        for dependency_id, classification in BUNDLE.PHASE1_REQUIRED_DEPENDENCIES:
            self.assertEqual(dependency_classes[dependency_id], classification)
        self.assertEqual(record["known_blockers"], list(BUNDLE.KNOWN_BLOCKERS))
        self.assertEqual(record["source"]["worktree"], "clean")
        self.assertEqual(record["candidate_artifacts"]["accepted"], [])
        self.assertEqual(
            [
                (artifact["path"], artifact["length"], artifact["sha256"])
                for artifact in record["candidate_artifacts"]["rejected"]
            ],
            [
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
            ],
        )
        self.assertEqual(
            [
                receipt
                for receipt in record["receipt_inventory"]
                if receipt["kind"] == "narrative_qualification_only"
            ],
            [
                {
                    "digest": digest,
                    "kind": "narrative_qualification_only",
                    "length": length,
                    "path": path,
                    "schema": "none",
                    "status": status,
                }
                for path, length, digest, status in BUNDLE.PHASE1_NARRATIVE_RECEIPTS
            ],
        )

    def test_phase1_rejects_missing_or_reclassified_ambient_defect(self) -> None:
        record = BUNDLE.load_canonical_json(HERE / "phase1-starting-candidate.v1.json")
        missing_artifact = copy.deepcopy(record)
        missing_artifact["candidate_artifacts"]["rejected"].pop(1)
        self.assert_qualification_error(
            lambda: BUNDLE.validate_phase1_record(missing_artifact)
        )

        first_ambient = next(
            index
            for index, dependency in enumerate(record["dependency_inventory"])
            if dependency["classification"] == "undeclared_ambient_dependency"
        )
        missing = copy.deepcopy(record)
        missing["dependency_inventory"].pop(first_ambient)
        self.assert_qualification_error(lambda: BUNDLE.validate_phase1_record(missing))
        reclassified = copy.deepcopy(record)
        reclassified["dependency_inventory"][first_ambient]["classification"] = (
            "explicitly_documented_operator_prerequisite"
        )
        self.assert_qualification_error(
            lambda: BUNDLE.validate_phase1_record(reclassified)
        )

        missing_required = copy.deepcopy(record)
        missing_required["dependency_inventory"] = [
            dependency
            for dependency in missing_required["dependency_inventory"]
            if dependency["id"] != BUNDLE.PHASE1_REQUIRED_DEPENDENCIES[0][0]
        ]
        self.assert_qualification_error(
            lambda: BUNDLE.validate_phase1_record(missing_required)
        )

        stale_narrative = copy.deepcopy(record)
        narrative = next(
            receipt
            for receipt in stale_narrative["receipt_inventory"]
            if receipt["kind"] == "narrative_qualification_only"
        )
        narrative["digest"] = "sha256:" + "0" * 64
        self.assert_qualification_error(
            lambda: BUNDLE.validate_phase1_record(stale_narrative)
        )


if __name__ == "__main__":
    unittest.main()
