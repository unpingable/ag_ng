#!/usr/bin/python3
"""Golden, hostile, and deadline tests for the clean-VM fixture helper."""

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "clean_host_vm_fixture", HERE / "vm_fixture.py"
)
assert SPEC is not None and SPEC.loader is not None
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def public_key(key_type: str = "ssh-ed25519") -> str:
    encoded_type = key_type.encode("ascii")
    wire = (
        struct.pack(">I", len(encoded_type))
        + encoded_type
        + b"fixture-public-key-payload"
    )
    return f"{key_type} {base64.b64encode(wire).decode('ascii')} local comment\n"


class FakeClock:
    def __init__(
        self,
        nanoseconds: int = 1_000_000_000,
        boot_id: str = "11111111-2222-3333-4444-555555555555",
    ) -> None:
        self.nanoseconds = nanoseconds
        self._boot_id = boot_id
        self.base = dt.datetime(2026, 7, 20, 12, 0, tzinfo=dt.timezone.utc)

    def now_ns(self) -> int:
        return self.nanoseconds

    def utc_now(self) -> dt.datetime:
        return self.base + dt.timedelta(microseconds=self.nanoseconds // 1000)

    def sleep(self, seconds: float) -> None:
        self.nanoseconds += round(seconds * 1_000_000_000)

    def boot_id(self) -> str:
        return self._boot_id


class VmFixtureTests(unittest.TestCase):
    def assert_fixture_error(self, callback) -> None:
        with self.assertRaises(FIXTURE.FixtureError):
            callback()

    def test_nocloud_golden_output_is_deterministic_and_drops_key_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "fixture.pub"
            key.write_text(public_key(), encoding="ascii")
            output = root / "seed"
            record = FIXTURE.render_nocloud(
                output,
                instance_id="agq-debian-12-amd64",
                hostname="agq-debian-12-amd64",
                username="agqual",
                authorized_key_file=key,
            )
            normalized_key = public_key().split(" local comment", 1)[0]
            self.assertEqual(
                (output / "meta-data").read_text(encoding="utf-8"),
                'instance-id: "agq-debian-12-amd64"\n'
                'local-hostname: "agq-debian-12-amd64"\n',
            )
            self.assertEqual(
                (output / "user-data").read_text(encoding="utf-8"),
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
                f"      - {json.dumps(normalized_key)}\n",
            )
            self.assertFalse(record["private_key_copied"])
            self.assertEqual(
                (output / "fixture.v1.json").read_bytes(),
                FIXTURE.canonical_json_bytes(record),
            )
            self.assertNotIn(b"local comment", (output / "user-data").read_bytes())

    def test_nocloud_rejects_private_key_and_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "id"
            private.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n", encoding="ascii"
            )
            self.assert_fixture_error(
                lambda: FIXTURE.render_nocloud(
                    root / "private-seed",
                    instance_id="fixture",
                    hostname="fixture",
                    username="agqual",
                    authorized_key_file=private,
                )
            )
            key = root / "fixture.pub"
            key.write_text(public_key(), encoding="ascii")
            self.assert_fixture_error(
                lambda: FIXTURE.render_nocloud(
                    root / "injected-seed",
                    instance_id="fixture",
                    hostname="fixture\nusers: []",
                    username="agqual",
                    authorized_key_file=key,
                )
            )

    def test_nocloud_refuses_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "fixture.pub"
            key.write_text(public_key(), encoding="ascii")
            output = root / "seed"
            output.mkdir()
            self.assert_fixture_error(
                lambda: FIXTURE.render_nocloud(
                    output,
                    instance_id="fixture",
                    hostname="fixture",
                    username="agqual",
                    authorized_key_file=key,
                )
            )

    def test_readiness_records_refusal_then_exact_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "id"
            identity.write_bytes(b"not-copied-private-test-placeholder")
            clock = FakeClock()
            tcp_outcomes = iter((("connection_refused", 111), ("connected", None)))

            def tcp_probe(host: str, port: int, timeout: float):
                self.assertEqual((host, port), ("127.0.0.1", 2222))
                self.assertGreater(timeout, 0)
                clock.nanoseconds += 10_000_000
                return next(tcp_outcomes)

            def ssh_runner(executable: Path, argv: list[str], timeout: float):
                self.assertEqual(executable, Path("/usr/bin/ssh"))
                self.assertIn("agqual@127.0.0.1", argv)
                for index, argument in enumerate(argv[:-1]):
                    if argument == "-o":
                        self.assertNotEqual(argv[index + 1], "-o")
                self.assertEqual(argv[-1], "/usr/bin/true")
                self.assertGreater(timeout, 0)
                clock.nanoseconds += 20_000_000
                return {
                    "executable": {
                        "length": 1,
                        "path": "/usr/bin/ssh",
                        "sha256": "sha256:" + "0" * 64,
                    },
                    "exit_code": 0,
                    "outcome": "exit",
                    "stderr": FIXTURE._stream_record(b""),
                    "stdout": FIXTURE._stream_record(b"ready\n"),
                }

            record, ready = FIXTURE.wait_for_ssh(
                host="127.0.0.1",
                port=2222,
                username="agqual",
                identity_file=identity,
                known_hosts_file=root / "known_hosts",
                ssh_executable=Path("/usr/bin/ssh"),
                remote_argv=("/usr/bin/true",),
                timeout_seconds=5,
                poll_interval_ms=100,
                connect_timeout_ms=500,
                ssh_attempt_timeout_seconds=2,
                clock=clock,
                tcp_probe=tcp_probe,
                ssh_runner=ssh_runner,
            )
            self.assertTrue(ready)
            self.assertEqual(record["result"], "ready")
            self.assertEqual(record["rendered_remote_command"], "/usr/bin/true")
            self.assertIsNotNone(record["identity_file"])
            self.assertEqual(
                [attempt["tcp"]["outcome"] for attempt in record["attempts"]],
                ["connection_refused", "connected"],
            )
            self.assertIsNone(record["attempts"][0]["ssh"])
            self.assertEqual(record["attempts"][1]["ssh"]["outcome"], "exit")
            self.assertEqual(
                FIXTURE.canonical_json_bytes(record),
                FIXTURE.canonical_json_bytes(
                    json.loads(FIXTURE.canonical_json_bytes(record))
                ),
            )

    def test_readiness_stops_at_monotonic_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "id"
            identity.write_bytes(b"placeholder")
            clock = FakeClock()

            def tcp_probe(_host: str, _port: int, _timeout: float):
                return "connection_refused", 111

            record, ready = FIXTURE.wait_for_ssh(
                host="127.0.0.1",
                port=2222,
                username="agqual",
                identity_file=identity,
                known_hosts_file=root / "known_hosts",
                ssh_executable=Path("/usr/bin/ssh"),
                remote_argv=("/usr/bin/true",),
                timeout_seconds=1,
                poll_interval_ms=250,
                connect_timeout_ms=100,
                ssh_attempt_timeout_seconds=1,
                clock=clock,
                tcp_probe=tcp_probe,
                ssh_runner=lambda *_args: self.fail("SSH must not run"),
            )
            self.assertFalse(ready)
            self.assertEqual(record["result"], "deadline_exhausted")
            self.assertEqual(record["duration_ms"], 1000)
            self.assertEqual(len(record["attempts"]), 4)

    class FakeQmpConnection:
        def __init__(self, messages: list[dict]) -> None:
            self.messages = iter(messages)
            self.sent: list[dict] = []
            self.closed = False

        def receive(self) -> dict:
            return next(self.messages)

        def send(self, value: dict) -> None:
            self.sent.append(value)

        def close(self) -> None:
            self.closed = True

    def test_qmp_query_status_system_powerdown_and_quit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            query_socket = root / "query.sock"
            query_connection = self.FakeQmpConnection(
                [
                    {"QMP": {"capabilities": [], "version": {}}},
                    {"id": "ag-ng-capabilities", "return": {}},
                    {
                        "id": "ag-ng-command",
                        "return": {
                            "running": True,
                            "singlestep": False,
                            "status": "running",
                        },
                    },
                ]
            )
            record, success = FIXTURE.qmp_operation(
                query_socket,
                "query-status",
                2,
                connection_factory=lambda _path, _timeout: query_connection,
            )
            self.assertTrue(success)
            self.assertEqual(record["response"]["return"]["status"], "running")
            self.assertEqual(query_connection.sent[0]["execute"], "qmp_capabilities")
            self.assertEqual(query_connection.sent[1]["execute"], "query-status")
            self.assertTrue(query_connection.closed)

            power_socket = root / "power.sock"
            power_connection = self.FakeQmpConnection(
                [
                    {"QMP": {}},
                    {"id": "ag-ng-capabilities", "return": {}},
                    {"id": "ag-ng-command", "return": {}},
                ]
            )
            record, success = FIXTURE.qmp_operation(
                power_socket,
                "system-powerdown",
                2,
                connection_factory=lambda _path, _timeout: power_connection,
            )
            self.assertTrue(success)
            self.assertEqual(record["operation"], "system-powerdown")
            self.assertEqual(power_connection.sent[1]["execute"], "system_powerdown")

            quit_socket = root / "quit.sock"
            quit_connection = self.FakeQmpConnection(
                [
                    {"QMP": {}},
                    {"id": "ag-ng-capabilities", "return": {}},
                    {"id": "ag-ng-command", "return": {}},
                ]
            )
            record, success = FIXTURE.qmp_operation(
                quit_socket,
                "quit",
                2,
                connection_factory=lambda _path, _timeout: quit_connection,
            )
            self.assertTrue(success)
            self.assertEqual(record["operation"], "quit")
            self.assertEqual(quit_connection.sent[1]["execute"], "quit")

            class ClosingAfterQuit(self.FakeQmpConnection):
                def receive(self) -> dict:
                    try:
                        return super().receive()
                    except StopIteration as error:
                        raise FIXTURE.FixtureError(
                            "QMP: peer closed before a complete response"
                        ) from error

            closing_connection = ClosingAfterQuit(
                [
                    {"QMP": {}},
                    {"id": "ag-ng-capabilities", "return": {}},
                ]
            )
            record, success = FIXTURE.qmp_operation(
                root / "closing.sock",
                "quit",
                2,
                connection_factory=lambda _path, _timeout: closing_connection,
            )
            self.assertTrue(success)
            self.assertEqual(record["outcome"], "accepted")
            self.assertEqual(
                record["response"],
                {"accepted_without_reply": "peer_closed_after_quit_request"},
            )

    def test_qmp_rejects_wrong_reply_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "bad.sock"
            connection = self.FakeQmpConnection(
                [{"QMP": {}}, {"id": "wrong", "return": {}}]
            )
            self.assert_fixture_error(
                lambda: FIXTURE.qmp_operation(
                    socket_path,
                    "query-status",
                    2,
                    connection_factory=lambda _path, _timeout: connection,
                )
            )
            self.assertTrue(connection.closed)

    def test_qmp_missing_socket_is_a_typed_transport_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, success = FIXTURE.qmp_operation(
                Path(temporary) / "missing.sock", "query-status", 1
            )
            self.assertFalse(success)
            self.assertEqual(record["outcome"], "transport_error")
            self.assertIn(
                record["response"]["error"]["class"],
                {"FileNotFoundError", "PermissionError"},
            )

    def test_qmp_cli_reserves_output_before_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "result.json"
            output.write_bytes(b"preexisting\n")
            result = FIXTURE.main(
                [
                    "qmp",
                    "--output",
                    str(output),
                    "--socket",
                    str(root / "missing.sock"),
                    "--operation",
                    "system-powerdown",
                ]
            )
            self.assertEqual(result, 2)
            self.assertEqual(output.read_bytes(), b"preexisting\n")

    def test_case_records_bind_frozen_deadline_and_exact_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            clock = FakeClock()
            start, deadline = FIXTURE.start_case(
                state, "debian-12-amd64", "fresh_install_and_reboot", clock
            )
            self.assertEqual(deadline["deadline_seconds"], 1800)
            self.assertEqual(
                deadline["deadline_boottime_ns"],
                start["started_boottime_ns"] + 1_800_000_000_000,
            )
            clock.nanoseconds = deadline["deadline_boottime_ns"]
            check, within = FIXTURE.check_case(state, clock)
            self.assertTrue(within)
            self.assertEqual(check["remaining_ns"], 0)
            finish, within = FIXTURE.finish_case(
                state, "pass", "completed at exact boundary", clock
            )
            self.assertTrue(within)
            self.assertTrue(finish["within_deadline"])
            self.assertEqual(finish["effective_result"], "pass")
            self.assertEqual(
                (state / "case-finish.v1.json").read_bytes(),
                FIXTURE.canonical_json_bytes(finish),
            )

    def test_late_case_persists_deadline_failure_and_cannot_refinish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            clock = FakeClock()
            _start, deadline = FIXTURE.start_case(
                state, "debian-12-amd64", "package_build_and_payload", clock
            )
            clock.nanoseconds = deadline["deadline_boottime_ns"] + 1
            check, within = FIXTURE.check_case(state, clock)
            self.assertFalse(within)
            self.assertEqual(check["status"], "deadline_exceeded")
            finish, within = FIXTURE.finish_case(
                state, "pass", "late completion", clock
            )
            self.assertFalse(within)
            self.assertEqual(finish["requested_result"], "pass")
            self.assertEqual(finish["effective_result"], "deadline_exceeded")
            self.assert_fixture_error(
                lambda: FIXTURE.finish_case(state, "fail", "second finish", clock)
            )

    def test_case_timing_rejects_reboot_and_tampered_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            clock = FakeClock()
            FIXTURE.start_case(
                state, "debian-12-amd64", "hostile_target_and_store", clock
            )
            rebooted = FakeClock(boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            self.assert_fixture_error(lambda: FIXTURE.check_case(state, rebooted))

            deadline_path = state / "case-deadline.v1.json"
            deadline = json.loads(deadline_path.read_bytes())
            deadline["deadline_seconds"] = 1801
            deadline_path.write_bytes(FIXTURE.canonical_json_bytes(deadline))
            self.assert_fixture_error(lambda: FIXTURE.check_case(state, clock))

    def test_source_never_uses_shell_or_launches_qemu(self) -> None:
        source = (HERE / "vm_fixture.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("qemu-system", source)


if __name__ == "__main__":
    unittest.main()
