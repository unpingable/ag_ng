#!/usr/bin/python3
"""Focused tests for the dependency-free clean-host guest probe."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "clean_host_guest_probe", HERE / "guest_probe.py"
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class GuestProbeTests(unittest.TestCase):
    def fixture_root(self, parent: Path) -> Path:
        files = {
            "etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
            "var/lib/dpkg/status": (
                "Package: unrelated\nStatus: install ok installed\nVersion: 1\n\n"
                "Package: systemd\nStatus: install ok installed\n"
                "Architecture: amd64\nVersion: 252.38-1~deb12u1\n"
                "Description: system and service manager\n continued text\n"
            ),
            "sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n",
            "proc/self/cgroup": "0::/user.slice/user-1000.slice/session-1.scope\n",
            "proc/self/mountinfo": (
                "22 1 8:1 / / rw,relatime - ext4 /dev/vda1 rw,errors=remount-ro\n"
                "23 22 0:5 / /dev rw,nosuid - devtmpfs udev rw,size=1k\n"
            ),
        }
        root = parent / "guest"
        for relative, payload in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
        return root

    def test_collects_exact_canonical_debian_guest_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture_root(Path(temporary))
            record = PROBE.collect_guest_facts(
                "debian-12-amd64",
                root=root,
                uname_provider=lambda: SimpleNamespace(
                    machine="x86_64", release="6.1.0-37-cloud-amd64"
                ),
                landlock_query=lambda: 4,
            )
            self.assertEqual(
                record,
                {
                    "guest_id": "debian-12-amd64",
                    "observed": {
                        "active_lsms": "lockdown,capability,landlock,yama,apparmor",
                        "architecture": "amd64",
                        "cgroup": "unified-v2:/user.slice/user-1000.slice/session-1.scope",
                        "distribution": "debian",
                        "filesystem": (
                            "ext4 mount_options=rw,relatime source=/dev/vda1 "
                            "super_options=rw,errors=remount-ro"
                        ),
                        "kernel": "6.1.0-37-cloud-amd64",
                        "landlock_abi": "4",
                        "release": "12",
                        "systemd": "252.38-1~deb12u1",
                    },
                    "schema": "ag.clean-host-guest-facts/v1",
                },
            )
            encoded = PROBE.canonical_json_bytes(record)
            self.assertEqual(
                encoded,
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                + b"\n",
            )

    def test_maps_aarch64_to_arm64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture_root(Path(temporary))
            record = PROBE.collect_guest_facts(
                "debian-12-arm64",
                root=root,
                uname_provider=lambda: SimpleNamespace(
                    machine="aarch64", release="6.1.0-arm64"
                ),
                landlock_query=lambda: 3,
            )
            self.assertEqual(record["observed"]["architecture"], "arm64")

    def test_parses_quoted_os_release_and_rejects_duplicate_or_shell_syntax(
        self,
    ) -> None:
        self.assertEqual(
            PROBE.parse_os_release('ID="debian"\nVERSION_ID="12\\$stable"\n'),
            {"ID": "debian", "VERSION_ID": "12$stable"},
        )
        for payload in (
            "ID=debian\nID=ubuntu\nVERSION_ID=12\n",
            "ID=$(uname)\nVERSION_ID=12\n",
            'ID="debian\nVERSION_ID=12\n',
            "ID=debian\n",
        ):
            with self.subTest(payload=payload), self.assertRaises(PROBE.ProbeError):
                PROBE.parse_os_release(payload)

    def test_dpkg_status_requires_one_installed_systemd_with_version(self) -> None:
        self.assertEqual(
            PROBE.parse_dpkg_status(
                "Package: systemd\nStatus: install ok installed\nVersion: 252.1-1\n"
            ),
            "252.1-1",
        )
        invalid = (
            "Package: systemd\nStatus: deinstall ok config-files\nVersion: 252\n",
            "Package: systemd\nStatus: install ok installed\n",
            " Continuation without a field\n",
            "Package systemd\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(PROBE.ProbeError):
                PROBE.parse_dpkg_status(payload)

    def test_cgroup_and_mountinfo_are_strict(self) -> None:
        self.assertEqual(PROBE.parse_cgroup("0::/\n"), "unified-v2:/")
        self.assertEqual(
            PROBE.parse_cgroup("2:cpu,cpuacct:/work\n0::/work\n"),
            "legacy-or-hybrid:2:cpu,cpuacct:/work;0::/work",
        )
        self.assertEqual(
            PROBE.parse_root_filesystem(
                "1 0 8:1 / / rw - ext4 /dev/disk\\040name rw\n"
            ),
            "ext4 mount_options=rw source=/dev/disk name super_options=rw",
        )
        for payload in ("", "0:/missing-field\n", "0::relative\n", "0::/\n0::/again\n"):
            with self.subTest(payload=payload), self.assertRaises(PROBE.ProbeError):
                PROBE.parse_cgroup(payload)
        for payload in (
            "1 0 8:1 / / rw ext4 /dev/vda rw\n",
            "1 0 8:1 / / rw - ext4 /dev/vda rw\n2 0 8:2 / / ro - ext4 /dev/vdb ro\n",
            "1 0 8:1 / / rw - ext4 /dev\\999 rw\n",
        ):
            with self.subTest(payload=payload), self.assertRaises(PROBE.ProbeError):
                PROBE.parse_root_filesystem(payload)

    def test_missing_malformed_and_unsupported_evidence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.fixture_root(Path(temporary))
            (root / "sys/kernel/security/lsm").unlink()
            with self.assertRaisesRegex(
                PROBE.ProbeError, "cannot read required evidence"
            ):
                PROBE.collect_guest_facts(
                    "debian-12-amd64",
                    root=root,
                    uname_provider=lambda: SimpleNamespace(
                        machine="x86_64", release="6.1"
                    ),
                    landlock_query=lambda: 3,
                )
            with self.assertRaisesRegex(PROBE.ProbeError, "unsupported machine"):
                PROBE.collect_guest_facts(
                    "debian-12-riscv64",
                    root=self.fixture_root(Path(temporary) / "other"),
                    uname_provider=lambda: SimpleNamespace(
                        machine="riscv64", release="6.1"
                    ),
                    landlock_query=lambda: 3,
                )

    def test_landlock_query_uses_syscall_444_and_version_flag(self) -> None:
        calls: list[tuple[int, int | None, int, int]] = []

        class FakeSyscall:
            restype = None

            def __call__(self, number, attribute, size, flags):
                calls.append((number.value, attribute.value, size.value, flags.value))
                return 5

        class FakeLibc:
            syscall = FakeSyscall()

        original = PROBE.ctypes.CDLL
        PROBE.ctypes.CDLL = lambda name, use_errno: FakeLibc()
        try:
            self.assertEqual(PROBE.query_landlock_abi(), 5)
        finally:
            PROBE.ctypes.CDLL = original
        self.assertEqual(calls, [(444, None, 0, 1)])

    def test_source_has_no_subprocess_dependency(self) -> None:
        source = (HERE / "guest_probe.py").read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("os.system", source)


if __name__ == "__main__":
    unittest.main()
