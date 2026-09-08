"""Modern dependency selection controls; does not qualify the cross-office run."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BUILDER = Path(__file__).parent / "velvet-pigeon/build_specimen.py"
PACKET_BUILDER = Path(__file__).parent / "glass-heron/build_packet.py"


class ModernGeneratorBoundary(unittest.TestCase):
    def invoke(self, **settings):
        env = {key: value for key, value in os.environ.items() if key not in (
            "NQ_NG_BIN", "NIGHTSHIFT_BIN", "NIGHTSHIFT_RESOLVER_BIN", "RETIREMENT_SPECIMEN_OUT"
        )}
        env.update(settings)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run([sys.executable, str(BUILDER)], env=env,
                              capture_output=True, timeout=10)

    def test_missing_selection_has_no_classic_fallback(self):
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"RETIREMENT_SPECIMEN_OUT", result.stderr)

    def test_classic_basename_is_refused_before_work(self):
        with tempfile.TemporaryDirectory() as root:
            output = str(Path(root) / "new-output")
            result = self.invoke(RETIREMENT_SPECIMEN_OUT=output,
                                 NQ_NG_BIN="/unavailable/nq-monitor",
                                 NIGHTSHIFT_BIN="/unavailable/nightshift",
                                 NIGHTSHIFT_RESOLVER_BIN="/unavailable/nightshift-observation-resolver")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"modern nq", result.stderr)
            self.assertFalse(Path(output).exists())

    def test_existing_evidence_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as root:
            sentinel = Path(root) / "original"
            sentinel.write_text("retained history")
            result = self.invoke(RETIREMENT_SPECIMEN_OUT=root,
                                 NQ_NG_BIN="/unavailable/nq",
                                 NIGHTSHIFT_BIN="/unavailable/nightshift",
                                 NIGHTSHIFT_RESOLVER_BIN="/unavailable/nightshift-observation-resolver")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sentinel.read_text(), "retained history")


class ModernPacketBoundary(unittest.TestCase):
    def test_fresh_packet_is_bounded_preparation_not_historical_start(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            # Explicit session-shaped fixture, not an enrolled VM session. This
            # exercises packet construction only; it never executes the worker.
            manifest = root / "session.json"
            manifest.write_text(json.dumps({"session_id": "retirement-packet-fixture",
                                            "capacity": 3, "porter": {"commit": "1" * 40}}))
            profile = root / "profile.json"
            profile.write_text("{}")
            output = root / "prepared"
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                       RETIREMENT_PACKET_OUT=str(output),
                       RETIREMENT_SESSION_MANIFEST=str(manifest),
                       RETIREMENT_SESSION_MANIFEST_SHA256="sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                       RETIREMENT_PORTER_PROFILE=str(profile),
                       RETIREMENT_AG_PRODUCER_BIN=sys.executable)
            refusal_env = dict(env, RETIREMENT_SESSION_MANIFEST_SHA256="sha256:" + "0" * 64)
            refusal = subprocess.run([sys.executable, str(PACKET_BUILDER)], env=refusal_env,
                                     capture_output=True, timeout=10)
            self.assertNotEqual(refusal.returncode, 0)
            self.assertIn(b"manifest substitution", refusal.stderr)
            self.assertFalse(output.exists())
            result = subprocess.run([sys.executable, str(PACKET_BUILDER)], env=env,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            packet = json.loads((output / "packet.v1.json").read_bytes())
            self.assertEqual(packet["workspace"], str(output / "fixture"))
            self.assertEqual(len(packet["stages"]), 3)
            for stage in packet["stages"]:
                self.assertEqual(stage["nq_profile_template"]["runtime_schema"],
                                 "nq-ng.campaign-stage-realization-profile/v2")
            preparation = json.loads((output / "packet-preparation.v1.json").read_bytes())
            self.assertIn("human start verification", preparation["does_not_establish"])
            self.assertFalse((output / "verified-human-start-record.v1.json").exists())
            original = (output / "packet.v1.json").read_bytes()
            repeat = subprocess.run([sys.executable, str(PACKET_BUILDER)], env=env,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(repeat.returncode, 0)
            self.assertEqual((output / "packet.v1.json").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
