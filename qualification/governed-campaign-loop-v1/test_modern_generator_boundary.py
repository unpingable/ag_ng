"""Modern dependency selection controls; does not qualify the cross-office run."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BUILDER = Path(__file__).parent / "velvet-pigeon/build_specimen.py"


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


if __name__ == "__main__":
    unittest.main()
