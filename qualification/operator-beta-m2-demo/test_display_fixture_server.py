import pathlib
import socket
import subprocess
import sys
import unittest


SCRIPT = pathlib.Path(__file__).with_name("display_fixture_server.py")


class DisplayFixtureServerTests(unittest.TestCase):
    def test_sigterm_stops_the_server(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "refused", "--port", str(port), "--max-seconds", "30"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertIn("DISPLAY_FIXTURE", process.stdout.readline())
            process.terminate()
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()

    def test_rejects_unbounded_duration(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "refused", "--max-seconds", "7201"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("max-seconds must be in 1..7200", result.stderr)

    def test_rejects_non_tcp_port(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "refused", "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("port must be in 1..65535", result.stderr)


if __name__ == "__main__":
    unittest.main()
