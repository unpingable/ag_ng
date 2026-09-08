#!/usr/bin/env python3
"""Bounded display fixture: every status read advances phase; no real producer."""
import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import threading

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("transition_fixture", HERE / "browser_fixture.py")
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
demo = fixture_module.demo


class AdvancingFixture(fixture_module.Fixture):
    def __init__(self):
        super().__init__("active")
        self.reads = 0

    def query(self, operation):
        assert operation == "status", "observation-only fixture never permits RUN"
        self.reads += 1
        phase = "fixture_phase_" + str(self.reads)
        self.value["runner_durable"].update(state=phase, recovery={"state": "REOPENED", "phase": phase,
            "last_completed_phase": "fixture_prior", "next_lawful_action": "observe fixture only",
            "effect_outcome": "NOT_OBSERVABLE", "producer": {"systemd_unit": "fixture.service",
            "invocation_id": "0" * 32, "main_pid": 1234, "start_ticks": 10}})
        demo.validate_projection(self.value)
        return copy.deepcopy(self.value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--mismatch", action="store_true")
    args = parser.parse_args()
    if args.mismatch:
        original = "text('durable',runner.state)"
        assert original in demo.PAGE
        demo.PAGE = demo.PAGE.replace(original, "text('durable','DISPLAY_FIXTURE_INCORRECT_PHASE')")
    fixture = AdvancingFixture()
    server = demo.DemoServer(("127.0.0.1", 0), fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(["node", str(HERE / "browser_exercise.cjs"), "--url", server.origin + "/",
            "--out", str(args.out), "--mode", "DISPLAY_FIXTURE", "--action", "observe", "--max-seconds", "30"],
            timeout=40, check=False)
        if args.mismatch:
            assert result.returncode != 0
            record = json.loads((args.out / "CAPTURE-FAILED.json").read_text())
            assert "No browser response matches" in record["reason"]
        else:
            assert result.returncode == 0
            records = [json.loads(path.read_text()) for path in sorted(args.out.glob("*.status.json"))]
            assert len(records) >= 3
            assert len({item["runner_durable"]["state"] for item in records}) == len(records)
        record = {"mode": "DISPLAY_FIXTURE", "state": "TRANSITION_CONTROL_PASSED", "mismatch": args.mismatch,
            "reads": fixture.reads, "start_requests": fixture.starts, "integration": "NOT_RUN",
            "ui_sha256": hashlib.sha256(fixture_module.UI_SOURCE).hexdigest(),
            "fixture_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
        with (args.out / "TRANSITION-CONTROL.json").open("x") as output:
            json.dump(record, output, sort_keys=True)
            output.write("\n")
        print(json.dumps(record, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
