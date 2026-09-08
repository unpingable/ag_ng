#!/usr/bin/env python3
"""One bounded DISPLAY_FIXTURE browser case; never loads the Docket controller."""
import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import threading
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m2_fixture_demo", ROOT / "crates/ag-operator-ui/demo/fixed_demo.py")
demo = importlib.util.module_from_spec(SPEC)
UI_SOURCE = pathlib.Path(SPEC.origin).read_bytes()
exec(compile(UI_SOURCE, SPEC.origin, "exec"), demo.__dict__)
sys.path.insert(0, str(ROOT / "crates/ag-operator-ui/demo"))
from test_fixed_demo import projection


class Fixture:
    def __init__(self, case):
        self.case, self.starts, self.launches = case, 0, 0
        self.value = projection()
        self.value["controller_custody"]["state"] = "ACCEPTANCE_VALIDATED"
        self.outage, self.timer = False, None
        if case == "launch":
            self.value["controller_custody"]["state"] = "NO_INTENT_RECORDED"
        elif case == "active":
            self.value["liveness"].update(state="PROCESS_ACTIVE", main_pid=1234, start_ticks=10,
                                          invocation_id="0" * 32, execution_sha256="0" * 64, execution_matches=True)
        elif case == "uncertain":
            self.value["controller_custody"]["state"] = "INDETERMINATE"
            self.value["disagreements"] = ["DISPLAY_FIXTURE: launch intent has no retained acceptance"]
        elif case in ("refused", "failed", "success", "outage"):
            state = "REFUSED" if case in ("refused", "failed") else "TERMINAL"
            self.value["runner_durable"] = {"source": "composition owner records", "state": state, "recovery": None, "terminal": {
                "state": state, "disposition": "ONE_SPEND_ONE_ATTEMPT_BOUNDED_EFFECT_CUSTODY_WITH_DECLARED_LIMITATIONS" if state == "TERMINAL" else "REFUSED",
                "reason": "DISPLAY_FIXTURE: owner effect failure" if case == "failed" else "DISPLAY_FIXTURE: bounded result",
                "owner": "Docket", "evidence": "/fixture/RESULT.json" if state == "TERMINAL" else "/fixture/REFUSAL.json",
                "replay": "check-run" if state == "TERMINAL" else "check-refusal",
            }}

    def query(self, operation):
        if self.case == "unavailable" or self.outage:
            raise demo.Unavailable("DISPLAY_FIXTURE unavailable source")
        if self.case == "outage" and self.timer is None:
            self.timer = threading.Timer(2, lambda: setattr(self, "outage", True))
            self.timer.start()
        if operation == "start":
            self.starts += 1
            if self.launches == 0:
                self.launches += 1
                self.value["controller_custody"]["state"] = "ACCEPTANCE_VALIDATED"
        demo.validate_projection(self.value)
        return copy.deepcopy(self.value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["launch", "active", "no-process", "uncertain", "refused", "failed", "success", "unavailable", "outage"])
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.case)
    server = demo.DemoServer(("127.0.0.1", 0), fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = ["node", str(pathlib.Path(__file__).with_name("browser_exercise.cjs")),
               "--url", server.origin + "/", "--out", str(args.out), "--mode", "DISPLAY_FIXTURE", "--max-seconds", "35"]
    if args.case == "launch":
        command += ["--action", "launch", "--repeat-run"]
    if args.case == "outage":
        command += ["--expect-outage-after-good"]
    if args.case != "unavailable":
        command += ["--expect-state", fixture.value["runner_durable"]["state"],
                    "--expect-live", fixture.value["liveness"]["state"]]
    try:
        result = subprocess.run(command, timeout=45, check=False)
        with (args.out / "FIXTURE-SOURCES.json").open("x") as output:
            json.dump({"mode": "DISPLAY_FIXTURE", "case": args.case,
                       "ui_source_sha256": hashlib.sha256(UI_SOURCE).hexdigest(),
                       "fixture_source_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                       "start_requests": fixture.starts, "fixture_launches": fixture.launches,
                       "integration": "NOT_RUN"}, output, sort_keys=True)
            output.write("\n")
        if args.case == "unavailable":
            assert result.returncode != 0
            record = json.loads((args.out / "CAPTURE-FAILED.json").read_text())
            assert "Owner projection unavailable" in record["reason"]
        else:
            assert result.returncode == 0
        if args.case == "launch":
            assert fixture.starts == 3 and fixture.launches == 1
        else:
            assert fixture.starts == 0
        print(json.dumps({"case": args.case, "state": "DISPLAY_FIXTURE_BROWSER_CHECK_PASSED", "start_calls": fixture.starts,
                          "fixture_launches": fixture.launches, "integration": "NOT_RUN", "capture": str(args.out)}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
