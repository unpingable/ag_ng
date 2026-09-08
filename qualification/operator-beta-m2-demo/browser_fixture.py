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

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("m2_fixture_demo", ROOT / "crates/ag-operator-ui/demo/fixed_demo.py")
demo = importlib.util.module_from_spec(SPEC)
UI_SOURCE = pathlib.Path(SPEC.origin).read_bytes()
exec(compile(UI_SOURCE, SPEC.origin, "exec"), demo.__dict__)


class Fixture:
    def __init__(self, case):
        self.case, self.starts, self.launches = case, 0, 0
        self.value = {
            "schema": demo.SCHEMA, "scenario": demo.SCENARIO,
            "subject": {"run_id": "DISPLAY_FIXTURE", "spec_sha256": "0" * 64},
            "controller_custody": {"state": "ACCEPTANCE_VALIDATED"},
            "runner_durable": {"state": "collecting_observations", "terminal": None, "recovery": None},
            "liveness": {"state": "PROCESS_EXITED", "source": "DISPLAY_FIXTURE"},
            "execution": {"identity": "DISPLAY_FIXTURE", "model_provider": "NOT_APPLICABLE"},
            "live_sources": {}, "limitations": {"integration": "NOT_RUN", "fixture": True},
            "disagreements": [],
        }
        if case == "launch":
            self.value["controller_custody"]["state"] = "NO_INTENT_RECORDED"
        elif case == "active":
            self.value["liveness"]["state"] = "PROCESS_ACTIVE"
        elif case == "uncertain":
            self.value["controller_custody"]["state"] = "INDETERMINATE"
            self.value["disagreements"] = ["DISPLAY_FIXTURE: launch intent has no retained acceptance"]
        elif case in ("refused", "failed", "success"):
            state = "REFUSED" if case != "success" else "TERMINAL"
            self.value["runner_durable"] = {"state": state, "recovery": None, "terminal": {
                "state": state, "disposition": "DISPLAY_FIXTURE_SUCCESS" if case == "success" else "REFUSED",
                "reason": "DISPLAY_FIXTURE: owner effect failure" if case == "failed" else "DISPLAY_FIXTURE: bounded result",
                "owner": "DISPLAY_FIXTURE", "evidence": "/fixture/RESULT.json" if case == "success" else "/fixture/REFUSAL.json",
                "replay": "DISPLAY_FIXTURE_ONLY",
            }}

    def query(self, operation):
        if self.case == "unavailable":
            raise demo.Unavailable("DISPLAY_FIXTURE unavailable source")
        if operation == "start":
            self.starts += 1
            if self.launches == 0:
                self.launches += 1
                self.value["controller_custody"]["state"] = "ACCEPTANCE_VALIDATED"
        return copy.deepcopy(self.value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["launch", "active", "no-process", "uncertain", "refused", "failed", "success", "unavailable"])
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
