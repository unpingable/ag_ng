"""Local adapter fixtures only; these tests do not qualify composed execution."""
import copy
import hashlib
import http.client
import json
import pathlib
import tempfile
import threading
import unittest
import urllib.parse
import time
from unittest import mock

import fixed_demo as demo


def projection():
    return {
        "schema": demo.SCHEMA, "scenario": demo.SCENARIO,
        "subject": {"run_id": "LABELED_LOCAL_FIXTURE", "spec_sha256": "0" * 64},
        "controller_custody": {"source": "Docket fixed controller", "state": "NO_INTENT_RECORDED"},
        "runner_durable": {"source": "composition owner records", "state": "NOT_OBSERVABLE", "terminal": None, "recovery": None},
        "liveness": {"state": "PROCESS_EXITED", "source": "user-systemd", "main_pid": 0},
        "execution": {"identity": "BOUNDED_COMPOSITION_RUNNER", "model_provider": "NOT_APPLICABLE",
                      "producer_subject": "0" * 40, **{key: "0" * 64 for key in
                      ("producer_sha256", "checker_sha256", "controller_sha256", "code_capsule_sha256")}},
        "live_sources": {key: {"state": "NOT_OBSERVABLE", "source": source, "reason": "LABELED_LOCAL_FIXTURE"}
                         for key, source in (("manager", "user-systemd"), ("os", "OS process table"))},
        "limitations": {"aggregate_postcondition": "NOT_RECORDED", "literal_distributed_exactly_once": "NOT_CLAIMED",
                        "signed_upstream_checksum": "NOT_QUALIFIED", "deployment": "NOT_RUN", "production": "NOT_RUN"},
        "evidence": [{"source": "Docket", "label": "LABELED_LOCAL_FIXTURE evidence", "evidence": "/fixture/RESULT.json", "state": "MISSING"}],
        "disagreements": [],
    }


class FixtureController:
    def __init__(self):
        self.value = projection()
        self.calls = []
        self.launches = 0
        self.unavailable = False

    def query(self, operation):
        self.calls.append(operation)
        if self.unavailable:
            raise demo.Unavailable("LOCAL_FIXTURE unavailable")
        if operation == "start" and self.launches == 0:
            self.launches += 1
            self.value["controller_custody"]["state"] = "ACCEPTANCE_VALIDATED"
        return copy.deepcopy(self.value)


class HttpBoundary(unittest.TestCase):
    def setUp(self):
        self.controller = FixtureController()
        self.server = demo.DemoServer(("127.0.0.1", 0), self.controller)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host = self.server.origin.removeprefix("http://")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def run_form(self):
        return self.request("POST", "/run", urllib.parse.urlencode({"token": self.server.token}),
                            {"Origin": self.server.origin})

    def test_screen_and_head_never_start(self):
        self.assertIn(b"Investigate", self.request("GET", "/")[2])
        self.assertEqual(self.request("HEAD", "/")[2], b"")
        self.assertEqual(self.controller.calls, [])

    def test_refresh_and_reconnect_reopen_status(self):
        for _ in range(3):
            self.assertEqual(self.request("GET", "/api/v1/status")[0], 200)
        self.assertEqual(self.controller.calls, ["status"] * 3)

    def test_repeated_run_delegates_same_owner_occurrence(self):
        for _ in range(2):
            status, headers, _ = self.run_form()
            self.assertEqual((status, headers["Location"]), (303, "/"))
        self.assertEqual(self.controller.calls, ["start", "start"])
        self.assertEqual(self.controller.launches, 1)

    def test_refused_is_normal_authoritative_response(self):
        self.controller.value["runner_durable"] = {
            "state": "REFUSED", "terminal": {"state": "REFUSED", "owner": "Docket", "evidence": "/fixture/REFUSAL.json"}}
        status, _, raw = self.request("GET", "/api/v1/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), self.controller.value)

    def test_phase_and_liveness_remain_independent(self):
        self.controller.value["runner_durable"]["state"] = "collecting_observations"
        self.controller.value["liveness"]["state"] = "PROCESS_EXITED"
        value = json.loads(self.request("GET", "/api/v1/status")[2])
        self.assertEqual(value["runner_durable"]["state"], "collecting_observations")
        self.assertEqual(value["liveness"]["state"], "PROCESS_EXITED")

    def test_terminal_and_disagreement_both_survive(self):
        self.controller.value["runner_durable"]["terminal"] = {"state": "TERMINAL", "disposition": "BOUNDED_FIXTURE"}
        self.controller.value["disagreements"] = ["missing acceptance"]
        self.assertEqual(json.loads(self.request("GET", "/api/v1/status")[2]), self.controller.value)

    def test_unavailability_never_becomes_completion(self):
        self.controller.unavailable = True
        status, _, raw = self.request("GET", "/api/v1/status")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["state"], "NOT_OBSERVABLE")
        status, headers, _ = self.run_form()
        self.assertEqual((status, headers["Location"]), (303, "/?launch=unconfirmed"))
        self.assertEqual(self.controller.calls, ["status", "start"])

    def test_no_browser_selectors_or_foreign_origin(self):
        cases = [({"Origin": "http://elsewhere"}, "token=" + self.server.token),
                 ({"Origin": self.server.origin}, "token=" + self.server.token + "&run_id=another"),
                 ({"Origin": self.server.origin}, "token=wrong")]
        for headers, body in cases:
            self.assertIn(self.request("POST", "/run", body, headers)[0], (400, 403))
        self.assertEqual(self.controller.calls, [])

    def test_get_run_and_unknown_actions_do_not_execute(self):
        for method, path in [("GET", "/run"), ("POST", "/restart"), ("GET", "/?run=1")]:
            self.assertEqual(self.request(method, path)[0], 404)
        self.assertEqual(self.controller.calls, [])

    def test_unexpected_host_refuses(self):
        self.assertEqual(self.request("GET", "/", headers={"Host": "elsewhere"})[0], 400)


class SourceAdmission(unittest.TestCase):
    def test_refusal_owner_is_distinct_from_validator(self):
        value = projection()
        value["runner_durable"].update(state="REFUSED", terminal={"state": "REFUSED", "disposition": "REFUSED",
            "owner": "NQ-ng", "validator": "Docket", "evidence": "/fixture/REFUSAL.json", "replay": "check-refusal"})
        demo.validate_projection(value)
        value["runner_durable"]["terminal"]["owner"] = "Docket"
        with self.assertRaises(ValueError):
            demo.validate_projection(value)

    def test_execution_reports_retained_source_digest(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "fixture.py"
            raw = ("import json\nv=" + repr(projection()) + "\nv['execution']['controller_sha256']=__executed_source_sha256__\nprint(json.dumps(v))\n").encode()
            path.write_bytes(raw)
            admitted = hashlib.sha256(raw).hexdigest()
            controller = demo.Controller(path, admitted)
            path.write_text("raise RuntimeError('replacement must never execute')")
            self.assertEqual(controller.query("status")["execution"]["controller_sha256"], admitted)

    def test_projection_structure_is_closed_at_consumed_fields(self):
        demo.validate_projection(projection())
        mutations = [lambda v: v.update(subject={}), lambda v: v.pop("evidence"),
                     lambda v: v.update(execution={}), lambda v: v["controller_custody"].update(state="READY_BUT_INVENTED"),
                     lambda v: v["runner_durable"].update(state="TERMINAL", terminal={"state": "TERMINAL"}),
                     lambda v: v["liveness"].update(state="PROCESS_ACTIVE"),
                     lambda v: v["live_sources"].clear(), lambda v: v["evidence"][0].update(state="ACCEPTED_BY_UI"),
                     lambda v: v["runner_durable"].update(state="made_up"), lambda v: v.update(limitations={})]
        for change in mutations:
            with self.subTest(change=change):
                value = projection()
                change(value)
                with self.assertRaises(ValueError):
                    demo.validate_projection(value)

    def test_child_not_reading_input_is_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "fixture.py"
            raw = b"#" + b"x" * (256 * 1024)
            path.write_bytes(raw)
            controller = demo.Controller(path, hashlib.sha256(raw).hexdigest())
            started = time.monotonic()
            with mock.patch.object(demo, "BOOTSTRAP", "import time; time.sleep(60)"), mock.patch.object(demo, "OWNER_TIMEOUT_SECONDS", 0.15):
                with self.assertRaises(demo.Unavailable):
                    controller.query("status")
            self.assertLess(time.monotonic() - started, 2)

    def test_retained_controller_bytes_survive_path_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "fixture.py"
            raw = ("import json\nprint(" + repr(json.dumps(projection())) + ")\n").encode()
            path.write_bytes(raw)
            controller = demo.Controller(path, hashlib.sha256(raw).hexdigest())
            path.write_text("raise RuntimeError('replacement must never execute')")
            self.assertEqual(controller.query("status"), projection())

    def test_wrong_digest_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "fixture.py"
            path.write_text("pass")
            with self.assertRaises(ValueError):
                demo.Controller(path, "0" * 64)
            link = pathlib.Path(root) / "link.py"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                demo.Controller(link, hashlib.sha256(b"pass").hexdigest())

    def test_transport_exit_is_not_success(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "fixture.py"
            raw = b"print('worker finished')\n"
            path.write_bytes(raw)
            controller = demo.Controller(path, hashlib.sha256(raw).hexdigest())
            with self.assertRaises(demo.Unavailable):
                controller.query("status")

    def test_duplicate_fields_refuse(self):
        with self.assertRaises(ValueError):
            json.loads('{"state":"one","state":"two"}', object_pairs_hook=demo.unique_object)

    def test_nonloopback_refuses(self):
        with self.assertRaises(ValueError):
            demo.DemoServer(("0.0.0.0", 0), FixtureController())


if __name__ == "__main__":
    unittest.main()
