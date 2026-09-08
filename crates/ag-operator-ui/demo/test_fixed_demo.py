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

import fixed_demo as demo


def projection():
    return {
        "schema": demo.SCHEMA, "scenario": demo.SCENARIO,
        "subject": {"run_id": "LABELED_LOCAL_FIXTURE"},
        "controller_custody": {"state": "NO_INTENT_RECORDED"},
        "runner_durable": {"state": "NOT_OBSERVABLE", "terminal": None, "recovery": None},
        "liveness": {"state": "PROCESS_EXITED", "source": "LOCAL_FIXTURE"},
        "execution": {"identity": "LABELED_LOCAL_FIXTURE"},
        "live_sources": {}, "limitations": {"integration": "NOT_RUN"},
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
