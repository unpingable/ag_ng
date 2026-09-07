import json
import pathlib
import subprocess
import unittest

from jsonschema import Draft202012Validator, ValidationError

ROOT = pathlib.Path(__file__).resolve().parent


def digest(char: str) -> str:
    return "sha256:" + char * 64


def load(name: str):
    return json.loads((ROOT / name).read_text())


def beta_plan():
    return {
        "schema": "ag-effectd.docket-executor-systemd-plan/v2",
        "attempt_store": "/var/lib/ag/effect-attempts.sqlite3",
        "subject": digest("1"),
        "scope": digest("2"),
        "effect_index": 0,
        "effect": {
            "kind": "systemd_unit",
            "target": "constellation-beta-http-fixture",
            "unit": "constellation-beta-http-fixture.service",
            "action": "start",
            "expected_active_state": "inactive",
            "expected_unit_file_state": "disabled",
        },
        "file_policy": {
            "max_content_bytes": 1024,
            "trusted_ancestor_uid": 0,
            "trusted_parent_uid": 0,
            "require_private_parent_writes": True,
        },
        "systemd_machine_identity": "0123456789abcdef0123456789abcdef",
        "execution_lock_timeout_ms": 5000,
        "job_timeout_ms": 30000,
    }


def success_evidence():
    return {
        "schema": "ag-effectd.systemd-dbus-evidence/v1",
        "work": digest("3"),
        "attempt": digest("4"),
        "marker": digest("5"),
        "effect_index": 0,
        "systemd_machine_identity": "0123456789abcdef0123456789abcdef",
        "unit": "constellation-beta-http-fixture.service",
        "action": "start",
        "expected_active_state": "inactive",
        "expected_unit_file_state": "disabled",
        "execution_lock_timeout_ms": 5000,
        "job_timeout_ms": 30000,
        "started_at_unix_ms": 1000,
        "finished_at_unix_ms": 1025,
        "elapsed_ms": 25,
        "live_machine_identity": "0123456789abcdef0123456789abcdef",
        "unit_object_path": "/org/freedesktop/systemd1/unit/example",
        "previous_active_state": "inactive",
        "previous_unit_file_state": "disabled",
        "job_path": "/org/freedesktop/systemd1/job/42",
        "job_result": "done",
        "resulting_active_state": "active",
        "resulting_unit_file_state": "disabled",
        "outcome_class": "success",
        "outcome_code": "start_unit_completed",
        "messages": [
            {"kind": kind, "elapsed_ms": index + 1, "bytes": [index]}
            for index, kind in enumerate(
                [
                    "get_machine_id_reply",
                    "ref_unit_reply",
                    "get_unit_reply",
                    "pre_active_state_reply",
                    "pre_unit_file_state_reply",
                    "start_unit_reply",
                    "job_removed_signal",
                    "post_active_state_reply",
                    "post_unit_file_state_reply",
                ]
            )
        ],
    }


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = Draft202012Validator(load("systemd-plan-v2.schema.json"))
        cls.evidence = Draft202012Validator(load("systemd-evidence-v1.schema.json"))
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "-q",
                "-p",
                "ag-app",
                "--lib",
                "--features",
                "systemd-dbus",
                "effect_executor_adapter::systemd_executor_v2::qualification_tests::emit_systemd_schema_fixtures",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
            ],
            cwd=ROOT.parents[1],
            check=True,
            capture_output=True,
            text=True,
        )
        fixtures = {}
        for line in completed.stdout.splitlines():
            if line.startswith("AG_SYSTEMD_"):
                name, raw = line.split("=", 1)
                fixtures[name] = json.loads(raw)
        cls.runtime_plan = fixtures["AG_SYSTEMD_PLAN"]
        cls.runtime_evidence = fixtures["AG_SYSTEMD_EVIDENCE"]

    def test_beta_plan_and_success_evidence_validate(self):
        self.plan.validate(beta_plan())
        self.evidence.validate(success_evidence())

    def test_plan_is_closed_and_machine_bound(self):
        for field, value in [
            ("systemd_machine_identity", "A" * 32),
            ("execution_lock_timeout_ms", 5001),
            ("job_timeout_ms", 30001),
        ]:
            candidate = beta_plan()
            candidate[field] = value
            with self.assertRaises(ValidationError):
                self.plan.validate(candidate)
        candidate = beta_plan()
        candidate["unowned"] = True
        with self.assertRaises(ValidationError):
            self.plan.validate(candidate)

    def test_v2_accepts_only_systemd_unit_effects(self):
        candidate = beta_plan()
        candidate["effect"]["kind"] = "managed_file_put"
        with self.assertRaises(ValidationError):
            self.plan.validate(candidate)

    def test_evidence_message_bounds_are_closed(self):
        candidate = success_evidence()
        candidate["messages"][0]["bytes"] = [0] * 65537
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)
        candidate = success_evidence()
        candidate["messages"] = candidate["messages"] * 17
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)

    def test_evidence_unknown_and_identity_substitutions_refuse(self):
        candidate = success_evidence()
        candidate["unexpected"] = "value"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)
        candidate = success_evidence()
        candidate["attempt"] = "not-a-digest"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)


    def test_runtime_emitted_documents_validate(self):
        self.plan.validate(self.runtime_plan)
        self.evidence.validate(self.runtime_evidence)

    def test_evidence_outcome_shapes_are_closed(self):
        for field in ["job_path", "job_result", "resulting_active_state"]:
            candidate = success_evidence()
            candidate[field] = None
            with self.assertRaises(ValidationError):
                self.evidence.validate(candidate)

        candidate = success_evidence()
        candidate["outcome_code"] = "worker_claimed_success"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)

        candidate = success_evidence()
        candidate["outcome_class"] = "failure"
        candidate["outcome_code"] = "system_bus_unavailable"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)
        candidate["resulting_active_state"] = None
        candidate["resulting_unit_file_state"] = None
        candidate["job_path"] = None
        candidate["job_result"] = None
        candidate["messages"] = candidate["messages"][:4]
        self.evidence.validate(candidate)
        for outcome_class, known_code in [
            ("failure", "system_bus_unavailable"),
            ("indeterminate", "systemd_start_reply_timeout"),
        ]:
            candidate = success_evidence()
            candidate["outcome_class"] = outcome_class
            candidate["outcome_code"] = "unrecognized_owner_outcome"
            candidate["resulting_active_state"] = None
            candidate["resulting_unit_file_state"] = None
            candidate["job_path"] = None
            candidate["job_result"] = None
            candidate["messages"] = []
            with self.assertRaises(ValidationError):
                self.evidence.validate(candidate)
            candidate["outcome_code"] = known_code
            self.evidence.validate(candidate)

    def test_message_vocabulary_and_unit_shape_are_closed(self):
        candidate = success_evidence()
        candidate["messages"][0]["kind"] = "unrecorded_reply"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)
        candidate = success_evidence()
        candidate["unit"] = "../other.service"
        with self.assertRaises(ValidationError):
            self.evidence.validate(candidate)

if __name__ == "__main__":
    unittest.main()
