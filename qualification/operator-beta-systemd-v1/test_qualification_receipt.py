import copy
import hashlib
import json
import pathlib
import unittest

from jsonschema import Draft202012Validator, ValidationError


ROOT = pathlib.Path(__file__).resolve().parent


def load(name: str):
    return json.loads((ROOT / name).read_text())


def canonical_json_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def hash_domain(domain: str, payload: bytes) -> str:
    framing = (
        b"ag-ng\0digest\0v1\0"
        + len(domain.encode()).to_bytes(16, "big")
        + domain.encode()
        + len(payload).to_bytes(16, "big")
        + payload
    )
    return "sha256:" + hashlib.sha256(framing).hexdigest()


class QualificationReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = load("qualification-receipt.v1.json")
        cls.schema_document = load("qualification-receipt.v1.schema.json")
        Draft202012Validator.check_schema(cls.schema_document)
        cls.schema = Draft202012Validator(cls.schema_document)

    def test_exact_receipt_validates(self):
        self.schema.validate(self.receipt)

    def test_every_committed_artifact_has_exact_bytes(self):
        for artifact in self.receipt["artifacts"]:
            path = ROOT / artifact["path"]
            raw = path.read_bytes()
            self.assertEqual(len(raw), artifact["length"], artifact["path"])
            self.assertEqual(
                "sha256:" + hashlib.sha256(raw).hexdigest(),
                artifact["sha256"],
                artifact["path"],
            )

    def test_owner_chain_and_temporal_claims_remain_distinct(self):
        plan = load("evidence/run-004-systemd-plan-v2.json")
        dispatch = load("evidence/run-004-docket-dispatch-v1.json")
        outcome = load("evidence/run-004-executor-outcome-v1.json")
        effect_receipt = load("evidence/run-004-effect-receipt-v1.json")
        evidence = load("evidence/run-004-systemd-evidence-v1.json")
        occurrence = self.receipt["occurrence"]

        self.assertEqual(
            hash_domain(plan["schema"], canonical_json_bytes(plan)),
            occurrence["work"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(canonical_json_bytes(effect_receipt)).hexdigest(),
            occurrence["receipt"],
        )
        self.assertEqual(
            hash_domain(evidence["schema"], canonical_json_bytes(evidence)),
            occurrence["evidence"],
        )
        self.assertEqual(plan["subject"], dispatch["subject"])
        self.assertEqual(plan["scope"], dispatch["scope"])
        self.assertEqual(dispatch["work"], occurrence["work"])
        self.assertEqual(dispatch["attempt"], outcome["attempt"])
        self.assertEqual(dispatch["marker"], outcome["marker"])
        self.assertEqual(outcome["receipt"], occurrence["receipt"])
        self.assertEqual(effect_receipt["work"], dispatch["work"])
        self.assertEqual(effect_receipt["attempt"], dispatch["attempt"])
        self.assertEqual(effect_receipt["executor_marker"], dispatch["marker"])
        self.assertEqual(
            effect_receipt["outcome"]["success"]["evidence"],
            occurrence["evidence"],
        )
        self.assertEqual(evidence["work"], dispatch["work"])
        self.assertEqual(evidence["attempt"], dispatch["attempt"])
        self.assertEqual(evidence["marker"], dispatch["marker"])
        self.assertEqual(evidence["outcome_class"], "success")
        self.assertEqual(len(evidence["messages"]), 9)
        self.assertEqual(
            self.receipt["live_qualification"]["current_support_after_restart"],
            "NOT_ESTABLISHED_TARGET_INACTIVE_HTTP_ABSENT",
        )
        self.assertFalse(self.receipt["authority"]["proves_current_postcondition"])

        guest = (
            ROOT / "evidence/run-004-final-guest-teardown-observation.txt"
        ).read_text()
        host = (
            ROOT / "evidence/run-004-final-host-teardown-observation.txt"
        ).read_text()
        for fact in (
            "package_absent=true",
            "unit_absent=true",
            "data_absent=true",
            "store_absent=true",
            "backup_absent=true",
            "campaign_processes_absent=true",
            "target_listener_absent=true",
            "effect_or_mechanics_invoked=false",
            "observation_complete=true",
        ):
            self.assertIn(fact, guest)
        for fact in (
            "campaign_vm_process_absent=true",
            "campaign_overlay_open_by_process_absent=true",
            "forwarded_listener_24444_absent=true",
            "forwarded_listener_24445_absent=true",
            "controller_evidence_retained=true",
            "effect_or_mechanics_invoked=false",
            "observation_complete=true",
        ):
            self.assertIn(fact, host)
        self.assertTrue(all(self.receipt["teardown"].values()))

    def test_receipt_substitutions_refuse(self):
        plan = load("evidence/run-004-systemd-plan-v2.json")
        effect_receipt = load("evidence/run-004-effect-receipt-v1.json")
        evidence = load("evidence/run-004-systemd-evidence-v1.json")
        occurrence = self.receipt["occurrence"]
        substituted_plan = copy.deepcopy(plan)
        substituted_plan["job_timeout_ms"] -= 1
        self.assertNotEqual(
            hash_domain(plan["schema"], canonical_json_bytes(substituted_plan)),
            occurrence["work"],
        )
        substituted_receipt = copy.deepcopy(effect_receipt)
        substituted_receipt["effect_index"] += 1
        self.assertNotEqual(
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(substituted_receipt)).hexdigest(),
            occurrence["receipt"],
        )
        substituted_evidence = copy.deepcopy(evidence)
        substituted_evidence["finished_at_unix_ms"] += 1
        self.assertNotEqual(
            hash_domain(
                evidence["schema"], canonical_json_bytes(substituted_evidence)
            ),
            occurrence["evidence"],
        )

        substitutions = []
        candidate = copy.deepcopy(self.receipt)
        candidate["classification"] = "NOT_QUALIFIED"
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["artifacts"][0]["sha256"] = "sha256:" + "0" * 64
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["live_qualification"]["current_support_after_restart"] = "ESTABLISHED"
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["aggregate_success"] = True
        substitutions.append(candidate)

        for candidate in substitutions:
            with self.assertRaises(ValidationError):
                self.schema.validate(candidate)


if __name__ == "__main__":
    unittest.main()
