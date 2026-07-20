#!/usr/bin/python3
"""Mutation tests for the clean-host qualification contract validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("clean_host_validate", HERE / "validate.py")
assert SPEC is not None and SPEC.loader is not None
VALIDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATE)


class QualificationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.claim = VALIDATE.load_canonical_json(HERE / "claim.v1.json")
        cls.matrix = VALIDATE.load_matrix(HERE / "matrix.toml")
        cls.receipt = VALIDATE.load_canonical_json(HERE / "receipt.template.v1.json")

    def assert_contract_error(self, callback) -> None:
        with self.assertRaises(VALIDATE.ContractError):
            callback()

    def test_checked_in_contract_validates(self) -> None:
        VALIDATE.validate_contract(HERE)

    def test_json_must_be_canonical_and_lf_terminated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claim.json"
            path.write_text(json.dumps(self.claim, indent=2) + "\n", encoding="utf-8")
            self.assert_contract_error(lambda: VALIDATE.load_canonical_json(path))

    def test_claim_unknown_field_is_rejected(self) -> None:
        claim = copy.deepcopy(self.claim)
        claim["comment"] = "not part of the schema"
        self.assert_contract_error(lambda: VALIDATE.validate_claim(claim))

    def test_claim_invalid_layer_enum_is_rejected(self) -> None:
        claim = copy.deepcopy(self.claim)
        claim["claim_layers"][0]["status"] = "partial"
        self.assert_contract_error(lambda: VALIDATE.validate_claim(claim))

    def test_reconstructing_standing_is_rejected(self) -> None:
        claim = copy.deepcopy(self.claim)
        claim["reconstructs_standing"] = True
        self.assert_contract_error(lambda: VALIDATE.validate_claim(claim))

        receipt = copy.deepcopy(self.receipt)
        receipt["reconstructs_standing"] = True
        self.assert_contract_error(
            lambda: VALIDATE.validate_receipt_template(receipt, self.claim, self.matrix)
        )

    def test_matrix_requires_exact_four_guest_cells(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        matrix["guests"].pop()
        self.assert_contract_error(lambda: VALIDATE.validate_matrix(matrix))

    def test_matrix_requires_complete_ordered_case_families(self) -> None:
        matrix = copy.deepcopy(self.matrix)
        matrix["mandatory_case_families"][0] = matrix["mandatory_case_families"][1]
        self.assert_contract_error(lambda: VALIDATE.validate_matrix(matrix))

    def test_receipt_requires_every_family_for_every_guest(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        del receipt["cases"][2]["results"][VALIDATE.CASE_FAMILIES[3]]
        self.assert_contract_error(
            lambda: VALIDATE.validate_receipt_template(receipt, self.claim, self.matrix)
        )

    def test_receipt_must_carry_claim_blockers_and_exclusions(self) -> None:
        for field in ("blockers", "exclusions"):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt[field].pop()
                self.assert_contract_error(
                    lambda: VALIDATE.validate_receipt_template(
                        receipt, self.claim, self.matrix
                    )
                )

    def test_template_schema_cannot_be_a_final_receipt_schema(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["schema"] = VALIDATE.RECEIPT_SCHEMA
        self.assert_contract_error(
            lambda: VALIDATE.validate_receipt_template(receipt, self.claim, self.matrix)
        )

    def test_blocked_shipped_workflow_prevents_qualified_verdict(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["verdict"] = "qualified"
        self.assert_contract_error(
            lambda: VALIDATE.validate_receipt_template(receipt, self.claim, self.matrix)
        )

        self.assertEqual(
            VALIDATE._expected_verdict(
                ["pass", "pass", "blocked"],
                ["pass"] * (len(VALIDATE.GUESTS) * len(VALIDATE.CASE_FAMILIES)),
                list(VALIDATE.BLOCKERS),
            ),
            "blocked",
        )

    def test_source_template_cannot_contain_results(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["cases"][0]["results"][VALIDATE.CASE_FAMILIES[0]] = "pass"
        self.assert_contract_error(
            lambda: VALIDATE.validate_receipt_template(receipt, self.claim, self.matrix)
        )


if __name__ == "__main__":
    unittest.main()
