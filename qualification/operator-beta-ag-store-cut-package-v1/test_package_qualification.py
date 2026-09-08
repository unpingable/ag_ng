import copy
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

from jsonschema import Draft202012Validator, ValidationError


HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]


def load_json(name: str):
    return json.loads((HERE / name).read_text())


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class StoreCutPackageQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = load_json("package-qualification.v1.json")
        cls.schema_document = load_json("package-qualification.v1.schema.json")
        Draft202012Validator.check_schema(cls.schema_document)
        cls.validator = Draft202012Validator(cls.schema_document)
        cls.archive = REPO / cls.receipt["package"]["archive_path"]

    def test_closed_receipt_validates_and_substitutions_refuse(self):
        self.validator.validate(self.receipt)
        substitutions = []
        candidate = copy.deepcopy(self.receipt)
        candidate["package"]["archive_sha256"] = "sha256:" + "0" * 64
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["package"]["version"] = "0.1.0-1+m1a3"
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["authority"]["invokes_effect"] = True
        substitutions.append(candidate)
        candidate = copy.deepcopy(self.receipt)
        candidate["aggregate_success"] = True
        substitutions.append(candidate)
        for candidate in substitutions:
            with self.assertRaises(ValidationError):
                self.validator.validate(candidate)

    def test_archive_bytes_and_control_fields_are_exact(self):
        raw = self.archive.read_bytes()
        package = self.receipt["package"]
        self.assertEqual(len(raw), package["archive_length"])
        self.assertEqual(sha256(raw), package["archive_sha256"])
        for field, expected in (
            ("Package", package["name"]),
            ("Version", package["version"]),
            ("Architecture", package["architecture"]),
        ):
            observed = subprocess.check_output(
                ["dpkg-deb", "-f", self.archive, field], text=True
            ).strip()
            self.assertEqual(observed, expected)

    def test_control_archive_has_no_lifecycle_scripts(self):
        raw = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", self.archive])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            self.assertEqual([member.name for member in archive.getmembers()], [".", "./control"])

    def test_data_archive_is_one_root_owned_executable(self):
        raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", self.archive])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [
                    ".",
                    "./usr",
                    "./usr/libexec",
                    "./usr/libexec/agent-governor-ng",
                    "./usr/libexec/agent-governor-ng/ag-effectd",
                ],
            )
            for member in members:
                self.assertEqual((member.uname, member.gname), ("root", "root"))
                self.assertEqual(member.mode, 0o755)
            executable = members[-1]
            self.assertTrue(executable.isfile())
            embedded = archive.extractfile(executable).read()
            package = self.receipt["package"]
            self.assertEqual(len(embedded), package["executable_length"])
            self.assertEqual(sha256(embedded), package["executable_sha256"])

    def test_embedded_binary_exposes_only_the_expected_query_surface(self):
        raw = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", self.archive])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            embedded = archive.extractfile(
                "./usr/libexec/agent-governor-ng/ag-effectd"
            ).read()
        with tempfile.TemporaryDirectory() as directory:
            executable = pathlib.Path(directory) / "ag-effectd"
            executable.write_bytes(embedded)
            executable.chmod(0o755)
            completed = subprocess.run(
                [executable, "audit-store", "--help"],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.stderr, "")
        for required in (
            "Validate a copied terminal Systemd V2 store without invoking mechanics",
            "--store-cut",
            "--store-bytes",
            "--store-sha256",
        ):
            self.assertIn(required, completed.stdout)

    def test_retained_stage_reconstructs_the_archive_byte_identically(self):
        stage = self.archive.parent / "stage"
        self.assertTrue(stage.is_dir())
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(
            self.receipt["package"]["source_date_epoch"]
        )
        with tempfile.TemporaryDirectory() as directory:
            rebuilt = pathlib.Path(directory) / self.archive.name
            subprocess.run(
                [
                    "dpkg-deb",
                    "--root-owner-group",
                    "--build",
                    stage,
                    rebuilt,
                ],
                check=True,
                capture_output=True,
                env=environment,
            )
            self.assertEqual(rebuilt.read_bytes(), self.archive.read_bytes())


if __name__ == "__main__":
    unittest.main()
