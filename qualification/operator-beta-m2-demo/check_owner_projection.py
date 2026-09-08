#!/usr/bin/env python3
"""Check actual Docket projection interoperability using its local test fixture."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/ag-operator-ui/demo"))
import fixed_demo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docket-fixture", type=pathlib.Path, required=True)
    args = parser.parse_args()
    specification = importlib.util.spec_from_file_location("docket_interop_fixture", args.docket_fixture)
    fixture = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(fixture)
    case = fixture.FixedDemoControllerTests()
    try:
        with tempfile.TemporaryDirectory(prefix="m2-owner-projection-") as temporary:
            _, path, size, digest = case.fixture(pathlib.Path(temporary))
            manager = fixture.FakeManager()
            value = fixture.controller.FixedController(path, size, digest, manager).status()
            fixed_demo.validate_projection(value)
            assert manager.starts == 0
            print(json.dumps({"state": "OWNER_PROJECTION_FIXTURE_ACCEPTED", "manager_calls": manager.starts,
                              "evidence_entries": len(value["evidence"]), "integration": "NOT_RUN",
                              "controller_sha256": hashlib.sha256(pathlib.Path(fixture.controller.__file__).read_bytes()).hexdigest(),
                              "ui_sha256": hashlib.sha256(pathlib.Path(fixed_demo.__file__).read_bytes()).hexdigest()}, sort_keys=True))
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
