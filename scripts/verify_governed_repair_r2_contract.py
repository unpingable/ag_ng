#!/usr/bin/env python3
"""Fail closed when AG's governed-repair contract and Docket's mirror drift.

AG owns the canonical producer contract.  Docket's checked-in copy is a pinned
consumer mirror.  This verifier is a release/development conformance check; it
creates no governance or custody authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PINNED_FILES = {
    Path("conformance/governed-repair-r2/manifest.v1.json"):
        "74c429d8d32341fc31fba45e4cdd1a0b6d994bace4c7d4d8ccfccfc9dad8aded",
    Path("conformance/governed-repair-r2/contract.v1.json"):
        "d3fc470761d8550f733e2528f0a2589e93717bd120e9b1ffbae687942168458b",
    Path("conformance/governed-repair-r2/labels.v1.json"):
        "47a2a8d97e700c0296044d5bb7d795e51b609860875062aaa633ced7498215b6",
    Path("conformance/governed-repair-r2/reconciliation-rounds.v1.json"):
        "408a2fe3ddf75621c43da441cbdcd33c7fe0845abadd9b02adc72038d01496fc",
    Path("conformance/governed-repair-r2/scopes.v1.json"):
        "905e9b96ba81a2dcc072f243b3bb1b8a02381377b2cebf61e98eaff033c3abaa",
    Path("conformance/governed-repair-r2/wire-hostiles.v1.json"):
        "9862a1e38bb9db11cd39aebe04b3bd8ffaed7d315b67becc1e164176a20858b9",
    Path("conformance/governed-repair-r2/wire-vectors.v1.json"):
        "ff75b856fd1a3076809d26f40d987b114046226aa15e7eeeb46db3388f36ea90",
}


def exact_contract(path: Path, expected_sha256: str) -> bytes:
    data = path.read_bytes()
    value = json.loads(data)
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()
    if data != canonical:
        raise SystemExit(f"contract is not exact compact canonical JSON: {path}")
    identity = hashlib.sha256(data).hexdigest()
    if identity != expected_sha256:
        raise SystemExit(
            f"contract identity drift at {path}: expected {expected_sha256}, observed {identity}"
        )
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docket-root", required=True)
    args = parser.parse_args()
    ag_root = Path(__file__).resolve().parent.parent
    docket_root = Path(args.docket_root).resolve(strict=True)
    expected_members = {path.name for path in PINNED_FILES}
    for root in (ag_root, docket_root):
        observed_members = {
            path.name
            for path in (root / "conformance/governed-repair-r2").iterdir()
            if path.is_file()
        }
        if observed_members != expected_members:
            raise SystemExit(
                "conformance corpus membership drift at "
                f"{root}: expected {sorted(expected_members)}, "
                f"observed {sorted(observed_members)}"
            )
    identities = {}
    for relative, expected in PINNED_FILES.items():
        producer = exact_contract(ag_root / relative, expected)
        consumer = exact_contract(docket_root / relative, expected)
        if producer != consumer:
            raise SystemExit(f"AG producer and Docket consumer differ: {relative}")
        identities[str(relative)] = expected
    print(
        json.dumps(
            {
                "schema": "ag-docket.governed-repair-wire-drift-check/v1",
                "pinned_sha256": identities,
                "producer_root": str(ag_root),
                "consumer_root": str(docket_root),
                "status": "match",
                "qualification_status": "not_assessed",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
