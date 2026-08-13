#!/usr/bin/env python3
"""Self-test the AG operational harness metadata and nonclaim discipline."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXPECTED = {
    "ag.sqlite_wal_power_loss_recovery": "requires_fault_injection_environment",
    "ag.multi_process_contention": "runnable_locally_now",
    "ag.service_currentness_behavior": "requires_deployed_service",
    "ag.clock_and_expiry": "requires_deployed_service",
    "ag.process_isolation": "requires_trusted_host",
    "ag.executor_physical_idempotency": "requires_fault_injection_environment",
    "ag.deployed_standing_docket_correspondence": "requires_deployed_service",
    "ag.governed_repair_durable_halt_successor": "runnable_locally_now",
    "ag.governed_repair_external_human_verification": "requires_deployed_service",
}


def main() -> int:
    gates = json.loads((ROOT / "gates.json").read_bytes())
    assert gates["qualification_status"] == "not_assessed"
    observed = {item["id"]: item["classification"] for item in gates["gates"]}
    assert observed == EXPECTED
    for name in ["trusted-host-plan.json", "deployed-service-plan.json", "fault-injection-plan.json"]:
        plan = json.loads((ROOT / name).read_bytes())
        assert plan["qualification_status"] == "not_assessed"
        assert plan["pass_interpretation_owner"] == "later qualification campaign"
        assert plan["preconditions"] and plan["procedure"] and plan["forbidden_shortcuts"]
    print(json.dumps({
        "schema": "ag.operational-harness-self-test.v1",
        "qualification_status": "not_assessed",
        "development_check": "passed",
        "gate_count": len(EXPECTED),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
