#!/usr/bin/python3
"""Build the VELVET-PIGEON frozen packet and synthetic cross-office witness."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path("/data/git")
AG = Path(__file__).resolve().parents[3]
PORTER = ROOT / "porter"
# Explicit modern dependencies: no default classic checkout or fallback.
OUT = Path(os.environ["RETIREMENT_SPECIMEN_OUT"])
NQ_BIN = Path(os.environ["NQ_NG_BIN"])
NS_BIN = Path(os.environ["NIGHTSHIFT_BIN"])
RESOLVER_BIN = Path(os.environ["NIGHTSHIFT_RESOLVER_BIN"])
if not OUT.is_absolute() or OUT.exists():
    raise ValueError("RETIREMENT_SPECIMEN_OUT must be a new absolute artifact directory")
if NQ_BIN.name != "nq" or not all(p.is_absolute() for p in (NQ_BIN, NS_BIN, RESOLVER_BIN)):
    raise ValueError("explicit absolute modern nq and Nightshift binary paths required")

CAMPAIGN = "sha256:606605c73dcea732c7b937c27dd6d9c19f2b4e37109ecec7cbdb8d85d0f60466"
SUBJECT = "sha256:3dbab9cb9e27fa0a039a75c275834d633b658c25db6a252c5924999d5bc4989c"
OCCURRENCE = "00000000-0000-0000-0000-000000000001"
SESSION_ID = "gcl-v1-20260828-007"
SESSION_MANIFEST = "sha256:bb9b3c6d96d79ffe3d4d8e8a7565cd17c591bd4e2af10ab8f8bfbad6cd37e25f"
NONCLAIMS = ["execution", "success", "qualification", "applicability", "standing", "settlement", "authorization", "continuation"]


def jcs(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(jcs(value)).hexdigest()


def text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def domain_digest(domain: str, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + jcs(value)).hexdigest()


def ag_domain_digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode()
    payload = jcs(value)
    preimage = b"ag-ng\0digest\0v1\0" + len(domain_bytes).to_bytes(16, "big") + domain_bytes + len(payload).to_bytes(16, "big") + payload
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def write(name: str, value: object) -> Path:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(jcs(value))
    return path


def run(argv: list[str], *, stdin: bytes | None = None, expect: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, input=stdin, capture_output=True)
    if result.returncode != expect:
        raise RuntimeError(f"command returned {result.returncode}, expected {expect}: {argv}\n{result.stderr.decode(errors='replace')}")
    return result


def plan_template(ordinal: int, predecessor: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "ag.gcl-v1-worker-vm-plan-template/v1",
        "runtime_schema": "campaign-driver-ng.gcl-v1-worker-vm-plan/v2",
        "work_schema": "campaign-driver-ng.gcl-v1-worker-vm-work/v1",
        "attempt_store": "/var/lib/gcl-v1/velvet-pigeon/attempts.sqlite3",
        "subject": SUBJECT,
        "scope": text_digest(f"glass-heron-stage-{ordinal}-scope"),
        "ordinal": ordinal,
        "evidence_reservation": "",
        "predecessor": predecessor,
        "session_id": SESSION_ID,
        "session_manifest": f"/var/lib/gcl-v1/sessions/{SESSION_ID}/manifest.json",
        "session_manifest_sha256": SESSION_MANIFEST[7:],
        "porter_program": "/data/git/porter/porter",
        "porter_program_sha256": "2fad0404ca1d394da8b93ac563c8325686c950ec0b5ddd09f2f10fd5161e6625",
        "porter_repository": "/data/git/porter",
        "porter_commit": "a838501de2fc220bfc838904733114e41124b744",
        "porter_profile": f"/var/lib/gcl-v1/sessions/{SESSION_ID}/porter-profile.json",
        "porter_profile_sha256": "31406bdb1b75598e276283ce4fe394423cc807472d4e81c3230f039021cabcdd",
        "executor_module": "/data/git/campaign-driver-ng/qualification/gcl-v1/worker_vm_executor.py",
        "executor_module_sha256": "7dbe858036f99c26d5711164a72ac1d15a7a1bc6df9d397594a885f5a3651bc5",
        "custody_module": "/data/git/campaign-driver-ng/qualification/gcl-v1/worker_vm_custody.py",
        "custody_module_sha256": "40b3d5737459290a79889fb4766f24d0bb41155bdd2d10a7754e78e1218229fe",
        "porter_runs": "/var/lib/gcl-v1/velvet-pigeon/porter-runs",
        "governed_repository": "/var/lib/gcl-v1/glass-heron/repository",
        "prompt": f"/var/lib/gcl-v1/glass-heron/stage-{ordinal}.txt",
        "prompt_sha256": hashlib.sha256(f"GLASS-HERON predeclared stage {ordinal}\n".encode()).hexdigest(),
        "allowed_paths": [f"src/stage_{ordinal}.py", f"tests/test_stage_{ordinal}.py"],
        "model": "gpt-5.6-sol",
        "effort": "medium",
        "timeout_seconds": 900,
        "host_custody_root": "/var/lib/gcl-v1/velvet-pigeon/custody",
    }


def nq_template(ordinal: int, predecessor: dict[str, object], executor_template: str) -> dict[str, object]:
    context = {
        "executable_sha256": text_digest("/usr/bin/python3"),
        "argv_transcript_sha256": text_digest(f"stage-{ordinal}-gate-argv"),
        "repository_relative_cwd": ".",
        "environment_transcript_sha256": text_digest("LC_ALL=C"),
    }
    return {
        "schema": "ag.nq-campaign-stage-realization-profile-template/v1",
        "runtime_schema": "nq-ng.campaign-stage-realization-profile/v2",
        "profile_id": f"glass-heron.stage-{ordinal}.reservation/v2",
        "evidence_reservation": "",
        "campaign_packet_sha256": "",
        "stage_id": f"stage-{ordinal}",
        "repository_id": text_digest("glass-heron-disposable-repository"),
        "repository_ref": "refs/heads/main",
        "predecessor": predecessor,
        "executor_plan_template": executor_template,
        "expected_evidence_producer": {"producer_id": "velvet-pigeon.synthetic-evidence/v1", "producer_version": "1", "executable_sha256": text_digest("velvet-pigeon-evidence-producer/v1")},
        "ordered_gates": [{"ordinal": 0, "gate_id": "synthetic-chain-contract", "context": context, "required_exit_code": 0}],
        "required_artifacts": [],
        "required_workspace_predicates": ["REPOSITORY_IDENTITY_MATCHES"],
        "expected_clean_worktree": True,
    }


def seal_reservation(value: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(value)
    value["schema"] = "ag.external-evidence-reservation/v1"
    value["reservation_id"] = ""
    value["reservation_id"] = domain_digest("ag.external-evidence-reservation/v1", value)
    return value


def build_packet() -> dict[str, object]:
    initial_head = "17e910339353a8143aadf8ba6e1b320b75a2963e"
    initial_tree = "fa99fe996205236c10f31a84a41b607a7be44f26"
    works = [text_digest(f"glass-heron-stage-{i}-work") for i in range(1, 4)]
    stages: list[dict[str, object]] = []
    prior_reservation = ""
    for ordinal in range(1, 4):
        predecessor = ({"kind": "initial_git", "head": {"object_format": "sha1", "digest": initial_head}, "tree": {"object_format": "sha1", "digest": initial_tree}}
                       if ordinal == 1 else {"kind": "prior_stage_realization", "stage_id": f"stage-{ordinal - 1}", "reservation": prior_reservation})
        plan = plan_template(ordinal, predecessor)
        plan_hash = digest(plan)
        nq = nq_template(ordinal, predecessor, plan_hash)
        successor = ({"kind": "stage", "stage_id": f"stage-{ordinal + 1}", "work_schema": f"glass-heron.stage-{ordinal + 1}/v1", "work": works[ordinal]}
                     if ordinal < 3 else {"kind": "human_required"})
        reservation = seal_reservation({
            "schema": "", "reservation_id": "", "campaign_id": CAMPAIGN,
            "stage_id": f"stage-{ordinal}", "ordinal": ordinal, "logical_attempt_id": f"glass-heron-attempt-{ordinal}",
            "predecessor": predecessor,
            "result_constraints": {"must_descend_from_predecessor": True, "required_commit_count": 1, "expected_clean_worktree": True, "allowed_mutation_paths": plan["allowed_paths"], "factual_gate_profile_sha256": text_digest(f"stage-{ordinal}-gates")},
            "successor": successor, "worker_session_manifest_sha256": SESSION_MANIFEST,
            "executor_plan_template_sha256": plan_hash, "instruction_sha256": text_digest(f"stage-{ordinal}-instructions"),
            "mutation_profile_sha256": text_digest(f"stage-{ordinal}-mutation"), "resource_profile_sha256": text_digest("w6-qualified-resource-profile"),
            "nq_profile_template_sha256": digest(nq), "does_not_establish": NONCLAIMS,
        })
        prior_reservation = str(reservation["reservation_id"])
        stages.append({
            "stage_id": f"stage-{ordinal}", "ordinal": ordinal, "logical_attempt_id": f"glass-heron-attempt-{ordinal}",
            "work_schema": f"glass-heron.stage-{ordinal}/v1", "work": works[ordinal - 1],
            "instruction_sha256": reservation["instruction_sha256"], "mutation_profile_sha256": reservation["mutation_profile_sha256"],
            "resource_profile_sha256": reservation["resource_profile_sha256"], "worker_session_manifest_sha256": SESSION_MANIFEST,
            "executor_plan_template": plan, "executor_plan_template_sha256": plan_hash,
            "nq_profile_template": nq, "nq_profile_template_sha256": digest(nq), "reservation": reservation,
        })
    packet = {"schema": "ag.governed-campaign.packet/v1", "packet_id": "", "campaign_id": CAMPAIGN,
              "repository_id": text_digest("glass-heron-disposable-repository"), "workspace": "/var/lib/gcl-v1/glass-heron/repository",
              "repository_ref": "refs/heads/main", "stages": stages}
    packet["packet_id"] = domain_digest("ag.governed-campaign.packet/v1", packet)
    return packet


def porter_record(reservation: str, label: str) -> tuple[str, str]:
    sys.path.insert(0, str(PORTER))
    from porterlib import record as records  # pylint: disable=import-outside-toplevel
    run_id = records.new_run_id()
    base = OUT / "porter-runs" / run_id
    records.ensure_layout(base)
    factual = records.new_serial_record(run_id, f"serial:/run/{label}.sock", f"/run/{label}.sock")
    records.bind_reservation(factual, reservation)
    factual["notes"] = "synthetic contract specimen; no endpoint or campaign execution claim"
    records.save_record(base, factual)  # durable (P,R) precedes any later evidence construction
    records.seal_run(base)
    return run_id, "sha256:" + hashlib.sha256((base / "record.json").read_bytes()).hexdigest()


def main() -> None:
    if OUT.exists() and any(OUT.iterdir()):
        raise SystemExit(f"refusing to replace existing evidence directory: {OUT}")
    OUT.mkdir(parents=True, exist_ok=True)
    packet = build_packet()
    packet_path = write("glass-heron-packet.v1.json", packet)
    stage = packet["stages"][0]
    reservation = stage["reservation"]["reservation_id"]
    construction = {"packet_sha256": digest(packet), "packet_id": packet["packet_id"], "reservations": [s["reservation"]["reservation_id"] for s in packet["stages"]], "future_porter_run_ids": None, "future_result_heads": None, "future_settlements": None}
    write("pre-execution-custody.json", construction)

    run_id, record_sha = porter_record(reservation, "velvet-pigeon-primary")
    plan = copy.deepcopy(stage["executor_plan_template"])
    plan["evidence_reservation"] = reservation
    plan["schema"] = plan.pop("runtime_schema")
    plan.pop("predecessor")
    plan["predecessor_head"] = stage["reservation"]["predecessor"]["head"]["digest"]
    plan["predecessor_tree"] = stage["reservation"]["predecessor"]["tree"]["digest"]
    attempt = text_digest("velvet-pigeon-docket-attempt")
    plan_identity = ag_domain_digest("ag-effectd.docket-executor-plan/v2", plan)
    settlement = text_digest("velvet-pigeon-docket-settlement")
    executor_receipt = text_digest("velvet-pigeon-executor-receipt")
    profile = copy.deepcopy(stage["nq_profile_template"])
    profile["evidence_reservation"] = reservation
    profile["campaign_packet_sha256"] = packet["packet_id"]
    profile["schema"] = profile.pop("runtime_schema")
    predecessor = profile["predecessor"]
    profile["predecessor_head"] = predecessor["head"]
    profile["predecessor_tree"] = predecessor["tree"]
    profile_path = write("nq-profile.v2.json", profile)
    profile_sha = digest(profile)
    context = profile["ordered_gates"][0]["context"]
    chain = {"evidence_reservation": reservation, "docket_attempt": attempt, "executor_plan_template": stage["executor_plan_template_sha256"],
             "executor_plan": plan_identity, "docket_settlement": settlement, "porter_run_id": run_id, "porter_record_sha256": record_sha,
             "executor_receipt": executor_receipt, "predecessor_head": profile["predecessor_head"], "predecessor_tree": profile["predecessor_tree"],
             "result_head": {"object_format": "sha1", "digest": "4" * 40}, "result_tree": {"object_format": "sha1", "digest": "d" * 40}}
    evidence = {"schema": "nq-ng.campaign-stage-realization-evidence/v2", "evidence_id": "velvet-pigeon.synthetic-realization-1", "profile_id": profile["profile_id"],
                "profile_sha256": profile_sha, "evidence_reservation": reservation, "campaign_packet_sha256": packet["packet_id"], "stage_id": profile["stage_id"],
                "repository_id": profile["repository_id"], "repository_ref": profile["repository_ref"], "realizations": [chain], "producer": profile["expected_evidence_producer"],
                "predecessor_qualification": None,
                "qualification_started_at_unix_ms": 900, "qualification_finished_at_unix_ms": 950,
                "gates": [{"ordinal": 0, "gate_id": "synthetic-chain-contract", "context": context, "started_at_unix_ms": 910, "finished_at_unix_ms": 920,
                           "outcome": {"outcome": "COMPLETED", "exit_code": 0, "stdout_sha256": text_digest("synthetic chain exact"), "stderr_sha256": text_digest("")}}],
                "artifacts": [], "workspace_custody": [{"predicate": "REPOSITORY_IDENTITY_MATCHES", "observation_sha256": text_digest("synthetic repository identity exact"), "outcome": {"outcome": "PASSED"}}],
                "observed_clean_worktree": True}
    evidence_path = write("nq-evidence.v2.json", evidence)
    receipt_path = OUT / "nq-receipt.v2.json"
    run([str(NQ_BIN), "campaign-stage-realization", "evaluate", "--profile", str(profile_path), "--evidence", str(evidence_path), "--evaluated-at-unix-ms", "1000", "--output", str(receipt_path)])
    receipt = json.loads(receipt_path.read_bytes())
    if receipt["status"] != "QUALIFIED":
        raise RuntimeError(f"NQ did not qualify: {receipt}")

    applicability = {"schema": "nightshift.repository-qualification-reservation-applicability-profile/v1", "profile_id": "", "evidence_reservation": reservation,
                     "expected_nq_profile_id": profile["profile_id"], "expected_nq_profile_sha256": profile_sha,
                     "expected_nq_evaluator_id": receipt["evaluator_id"], "expected_nq_evaluator_version": receipt["evaluator_version"],
                     "expected_nq_evaluator_executable_sha256": receipt["evaluator_executable_sha256"], "source_campaign_id": CAMPAIGN,
                     "source_occurrence_id": OCCURRENCE, "source_attempt_id": attempt, "source_settlement_id": settlement,
                     "subject_digest": SUBJECT, "resolver_id": "nightshift.repository-qualification-resolver/v1", "max_age_ms": 100000}
    applicability["profile_id"] = digest({key: value for key, value in applicability.items() if key != "profile_id"})
    applicability_path = write("nightshift-applicability.v1.json", applicability)
    store = OUT / "nightshift-realizations.sqlite3"
    ingest = run([str(NS_BIN), "--store", str(store), "reservation-qualification", "ingest", "--applicability", str(applicability_path), "--nq-profile", str(profile_path), "--nq-evidence", str(evidence_path), "--nq-receipt", str(receipt_path), "--nq-executable", str(NQ_BIN)])
    (OUT / "nightshift-ingest.json").write_bytes(ingest.stdout)

    snapshot = {"schema": "ag.governed-loop.snapshot/v1", "reservation": reservation, "attempt": attempt, "settlement": settlement}
    source = {"schema": "nightshift.ag_occurrence_reference.v1", "campaign_id": CAMPAIGN, "occurrence_id": OCCURRENCE,
              "state_digest": text_digest("velvet-pigeon-settled-state"), "snapshot_digest": digest(snapshot), "program_counter": "settled_observation_required",
              "docket_attempt_id": attempt, "settlement_id": settlement, "exact_snapshot": snapshot}
    binding = {"schema": "nightshift.repository-qualification-reservation-resolver-binding/v1", "applicability": applicability, "source": source}
    binding_path = write("nightshift-resolver-binding.v1.json", binding)
    request = {"schema": "ag.governed-loop.observation-request/v1", "key": {"campaign": CAMPAIGN, "occurrence": OCCURRENCE}, "observation": reservation, "subject": SUBJECT, "now_unix_ms": 30000}
    request_path = write("ag-observation-request.v1.json", request)
    resolution = run([str(RESOLVER_BIN), "--store", str(store), "--resolver-id", applicability["resolver_id"], "--default-ttl-ms", "100000", "--reservation-qualification-binding", str(binding_path)], stdin=jcs(request))
    (OUT / "nightshift-resolution.v3.json").write_bytes(resolution.stdout)

    second_run, second_record_sha = porter_record(reservation, "velvet-pigeon-conflict")
    conflicting = copy.deepcopy(evidence)
    conflicting["evidence_id"] = "velvet-pigeon.synthetic-realization-conflict"
    conflicting["realizations"][0]["porter_run_id"] = second_run
    conflicting["realizations"][0]["porter_record_sha256"] = second_record_sha
    conflicting["realizations"][0]["executor_receipt"] = text_digest("velvet-pigeon-conflicting-executor-receipt")
    conflicting_path = write("nq-evidence-conflict.v2.json", conflicting)
    conflicting_receipt = OUT / "nq-receipt-conflict.v2.json"
    run([str(NQ_BIN), "campaign-stage-realization", "evaluate", "--profile", str(profile_path), "--evidence", str(conflicting_path), "--evaluated-at-unix-ms", "1001", "--output", str(conflicting_receipt)])
    conflict_store = OUT / "nightshift-conflict.sqlite3"
    shutil.copyfile(store, conflict_store)
    conflict_ingest = run([str(NS_BIN), "--store", str(conflict_store), "reservation-qualification", "ingest", "--applicability", str(applicability_path), "--nq-profile", str(profile_path), "--nq-evidence", str(conflicting_path), "--nq-receipt", str(conflicting_receipt), "--nq-executable", str(NQ_BIN)])
    (OUT / "nightshift-conflict-ingest.json").write_bytes(conflict_ingest.stdout)
    conflict_resolution = run([str(RESOLVER_BIN), "--store", str(conflict_store), "--resolver-id", applicability["resolver_id"], "--default-ttl-ms", "100000", "--reservation-qualification-binding", str(binding_path)], stdin=jcs(request), expect=1)
    write("conflict-resolution-refusal.json", {"returncode": conflict_resolution.returncode, "stderr": conflict_resolution.stderr.decode().strip()})

    manifest = {"schema": "ag.velvet-pigeon.synthetic-specimen/v1", "packet": packet["packet_id"], "reservation": reservation,
                "porter_run": run_id, "porter_record_sha256": record_sha, "docket_attempt": attempt, "executor_plan": plan_identity,
                "docket_settlement": settlement, "executor_receipt": executor_receipt, "nq_receipt": receipt["receipt_sha256"],
                "nightshift_basis": {"basis_type": "nightshift.repository-qualification-reservation-applicability/v1", "basis_identity": reservation},
                "future_run_was_absent_from_packet": run_id.encode() not in packet_path.read_bytes(), "conflicting_run_refused_currentness": conflict_resolution.returncode != 0}
    write("specimen-manifest.json", manifest)


if __name__ == "__main__":
    main()
