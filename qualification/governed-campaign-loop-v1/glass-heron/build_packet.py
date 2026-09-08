#!/usr/bin/python3
"""Freeze the real GLASS-HERON fixture and pre-execution packet.

This builder runs only before Stage 1.  It creates no AG issuance, Docket
attempt, Porter run, qualification receipt, or candidate identity.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path("/data/git")
AG = Path(__file__).resolve().parents[3]
HERE = AG / "qualification/governed-campaign-loop-v1/glass-heron"
OUT = Path(os.environ["RETIREMENT_PACKET_OUT"])
if not OUT.is_absolute() or OUT.exists():
    raise ValueError("RETIREMENT_PACKET_OUT must be a new absolute artifact directory")
FIXTURE = OUT / "fixture"
LOCAL = OUT / "local-custody"
MANIFEST = Path(os.environ["RETIREMENT_SESSION_MANIFEST"])
MANIFEST_SHA256 = os.environ["RETIREMENT_SESSION_MANIFEST_SHA256"]
PROFILE = Path(os.environ["RETIREMENT_PORTER_PROFILE"])
PRODUCER = Path(os.environ["RETIREMENT_AG_PRODUCER_BIN"])
if not all(path.is_absolute() for path in (MANIFEST, PROFILE, PRODUCER)):
    raise ValueError("explicit absolute frozen input paths required")
EXECUTOR = ROOT / "campaign-driver-ng/qualification/gcl-v1/worker_vm_executor.py"
CUSTODY = ROOT / "campaign-driver-ng/qualification/gcl-v1/worker_vm_custody.py"
PORTER = ROOT / "porter/porter"
NONCLAIMS = [
    "execution", "success", "qualification", "applicability",
    "standing", "settlement", "authorization", "continuation",
]


def jcs(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def label(value: str) -> str:
    return sha_bytes(value.encode())


def domain(domain_name: str, value: object) -> str:
    return sha_bytes(domain_name.encode() + b"\0" + jcs(value))


def write(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(jcs(value))


def run(argv: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"command failed {argv}: {result.stderr.strip()}")
    return result.stdout.strip()


def git(*args: str, cwd: Path = FIXTURE) -> str:
    return run(["/usr/bin/git", *args], cwd=cwd, env={
        "HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C", "GIT_AUTHOR_NAME": "GLASS-HERON Fixture",
        "GIT_AUTHOR_EMAIL": "glass-heron@invalid", "GIT_COMMITTER_NAME": "GLASS-HERON Fixture",
        "GIT_COMMITTER_EMAIL": "glass-heron@invalid", "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    })


def create_fixture() -> tuple[str, str]:
    if FIXTURE.exists():
        raise RuntimeError(f"refusing to replace existing fixture: {FIXTURE}")
    FIXTURE.mkdir(mode=0o700)
    git("init", "--initial-branch=main")
    (FIXTURE / "src").mkdir()
    (FIXTURE / "tests").mkdir()
    (FIXTURE / "src/__init__.py").write_text('"""GLASS-HERON disposable specimen."""\n')
    (FIXTURE / "README.md").write_text(
        "# GLASS-HERON disposable qualification fixture\n\n"
        "This repository is evidence, not production source.\n"
    )
    git("add", "README.md", "src/__init__.py")
    git("commit", "-m", "Initialize GLASS-HERON qualification fixture")
    return git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")


def seal_reservation(value: dict[str, object]) -> dict[str, object]:
    value["schema"] = "ag.external-evidence-reservation/v1"
    value["reservation_id"] = ""
    value["reservation_id"] = domain("ag.external-evidence-reservation/v1", value)
    return value


def main() -> None:
    if OUT.exists() or LOCAL.exists():
        raise RuntimeError("GLASS-HERON pre-stage1 or local custody already exists")
    for path in (MANIFEST, PROFILE, PRODUCER, EXECUTOR, CUSTODY, PORTER):
        if not path.is_file():
            raise RuntimeError(f"missing frozen input: {path}")
    manifest_sha = sha_file(MANIFEST)
    if manifest_sha != MANIFEST_SHA256:
        raise RuntimeError("session manifest substitution")
    manifest = json.loads(MANIFEST.read_bytes())
    session_id = manifest.get("session_id")
    if not isinstance(session_id, str) or not session_id or manifest.get("capacity") != 3:
        raise RuntimeError("session identity/capacity mismatch")
    # All generated state is new and campaign-owned. Frozen source sessions and
    # prior qualification fixtures are inputs only; never reuse their custody.
    OUT.mkdir(mode=0o700, parents=True)
    initial_head, initial_tree = create_fixture()
    LOCAL.mkdir(mode=0o700, parents=True)

    prompts = [
        """Implement Stage 1 only. Create src/stage_1.py with a pure function normalize_slug(value: str) -> str that lowercases ASCII letters, converts each maximal run of non-alphanumeric characters to one hyphen, and strips leading/trailing hyphens. Raise TypeError for non-str input. Create tests/test_stage_1.py using unittest with exact normal, repeated-separator, edge, empty, and non-string cases. Do not modify any other path. Run the full unittest suite before finishing.\n""",
        """Implement Stage 2 only. Create src/stage_2.py with bounded_retry_delays(base_ms: int, attempts: int) -> list[int]. Require base_ms > 0 and 0 <= attempts <= 8, raising ValueError otherwise. Return deterministic exponential delays base_ms * 2**index for each attempt. Create tests/test_stage_2.py using unittest for zero, ordinary, upper-bound, and invalid inputs. Do not modify any other path. Run the full unittest suite before finishing.\n""",
        """Implement Stage 3 only. Create src/stage_3.py as a small CLI that accepts exactly one positional string, calls src.stage_1.normalize_slug, prints the normalized value followed by one newline, returns 0, and uses argparse's ordinary nonzero refusal for wrong arity. Create tests/test_stage_3.py using unittest and subprocess for success, normalization, and wrong arity. Do not modify any other path. Run the full unittest suite before finishing.\n""",
    ]
    prompt_paths: list[Path] = []
    for ordinal, prompt in enumerate(prompts, 1):
        path = OUT / f"stage-{ordinal}.prompt.txt"
        path.write_text(prompt)
        prompt_paths.append(path)

    campaign_id = label("GLASS-HERON:gcl-v1-w7-w8-real-codex-specimen-reconcile")
    repository_id = label(f"glass-heron-fixture:{initial_head}:{initial_tree}")
    subject = label(f"glass-heron-subject:{repository_id}")
    works = [label(f"glass-heron-stage-{ordinal}-logical-work/v1") for ordinal in range(1, 4)]
    resource = label("gcl-v1-w6-qualified-resource-profile:8G:400%:512")
    producer = {
        "producer_id": "ag.glass-heron-real-evidence-controller/v1",
        "producer_version": "1",
        "executable_sha256": sha_file(PRODUCER),
    }
    python_sha = sha_file(Path("/usr/bin/python3"))
    gate_argv = ["/usr/bin/python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
    gate_context = {
        "executable_sha256": python_sha,
        "argv_transcript_sha256": sha_bytes(jcs(gate_argv)),
        "repository_relative_cwd": ".",
        "environment_transcript_sha256": sha_bytes(jcs({"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})),
    }
    stages: list[dict[str, object]] = []
    prior_reservation = ""
    for ordinal in range(1, 4):
        predecessor = ({
            "kind": "initial_git",
            "head": {"object_format": "sha1", "digest": initial_head},
            "tree": {"object_format": "sha1", "digest": initial_tree},
        } if ordinal == 1 else {
            "kind": "prior_stage_realization", "stage_id": f"stage-{ordinal - 1}",
            "reservation": prior_reservation,
        })
        allowed = [f"src/stage_{ordinal}.py", f"tests/test_stage_{ordinal}.py"]
        scope = label("glass-heron-scope:" + ":".join(allowed))
        plan = {
            "schema": "ag.gcl-v1-worker-vm-plan-template/v1",
            "runtime_schema": "campaign-driver-ng.gcl-v1-worker-vm-plan/v2",
            "work_schema": "campaign-driver-ng.gcl-v1-worker-vm-work/v1",
            "attempt_store": str(LOCAL / "executor-attempts.sqlite3"),
            "subject": subject, "scope": scope, "ordinal": ordinal,
            "evidence_reservation": "", "predecessor": predecessor,
            "session_id": session_id, "session_manifest": str(MANIFEST),
            "session_manifest_sha256": manifest_sha[7:],
            "porter_program": str(PORTER), "porter_program_sha256": sha_file(PORTER)[7:],
            "porter_repository": str(ROOT / "porter"), "porter_commit": manifest["porter"]["commit"],
            "porter_profile": str(PROFILE), "porter_profile_sha256": sha_file(PROFILE)[7:],
            "executor_module": str(EXECUTOR), "executor_module_sha256": sha_file(EXECUTOR)[7:],
            "custody_module": str(CUSTODY), "custody_module_sha256": sha_file(CUSTODY)[7:],
            "porter_runs": str(LOCAL / "porter-runs"), "governed_repository": str(FIXTURE),
            "prompt": str(prompt_paths[ordinal - 1]), "prompt_sha256": sha_file(prompt_paths[ordinal - 1])[7:],
            "allowed_paths": allowed, "model": "gpt-5.6-sol", "effort": "medium",
            "timeout_seconds": 900, "host_custody_root": str(LOCAL / "custody"),
        }
        plan_sha = sha_bytes(jcs(plan))
        nq = {
            "schema": "ag.nq-campaign-stage-realization-profile-template/v1",
            "runtime_schema": "nq-ng.campaign-stage-realization-profile/v2",
            "profile_id": f"glass-heron.stage-{ordinal}.real/v2",
            "evidence_reservation": "", "campaign_packet_sha256": "",
            "stage_id": f"stage-{ordinal}", "repository_id": repository_id,
            "repository_ref": "refs/heads/main", "predecessor": predecessor,
            "executor_plan_template": plan_sha, "expected_evidence_producer": producer,
            "ordered_gates": [{"ordinal": 0, "gate_id": "python-unittest", "context": gate_context, "required_exit_code": 0}],
            "required_artifacts": [], "required_workspace_predicates": ["REPOSITORY_IDENTITY_MATCHES"],
            "expected_clean_worktree": True,
        }
        nq_sha = sha_bytes(jcs(nq))
        successor = ({
            "kind": "stage", "stage_id": f"stage-{ordinal + 1}",
            "work_schema": f"glass-heron.stage-{ordinal + 1}/v1", "work": works[ordinal],
        } if ordinal < 3 else {"kind": "human_required"})
        reservation = seal_reservation({
            "schema": "", "reservation_id": "", "campaign_id": campaign_id,
            "stage_id": f"stage-{ordinal}", "ordinal": ordinal,
            "logical_attempt_id": f"glass-heron-real-attempt-{ordinal}",
            "predecessor": predecessor,
            "result_constraints": {
                "must_descend_from_predecessor": True, "required_commit_count": 1,
                "expected_clean_worktree": True, "allowed_mutation_paths": allowed,
                "factual_gate_profile_sha256": sha_bytes(jcs({"gate": "python-unittest", "context": gate_context})),
            },
            "successor": successor, "worker_session_manifest_sha256": manifest_sha,
            "executor_plan_template_sha256": plan_sha,
            "instruction_sha256": sha_file(prompt_paths[ordinal - 1]),
            "mutation_profile_sha256": sha_bytes(jcs(allowed)), "resource_profile_sha256": resource,
            "nq_profile_template_sha256": nq_sha, "does_not_establish": NONCLAIMS,
        })
        prior_reservation = str(reservation["reservation_id"])
        stages.append({
            "stage_id": f"stage-{ordinal}", "ordinal": ordinal,
            "logical_attempt_id": f"glass-heron-real-attempt-{ordinal}",
            "work_schema": f"glass-heron.stage-{ordinal}/v1", "work": works[ordinal - 1],
            "instruction_sha256": reservation["instruction_sha256"],
            "mutation_profile_sha256": reservation["mutation_profile_sha256"],
            "resource_profile_sha256": resource, "worker_session_manifest_sha256": manifest_sha,
            "executor_plan_template": plan, "executor_plan_template_sha256": plan_sha,
            "nq_profile_template": nq, "nq_profile_template_sha256": nq_sha,
            "reservation": reservation,
        })
    packet = {
        "schema": "ag.governed-campaign.packet/v1", "packet_id": "",
        "campaign_id": campaign_id, "repository_id": repository_id,
        "workspace": str(FIXTURE), "repository_ref": "refs/heads/main", "stages": stages,
    }
    packet["packet_id"] = domain("ag.governed-campaign.packet/v1", packet)
    write(OUT / "packet.v1.json", packet)
    preparation = {
        "schema": "ag.glass-heron.packet-preparation/v1",
        "campaign": "GLASS-HERON", "slug": "gcl-v1-w7-w8-real-codex-specimen-reconcile",
        "decision": "packet prepared; execution not started",
        "does_not_establish": ["human start verification", "session availability", "authority", "execution", "qualification"],
        "campaign_packet_id": packet["packet_id"], "stage_1_work": works[0],
        "session_manifest_sha256": manifest_sha,
    }
    # GH_START must come from the actual separately verified operator decision.
    # Regeneration must not mint a new human-start claim from an old campaign.
    write(OUT / "packet-preparation.v1.json", preparation)
    custody = {
        "schema": "ag.glass-heron.pre-stage1-custody/v1", "packet_id": packet["packet_id"],
        "packet_sha256": sha_file(OUT / "packet.v1.json"),
        "reservations": [stage["reservation"]["reservation_id"] for stage in stages],
        "future_porter_run_ids": None, "future_executor_receipts": None,
        "future_docket_settlements": None, "future_nq_receipts": None,
        "future_result_heads": None, "fixture_initial_head": initial_head,
        "fixture_initial_tree": initial_tree, "producer_executable_sha256": sha_file(PRODUCER),
        "worker_session": session_id, "worker_session_manifest_sha256": manifest_sha,
    }
    write(OUT / "pre-execution-custody.v1.json", custody)
    print(json.dumps(custody, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"GLASS-HERON PACKET REFUSAL: {error}", file=sys.stderr)
        raise SystemExit(1)
