#!/usr/bin/python3
"""Authority-free persistent mechanics for one three-attempt GCL V1 worker."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

REQUEST_SCHEMA = "ag.gcl-v1-worker-request/v1"
OUTCOME_SCHEMA = "ag.gcl-v1-worker-outcome/v1"
JOURNAL_SCHEMA = "ag.gcl-v1-worker-journal/v1"
STATE = Path("/var/lib/gcl-state")
CREDS = Path("/var/lib/gcl-credentials/codex")
JOURNAL = STATE / "journal" / "attempts.json"
LOCK = STATE / "journal" / "attempts.lock"
ATTEMPTS = STATE / "attempts"
INBOX = STATE / "inbox"
CODEX = Path("/usr/local/libexec/gcl/codex")
BWRAP = Path("/usr/local/libexec/gcl/bwrap")
MODEL = "gpt-5.6-sol"
EFFORT = "medium"
CODEX_SHA256 = "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40"
BWRAP_SHA256 = "77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
HEX_RE = re.compile(r"^[0-9a-f]{40,64}$")


class Refusal(RuntimeError):
    """A factual-mechanics refusal, never a qualification verdict."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def emit(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_bytes(value))
    sys.stdout.flush()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    uid: int | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command = argv
    if uid is not None:
        command = [
            "/usr/bin/setpriv",
            f"--reuid={uid}",
            f"--regid={uid}",
            "--clear-groups",
            "--",
            *argv,
        ]
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=True,
        text=True,
        capture_output=True,
    )


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_journal() -> dict[str, Any]:
    if not JOURNAL.exists():
        return {"schema": JOURNAL_SCHEMA, "attempts": []}
    value = json.loads(JOURNAL.read_bytes())
    if value.get("schema") != JOURNAL_SCHEMA or not isinstance(value.get("attempts"), list):
        raise Refusal("worker journal malformed")
    return value


def save_journal(value: dict[str, Any]) -> None:
    JOURNAL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = JOURNAL.with_suffix(".new")
    with temporary.open("wb") as handle:
        handle.write(canonical_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, JOURNAL)
    fsync_dir(JOURNAL.parent)


class JournalLock:
    def __enter__(self) -> "JournalLock":
        LOCK.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.handle = LOCK.open("a+b")
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_: object) -> None:
        fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()


def session_id() -> str:
    value = Path("/run/gcl-session-id").read_text().strip()
    if not ID_RE.fullmatch(value):
        raise Refusal("invalid QEMU session identity")
    return value


def exact_request_path(raw_value: str) -> Path:
    path = Path(raw_value).resolve(strict=True)
    if path.parent.parent != INBOX or path.name != "request.json":
        raise Refusal("request path outside exact inbox")
    if path.is_symlink() or not path.is_file():
        raise Refusal("request is not a regular file")
    return path


def load_request(raw_value: str) -> tuple[Path, dict[str, Any], str]:
    path = exact_request_path(raw_value)
    request = json.loads(path.read_bytes())
    required = {
        "schema",
        "session_id",
        "attempt_id",
        "marker",
        "ordinal",
        "bundle_path",
        "bundle_sha256",
        "prompt_path",
        "prompt_sha256",
        "base_commit",
        "base_tree",
        "allowed_paths",
        "model",
        "effort",
        "timeout_seconds",
    }
    if set(request) != required or request.get("schema") != REQUEST_SCHEMA:
        raise Refusal("request schema or fields mismatch")
    if request["session_id"] != session_id():
        raise Refusal("session substitution")
    for key in ("attempt_id", "marker"):
        if not isinstance(request[key], str) or not ID_RE.fullmatch(request[key]):
            raise Refusal(f"invalid {key}")
    if request["ordinal"] not in (1, 2, 3):
        raise Refusal("attempt capacity is exactly three")
    if request["model"] != MODEL or request["effort"] != EFFORT:
        raise Refusal("Codex profile substitution")
    timeout = request["timeout_seconds"]
    if not isinstance(timeout, int) or not 60 <= timeout <= 3600:
        raise Refusal("worker timeout outside frozen bounds")
    for key in ("bundle_sha256", "prompt_sha256"):
        if not isinstance(request[key], str) or not re.fullmatch(r"[0-9a-f]{64}", request[key]):
            raise Refusal(f"invalid {key}")
    for key in ("base_commit", "base_tree"):
        if not isinstance(request[key], str) or not HEX_RE.fullmatch(request[key]):
            raise Refusal(f"invalid {key}")
    allowed = request["allowed_paths"]
    if not isinstance(allowed, list) or not allowed or len(allowed) > 16:
        raise Refusal("invalid allowed mutation paths")
    for item in allowed:
        if (
            not isinstance(item, str)
            or item in ("", ".")
            or item.startswith("/")
            or ".." in Path(item).parts
        ):
            raise Refusal("unsafe allowed mutation path")
    for field, filename, digest_field in (
        ("bundle_path", "predecessor.bundle", "bundle_sha256"),
        ("prompt_path", "prompt.txt", "prompt_sha256"),
    ):
        artifact = Path(request[field]).resolve(strict=True)
        if artifact.parent != path.parent or artifact.name != filename or artifact.is_symlink():
            raise Refusal(f"unsafe {field}")
        if sha256_path(artifact) != request[digest_field]:
            raise Refusal(f"{field} digest mismatch")
    digest = hashlib.sha256(canonical_bytes(request)).hexdigest()
    return path, request, digest


def find_attempt(journal: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    for attempt in journal["attempts"]:
        if attempt["attempt_id"] == request["attempt_id"] or attempt["marker"] == request["marker"]:
            return attempt
    return None


def public_outcome(attempt: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "session_id",
        "attempt_id",
        "marker",
        "ordinal",
        "request_sha256",
        "state",
        "worker_invocations",
        "codex_exit_code",
        "transcript_sha256",
        "candidate_path",
        "candidate_sha256",
        "candidate_head",
        "candidate_tree",
        "changed_paths",
        "detail",
    )
    value = {"schema": OUTCOME_SCHEMA}
    value.update({key: attempt.get(key) for key in keys})
    return value


def identity() -> None:
    root = json.loads(
        run(["/usr/bin/findmnt", "-J", "-o", "SOURCE,FSTYPE,OPTIONS", "/"]).stdout
    )["filesystems"][0]
    emit(
        {
            "schema": "ag.gcl-v1-worker-identity/v1",
            "session_id": session_id(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "machine_id": Path("/etc/machine-id").read_text().strip(),
            "root_mount": root,
            "agent_sha256": sha256_path(Path(__file__).resolve()),
            "codex_sha256": sha256_path(CODEX),
            "bwrap_sha256": sha256_path(BWRAP),
            "codex_version": run([str(CODEX), "--version"]).stdout.strip(),
            "capacity": 3,
        }
    )


def auth_status() -> None:
    environment = {
        "HOME": "/home/gcl-parent",
        "USER": "gcl-parent",
        "LOGNAME": "gcl-parent",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "CODEX_HOME": str(CREDS),
    }
    result = subprocess.run(
        [str(CODEX), "login", "status"],
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    text = f"{result.stdout}\n{result.stderr}".lower()
    method = "chatgpt" if result.returncode == 0 and "chatgpt" in text else "unrecognized"
    emit(
        {
            "schema": "ag.gcl-v1-worker-auth-status/v1",
            "authenticated": result.returncode == 0 and method == "chatgpt",
            "method": method,
            "exit_code": result.returncode,
        }
    )


def update_attempt(attempt_id: str, **fields: Any) -> dict[str, Any]:
    with JournalLock():
        journal = load_journal()
        attempt = next((a for a in journal["attempts"] if a["attempt_id"] == attempt_id), None)
        if attempt is None:
            raise Refusal("attempt journal disappeared")
        attempt.update(fields)
        save_journal(journal)
        return dict(attempt)


def reserve(request: dict[str, Any], digest: str) -> tuple[dict[str, Any], bool]:
    with JournalLock():
        journal = load_journal()
        prior = find_attempt(journal, request)
        if prior is not None:
            if prior["request_sha256"] != digest:
                raise Refusal("conflicting exact replay")
            return dict(prior), False
        if len(journal["attempts"]) >= 3 or request["ordinal"] != len(journal["attempts"]) + 1:
            raise Refusal("attempt ordinal or three-attempt capacity refusal")
        attempt = {
            "session_id": request["session_id"],
            "attempt_id": request["attempt_id"],
            "marker": request["marker"],
            "ordinal": request["ordinal"],
            "request_sha256": digest,
            "state": "reserved",
            "worker_invocations": 1,
            "reserved_at_ns": time.time_ns(),
        }
        journal["attempts"].append(attempt)
        save_journal(journal)
        return dict(attempt), True


def current(request: dict[str, Any], digest: str) -> dict[str, Any]:
    with JournalLock():
        journal = load_journal()
        attempt = find_attempt(journal, request)
        if attempt is None:
            return {
                "schema": OUTCOME_SCHEMA,
                "session_id": request["session_id"],
                "attempt_id": request["attempt_id"],
                "marker": request["marker"],
                "ordinal": request["ordinal"],
                "request_sha256": digest,
                "state": "absent",
                "worker_invocations": 0,
                "detail": "no exact attempt exists",
            }
        if attempt["request_sha256"] != digest:
            raise Refusal("conflicting exact replay")
        return public_outcome(attempt)


def start_unit(path: Path, request: dict[str, Any]) -> None:
    unit = f"gcl-worker-attempt-{request['ordinal']}-{request['attempt_id'][:12]}"
    environment = dict(os.environ)
    environment["XDG_RUNTIME_DIR"] = "/run/user/2000"
    result = subprocess.run(
        [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--collect",
            f"--unit={unit}",
            "--property=KillMode=control-group",
            "--property=TasksMax=256",
            "--property=MemoryMax=6G",
            "--property=TimeoutStopSec=20s",
            str(Path(__file__).resolve()),
            "internal-run",
            str(path),
        ],
        env=environment,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        update_attempt(
            request["attempt_id"],
            state="indeterminate",
            detail="guest attempt unit did not start",
            unit_start_exit=result.returncode,
        )
        raise Refusal("guest attempt unit did not start")


def execute(raw_path: str) -> None:
    path, request, digest = load_request(raw_path)
    _, created = reserve(request, digest)
    if created:
        start_unit(path, request)
    deadline = time.monotonic() + request["timeout_seconds"] + 30
    while time.monotonic() < deadline:
        outcome = current(request, digest)
        if outcome["state"] in ("completed", "failed", "indeterminate"):
            emit(outcome)
            return
        time.sleep(1)
    emit(current(request, digest))


def reconcile(raw_path: str) -> None:
    _, request, digest = load_request(raw_path)
    emit(current(request, digest))


def prepare_workspace(request: dict[str, Any]) -> tuple[Path, Path, Path]:
    attempt_root = ATTEMPTS / request["attempt_id"]
    repo = attempt_root / "repo"
    transcript = attempt_root / "codex.jsonl"
    if attempt_root.exists():
        raise Refusal("fresh attempt workspace already exists")
    attempt_root.mkdir(mode=0o755, parents=True)
    transcript.touch(mode=0o600)
    bundle = Path(request["bundle_path"])
    run(["/usr/bin/git", "clone", "--no-checkout", str(bundle), str(repo)], uid=2000)
    run(["/usr/bin/git", "remote", "remove", "origin"], cwd=repo, uid=2000)
    run(["/usr/bin/git", "checkout", "--detach", request["base_commit"]], cwd=repo, uid=2000)
    head = run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=repo, uid=2000).stdout.strip()
    tree = run(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], cwd=repo, uid=2000).stdout.strip()
    if head != request["base_commit"] or tree != request["base_tree"]:
        raise Refusal("wrong predecessor in guest workspace")
    run(["/usr/bin/git", "config", "user.name", "GCL V1 Worker"], cwd=repo, uid=2000)
    run(
        ["/usr/bin/git", "config", "user.email", "gcl-v1-worker@invalid"],
        cwd=repo,
        uid=2000,
    )
    return attempt_root, repo, transcript


def internal_run(raw_path: str) -> None:
    _, request, digest = load_request(raw_path)
    with JournalLock():
        journal = load_journal()
        attempt = find_attempt(journal, request)
        if attempt is None or attempt["request_sha256"] != digest:
            raise Refusal("internal runner lacks exact reservation")
        if attempt["state"] != "reserved":
            raise Refusal("internal runner cannot repeat an attempt")
        attempt.update(
            state="running",
            started_at_ns=time.time_ns(),
            runner_pid=os.getpid(),
        )
        save_journal(journal)

    try:
        attempt_root, repo, transcript = prepare_workspace(request)
        environment = {
            "HOME": "/home/gcl-parent",
            "USER": "gcl-parent",
            "LOGNAME": "gcl-parent",
            "SHELL": "/usr/local/bin/bash",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "CODEX_HOME": str(CREDS),
            "GCL_WORKSPACE": str(repo),
        }
        argv = [
            str(CODEX),
            "exec",
            "--json",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--sandbox",
            "workspace-write",
            "--ask-for-approval",
            "never",
            "-C",
            str(repo),
            "-m",
            MODEL,
            "-c",
            f'model_reasoning_effort="{EFFORT}"',
            "-",
        ]
        with transcript.open("wb") as output:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.STDOUT,
                env=environment,
                start_new_session=True,
            )
            update_attempt(request["attempt_id"], codex_pid=process.pid)
            try:
                process.communicate(
                    Path(request["prompt_path"]).read_bytes(),
                    timeout=request["timeout_seconds"],
                )
                codex_exit = process.returncode
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, 15)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, 9)
                    process.wait()
                codex_exit = None
            output.flush()
            os.fsync(output.fileno())

        transcript_digest = sha256_path(transcript)
        if codex_exit is None:
            update_attempt(
                request["attempt_id"],
                state="indeterminate",
                codex_exit_code=None,
                transcript_sha256=transcript_digest,
                detail="Codex timeout; no candidate admitted",
                completed_at_ns=time.time_ns(),
            )
            return
        if codex_exit != 0:
            update_attempt(
                request["attempt_id"],
                state="failed",
                codex_exit_code=codex_exit,
                transcript_sha256=transcript_digest,
                detail="Codex returned nonzero",
                completed_at_ns=time.time_ns(),
            )
            return

        dirty = run(
            ["/usr/bin/git", "status", "--porcelain=v1", "-z"], cwd=repo, uid=2000
        ).stdout
        if dirty:
            run(["/usr/bin/git", "add", "-A"], cwd=repo, uid=2000)
            commit_environment = dict(os.environ)
            commit_environment.update(
                {
                    "GIT_AUTHOR_NAME": "GCL V1 Worker",
                    "GIT_AUTHOR_EMAIL": "gcl-v1-worker@invalid",
                    "GIT_AUTHOR_DATE": f"2001-01-0{request['ordinal']}T00:00:00+00:00",
                    "GIT_COMMITTER_NAME": "GCL V1 Worker",
                    "GIT_COMMITTER_EMAIL": "gcl-v1-worker@invalid",
                    "GIT_COMMITTER_DATE": f"2001-01-0{request['ordinal']}T00:00:00+00:00",
                }
            )
            run(
                [
                    "/usr/bin/git",
                    "commit",
                    "-m",
                    f"GCL V1 stage {request['ordinal']} candidate",
                ],
                cwd=repo,
                uid=2000,
                environment=commit_environment,
            )
        head = run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=repo, uid=2000).stdout.strip()
        if head == request["base_commit"]:
            update_attempt(
                request["attempt_id"],
                state="failed",
                codex_exit_code=codex_exit,
                transcript_sha256=transcript_digest,
                detail="zero exit with no candidate commit",
                completed_at_ns=time.time_ns(),
            )
            return
        ancestor = subprocess.run(
            ["/usr/bin/git", "merge-base", "--is-ancestor", request["base_commit"], head],
            cwd=repo,
        )
        if ancestor.returncode != 0:
            raise Refusal("candidate does not descend from predecessor")
        candidate = attempt_root / "candidate.bundle"
        run(
            [
                "/usr/bin/git",
                "bundle",
                "create",
                str(candidate),
                "HEAD",
                f"^{request['base_commit']}",
            ],
            cwd=repo,
            uid=2000,
        )
        changed = run(
            [
                "/usr/bin/git",
                "diff",
                "--name-only",
                "-z",
                request["base_commit"],
                head,
            ],
            cwd=repo,
            uid=2000,
        ).stdout.split("\0")
        changed = [item for item in changed if item]
        tree = run(
            ["/usr/bin/git", "rev-parse", f"{head}^{{tree}}"], cwd=repo, uid=2000
        ).stdout.strip()
        update_attempt(
            request["attempt_id"],
            state="completed",
            codex_exit_code=codex_exit,
            transcript_sha256=transcript_digest,
            candidate_path=str(candidate),
            candidate_sha256=sha256_path(candidate),
            candidate_head=head,
            candidate_tree=tree,
            changed_paths=changed,
            detail="courier candidate produced; no qualification claim",
            completed_at_ns=time.time_ns(),
        )
    except Exception as error:
        update_attempt(
            request["attempt_id"],
            state="indeterminate",
            detail=f"worker mechanics exception: {type(error).__name__}",
            completed_at_ns=time.time_ns(),
        )
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    children = parser.add_subparsers(dest="command", required=True)
    children.add_parser("identity")
    children.add_parser("auth-status")
    for name in ("execute", "reconcile", "internal-run"):
        child = children.add_parser(name)
        child.add_argument("request")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "identity":
            identity()
        elif args.command == "auth-status":
            auth_status()
        elif args.command == "execute":
            execute(args.request)
        elif args.command == "reconcile":
            reconcile(args.request)
        else:
            internal_run(args.request)
        return 0
    except Refusal as error:
        print(f"gcl-worker-agent refusal: {error}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
