# M2 screen candidate qualification boundary

Date: 2026-09-08. Status: **local adapter/display qualification only;
independent and integrated acceptance pending**.

The AG-ng candidate starts at the reconciled adoption revision
`44271684f6fb647620d8cade291814dadd08be18`. The separate screen consumes the
Docket `constellation.operator_beta.fixed_demo_status.v1` interface and its
closed `start`/`status` commands. Final controller implementation pins and the
integrated acceptance record are owned by the main M2 campaign. Earlier M1
acceptance remains attached to its original revisions.

The exact `fixed_demo.py` bytes tested here have SHA-256
`63a43bff807849ca8e35048899ab5385ba72fef84cb4daeb3f1a38d0c140ba18`.

The current bounded correction succeeds independently rejected
`215a1955a4bf6771408cc1d4aaf5222b92f8b47c`. It constant-time compares the returned
controller digest with the digest admitted by this adapter, rejects a
well-formed wrong digest, and corrects the remaining HTTP refusal fixture to
the same NQ-ng owner / Docket validator shape already required by the adapter.

This successor adds explicit refusal owner/validator attribution and captured
execution-source identity to the locally accepted screen revision
`5cec943c25e28f47069f7bf6bdf8c81be9fb6637`, which corrected the independently
rejected `a6eff2dcbab32a02436b50624d55a0376f00224e`. Earlier evidence and
acceptance remain attached to their original source bytes.

Observed local validation:

- `python3 -m unittest discover -s crates/ag-operator-ui/demo -p 'test_*.py' -v`:
  20 passed, final correction run 5.322 seconds. HTTP cases used approved ephemeral
  loopback sockets. Initial sandbox socket denial was an environment refusal,
  followed by the same test invocation with platform approval.
- `node --check qualification/operator-beta-m2-demo/browser_exercise.cjs`:
  passed.
- `git diff --check`: passed.
- Current source accepted the frozen Docket `d3ff31c…` status fixture at
  controller SHA-256
  `181b2aabe12e10f519004d2ed3fb55f7d908f4cfa1475079d164a49380d48b09`:
  ten evidence entries, zero manager calls. No dependency worktree bytecode
  writes were permitted.
- Prior screen source `35099100…` accepted the corrected actual Docket owner status fixture
  at controller SHA-256
  `28b9c3604156da1a31680ba1d85b0b6d19cfad3d9017408cd448d942eea05c25`:
  ten evidence entries, zero manager calls. This is byte-specific development
  interoperability evidence; final controller acceptance and installation pins
  remain primary responsibilities.
- Prior screen source `19d72bce…` accepted actual Docket owner `FixedController.status()` with its own local fixture and
  `FakeManager` was accepted by the screen adapter: ten evidence entries, zero
  manager calls, controller source SHA-256
  `6c27354b6d50ad18e2ee49245bd50cf16c2f70d94cf43270eb3cde8949900a2d`.
  Reproduce with `qualification/operator-beta-m2-demo/check_owner_projection.py
  --docket-fixture ABSOLUTE_DOCKET_TEST_FIXED_DEMO_CONTROLLER_PATH` using Python.

Correction coverage includes missing/incompatible source shapes, evidence,
execution identity, digests, enums and terminal records; a child that never
reads controller stdin is stopped by the shared transfer/reply deadline.
Browser qualification additionally checks an observed terminal receipt followed
by source outage: all current-value regions become `NOT_OBSERVABLE`.
Additional cases require NQ-ng as the refusal-record owner and Docket as its
validator, and prove the executing controller receives the hash of its retained
source bytes even after the source pathname changes. The bootstrap supplies
`__executed_source_sha256__`; it does not derive that identity from a later
pathname read.

These tests establish bounded adapter behavior using explicitly labeled local
fixtures: source admission, retained controller bytes despite pathname
replacement, closed HTTP delegation, repeated requests, read-only refresh,
separate position/liveness, ordinary refusal rendering, source disagreement and
unavailability. The fixture controller supplies the one-occurrence behavior in
the HTTP test; Docket's own qualification must establish that behavior for the
real execution mechanism.

The sibling adds no Rust changes. The existing Phosphor-ng GET/HEAD regression
gate remains a prerequisite in the primary campaign's durable validation run.
No VM, real controller start, effect, provider, external deployment, or
publication was performed by this implementation lane. Browser display fixture
captures are additional display evidence, never integrated execution evidence.
