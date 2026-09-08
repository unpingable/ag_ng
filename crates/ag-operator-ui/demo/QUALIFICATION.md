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
`19d72bce3c0d692179286e46cfbfa36ab10dde182ef85e10f1f183c1f9cdfd1c`.

This correction succeeds the independently rejected screen revision
`a6eff2dcbab32a02436b50624d55a0376f00224e`. Its earlier display evidence remains
attached to that original source; it does not establish acceptance here.

Observed local validation:

- `python3 -m unittest discover -s crates/ag-operator-ui/demo -p 'test_*.py' -v`:
  17 passed, final correction run 5.226 seconds. HTTP cases used approved ephemeral
  loopback sockets. Initial sandbox socket denial was an environment refusal,
  followed by the same test invocation with platform approval.
- `node --check qualification/operator-beta-m2-demo/browser_exercise.cjs`:
  passed.
- `git diff --check`: passed.
- Actual Docket owner `FixedController.status()` with its own local fixture and
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
