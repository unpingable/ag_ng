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
`769c92939a7668140e3f2c835f2c0d7d0115748e408de9ae7d2af735a3b4f8bc`.

Observed local validation:

- `python3 -m unittest discover -s crates/ag-operator-ui/demo -p 'test_*.py' -v`:
  15 passed, final run 4.662 seconds. HTTP cases used approved ephemeral
  loopback sockets. Initial sandbox socket denial was an environment refusal,
  followed by the same test invocation with platform approval.
- `node --check qualification/operator-beta-m2-demo/browser_exercise.cjs`:
  passed.
- `git diff --check`: passed for tracked changes; final staged check is required
  before committing these new files.

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
