# Canonical governed repair development ledger

Status: live development ledger; not qualification evidence.

## Bootstrap and design basis

This implementation campaign was authorized by the repository operator's
external human development instruction. The governed loop did not exist as a
canonical authority seam when that instruction was issued, so it did not and
cannot govern its own construction. The NQ C1 records used by tests are
immutable hostile specimens, not reconstructed AG or Docket authority.

Before implementation, the bounded design was:

- AG owns exact proposals and immutable occurrence scope, observation,
  standing, decision, one-use spend and issuance, durable program-counter
  transitions, reconciliation, human-decision requests, verified disposition
  consumption, successor creation, refusal, residuals, and escalation.
- Docket owns issuance acceptance/refusal, execution custody and attempt,
  effect journals, immutable checkpoint verification, exact executor results,
  sealed post-spend requirements, replay, and unknown-result reconciliation.
- A post-spend scope discovery halts the predecessor. Approval can only create
  an authority-empty successor with the exact additive delta; it never edits or
  resumes the predecessor. Readjudication is read-only and cannot become a
  wildcard repair grant.
- Product clients use versioned AG DTOs with expected-state and idempotency
  semantics. Deployment-owned clock, observation, standing, admissibility,
  Docket, signing, and verifier inputs are pinned at campaign genesis rather
  than supplied by each caller.

## Initial path census

The pre-edit census identified these directly necessary areas:

- AG kernel and public schemas: `crates/ag-campaign/src/governed.rs` and its
  governed-loop and NQ-fixture tests.
- AG persistence and replay: `crates/ag-store/src/campaign.rs`, its migration
  and store tests.
- AG application/product/CLI boundaries: `crates/ag-app/src/governed_loop.rs`,
  `governed_ports.rs`, `governed_product.rs`, `effect_executor_adapter.rs`,
  `ag-loopctl.rs`, and their integration tests.
- AG developer and operational truth: the two canonical governed-repair docs,
  campaign-office status doc, and `qualification/operational/` harness records.
- Docket public governed-repair schema, local custody store/CLI, migrations,
  exact executor adapter, fixtures, tests, and governed-runtime documentation.

New files in those areas are permitted only when they implement or defend the
same seam. No NQ, Gen4, Nightshift, Maude, Monitor, Pulse, trust-root, remote,
deployment, or external authority state belongs in this scope.

## Live scope rule

Every modified path must implement one of: canonical schema/state; durable
storage or migration; exact external boundary; stable product/CLI surface;
hostile, crash, replay, concurrency, mutation, or integration evidence; or
truthful developer/operational documentation. The final evidence bundle will
record the exact committed path inventory and command results. Additional
directly necessary AG or Docket paths are recorded, not treated as ambient
repository authority.

## Final AG path census

The completed AG change set contains these closed groups:

- Kernel and schemas: `crates/ag-campaign/src/governed.rs`,
  `crates/ag-campaign/src/external_repair_specimen.rs`, and
  `crates/ag-campaign/src/lib.rs`.
- Durable Store and replay: `crates/ag-store/src/campaign.rs` and
  `crates/ag-store/tests/governed_campaign_store.rs`.
- Product, CLI, and exact external boundaries:
  `crates/ag-app/src/bin/ag-loopctl.rs`,
  `crates/ag-app/src/effect_executor_adapter.rs`,
  `crates/ag-app/src/governed_loop.rs`,
  `crates/ag-app/src/governed_ports.rs`,
  `crates/ag-app/src/governed_product.rs`, and `crates/ag-app/src/lib.rs`.
- Executable/model evidence: `crates/ag-campaign/tests/governed_loop.rs`,
  `crates/ag-campaign/tests/nq_c1_repair_specimens.rs`,
  `crates/ag-app/tests/governed_docket_process.rs`,
  `crates/ag-app/tests/governed_loop_engine.rs`,
  `crates/ag-app/tests/governed_product.rs`,
  `crates/ag-app/tests/governed_repair_docket_process.rs`, and
  `crates/ag-app/tests/nq_c1_governed_repair_lifecycle.rs`.
- Immutable hostile fixture files: every file under
  `crates/ag-campaign/tests/fixtures/nq-c1/` (four canonical JSON specimens,
  `DIGESTS.txt`, and `README.md`).
- Developer truth: `docs/campaign-orchestration-office.md`,
  `docs/canonical-governed-repair.md`, `docs/nq-c1-repair-boundary.md`, and this
  ledger.
- Operational nonclaim/evidence harness:
  `qualification/operational/README.md`, `deployed-service-plan.json`,
  `fault-injection-plan.json`, `gates.json`, `run_local.py`, `self_test.py`, and
  `trusted-host-plan.json`.

No path outside AG or Docket was modified. Build output and the final external
development-evidence bundle are not source-tree state.
