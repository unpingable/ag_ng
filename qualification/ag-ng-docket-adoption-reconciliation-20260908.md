# AG-ng + Docket adoption successor reconciliation — 2026-09-08

**Status:** `READY_FOR_INDEPENDENT_AUDIT`

## Exact custody

- AG-ng subject: `837de287497942c79966aa05c083acee9c312261`.
- AG-ng tree: `20023de0b8299fa125ed5f9fcaf63383a4978e30`.
- Prior accepted/published integration result:
  `a05f7410cee0cca262d95ea198099f811091cc0f`.
- Docket dependency: accepted/published C2
  `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`, tree
  `19573c62de34efc4651b7af52bb9315339255194`.
- Integration branch:
  `campaign/constellation-operator-beta-ag-docket-adoption-integration-v1-20260907`.

The AG subject is a non-rewriting descendant of the prior integration result and retains
the original two-parent adoption/M1A history. It adds the independently accepted AG-owned
query-only systemd attempt-store audit. Docket source is unchanged. The original adoption,
M1A, integration, store-audit, and Docket qualifications remain attached to their exact
subjects; ancestry is not treated as transferred qualification.

## Fresh successor witness

Fresh locked debug builds completed for AG-ng `ag-effectd` and
`docket_file_harness`, and for Docket C2 `docket`. The exact built executable hashes were:

- AG `ag-effectd`: `ebeb3c4722e5764c00ac931ecb784ee892e16d7dc0962bd0c23e7dbc124c6d97`;
- AG `docket_file_harness`: `b9cfeb7ae1a89fac2bd981344745e1cd144210ea5f8a54a629b23c9dfbf749eb`;
- Docket `docket`: `a1c59b878624364e1f892f1ba906aacdde5cd91202f080b946a586c6f1d62211`.

The fresh four-case witness at
`/tmp/ag-ng-docket-reconciliation-20260908-g6FMat/run` reached:

- permitted: one AG spend, one Docket attempt, one settlement, effect present;
- refusal: zero AG spends and no effect;
- duplicate: identical custody and one Docket attempt;
- acknowledgement loss: effect present while Docket was indeterminate, followed by AG
  restart and same-attempt reconcile to `SettledObservationRequired`, with one spend, one
  attempt, and one settlement.

`summary.json` is 1,255 bytes with SHA-256
`1eb9edd7073b8ccfe69580f93f5afa568d2d2683aee339d04135c9b57b483760`.
Docket's query-only `governed-loop inspect` reopened permitted issuance
`sha256:198fdeafa38037abe5a28389f4a8ec012f17c307b1527f8b797980d0bed316c8`
as exact settled custody. Its reproducible canonical output is 3,022 bytes with SHA-256
`fae843340daec3c3e51236bb8090e18e23801f670a60f80e9648d29ead3f00b8`.

## Proportional regression

- AG governed-loop engine: 42 passed, 1 intentional fixture-writer ignore.
- Docket governed-loop filter: 17 passed.
- AG operator-beta systemd owner gate: 28 Rust passed, 1 intentional ignore; 3 CLI cases
  passed; 13 Python cases passed; structural boundary gate passed.
- Locked AG and Docket builds passed.

The observed environment was x86-64 Linux 6.5.0 with Rust 1.94.0 and Cargo 1.94.0.
Both source worktrees were clean at the exact subjects before and after qualification.

## Scope and next gate

This checkpoint establishes only that the existing managed-file adoption path still
composes with exact Docket C2 after the accepted AG store-audit owner changes. The new
store-audit interface is not exercised by the managed-file witness. This result does not
qualify the pending Docket/systemd composed occurrence, transfer any predecessor
certificate, prove a current postcondition, invoke NQ-ng, deploy a service, contact a
provider, or establish production placement.

Independent review must reproduce the exact ancestry, source cleanliness, four cases,
query-only Docket reopen, and proportional gates before this successor pin is accepted or
published.
