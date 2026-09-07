# Operator-beta systemd D-Bus backend V1 — package checkpoint

Status: **PACKAGE CORRECTION READY FOR INDEPENDENT RE-AUDIT / LIVE PACKAGE
LIFECYCLE NOT RUN**

The runtime parent `3dd6cbd394e05b4ba3ac2504cebd11a75996fcae` is independently
accepted. The first package checkpoint
`ca8fa74fe55085acb9cb9f53bb5027e77b686884` is its exact non-rewriting child;
this correction retains that ancestry. It does not qualify, publish, deploy,
or activate the backend.

## Implemented boundary

- Legacy `EffectExecutorPlanV1` loading, identity, unavailable-systemd result,
  and terminal replay remain unchanged.
- `EffectExecutorSystemdPlanV2` is machine-, timeout-, attempt-store-, and
  work-bound and is selected only with the explicit `systemd-dbus` feature.
- The V2 driver uses the local system bus, records exact bounded D-Bus message
  bytes, subscribes to `JobRemoved` before `StartUnit`, and keeps
  pre-transmission failure separate from post-transmission indeterminate
  outcomes.
- One logical execution lock combines a stable derived sidecar lock with the
  attempt-store inode lock. The sidecar durably binds the exact store
  device/inode, and path identity is checked around SQLite access, so pathname
  replacement cannot split campaign-owned concurrent writers. Evidence and the
  terminal Docket receipt commit in one SQLite immediate transaction.
  Reconciliation reopens exact custody and never resumes mechanics.
- Evidence validation closes message shape/order, byte bounds, owner outcome
  codes, plan/dispatch bindings, append-only guards, and receipt agreement
  before accepting retained testimony.
- The CLI reads one bounded regular plan file with no pathname following,
  preserves Docket transport V1 stdout/stderr behavior, and maps bounded lock
  contention to exit 75 with `systemd_attempt_in_progress`.

## Repository-local qualification

The implementation checkpoint passed:

- focused Rust adapter replay: 24 passed; one schema fixture emitter ignored;
- CLI transport qualification: 1 passed;
- Draft 2020-12 schema/runtime/package parity: 9 passed;
- the operator-beta boundary gate and deterministic injected negative control;
- feature-enabled release build and dependency/isolation inspection;
- attributable all-target Clippy with accepted-base lint allowances;
- the full workspace suite serially, excluding only worker fixtures reproduced
  as environment failures on the exact accepted parent.

The accepted-base authority-surface gate remains red because two
`campaign-driver-ng` references already exist unchanged in
`governed_campaign_v1.rs`. This checkpoint does not alter or waive that debt.

## Explicitly not run or claimed

No `.deb` was constructed or installed for this checkpoint. Package
install/remove/reinstall, its before/after target-state and attempt-store cuts,
and package-origin execution remain NOT_RUN. No new system-bus call, systemd
unit action, provider contact, deployment, service activation, Docket process
integration, or production target mutation was performed by the package
checkpoint. The retained run-003 owner evidence is prior runtime qualification,
not package-lifecycle evidence and not a present-postcondition claim.

The next lawful transition is independent re-audit of the exact non-rewriting
package correction. Only an accepted result may construct the campaign-owned
binary package and proceed to the isolated Debian 12 install/remove/reinstall,
reconcile, and teardown matrix defined by the parent campaign records.
