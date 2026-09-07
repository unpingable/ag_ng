# Operator-beta systemd D-Bus backend V1 — M1A owner result

Status: **QUALIFIED FOR THE BOUNDED M1A OWNER SCOPE / PUBLICATION NOT ASSERTED
BY THIS ARTIFACT**

The runtime parent `3dd6cbd394e05b4ba3ac2504cebd11a75996fcae` and package
correction `4f64dbe551356b7cc891134f51ec03fc3c856c9f` are independently
accepted. The bounded owner result qualifies that exact package subject and
tree; it does not qualify Docket integration, classic NQ observation,
production deployment, or current target state after restart. Publication is
repository custody and is not inferred by this result artifact.

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

The implementation and result passed:

- focused Rust adapter replay: 24 passed; one schema fixture emitter ignored;
- CLI transport qualification: 1 passed;
- Draft 2020-12 schema/runtime/package/receipt qualification: 13 passed;
- the operator-beta boundary gate and deterministic injected negative control;
- feature-enabled release build and dependency/isolation inspection;
- attributable all-target Clippy with accepted-base lint allowances;
- the full workspace suite serially, excluding only worker fixtures reproduced
  as environment failures on the exact accepted parent.

The accepted-base authority-surface gate remains red because two
`campaign-driver-ng` references already exist unchanged in
`governed_campaign_v1.rs`. This checkpoint does not alter or waive that debt.

## Live package qualification and remaining exclusions

Run-004 constructed and installed the campaign-owned binary package on an
isolated Debian 12 local VM. The fixed target started once, duplicate execute
and reconcile replayed the exact terminal result without mechanics, package
remove/reinstall preserved the invocation and store, and a cold restart kept
historical enactment distinct from the newly observed inactive target. The
package, target, guest data, store, backup, VM process, and forwarded listeners
were removed; controller evidence remains for audit.

The full Debian source-package build through `dpkg-buildpackage` remains
NOT_RUN because the controller lacks the declared Debian build dependencies.
Docket process integration, AG authorization consumption, classic NQ
observation, Nightshift launch, provider/model work, production deployment,
general systemd actions, literal physical exactly-once execution, and the
post-restart current postcondition remain unqualified. See
[`QUALIFICATION.md`](QUALIFICATION.md) and the closed
[`qualification-receipt.v1.json`](qualification-receipt.v1.json).

The next lawful transition is independent audit of the exact non-rewriting
M1A result. An accepted result may be published to its established campaign
remote; it does not authorize a default-branch merge, deployment, or target
activation.
