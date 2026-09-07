# Operator-beta systemd D-Bus backend V1 — implementation checkpoint

Status: **READY FOR INDEPENDENT CODE AUDIT / LIVE VM QUALIFICATION NOT RUN**

This checkpoint implements the accepted M1A contract at
`docs/operator-beta-systemd-dbus-backend-v1.md` on the exact contract parent
`60de056e32b4c070de050dabcc5e836d4c017aad`. It does not qualify, publish,
deploy, or activate the backend.

## Implemented boundary

- Legacy `EffectExecutorPlanV1` loading, identity, unavailable-systemd result,
  and terminal replay remain unchanged.
- `EffectExecutorSystemdPlanV2` is machine-, timeout-, attempt-store-, and
  work-bound and is selected only with the explicit `systemd-dbus` feature.
- The V2 driver uses the local system bus, records exact bounded D-Bus message
  bytes, subscribes to `JobRemoved` before `StartUnit`, and keeps
  pre-transmission failure separate from post-transmission indeterminate
  outcomes.
- One exclusive attempt-store lock serializes mechanics. Evidence and the
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

- focused Rust adapter replay: 22 passed; one schema fixture emitter ignored;
- CLI transport qualification: 1 passed;
- Draft 2020-12 schema/runtime parity: 8 passed;
- the operator-beta boundary gate and deterministic injected negative control;
- feature-enabled release build and dependency/isolation inspection;
- attributable all-target Clippy with accepted-base lint allowances;
- the full workspace suite serially, excluding only worker fixtures reproduced
  as environment failures on the exact accepted parent.

The accepted-base authority-surface gate remains red because two
`campaign-driver-ng` references already exist unchanged in
`governed_campaign_v1.rs`. This checkpoint does not alter or waive that debt.

## Explicitly not run or claimed

No system-bus call, systemd unit action, disposable VM exercise, provider
contact, deployment, service activation, Docket process integration, or
production target mutation was performed. No present postcondition is claimed.
A successful owner receipt would remain enactment testimony; fresh target-local
systemd state and controller-vantage HTTP evidence are separate M1A
live-qualification inputs.

The next lawful transition is independent code audit of the exact checkpoint.
Only an accepted code result may proceed to the isolated Debian 12 M1A package
and disposable-VM matrix defined by the parent campaign records.
