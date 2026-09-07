# Operator-beta systemd D-Bus backend contract

**Recorded:** 2026-09-07
**Status:** `CONTRACT_CORRECTION_READY_FOR_INDEPENDENT_REAUDIT__RUNTIME_NOT_IMPLEMENTED`
**Owner:** AG-ng
**Owner base:** `81bcdf9819f0ee3c388e4d0d4502db4769dc315f`
**Release-basis acceptance:** Cartography
`2e9a7657c414bd6307efd09fa0104fc6fb92938c`

This is the M1A contract freeze for the fixed non-production systemd HTTP
service recovery. It does not activate a backend, authorize an effect, contact
the system bus, create a VM, or qualify the end-to-end beta path.

## Existing owner boundary

The accepted base already owns:

- closed `CanonicalEffectV1::SystemdUnit` semantics;
- exact unit, action, expected `ActiveState`, and expected `UnitFileState`;
- the `SystemdDbusBackendV1` capability boundary;
- Docket work/attempt/marker custody and terminal replay through
  `ag-effectd`; and
- separate succeeded, known-no-effect, and outcome-unknown receipt classes.

The beta must use this boundary. It must not introduce shell text, `systemctl`
arguments, arbitrary D-Bus methods, a new Docket effect family, ABSD, or UI
authority.

The accepted base is intentionally non-executable for systemd:
`effect_executor_adapter.rs` installs `UnavailableSystemdBackendV1`.
The separate AG broker in `effectd.rs` also refuses systemd observation and
execution. This M1A tranche wires only the authority-neutral Docket executor.
The native broker path remains unavailable until separately justified and
qualified.

## Contract gap discovered at M1 entry

`EffectExecutorPlanV1` binds the effect, subject, scope, attempt-store path,
artifacts, file policy, and effect index, but it does not bind the local
systemd machine identity. `SystemdUnitRequestV1` likewise contains only unit,
action, and expected unit properties. The same sealed plan could therefore be
presented to another machine and still satisfy the current pure binding law.

The success receipt carries a D-Bus evidence digest, but the current executor
store has no owner-addressable bytes behind that digest. A generated hash alone
does not satisfy the release requirement to reopen bounded manager evidence.

Both gaps must close before the backend may be enabled.

## Machine-bound plan successor and V1 preservation

Do not change `EffectExecutorPlanV1`, its schema, canonical bytes, identity,
validation, execution behavior, or replay law. In particular:

- existing non-systemd V1 plan vectors retain their exact identities;
- a machine-less V1 `SystemdUnit` plan remains decodable;
- a new V1 systemd delivery still returns the existing definite
  unavailable-backend failure; and
- a retained V1 systemd terminal receipt reopens and replays against the exact
  same V1 plan without a system-bus call.

Add a distinct `EffectExecutorSystemdPlanV2` with schema
`ag-effectd.docket-executor-systemd-plan/v2` and work schema
`ag-effectd.docket-executor-systemd-work/v2`. It retains the V1
attempt-store, subject, scope, effect-index, file-policy, and exact
`CanonicalEffectV1::SystemdUnit` fields, and adds one required
`systemd_machine_identity`. V2 accepts only that effect family and no
preparation checkpoint or artifacts.

The machine identity is the lowercase 32-hex value returned by the target
system bus. It participates in V2 canonicalization and work identity. The
backend compares the live peer identity before any unit method call. A coherent
machine-ID substitution therefore changes the sealed work and refuses before
invocation.

The loader discriminates V1 and V2 by exact schema before typed decoding.
Docket's outer transport remains
`docket.governed-executor-transport/v1`; its existing exact `work_schema`
field names the corresponding executor-owned V1 or V2 work schema. This does
not create a new Docket effect family or reinterpret a V1 plan.

## Backend activation

The production implementation is Linux-only and build-feature gated as
`systemd-dbus`. Default builds retain the unavailable backend. Even in a
feature-enabled binary, V1 plans retain the unavailable backend; only an exact
V2 systemd plan selects the real backend. A qualified package binds the exact
feature set and executable digest; there is no runtime environment toggle,
schema fallback, or automatic backend substitution.

The backend connects directly to the local system bus. The beta target catalog
admits exactly:

- machine: the target VM's retained machine ID;
- unit: `constellation-beta-http-fixture.service`;
- action: `start`;
- expected active state: `inactive`; and
- expected unit-file state: `disabled`.

Other closed enum actions remain known vocabulary but return
`systemd_action_not_qualified` before invocation in this tranche. Supporting
them later requires their own owner qualification; the beta does not widen
itself into a general service controller.

## Ordered operation and outcome law

For one Docket-reserved V2 attempt the backend performs:

1. connect to the local system bus;
2. obtain and compare the peer machine ID;
3. resolve the exact unit and read `ActiveState` and `UnitFileState`;
4. compare both properties to the sealed prestate;
5. subscribe to the exact manager job result;
6. begin one `StartUnit(unit, "replace")` call;
7. retain the returned exact job object path;
8. wait within the declared bounded deadline for the matching job result;
9. read the same unit properties again; and
10. commit evidence and the terminal Docket execution receipt atomically.

`Failed` is permitted only when retained evidence proves that step 6 was not
transmitted, including connection, identity, lookup, property, prestate, and
subscription failures, or when an explicitly allowlisted manager method-error
reply proves no job was queued. A generic call error is not proof of
non-transmission.

The uncertainty boundary begins when transmission of `StartUnit` is
attempted, not when its reply or job path is received. Every unproved
post-transmission cut is `Indeterminate`: send/reply loss, missing job path,
timeout, unmatched or malformed job testimony, non-`done` terminal job
result, poststate-read failure, or terminal-custody failure. No transport error
is promoted into a known no-effect result.

Only the matching `JobRemoved` result `done`, followed by exact poststate
reads and durable evidence custody, yields the existing typed
`SystemdUnitSuccessV1`. That receipt is enactment testimony. Even if its
resulting active state is `active`, it does not establish the beta
postcondition; fresh target-local systemd and controller-vantage HTTP evidence
remain required.

## Evidence custody

Add one content-addressed `ag-effectd.systemd-dbus-evidence/v1` record to the
existing executor attempt store for V2 attempts. It binds:

- Docket work, attempt, marker, and effect index;
- sealed machine identity, unit, action, and expected prestate;
- live peer machine identity;
- ordered observation/invocation/completion timestamps;
- decoded unit object path, prestate, job path, job result, and poststate;
- ordered exact D-Bus reply/signal bytes with message-kind labels; and
- a domain-separated digest over the canonical record.

Limits are fixed at 16 messages, 64 KiB per retained message, and 256 KiB
cumulative bytes. Count and length metadata are checked before BLOB
materialization. The record is append-only and unique per attempt. Its digest
is the existing `evidence` field in the typed execution receipt.

The evidence insert and terminal attempt-row update occur in one SQLite
`IMMEDIATE` transaction. The transaction either retains both the complete
evidence record and its referencing terminal receipt or neither. A fault
between insert and update rolls back to the pre-existing `started` row; there
is no lawful durable evidence-only state. An evidence-bearing terminal row
without its exact evidence, or an evidence row without its exact terminal
reference, refuses replay.

Reconcile and terminal replay reopen the canonical evidence record, verify its
digest and all attempt/V2-plan bindings, and never call the system bus. Missing,
oversized, reordered, relabeled, or disagreeing evidence refuses the read; it
does not get reconstructed from the current unit state.

## Crash and concurrency cuts

Every execute or reconcile call first opens the validated regular attempt-store
file and participates in one bounded exclusive execution lock. The lock is
local concurrency evidence, not workflow authority. While the lock is held,
another caller performs no database transition and no system-bus call; it
returns an explicit nonterminal/in-progress transport result for Docket to
retain without inventing an executor receipt.

The lock holder then reopens the attempt:

- a terminal row returns its exact retained result;
- no row permits one reservation and makes that holder the sole mechanics
  writer; and
- a `started` row proves a prior lock holder is gone, so it is atomically
  terminalized as outcome unknown without invoking mechanics.

The sole mechanics writer holds the lock through the atomic evidence/receipt
commit. A crash before `StartUnit` transmission leaves `started`; later
reconciliation records indeterminate because the retained store cannot prove
the no-send cut. A crash at any post-transmission/pre-commit point has the same
honest result. A crash after the atomic terminal commit replays that result.
No successor writer resumes mechanics from `started`.

Thus concurrent delivery permits at most one `StartUnit` call. It cannot
terminalize another live writer's row, and a late success cannot disagree with
an earlier concurrent indeterminate terminal. Final attempt and evidence
custody have exactly one permitted relation.

## Qualification gate

Before this contract becomes an executable M1A result, directly exercise:

1. the existing pinned non-systemd V1 identity vector remains byte-identical;
2. a machine-less V1 systemd unavailable failure and terminal replay remain
   valid and never select the real backend;
3. exact successful V2 beta start with raw evidence reopen;
4. wrong plan/work schema, machine, unit, action, both prestates, work, attempt,
   marker, effect index, executable, and feature-set substitutions;
5. system bus unavailable and unit lookup/property-read refusal before call;
6. subscription failure and proven loss before transmission remain no-effect;
7. explicit allowlisted manager refusal with no job;
8. post-send/pre-reply loss, timeout, wrong job path, wrong job result,
   malformed and oversized message remain indeterminate;
9. duplicate and concurrent delivery with one observed method call, no
   concurrent terminal overwrite, and exact final attempt/evidence agreement;
10. restart and query-only reconcile with no method call;
11. fault between evidence insert and terminal update rolls back both;
12. evidence row deletion, content mutation, kind relabel, order change, and
    metadata/BLOB bound substitutions;
13. Debian 12 target-local package, system-bus permission, backup/restore,
    service restart order, and teardown; and
14. successful enactment followed by missing or contradictory fresh NQ
    postcondition evidence.

The corrected contract checkpoint requires independent re-audit before runtime
wiring. Current gate:
`M1A_CONTRACT_CORRECTION_READY_FOR_REAUDIT__RUNTIME_NOT_STARTED`.
