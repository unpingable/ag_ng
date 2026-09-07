# Operator-beta systemd D-Bus backend contract

**Recorded:** 2026-09-07
**Status:** `M1A_OWNER_RESULT_QUALIFIED__PUBLICATION_NOT_ASSERTED_BY_THIS_ARTIFACT`

**Owner:** AG-ng
**Owner base:** `81bcdf9819f0ee3c388e4d0d4502db4769dc315f`
**Release-basis acceptance:** Cartography
`2e9a7657c414bd6307efd09fa0104fc6fb92938c`

This is the implemented and locally qualified M1A owner contract for the fixed
non-production systemd HTTP service recovery. The bounded run used an isolated
Debian 12 local VM and exact campaign-owned fixture. This record does not
authorize another effect, activate production, qualify the Docket/NQ
composition, or assert current target state from the historical receipt.

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

V2 also requires `execution_lock_timeout_ms` and `job_timeout_ms`. Both
participate in canonicalization and work identity. Runtime validation admits
`1..=5_000` for lock acquisition and `1..=30_000` for the job result. The
beta plan fixes them to 5,000 ms and 30,000 ms respectively; neither Docket nor
an environment variable supplies a hidden wider wait.

The machine identity is the lowercase 32-hex value returned by the target
system bus. It participates in V2 canonicalization and work identity. The
backend compares the live peer identity before any unit method call. A coherent
machine-ID or timeout substitution therefore changes the sealed work and
refuses before invocation when outside its exact admitted plan.

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

The M1A package is the separate binary package
`agent-governor-ng-systemd-executor`. It installs only the feature-enabled
process adapter at `/usr/libexec/agent-governor-ng/ag-effectd`. It does not
replace the default `/usr/bin/ag-effectd`, install a service or target unit,
own an attempt store, or run a maintainer-script lifecycle action. The existing
`agent-governor-ng` package and its service-shaped deployment skeleton remain
outside this M1A change. Package presence is not execution standing; only an
exact Docket dispatch plus the sealed V2 plan admits one adapter attempt.

For qualification item 13, package lifecycle preservation has the following
bounded meaning. Before package removal or replacement, no adapter process may
be active. Both stable cuts require the SQLite WAL to be absent or zero-length;
a nonempty WAL refuses this qualification rather than being omitted or copied
as though the main database were complete. The target service state and exact
executor attempt-store database, WAL absence/zero-length fact, and
`.systemd-execution-lock` anchor are recorded. A campaign-owned backup is
accepted only when a read-only SQLite integrity check succeeds, the copied
database independently reopens, the copied WAL is likewise absent or
zero-length, and the database and anchor byte lengths and SHA-256 digests
reproduce. Install, remove, and reinstall must not change those files, the WAL
fact, or the target service. After reinstall, query-only `reconcile` must
reproduce the retained terminal outcome
without invoking mechanics. This is package-lifecycle evidence for the one
executor store; it is not the separately defined coherent three-store AG
backup protocol and does not authorize restoring a copied database as live
state. Package cleanup and fixture teardown occur only after the retained
outcome and postcondition observations have been captured.

The backend connects directly to the local system bus. The beta target catalog
admits exactly:

- machine: the target VM's retained machine ID;
- unit: `constellation-beta-http-fixture.service`;
- action: `start`;
- expected active state: `inactive`;
- expected unit-file state: `disabled`;
- execution-lock timeout: 5,000 ms; and
- job-result timeout: 30,000 ms.

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
8. wait until the V2-bound monotonic job deadline for the matching job result;
9. read the same unit properties again; and
10. commit evidence and the terminal Docket execution receipt atomically.

`Failed` is permitted only when retained evidence proves that step 6 was not
transmitted: connection, identity, unit reference/lookup, property, prestate, and subscription
failures. The M1A post-transmission manager-error allowlist is explicitly
empty.

The uncertainty boundary begins when transmission of `StartUnit` is
attempted, not when its reply or job path is received. Every method error and
every other unproved post-transmission cut is `Indeterminate`: send/reply
loss, missing job path, timeout, unmatched or malformed job testimony,
non-`done` terminal job result, poststate-read failure, or terminal-custody
failure. No transport or manager error is promoted into a known no-effect
result in this tranche.

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
- both V2 timeout values, ordered wall-clock testimony, and monotonic elapsed
  durations used for the local bounds;
- retained `RefUnit` reply, decoded unit object path, prestate, job path, job
  result, and poststate; the connection-scoped reference prevents an installed,
  inactive unit from being garbage-collected between lookup and `StartUnit` and
  grants no independent start authority;
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
file and participates in one exclusive execution lock bounded by the exact V2
`execution_lock_timeout_ms`. The lock is local concurrency evidence, not
workflow authority. If it remains held at the monotonic deadline, the adapter
exits nonzero with fixed sanitized `systemd_attempt_in_progress` stderr and no
stdout outcome or executor receipt. This is a Docket V1 process-transport
refusal, not a new executor outcome. Docket preserves its existing
transport-refusal/outcome-unknown custody and may later use its existing
reconcile path.

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

The bounded executable M1A owner result directly qualifies:

1. the existing pinned non-systemd V1 identity vector remains byte-identical;
2. a machine-less V1 systemd unavailable failure and terminal replay remain
   valid and never select the real backend;
3. exact successful V2 beta start with raw evidence reopen;
4. wrong plan/work schema, machine, either timeout, unit, action, both
   prestates, work, attempt, marker, effect index, executable, and feature-set
   substitutions;
5. system bus unavailable and unit reference/lookup/property-read refusal
   before call, including an installed inactive unit initially absent from
   `GetUnit`;
6. subscription failure and proven loss before transmission remain no-effect;
7. every post-transmission manager method error remains indeterminate under
   the explicitly empty allowlist;
8. post-send/pre-reply loss, job-deadline expiry, wrong job path, wrong job
   result, malformed and oversized message remain indeterminate;
9. duplicate and concurrent delivery with one observed method call, exact
   lock-deadline nonzero/no-stdout refusal, no concurrent terminal overwrite,
   and exact final attempt/evidence agreement;
10. restart and query-only reconcile with no method call;
11. fault between evidence insert and terminal update rolls back both;
12. evidence row deletion, content mutation, kind relabel, order change, and
    metadata/BLOB bound substitutions;
13. Debian 12 target-local package, system-bus permission, backup/restore,
    service restart order, and teardown; and
14. successful enactment followed by missing or contradictory fresh NQ
    postcondition evidence.

The exact result and retained run-004 evidence require independent result audit
before publication. Current gate:
`M1A_OWNER_RESULT_QUALIFIED__INDEPENDENT_RESULT_AUDIT_REQUIRED`.
