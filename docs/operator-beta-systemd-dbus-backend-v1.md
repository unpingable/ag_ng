# Operator-beta systemd D-Bus backend contract

**Recorded:** 2026-09-07
**Status:** `CONTRACT_CANDIDATE__RUNTIME_NOT_IMPLEMENTED`
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

## Narrow compatible plan extension

Add `systemd_machine_identity: Option<String>` to
`EffectExecutorPlanV1` with the following executable law:

- it is required for `CanonicalEffectV1::SystemdUnit`;
- it is absent for every other effect family;
- it is the lowercase 32-hex machine ID returned by the target system bus;
- omission remains the canonical encoding for existing non-systemd V1 plans,
  preserving their exact bytes and identities; and
- the backend compares the live peer machine ID before any unit method call.

This is an additive use of a previously unavailable effect branch, not
permission to reinterpret an existing executable systemd receipt. A coherent
machine-ID substitution must produce a different plan identity and must refuse
before invocation.

## Backend activation

The production implementation is Linux-only and build-feature gated as
`systemd-dbus`. Default builds retain the unavailable backend. A qualified
package binds the exact feature set and executable digest; there is no runtime
environment toggle or automatic fallback.

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

For one Docket-reserved attempt the backend performs:

1. connect to the local system bus;
2. obtain and compare the peer machine ID;
3. resolve the exact unit and read `ActiveState` and `UnitFileState`;
4. compare both properties to the sealed prestate;
5. subscribe to the exact manager job result;
6. call only `StartUnit(unit, "replace")`;
7. retain the returned exact job object path;
8. wait within the declared bounded deadline for the matching job result;
9. read the same unit properties again; and
10. retain the evidence before completing the Docket execution receipt.

Failures through step 4, and an explicit manager method-error reply that proves
no job was queued, are `Failed`: known no requested effect. Once a job path is
returned, the external commit boundary may have been crossed. Transport loss,
timeout, unmatched/malformed job testimony, non-`done` terminal job result,
poststate-read failure, or evidence-custody failure after that point is
`Indeterminate`, never a known no-effect result.

Only the matching `JobRemoved` result `done`, followed by exact poststate
reads and durable evidence custody, yields the existing typed
`SystemdUnitSuccessV1`. That receipt is enactment testimony. Even if its
resulting active state is `active`, it does not establish the beta
postcondition; fresh target-local systemd and controller-vantage HTTP evidence
remain required.

## Evidence custody

Add one content-addressed `ag-effectd.systemd-dbus-evidence/v1` record to the
existing executor attempt store. It binds:

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

Reconcile and terminal replay reopen the canonical evidence record, verify its
digest and all attempt/plan bindings, and never call the system bus. Missing,
oversized, reordered, relabeled, or disagreeing evidence refuses the read; it
does not get reconstructed from the current unit state.

## Crash and concurrency cuts

The existing attempt reservation precedes mechanics. A restart that finds only
a reserved attempt remains indeterminate and never invokes again. A crash:

- before the unit method call is known no effect only when retained evidence
  proves that boundary;
- after call transmission but before an explicit method-error or job reply is
  outcome unknown;
- after job acceptance but before evidence/receipt custody is outcome unknown;
  and
- after terminal receipt custody replays the same retained outcome without
  mechanics.

Concurrent delivery may produce only one reserved writer and at most one
`StartUnit` call. Other writers converge on retained custody or the same
outcome-unknown attempt; they never infer that process absence authorizes
another call.

## Qualification gate

Before this contract becomes an executable M1A result, directly exercise:

1. exact successful beta start with raw evidence reopen;
2. wrong machine, unit, action, both prestates, work, attempt, marker, effect
   index, executable, and feature-set substitutions;
3. system bus unavailable and unit lookup/property-read refusal before call;
4. explicit manager refusal with no job;
5. loss immediately before call, after send, after job reply, after job
   completion, after evidence custody, and before terminal receipt;
6. timeout, wrong job path, wrong job result, malformed and oversized message;
7. duplicate and concurrent delivery with one observed method call;
8. restart and query-only reconcile with no method call;
9. evidence row deletion, content mutation, kind relabel, order change, and
   metadata/BLOB bound substitutions;
10. Debian 12 target-local package, system-bus permission, backup/restore,
    service restart order, and teardown; and
11. successful enactment followed by missing or contradictory fresh NQ
    postcondition evidence.

The first contract checkpoint requires independent review before runtime
wiring. Current gate:
`M1A_CONTRACT_READY_FOR_INDEPENDENT_REVIEW__RUNTIME_NOT_STARTED`.
