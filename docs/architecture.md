# AG-ng implementation contract

## Constitutional boundary

`agd` may judge but may not mutate governed targets. `ag-providerd` may hold
machine inference credentials but has no authority state. `ag-effectd` may
execute only a closed, broker-compiled effect vocabulary and has no network,
planner, model, plugin, shell, or arbitrary-command surface.

The network-capable provider implementation is a separate Cargo package from
the `ag-app` package that produces `ag-effectd`. Release builds must run
`scripts/verify-effectd-isolation.sh`; it rejects provider HTTP/TLS crates in
the broker's dependency closure and checks the resulting artifact for injected
provider-network code.

Only `CanonicalEffectProposalV1` bytes compiled and persisted by `ag-effectd`
may be ratified. `agd` submits `ProposalIntentV1` plus already-admitted artifact
references; its projections are never ratification inputs.

## Target v1 surface

- Bounded, noninteractive proposal-workspace sessions.
- Strict Unix-socket protocols and content-addressed artifact ingestion.
- Exact human ratification and bounded host-effect mandates.
- Git managed-ref compare-and-swap promotion.
- Managed regular-file create, replace, and quarantined delete.
- Closed systemd unit actions over D-Bus.
- Durable burn-before-effect and reconciliation without automatic retry.

The current executable vertical slices are exact human ratification, managed
regular-file effects with broker-owned reconciliation, and a development-only
offline generic-worker ingress. Provider ingress, production-qualified worker
containment, admitted check launch, bounded mandates, managed-pointer
promotion, and typed systemd D-Bus backends remain fail-closed release
blockers; listing them above defines the v1 target and is not a present support
claim.

## Development worker ingress

The implemented worker path is deliberately narrower than the target worker
surface:

```text
root-reviewed fixed worker profile
-> durable WorkerSessionPrincipal and proposal workspace
-> exact executable launched with fixed argv under Bubblewrap
-> ephemeral-key-authenticated candidate ingress
-> agd reconstructs the reviewed target mapping and judges the candidate
-> ag-effectd compiles and persists CanonicalEffectProposalV1
-> durable terminal tombstone and process cleanup state
```

The control caller selects only a reviewed profile ID. It cannot supply an
executable, argv, target, workspace, UID/GID, epoch, or worker principal. The
launcher revalidates exact executable bytes and the launch profile, constructs
an independent proposal workspace, and binds the live principal to the
authority domain and epoch, session nonce, workspace, executable identity,
observed UID/GID, security profile, expiry, output budget, offline route, and
ephemeral ingress-key identity. The retained launch object supplies an
independent copy of the executable, workspace, UID/GID, profile, principal,
and session-spec bindings; ingress compares those facts with the reloaded
durable record instead of treating that record as its own live evidence.

The worker wire object contains candidate bytes, a closed semantic label, and
its lifecycle nonce. It has no field for a target, proposal authority,
ratification, admission, containment receipt, or canonical record. `agd`
revalidates the signed request against durable session state and maps accepted
candidate custody to the target already named by root-owned configuration.
Effectd independently checks the dynamic worker proof and continues to be the
only component that constructs canonical proposal bytes. Candidate content
occurs once on the governor-to-broker wire, inside that authenticated proof;
effectd derives the one admitted artifact from the verified content rather
than accepting a duplicate transfer supplied beside it.

Normal exit, abnormal exit, timeout, cancellation, exhausted output budget,
and startup recovery permanently fence the transient principal through a
durable tombstone. Historical inspection does not recreate it, and late output
cannot reuse it. A cleanup-complete receipt is written only after the retained
process has been synchronously reaped. Broker canonicalization, refusal, and
indeterminate outcomes are each terminal durable candidate states rather than
deferred custody. Commit-ambiguous launch or ingress storage errors fence the
running core until daemon restart and startup recovery instead of being
rewritten as semantic refusals. Provider routing is absent from this slice; no
provider secret or ambient credential enters the worker.

The catalog permits exactly one live worker. While it exists, new worker
launch and external proposal submission refuse with a busy conflict; health,
historical inspection, cancellation, and bounded polling remain available.
The worker's challenge policy is the exact configured governor enrollment
checked again by effectd, and no profile timeout may exceed its configured
clock-skew window.

This substrate is accepted only with `security_profile = "development"`.
Production and high-assurance configuration fail closed because the current
Bubblewrap launch has not earned host sandbox attestation, packaged lifecycle,
or distribution qualification. It is not the future systemd/DynamicUser
wrapper design and does not implement checks, provider-specific adapters,
multi-worker orchestration, managed-pointer promotion, host mandates, or
systemd effects.

BreakGlass, direct checkout, arbitrary privileged commands, hostile
multi-tenancy, public TCP APIs, and compatibility aliases are intentionally
absent.

## Implementation rule

No calculus family, abstraction, or crate is admitted unless it is consumed by
the next authority-bearing vertical slice or required by a compiled hostile
specimen.
