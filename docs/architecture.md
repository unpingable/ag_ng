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
regular-file effects with broker-owned reconciliation, a development-only
offline generic-worker ingress, and development-qualified managed-ref
promotion. Provider ingress, production-qualified worker containment,
admitted check launch, bounded mandates, typed systemd D-Bus backends, and
production qualification of managed-pointer execution remain fail-closed
release blockers; listing them above defines the v1 target and is not a
production support claim.

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
multi-worker orchestration, host mandates, or systemd effects.

## Development managed-pointer promotion

The implemented code-promotion path closes one development lifecycle without
giving either the worker or `agd` write access to the governed target:

```text
authenticated worker candidate Git bundle
-> agd reconstructs the reviewed effect family and target
-> ag-effectd admits the artifact and observes the managed ref
-> ag-effectd compiles and persists the canonical proposal
-> an independent human principal ratifies those exact broker-owned bytes
-> reversible preparation and a durable commit-may-proceed checkpoint
-> exact managed-ref compare-and-swap under the configured target owner
-> independent tree readback and a receipt or reconciliation requirement
```

The worker profile fixes `git_bundle_promotion_v1` and an opaque target ID.
The candidate is a strict, self-contained Git bundle v2 with one advertised
`refs/heads/ag-candidate`, no prerequisite lines, and no gitlinks. Its candidate
commit must have exactly one parent: the broker-observed commit currently named
by the managed ref. Candidate bytes remain proposal material; the worker cannot
name the destination repository or ref, construct canonical bytes, ratify the
proposal, or execute the promotion.

`ag-effectd` derives a proposal-scoped, single-use operation ID and binds the
activation domain and epoch, catalog and security-profile identities, expiry,
artifact and normalized pack digests, allowed root, repository and Git-directory
device/inode observations, repository identity and owner, exact ref, expected
base commit and tree, candidate commit and post-tree, staging root, and exact
Git executable and launch profile. The target is re-opened and every binding is
revalidated before mutation. Dirty, relocated, substituted, wrong-owner,
checked-out, stale-base, expired, or already-consumed targets refuse.

The ratifier is not predicted inside the pre-ratification proposal, which would
make the digest circular. The signed authorization, durable authority burn, and
one-shot attempt instead bind that exact canonical proposal to the
broker-reconstructed ratifier principal. Principal-chain independence from the
proposer is checked before any preparation or mutation.

The closed Git adapter runs an exact retained-descriptor executable with fixed
plumbing operations, an empty and rebuilt environment, isolated Git
configuration, disabled hooks and interactive helpers, and all Git protocols
disabled. Reversible candidate validation occurs in broker-owned staging
outside the governed repository. Preparation imports and durably syncs the
exact pack as unreachable objects under the configured target UID/GID, proves
the ref is still at the exact prestate, and only then emits the checkpoint.
The commit side changes only the configured ref by compare-and-swap. Success is
issued only after the ref and resulting tree are independently observed at the
ratified poststate.

Authority is burned before preparation. `ag-effectd` durably records that
reversible preparation is complete before entering the externally visible ref boundary.
A known pre-boundary failure with an exact unchanged prestate is terminal and
cannot be retried with the consumed operation. An ambiguous boundary becomes
reconciliation-required; automatic retry is forbidden. Reconciliation
independently classifies the live target as exact prestate (`not_applied`),
exact poststate (`applied`), or neither (`foreign`).

Version 1 manages one existing, descriptor-validated loose ref in a bare
repository or a ref that is not checked out in any attached worktree. A target
available only through `packed-refs` refuses. It deliberately refuses a
checked-out managed ref and does not update an index or working tree. There is
no hidden checkout synchronization, direct-checkout mode, generic Git command
effect, promoter daemon, provider adapter, check launcher, host mandate, or
systemd effect in this slice.

This is a development-qualified managed-ref CAS claim, not a production
deployment claim. The activation/upgrade ceremony, effective systemd sandbox
parity, target-owner capability packaging, host sandbox attestation, Git and
distribution qualification, and power-loss matrix remain open release gates.

BreakGlass, direct checkout, arbitrary privileged commands, hostile
multi-tenancy, public TCP APIs, and compatibility aliases are intentionally
absent.

## Formal calculus correspondence boundary

AG-ng's reviewed formal baseline is the public Governed Admissibility Calculus
at Lean revision `ff491b808ebeab2a132d9ade46d234cf85dcfbe9`. The calculus
constrains the operational contract but is neither linked nor executed by any
daemon. Its theorems do not authenticate runtime evidence and cannot mint
authority.

`ag-kernel` contains a pure, non-authorizing adapter which binds one complete
native Rust result to the exact calculus revision, adapter schema, authority
domain, epoch, lifecycle origin, evaluator identity, and input digest. It
preserves semantic refusal and operational indeterminacy as distinct outcomes.
A stored-decision ledger can record one projection of that evidence, but it is
not an authority ledger and cannot defend a copied old store without the
system's independent epoch and restore ceremonies.

The detailed correspondence dispositions and gaps live in
`docs/formal-calculus-crosswalk.md` and
`docs/formal-calculus-obligations.json`. No daemon consumes either document.
BreakGlass remains absent despite its formal instance; exceptional runtime
authority requires a separate model, custody design, hostile review, and
operator decision.

## Implementation rule

No calculus family, abstraction, or crate is admitted unless it is consumed by
the next authority-bearing vertical slice, by an explicit non-authorizing
correspondence adapter, or by a compiled hostile specimen. A theorem-shaped
Rust API is not correspondence evidence.
