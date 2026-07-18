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

The current executable vertical slice is exact human ratification plus managed
regular-file effects and broker-owned reconciliation. Session launch/provider
ingress, bounded mandates, managed-pointer promotion, and typed systemd D-Bus
backends remain fail-closed release blockers; listing them above defines the v1
target and is not a present support claim.

BreakGlass, direct checkout, arbitrary privileged commands, hostile
multi-tenancy, public TCP APIs, and compatibility aliases are intentionally
absent.

## Implementation rule

No calculus family, abstraction, or crate is admitted unless it is consumed by
the next authority-bearing vertical slice or required by a compiled hostile
specimen.
