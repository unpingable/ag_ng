# Agent Governor NG

## Implementation status (2026-08-10)

AG-ng is the canonical durable governor of exact-work occurrences. The
production-reachable path is `ag-loopctl` -> `CampaignEngineV1` ->
`GovernedLoopKernelV1` -> `CampaignStoreV1`: AG records the exact proposal,
resolves fresh observation and current standing, decides admissibility,
durably spends one AG authorization, issues one exact record to Docket, and
consumes Docket settlement into observation-required or reconciliation state.
Docket owns execution custody and attempt identity; executors own mechanics;
NQ owns diagnostic evaluation; Nightshift owns recurrence. This implementation
is qualification-ready development code, not an earned qualification or
deployment claim. Older vertical documents remain valid only for the narrower
surfaces they explicitly name.

Agent Governor NG is a Rust hard successor to the classic Python Agent
Governor. Its authority boundary is deliberately narrow:

> Workers propose. AG governs one exact occurrence. Docket custodies one
> attempt. An authority-neutral executor performs only the exact mechanics.

The workspace is organized around non-convertible judgment-family types, an
unprivileged governor daemon, a credential-isolated provider daemon, and a
minimal privileged effect broker. The initial production target is a
single-host Linux service for contained batch work, Git managed-ref promotion,
managed files, and systemd units.

The pure kernel is crosswalked against the public Governed Admissibility
Calculus v14 through an explicit, non-authorizing adapter. The adapter binds
native Rust decisions to a reviewed specification revision and operational
context; it cannot deserialize or convert them into runtime authority. See
`docs/formal-calculus-crosswalk.md` for correspondence and non-correspondence
claims.

AG-ng also produces authenticated authorization issuances for an external
governed-work runtime. That producer is deliberately narrow: it decides through
this office's own catalog and principal checks, burns its own decision authority
once, and emits an immutable authenticated record. The record is not authority —
`Authority` remains non-serializable and process-local — and it makes no claim
that anything executed or that any downstream claim is admissible. See
[`docs/docket-issuance.md`](docs/docket-issuance.md).

The `ag-campaign` crate now contains the pure generic occurrence/FSM law; the
transactional program counter and spend/attempt/settlement journals live in
`ag-store`, and `ag-app` composes the live observation, standing, Docket, and
human-authority boundaries. Residual preservation, bounded probe/retry/
escalation facts, reconciliation, and authority-safe halt/resume are part of
that path. The former fixed-stage campaign office is retired; its disposition
record is retained only as history in
[`docs/campaign-orchestration-office.md`](docs/campaign-orchestration-office.md).
The single current ownership, crash, retry, deployment-root, and qualification
law is [`docs/governed-loop-c1.md`](docs/governed-loop-c1.md).
Its minimal one-shot-process provisioning, restart matrix, custody assumptions,
structured inspection surface, and honest physical-environment limits are in
[`docs/governed-loop-deployment-qualification.md`](docs/governed-loop-deployment-qualification.md).
The loopback-only read interface is presented as **Phosphor-ng**, with the
qualified Rust package/binary name `ag-operator-ui`. Its campaign/occurrence
contract is in [`docs/operator-ui.md`](docs/operator-ui.md); it is a
canonical-fact projection with no runtime mutation surface. Maude/Phosphor-ng
roles, vocabulary, semantic deep links, and legacy Phosphor disposition are in
[`docs/operator-surface-convergence.md`](docs/operator-surface-convergence.md).
Authenticated operator intent is represented by several exact, narrow request
classes—never a generic retry—and is specified in
[`docs/governed-intervention-contract.md`](docs/governed-intervention-contract.md).
Those records select only existing authority-safe laws and do not themselves
mint standing or authorization. No browser write surface exists.
The production loading dock for those records is the authenticated one-shot
ingress in
[`docs/governed-intervention-ingress.md`](docs/governed-intervention-ingress.md).
It preserves exact inspected bytes, binds the configured submitting service
and target runtime, and returns immutable custody/evaluation receipts.
Submission is delivery of intent, not authorization.
For newly authenticated Maude handoffs it also displays Nightshift's separate
session-issuer/producer custody projection; that ingress fact is explicitly
not standing or authorization.

This repository does not preserve the classic command, API, database, or
authority-token surfaces. The Rust-only frozen archive verifier treats classic
files as bounded opaque evidence and never imports them as runtime authority.

The current tree also contains one deliberately bounded live-worker slice. In
the `development` security profile, `agd` can launch an offline worker selected
from a root-reviewed fixed executable/argv catalog inside a private Bubblewrap
proposal workspace. The worker receives a non-transferable session identity
and may return only authenticated candidate material; `agd` reconstructs the
reviewed mapping and `ag-effectd` still owns compilation and persistence of the
canonical proposal. Session authority is durably bound and tombstoned rather
than recreated after exit or restart. This slice admits exactly one live worker
at a time; while it is live, `agd` refuses other blocking proposal/launch work
so deadline supervision cannot be starved.

That development path can now carry one strict, self-contained Git bundle into
an independently ratified managed-pointer proposal. `ag-effectd` alone derives
the exact base/post trees and target bindings, durably arms a one-shot commit,
and compare-and-swaps one configured, existing loose ref that is not checked
out under the target owner. Success requires independent ref/tree readback;
ambiguity requires reconciliation. This is a managed-ref lifecycle only: it
does not synchronize or write a live checkout, and a packed-ref-only target
refuses.

This is not a production containment claim. `production` and
`high_assurance` configurations reject the development launcher, and the
packaged `agd.service` namespace restrictions are not a host for it. The
managed-pointer broker now has code-level live activation gating and a
complete inspectable activation receipt, but its host/Git/filesystem,
power-loss, and package matrices remain unqualified. Provider adapters, typed
systemd effects, admitted check launch, and production worker qualification
remain pending.

See `docs/architecture.md` and `docs/source-baseline.md` for the implementation
contract and source custody. Operational reviewers should also read
`docs/deployment.md`, `docs/managed-pointer-activation-readiness.md`,
`docs/clean-host-activation-qualification.md`, `docs/backup-restore.md`,
`docs/release-checklist.md`, `docs/worker-qualification.md`, and
`docs/migration-m8.md`; the current tree is explicitly not production
deployable until that checklist closes.

The live worker ingress substrate has its own qualified gate,
`scripts/run-worker-qualification.sh`, described in
`docs/worker-qualification.md`. It exercises the ingress path end to end against
a feature-gated fixture worker under real bubblewrap confinement, and it is
separate from the packaged test step because it needs host prerequisites a
package builder cannot guarantee. It qualifies the **ingress substrate**, not a
production worker; production worker qualification remains pending as stated
above.
