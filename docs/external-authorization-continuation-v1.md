# Exact external-authorization continuation v1

This record fixes the IRON-CHORUS continuation law shared by AG and the
Codex fork. It pairs AG implementation head `625f1d8` with Codex
implementation head `6e21836d37`; neither commit activates a production
service or installs a contributor.

## Ordering law

AG's normative order is:

1. fresh observation;
2. exact proposal;
3. fresh observation and standing;
4. admissibility;
5. consequence-time re-resolution;
6. atomic one-use AG spend and issuance;
7. Docket custody and dispatch;
8. settlement or reconciliation;
9. fresh postcondition observation;
10. successor.

At the Codex boundary the order is admissibility, native/user approval, fresh
AG authorization, Docket custody, exact execution, settlement or
reconciliation, and postcondition observation. Native denial, timeout, or
abort therefore occurs before any AG spend. Each distinct mechanics attempt,
including an alternate transition history after a sandboxed attempt cannot
proceed, needs a new durable authorization occurrence. `Authorized` is an AG
result, not native approval and not permission to execute directly.

## Exact admissibility currentness

Before currentness or standing is evaluated, both sides validate one receipt
identity transcript owned by Codex external-reviewer receipt v1. The transcript
is canonical JSON over `evaluation_time` in Unix seconds, `evidence_used` in
supplied order, `profile_id`, and `profile_revision`. Every evidence entry
binds `fact_id`, `qualifier_id`, `qualifier_revision`, `receipt_id`, and
`requirement_id`; optional provenance is explicit JSON `null`. Codex validates
this digest at reviewer intake and again immediately before request
construction. AG reconstructs the same transcript from its millisecond wire
field and validates it before request custody, governed state, or spend. A
subsecond wire time cannot name the seconds-domain receipt and is invalid.

The external authorizer accepts a structurally and cryptographically valid
admissibility receipt only while

`evaluation_time_unix_ms <= now_unix_ms < evaluation_time_unix_ms + max_admissibility_age_ms`.

The right edge is deliberately excluded. A future receipt, a stale receipt,
or equality at the expiry boundary yields the AG decision `refused` with code
`admissibility_not_current`, maps to the kernel's stale-observation law, and
spends no authority. The daemon never refreshes a supplied receipt.

## Request and result custody

Before adjudication AG creates and syncs
`<state-dir>/<authorization-occurrence-id>/request.json`. After the governed
engine transition is durable it writes a synced temporary outcome and
atomically publishes `outcome.json`. A request without a published outcome is
`outcome_unknown`; it is not permission to resubmit or create a replacement
effect.

Lookup is an exact, read-only adjudication query bound to authorization
request id, occurrence id, and the digest of the complete request. It returns
only `not_found`, `outcome_unknown`, or `resolved`. A mismatched query is
invalid; malformed or inconsistent custody is infrastructure failure. Lookup
never runs the engine, spends authority, repairs state, or creates an
occurrence.

The Codex client independently syncs a mode-0600 `*.pending.json` request
under an euid-owned mode-0700 custody directory before socket send. A
cross-process `flock` claim fence refuses every fresh occurrence while any
prior result is unknown. Timeout, cancellation, transport failure, malformed
response, or identity mismatch leaves that pending record in place. Only an
exact validated response or exact read-only reconciliation moves it to
terminal history. A resolved occurrence cannot be presented again.

## Closed outcomes and stopped boundaries

The continuation keeps native denial/timeout/abort, AG `refused`, AG
`indeterminate`, infrastructure failure, `outcome_unknown`, prior unknown
outcome, replay of a resolved occurrence, Docket refusal/unknown/unavailable,
execution failure, `ExpectedStateMismatch`, settlement, reconciliation, and
postcondition observation distinct where the participating contracts expose
them. No AG decision is collapsed into native approval.

Prepared generic, apply-patch, and MCP actions keep their canonical action
identities. Prepared MCP calls containing hosted-file parameters remain
fail-closed before AG authorization, upload, or tool transport because this
version does not bind the exact file bytes and digests plus the separate
upload effect.

## Docket provenance and remaining handoff

Docket's canonical contract is pinned to
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`, published unchanged as
`campaign/c2-governed-loop-layering` at
`git@github-unpingable:unpingable/docket.git`. At that commit Docket owns
`docket.governed-executor-transport/v1`, its schemas and conformance corpus,
`LocalGovernedExecutorV1`, and the `governed-loop accept`, reconciliation,
and inspection commands.

The retained clean checkout and all three corpus checksums were verified.
AG's ignored adjacent-process qualification passed with an authentic signed
AG issuance crossing that Docket binary, executing exactly once through
`ag-effectd`, and settling. AG also passed the Docket-owned transport corpus.

That evidence establishes the canonical downstream contract but does not
invent a Codex-side Docket protocol. The external authorizer currently parks
after its durable one-use authorization and returns reference identities; it
does not deliver the canonical signed issuance document to Docket. Codex has
no installed authenticated issuance-to-Docket custody adapter. Consequently
the Codex continuation stops with `DocketCustodyUnavailable` after
`Authorized`, before any effect. The exact handoff required to continue is an
AG-owned authenticated signed-issuance output connected to Docket's canonical
`governed-loop accept` custody, followed by its existing reconciliation and
settlement contracts.

## Qualification record

Classification: **pending independent re-audit**. The prior independent audit
refused the implementation because receipt identity was not recomputed at the
cross-process boundaries and generic direct handlers could bypass the
post-native-approval contributor. Repair commits now add the shared transcript
validator, deterministic bound-field substitutions, pre-custody AG rejection,
and fail-closed classification for unsupported Codex handler families. Prior
qualification results remain historical evidence; the repaired heads require
fresh independent acceptance before push or activation.

The implementation and boundary checks run for this campaign are recorded in
`qualification/iron-chorus-auth-continuation-v1/README.md`. Host-dependent
user-namespace, bubblewrap, and root-custody checks are intentionally sealed
as commands and expected evidence rather than fabricated on this host.
