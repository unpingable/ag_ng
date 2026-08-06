# Campaign orchestration office — disposition record

Status: **implemented as a bounded, local-only campaign layer** (`crates/ag-campaign`,
consumed by `ag-app`/`agctl campaign`). This record states what the office owns, the
invariants encoded in types, what it deliberately does not claim, and how it relates to
the constitutional office map. It is doctrine, not a production claim.

Authorization: this office layer exists under the human-authorized task "AG-NG
Orchestration Office + Docket Campaign-Stage Standing" of 2026-08-06, which lifted the
previously recorded office-assignment blocker. A campaign grants no authority; nothing in
this layer mints, converts, or deserializes `Authority`.

## Ownership

The campaign office owns **campaign semantics in AG-ng vocabulary**:

- campaign identity (exact, immutable, digest-derived from the human-authorized intent);
- the stage projection (each stage belongs to exactly one campaign and carries exactly
  one role);
- worker-role binding with enforced operator/reviewer distinctness;
- stage basis (exact commits/trees), stage scope (exact repositories and paths), and the
  stage evidence contract;
- stage receipts, reviewer verdict receipts, and proposed bounded repairs;
- campaign residuals, the campaign recomposition receipt, and campaign disposition
  vocabulary;
- the authority-neutral runtime-envelope seam toward the execution sidecar.

It does **not** own: Docket standing issuance (Docket's office, transcript domain
`gwr:campaign-stage-standing:v1` — its digests are recorded here as opaque identities and
verified by equality only, never recomputed across canonicalizations); execution
mechanics (the sidecar's); claim admissibility (a third office's); or any authority
family (the kernel's, unchanged).

## Invariants encoded in types

1. **Identity exact/immutable.** `CampaignId` is the domain-separated digest of the exact
   canonical intent bytes (`ag.campaign.identity/v1`); there is no mutator.
2. **Stage → exactly one campaign.** `StageProposalV1` carries one `campaign` field;
   the ledger refuses a proposal whose campaign identity differs from the ledger's.
3. **Stage → exactly one role.** The role is the variant of `StageKindV1`
   (`Operator`/`Review`); a stage cannot carry two roles or none.
4. **Operator ≠ reviewer.** `CampaignIntentV1::new` refuses when the operator and
   reviewer principal identities are equal (`RoleSeparation`).
5. **Reviewer stages have no mutation effects.** The `Review` variant carries a
   `ReviewScopeV1` (read paths plus the reviewed subject stage); mutation scope exists
   only on the `Operator` variant.
6. **Every consequential stage requires Docket standing.** `admit_stage` requires a
   standing digest bound to that exact stage; `consume_standing` is the only producer of
   the `ConsumedStandingV1` token that the runtime envelope requires.
7. **Evidence is not authority.** Receipts, envelopes, and standings are serializable
   evidence; none can construct or reconstruct `Authority` (the kernel seal is
   unchanged; no campaign type mentions it).
8. **A worker receipt cannot self-admit its next stage.** `record_stage_receipt`
   transitions only the recorded stage to `Executed`; admission is a separate call
   requiring fresh standing. There is no API path from a receipt to an admission.
9. **Repairs cite exact findings and the exact rejected review receipt.**
   `StageProposalV1::repair` requires a non-empty finding-ID set and the rejected
   verdict receipt digest; the ledger refuses a repair whose finding IDs are not exactly
   findings of that verdict (`AlteredFindingIdentity`).
10. **Residuals cannot disappear in recomposition.** The accounting plan requires one
    boundary per recorded residual; an omitted residual slice is a kernel
    `MissingBoundary` and an adapter `ResidualErasure` refusal.
11. **Accepted slice ≠ campaign discharge.** Disposition flags are computed
    independently; `campaign_discharged` additionally requires zero open residuals, and
    no flag implies another.
12. **Candidate/qualification need distinct future authority.**
    `request_candidate_standing` / `request_qualification_standing` always return a
    typed refusal; the receipt pins `candidate_standing` and `qualification_standing`
    to `false` with the refusal recorded.
13. **Recomposition refuses missing/duplicated/replayed/inconsistent receipts.** The
    adapter delegates boundary accounting to `ag-kernel`'s `recompose()` (missing,
    duplicate, unaccounted, foreign-origin, rewritten, obstructed) and adds campaign-law
    pre-checks: standing without consumption, consumption without admitted stage, worker
    output without review, reviewer output after repository mutation, repair without
    admitted repair standing, historical identity presented as current standing, and
    broadened path scope.

## Nonclaims

- No campaign, stage, receipt, envelope, or disposition **is authority** or creates any.
- Admission recording is not Docket admission: this office records the opaque standing
  digest Docket issued; it does not issue, interpret, or recompute it.
- The runtime envelope does not execute anything. Execution mechanics belong to the
  authority-neutral sidecar; this office only renders the exact envelope and verifies
  the sidecar's receipt against it.
- `run` is a local mock loop for the vertical slice. Full `agd`/`ag-effectd` broker
  wiring for campaign-stage execution is a bounded residual, not a hidden claim.
- Candidate standing, qualification standing, and campaign freeze actions do not exist;
  they refuse with typed refusals.
- Local-only: no network surface, no cross-process authority, no production claim.

## Relation to the constitutional office map

The constitutional office map document lives in the **Docket custody repository** and
remains a **document-layer follow-up residual**: it must be updated there to name this
campaign office. This repository does not own that document and does not modify that
repository. Nothing here pre-empts the map; the ownership list above is this office's
own statement of its boundary, consistent with the four-office posture in the README.

## Sidecar sunset condition

The authority-neutral sidecar (`campaign-driver`, Python, separate repository, read-only
to this one) exists to execute stage mechanics against an exact runtime envelope. Its
sunset condition: it is retired when an AG-native admitted execution path — broker-owned
compilation, ratification, and burn-before-effect execution through `ag-effectd` under a
qualified worker/containment surface — can carry campaign stages end to end with the
same exact-envelope guarantees. Until then the sidecar executes mechanics only, carries
no authority, and every dispatch requires a consumed-standing digest recorded before the
envelope is rendered.

## Digest domains

| domain | direction | meaning |
|---|---|---|
| `ag.campaign.identity/v1` | internal | campaign identity over exact intent bytes |
| `ag.campaign.stage-proposal/v1` | produced | stage proposal transcript digest, consumed by Docket as an opaque upstream identity |
| `gwr:campaign-stage-standing:v1` | consumed | Docket-issued campaign-stage standing; opaque, equality-verified only |
| `ag.campaign.stage-receipt/v1` | produced | worker/reviewer stage receipt |
| `ag.campaign.runtime-envelope/v1` | produced | exact sidecar execution envelope |
| `ag.campaign.recomposition-receipt/v1` | produced | durable campaign recomposition receipt |

All produced digests are SHA-256 over strict integer-only JCS transcripts under the
repository's existing `Digest::hash_domain` separation; no digest is derived from
another domain's digest.
