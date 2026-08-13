# Canonical governed repair

Status: **development candidate; operational qualification is
`not_assessed`**.

This is the current AG contract for consequence-bearing repair governance. It
replaces the retired fixed-stage campaign repair office as a production path.
The implementation is the governed-loop kernel in
`crates/ag-campaign/src/governed.rs`, the append-only store in
`crates/ag-store/src/campaign.rs`, the application engine and boundary adapters
in `crates/ag-app/src/governed_loop.rs` and
`crates/ag-app/src/governed_ports.rs`, and the reusable product surface in
`crates/ag-app/src/governed_product.rs`.

## Bootstrap fact and nonclaim

This loop was constructed under explicit external human development
authorization. It did not govern, authorize, ratify, or qualify its own
construction, and it cannot retrospectively do so. The NQ C1 records under
`crates/ag-campaign/tests/fixtures/nq-c1/` are immutable hostile development
specimens. They are not reconstructed AG observations, standing, decisions,
spends, issuances, Docket custody, human dispositions, or current authority.

Nothing in this implementation is a qualification certificate, activation,
deployment, or authority transfer. In particular, the test verifier named
`qualification-fixture-not-human-authority` is development-only and is not a
human-authority verifier.

## Ownership boundary

AG owns the exact-work occurrence, proposal and immutable effect scope;
observation and admissibility; standing, decision, one-use spend and issuance;
the durable program counter; ingestion and reconciliation of Docket results;
human-decision requests; acceptance or refusal of externally verified
dispositions; successor creation; terminal refusal, residuals, and escalation.

Docket owns execution custody, attempts, the exact executor/checkpoint/result
binding, effect journals, sealed outcomes, replay, and unknown-result
reconciliation. Docket reports an exact requirement and whether the newly
requested unauthorized effect was not performed. It does not decide whether an
NQ diagnosis is correct or whether a scope expansion is permissible.

The AG-side Docket outcome reference retains the sealed occurrence's exact
creation/expiry and idempotency identities, whether authorized effects were
already journaled, and the full immutable work checkpoint when present. A
human-decision request therefore binds those facts directly. A disposition
that echoes only the opaque Docket checkpoint while substituting the commit,
tree, diff, or content manifest is refused before successor creation.

The deployment, not an operation caller, owns AG's Docket adapter root. The
campaign genesis record pins the exact Docket executable, Docket state
directory, trust configuration, Standing resolver, executor adapter and
configuration, optional checkpoint verifier, and AG issuance signer
coordinates. Dispatch, reconciliation, and recovery reopen that pinned root;
their product calls accept no alternate Docket, trust, Standing, executor,
checkpoint, or signer premise.

The same genesis record pins AG's policy root: the consequence clock,
observation resolver, Standing resolver, exact-work catalog, and optional
controlling review are absolute paths plus exact measured-byte identities.
Normal product operations accept only expected state and their exact work or
transition input; callers cannot select a clock, resolver, catalog, review, or
verifier at an individual consequence boundary. Reopen remeasures every pinned
policy-root member and fails closed on substitution.

NQ owns diagnostic meaning. Nightshift owns recurrence. A future Maude client
consumes only the versioned AG product contract. Maude has no direct Docket or
executor contract, and this campaign makes no Maude or Nightshift change.

## Canonical lifecycle

An occurrence first opens as an authority-empty observation shell. Recording
its exact proposal then immutably binds the predecessor or rejected basis,
canonical effect scope and digest, explicit nonclaims, and absolute expiry.
Observation, standing, decision, spend, issuance, executor contract, and any
immutable checkpoint accumulate only through the legal transitions. The
issuance repeats the proposal nonclaims and expiry so Docket can independently
refuse fresh custody after expiry; the proposal identity prevents substitution.
Exact scope rejects repository-root grants, globbing, shell
expressions, path traversal, and mutable ref labels.

Before spend, discovery that the proposal is insufficient records no spend or
attempt. The occurrence may halt while a newly proposed exact scope is
assessed; it cannot fabricate execution history.

After spend, out-of-scope discovery follows this durable chain:

```text
AG issuance and consumed spend
  -> Docket custody and attempt
  -> executor performs only in-scope effects
  -> Docket seals ScopeExpansionRequired or ReadjudicationRequired
  -> AG ingests the exact sealed outcome
  -> predecessor occurrence halts with the typed requirement pinned in state
  -> AG emits an exact HumanDecisionRequest
  -> configured external verifier verifies one exact disposition
  -> rejection closes the predecessor, or approval opens a distinct successor
  -> successor obtains fresh observation, standing, decision, spend, issuance,
     and Docket custody
```

The predecessor scope and spend never change. Neither the Docket outcome, human
request, human prose, checkpoint, nor approved disposition resumes the halted
occurrence. Approval constrains one authority-empty successor proposal. The
checkpoint is exact content evidence (repository, commit, tree, optional diff,
content manifest, and where applicable Docket checkpoint), not authority.

`ReadjudicationRequiredV1` carries a bounded question, evidence and diagnostic
censuses, alternatives, unresolved facts, limitations, and a read-only scope.
It cannot be converted to wildcard mutation authority. Any resulting
adjudication is a separate occurrence and must return through normal AG law.

Repeated discoveries form a finite explicit chain. Every expansion needs a new
sealed requirement, decision request, verified one-use disposition, successor,
and fresh AG/Docket consequence chain. There is no ambient authorization pool
and no automatic continue-until-green mode.

## Versioned durable artifacts

The load-bearing public schemas are:

| Artifact | Schema / role |
| --- | --- |
| `CanonicalEffectScopeV1` | `ag.governed-loop.canonical-effect-scope/v1`; exact closed resources and operations |
| `AgIssuanceV2` | `ag.governed-loop.issuance/v2`; exact structured scope and optional immutable checkpoint |
| `DocketIssuanceRefusalV1` | `docket.governed-loop.issuance-refusal/v1`; sealed pre-custody semantic refusal that retains the consumed AG spend and creates no Docket attempt |
| `ScopeExpansionRequiredV1` | `ag.governed-loop.scope-expansion-required/v1`; additive delta plus Docket evidence and no-unauthorized-effect assertion |
| `ReadjudicationRequiredV1` | `ag.governed-loop.readjudication-required/v1`; bounded read-only normative question |
| `HumanDecisionRequestV1` | `ag.governed-loop.human-decision-request/v1`; immutable, expiring, non-authorizing request |
| `GovernedRepairDispositionV1` | `ag.governed-loop.governed-repair-disposition/v1`; exact externally verified decision |
| `GovernedRepairVerificationV1` | `ag.governed-loop.governed-repair-verification/v1`; exact verifier response |
| `GovernedRepairVerifierRootV1` | `ag.governed-loop.governed-repair-verifier-root/v1`; deployment-owned executable identity and closed profile catalog |
| `GovernedRepairVerifierCatalogV1` | `ag.governed-loop.governed-repair-verifier-catalog/v1`; root-owned principal/mandate profiles |
| `GovernedAgPolicyRootV1` | `ag.governed-loop.ag-policy-root/v1`; genesis-pinned consequence clock, observation/Standing resolvers, exact-work catalog, and optional controlling review |
| `PinnedDeploymentFileV1` | component of deployment-owned roots; absolute path plus exact measured-byte identity, not authority by possession |
| `GovernedDocketAdapterRootV1` | `ag.governed-loop.docket-adapter-root/v1`; genesis-pinned deployment-owned Docket, trust, Standing, executor, checkpoint, and signer coordinates |
| `OccurrenceViewV1` | `ag.governed-loop.occurrence-view/v1`; stable AG-owned projection of loop facts and evidence references, with no raw nested kernel/store state |
| `GovernedCampaignServiceV1` | `ag.governed-loop.product-service/v1`; reusable application contract |

Artifacts are strictly decoded, canonically serialized, domain-separated, and
identity-bound. Identical replay is idempotent. Reuse of an identity with
different bytes fails closed. Durable evidence survives restart; live
currentness and authority do not.

Production disposition verification fails closed unless the campaign store was
created with an immutable deployment-owned verifier root. The root binds an
absolute executable, its measured bytes, and a closed verifier-profile catalog.
Each use reopens and measures the executable before invoking the verifier. A
caller cannot nominate an executable, principal, mandate, or alternate catalog
on disposition submission.

Production Docket use likewise fails closed unless genesis contains a valid
deployment-owned Docket adapter root. The product creation record commits its
canonical bytes and identity into the genesis event. Each consequence-bearing
use remeasures the pinned deployment files before constructing the command
adapter. Changing the root on an idempotent create is a collision; changing the
durable root record contradicts genesis. These are exact application laws, not
an operational claim that an unlocked filesystem path cannot change between
measurement and process execution.

AG policy inputs follow the same product-creation rule. The canonical creation
record binds the complete policy root and its stable idempotency key. Exact
creation replay reopens the same campaign; changed canonical request bytes or a
changed idempotency identity refuse. Consequence time is sampled only from the
pinned clock and cannot regress behind the Store's last durable event.

## Stable AG producer surface

`GovernedCampaignServiceV1` is the application boundary for future clients.
`ag-loopctl` is a client/view over that boundary; its argument structs are not
the normative schema. Occurrence reads return `OccurrenceViewV1`, an AG-owned
projection of loop position, budgets, residuals, current-state identity, and
evidence references. They do not expose the persistence/kernel
`OccurrenceSnapshotV1` or its nested Docket-shaped state variants. The service
provides versioned DTOs and operations to:

- create or idempotently reopen a campaign with genesis-pinned AG policy,
  verifier, and Docket adapter roots;
- record an exact proposal and advance the ordinary observation, standing,
  decision, spend, dispatch, reconciliation, continuation, halt, and completion
  transitions under expected-state comparison;
- retrieve one occurrence, list occurrences with an exclusive stable cursor
  plus closed program-counter/governed-repair-pending filters, and list the
  ordered event stream by monotone sequence;
- read the current state, state digest, event sequence, and machine-readable
  allowed transitions, including the exact current unconsumed and unexpired
  human-decision request when one exists;
- retrieve canonical durable artifacts by exact identity and byte hash;
- retrieve or idempotently create an exact human-decision request under
  expected-state comparison;
- submit an exact disposition through the pinned external verifier; and
- observe the rejected predecessor or newly opened authority-empty successor.

The current-state projection is read in one SQLite snapshot: current
occurrence, head sequence, last durable consequence time, and any open
unexpired decision request cannot be cross-cut under a concurrent writer.
Exact artifact reads first replay the authoritative journal, then
strict-decode, canonical-roundtrip, and recompute the requested artifact's
semantic identity before returning its original bytes.

Clients do not reconstruct private AG state and do not call Docket directly.
Normal consequence transitions still resolve observation and standing at the
AG boundary and obtain Docket custody through the deployment-owned AG
application adapter. Dispatch, poll/reconciliation, and recovery calls do not
accept caller-selected Docket program, trust configuration, Standing resolver,
executor, checkpoint verifier, state directory, or issuance signer inputs.
Every post-genesis mutating product operation uses the caller's exact expected
state as a CAS premise. Campaign creation and decision-request production use
durable idempotency identities; identical replay returns the recorded result
while a changed request under the same identity refuses.

## Safety laws

The implementation and development tests defend these laws:

1. An occurrence's original scope never changes.
2. Every journaled executor effect belongs to the attempt's issuance scope.
3. An out-of-scope effect is not performed before approval.
4. A post-spend halt never refunds or revives the spend.
5. Checkpoint possession grants no authority.
6. Continuation after a governed repair halt occurs only through a distinct
   successor.
7. Dispositions are exact-bound, externally verified, expiring, and one-use.
8. Readjudication cannot become wildcard repair authority.
9. Restart recreates neither currentness nor live authority.
10. Exact replay is idempotent; changed bytes under the same identity are a
    contradiction.
11. Unknown Docket outcomes require reconciliation and never repeat execution.
12. Concurrent disposition/successor attempts admit one legal winner.
13. Docket does not interpret NQ semantics.
14. There is one production repair-governance path.

## Operational status

`qualification/operational/` records local development checks and the
additional trusted-host, deployed-service, and fault-injection premises. Its
machine-readable status remains `qualification_status: not_assessed`.

Local tests can establish deterministic state, replay, exact binding,
structural exclusivity, and fixture nonauthority. They do not establish a real
human verifier, deployed Standing/Docket correspondence, physical effect
idempotency, abrupt power-loss durability, host isolation, wall-clock
correctness, or production fitness. The current path-and-digest checks are
unlocked local-filesystem measurements followed by external-process execution;
they do not establish coherent deployment snapshots, freedom from path
replacement between measurement and use, executable semantics, signer-key
custody, or OS process isolation. Those premises remain operational
`not_assessed` work for a later declared environment and independent review.
