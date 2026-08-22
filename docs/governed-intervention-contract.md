# Canonical governed-intervention contract v1

Status: canonical runtime contract for authenticated operator intent at the
AG-NG governed-loop boundary. It adds no browser mutation surface and changes
no Nightshift, AG authorization, or Docket custody rule.

Authenticated non-browser delivery of these exact records is specified by
[`governed-intervention-ingress.md`](governed-intervention-ingress.md). That
custody layer does not change this taxonomy or confer authority.

> An operator intervention is a proposal for a governed transition. It is not
> the transition itself.

## Ownership and identities

AG owns intervention applicability because it already owns the campaign,
occurrence, exact program counter, budgets, authority history, and continuation
law. The pure owner is `GovernedLoopKernelV1`; `CampaignEngineV1` composes the
external verifier and, only for reconciliation, Docket's read-only attempt
query; `CampaignStoreV1` retains accepted intent in the existing immutable
transition journal. No second intervention state machine exists.

`ag.governed-loop.intervention-request/v1` binds every semantic field into the
content-derived `GovernedInterventionRequestIdV1`:

- authenticated principal, exact mandate, and replay nonce;
- exact campaign, occurrence, and target state digest;
- one closed intervention class and all of that class's exact targets;
- creation time as evidence and an exclusive evaluation expiry.

There is no metadata bag, AG authorization, spend, signature/capability,
Docket credential, or implied current-occurrence selector in the record.
Substitution followed by recomputation of the request digest still fails the
independent exact-state/work/issuance/attempt checks.

The genesis-pinned external human verifier is reused as the deployment
authentication/current-mandate owner, through a distinct versioned verifier
protocol. `HumanPrincipalRefV1` establishes who asked and `MandateRefV1` is
checked against deployment-owned expected scope. Authentication does not
satisfy Nightshift currentness, proposal admissibility, AG standing, AG spend,
or Docket execution standing.

## Closed taxonomy

| Request | Exact target | Legal boundary and effect | Freshness/evidence | Consumption/replay |
|---|---|---|---|---|
| `reconcile_attempt` | campaign, occurrence, state digest, issuance, attempt, sorted evidence refs | only `ReconciliationRequired`; permits one read-only `reconcile_attempt` query; cannot accept custody or dispatch | historical issuance/attempt plus current externally returned Docket fact; request expiry is consequence-time | while Docket remains indeterminate, exact replay is an idempotent read; exact settlement advances once and makes the target stale |
| `request_probe` | campaign, occurrence, state digest, exact read-only probe-work digest, sorted evidence refs | only `ObservationRequired` or `SettledObservationRequired`; consumes one bounded probe fact; performs no mechanics | evidence refs are historical motivation; any acquired observation must enter freshly through Nightshift | committed transition changes the state digest, so replay cannot consume the budget twice |
| `open_successor` | campaign, settled occurrence/state, independent successor occurrence, exact expected work | only `SettledObservationRequired`; opens `ObservationRequired` with no proposal, standing, authorization, spend, issuance, or custody | settlement is historical; successor still requires a fresh Nightshift observation and its own proposal | one exact state transition; predecessor request cannot target the successor |
| `halt_continuation` | campaign, occurrence/state, exact reason | only an existing authority-safe halt boundary; stops future continuation | exact target state is required; no blanket observation rule is invented | one exact state transition; it never means effectful containment |
| existing `human-disposition/v1` | halted campaign/occurrence/state plus typed disposition-specific basis | only `Halted`; separately externally verified and one-use | depends on the closed disposition: termination resolves a fresh observation, while exact residual disposition binds its accounting basis | `HumanDecisionIdV1` is durably consumed at most once |

The existing human disposition vocabulary remains deliberately separate:
`return_to_observation`, `replace_program`, `exact_residual_disposition`, and
fresh-observation `terminate` are not reduced to approve/reject.

No generic `retry`, `approve`, `continue`, `execute`, or `resolve` intervention
exists. A governed retry remains a **new occurrence** whose fresh observation
proves unchanged relevant preconditions and whose proposal identity is exactly
the prior retry basis. Changed work is a new proposal. An effectful diagnostic
or containment operation is ordinary exact work and must traverse fresh
observation, standing, admissibility, one-use spend, and Docket custody.

## Reconciliation is evidence acquisition, not settlement

A reconciliation request is not a reconciliation result. AG verifies its
principal/mandate and exact target, then calls only Docket's read-only
`reconcile_attempt` port. `Accepted` or the same `Indeterminate` fact leaves
the state and outcome unknown. Only Docket's exact bound `Settled` fact invokes
the pre-existing `record_reconciled_settlement` transition. Contrary or
substituted custody/evidence refuses; an operator assertion is not silently
converted into settlement. The reconciliation path has no call to
`accept_issuance`, dispatch, or the executor.

## Refusal and durable provenance

Authentication/integrity failures stop before any governed transition and are
not promoted into trusted operator provenance. Once the principal and mandate
are verified, a stale, foreign, or illegal request is recorded as a durable
non-authorizing refusal with its exact request and verification receipt. The
refusal coordinates identify where evaluation occurred; the retained request
shows what the operator actually targeted. Refusal never changes the program
counter or creates authority.

Accepted state-changing interventions are retained as
`CampaignTransitionEvidenceV1::GovernedIntervention`. The request and external
verification are inside the existing hash-chained transition event and are
revalidated on replay/reopen. Concurrent requests use the same authoritative
compare-and-swap: at most one exact predecessor transition wins. Restart may
recover the request evidence; it cannot recreate eligibility because the
request remains bound to its predecessor state digest.

## Ingress and surface roles

The contract-level campaign engine exposes several narrow typed operations.
The production operator ingress exposes only one generic *transport* verb over
an already typed request:

```text
submit-intervention     # exact signed closed-class request envelope
apply-disposition       # existing, distinct schema and rules
```

`submit-intervention` authenticates exact delivery, then routes the request's
already explicit class through the genesis-pinned external verifier and the
existing class-specific campaign law. It never infers a class from runtime
state. The pre-ingress class-specific CLI adapters were retired before
publication so they cannot bypass submitting-service custody. Reconciliation
additionally uses the genesis-pinned, non-dispatching Docket adapter. Older
low-level `note-probe`, `continue`, and `halt` engine/CLI operations remain
authority-neutral runtime mechanisms for the canonical autonomous loop; they
are not operator-request ingress and are not reachable from Maude or
Phosphor-ng.

Maude may author/package one of these exact records for the authenticated
non-browser ingress. It must not compute applicability, standing, or
authorization. No Maude browser write route is added here.

Phosphor-ng displays retained requests, principal, exact target, verification,
refusal, and resulting transition from the existing owner `history` and
`refusals` projections. It remains GET/HEAD-only and cannot construct or submit
an intervention.

## Human-required states and future controls

`Halted` retains the exact originating program counter, reason, unresolved
attempt (if any), residual work, and authority history. Those facts select the
meaningful future workflow; they do not support one universal “resolve” action.

- an unresolved attempt requires exact reconciliation and may remain unknown;
- unresolved residuals require an exact residual disposition or newly governed
  work, not acknowledgement-as-completion;
- a replaced program or return to observation opens authority-empty state;
- budget exhaustion cannot be bypassed by replay;
- policy/standing/currentness refusal requires fresh canonical evaluation, not
  a human override;
- physical containment, if desired, is new exact effectful work.

Future browser controls must originate these distinct contracts through an
authenticated write service. A Phosphor-ng link or UI click is a locator and
intent gesture, never a standing token or authorization capability.

## Nonclaims

This contract does not prove principal-key custody, mandate-authority honesty,
external-world truth, observation honesty, Docket/executor honesty, timely
revocation, or physical outcome absent a settlement. It does not make Maude or
Phosphor-ng an authority owner and does not add an emergency superuser path.
