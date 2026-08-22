# Canonical governed orchestration loop C1

Status: canonical AG-NG campaign-transition contract. The production path is
`ag-loopctl` → `CampaignEngineV1` → `GovernedLoopKernelV1` →
`CampaignStoreV1`. It composes the existing Nightshift observation resolver
and Docket governed-loop custody interface; it does not replace either office.

## One transition owner

AG owns campaign, occurrence, and continuation law. `ag-campaign` is the pure
state-transition kernel, `ag-store` is its durable program counter and journals,
and `ag-app` invokes the current external owners. These are layers of one state
machine, not competing campaign implementations.

`CampaignDriverNG` is not a campaign authority. If selected as the exact
Docket-custodied executor adapter, its production `execute` operation performs
only the sealed mechanics and its `reconcile` operation reads executor-local
idempotency state. Docket owns issuance custody, attempt identity, dispatch,
and execution receipt/reconciliation. An execution receipt is evidence for a
new observation cycle; it cannot advance AG by itself.

The retired fixed-stage `agctl campaign`/Docket campaign-stage-standing design
is historical. In C1 an **occurrence** is the durable authority boundary for
one typed exact-work proposal. A human-facing stage is a projection of the
current occurrence and proposal; no second stage state machine may mint or
consume authority.

## Durable loop law

The normative sequence is:

```text
fresh Nightshift observation
→ typed exact-work proposal
→ fresh observation and standing resolution
→ catalog admissibility decision
→ fresh observation and standing re-resolution
→ atomic one-use authorization spend and exact issuance
→ Docket custody and dispatch
→ settlement or exact reconciliation
→ observation required
→ fresh Nightshift observation
→ successor occurrence, refusal, human disposition, halt, or completion
```

`CampaignId` is durable across the loop. Each `OccurrenceId` is independently
allocated and never derived from proposal content. The occurrence binds the
program identity, expected exact work, residual set, and bounded retry/probe/
escalation facts. Its durable program counter is exactly one of:

```text
ObservationRequired | ProposalRecorded | StandingRequired
AdmissiblePendingAuthorization | AuthorizationConsumed | Dispatched
ReconciliationRequired | SettledObservationRequired | Halted | Completed
```

Proposal recording is informational. Standing is resolved at `decide` and
again immediately before `authorize`; observation currentness, exact basis,
standing, catalog, subject/scope, occurrence, and work bindings are rechecked
at the consequence boundary. `authorize` atomically commits the one-use spend
and exact Docket issuance before any dispatch. A spend cannot return to an
unconsumed state and no recovery API constructs one.

Campaign genesis atomically persists a canonical
`ag.governed-loop.runtime-profile/v1`. It byte-pins the observation resolver,
standing resolver, exact-work catalog, optional controlling review, optional
human verifier, and the Docket executable/trust/standing/executor/signing root.
The Docket state directory remains an explicitly mutable locator. The executor
plan is occurrence-bound work, not a global deployment grant: its content
identity must equal the work in AG's spent issuance and Docket verifies that
binding before mechanics. Later CLI
arguments repeat the pinned coordinates for compatibility; equality and byte
remeasurement make them assertions, not authority selectors. Drift or
substitution fails before the external program is invoked.

Every pinned file coordinate is an absolute path plus `sha256` of its exact
bytes. The profile contains the observation and standing resolver files and
identities, standing TTL ceiling, exact-work catalog, optional controlling
review, optional human verifier, and a Docket root containing its executable,
state-directory locator, trust file, standing resolver, executor adapter, and
AG issuance signer identity/key. Per-occurrence `--executor-config` is not a
profile member: it is exact work and Docket checks its content identity against
the signed issuance. Production genesis is therefore:

```text
ag-loopctl init --database DB --genesis GENESIS --runtime-profile PROFILE
```

The production CLI refuses stores created without this atomic profile binding;
the unbound library constructor exists only for closed in-process fixtures.
The canonical provisioning, identity/custody, restart, backup, structured
inspection, and environmental-qualification procedure is
[`governed-loop-deployment-qualification.md`](governed-loop-deployment-qualification.md).
The read-only `inspect`, `status`, `replay`, `history`, and `refusals`
projections are the sole AG inputs to the local operator UI. The UI contract
and launch procedure are [`operator-ui-read-model.md`](operator-ui-read-model.md)
and [`operator-ui.md`](operator-ui.md); neither introduces a transition.
Authenticated operator intent is separately governed by
[`governed-intervention-contract.md`](governed-intervention-contract.md).
An intervention request is exact input to an existing transition law, never
authority or a transition by itself.

## Crash and recovery law

| Last durable boundary | Meaning after restart | Legal next step |
|---|---|---|
| before spend | no authorization exists | repeat the read-only gate evaluation |
| `AuthorizationConsumed` before custody | spend is historical; outcome not inferred | present the same issuance to Docket or reconcile it |
| `Dispatched` without settlement | effect may have occurred | reconcile the exact issuance/attempt; never repeat mechanics |
| `ReconciliationRequired` | consumed but outcome unknown | exact read-only attempt reconciliation request, typed human disposition after safe halt, or safe halt; never repeat dispatch |
| `SettledObservationRequired` | receipt is durable, posture is not inferred | obtain a fresh Nightshift observation |

Attempted dispatch is neither success nor proof of non-execution. Docket's
settlement/reconciliation identifies the exact attempt. Duplicate exact facts
are idempotent; substituted facts refuse. Restart reconstructs state and
historical spends from the authoritative SQLite journals, never from a
sidecar, receipt, or caller assertion.

## Retry, successor, and terminal law

A retry is a new occurrence, not another dispatch. An indeterminate consumed
attempt must first reconcile. After settlement, a fresh Nightshift observation
is mandatory. If the decision-relative preconditions are unchanged, AG may
open a bounded `Retry` successor occurrence; changed preconditions require a
new proposal and basis. Residual work is exact and monotone: no completion or
program replacement may erase an unresolved residual or attempt.

Retry, probe, and escalation counters are durable facts with finite limits.
Exhaustion halts. Missing/stale/contradictory observation, missing/revoked/
expired standing, binding drift, unresolved outcome, incomplete residual
disposition, and unsupported human authority refuse or halt rather than infer
continuation. `Completed`, `Halted`, and recorded refusal/human-required
outcomes do not dispatch.

## Adversarial qualification map

The finite C1 pack maps composed requirements to executable witnesses. The
Nightshift cross-process suite uses production CLIs and real SQLite stores;
the AG engine/store suites inject deterministic boundary failures without
timing assumptions.

| # | Required attack | Executable witness |
|---:|---|---|
| 1 | admitted/current/authorized happy path | Nightshift `healthy_chain_reaches_docket_and_executes_exactly_once`; AG `production_path_spends_once_settles_and_requires_a_new_occurrence` |
| 2 | NQ-unadmitted evidence | Nightshift `unadmitted_artifact_is_refused_before_a_cycle_is_claimed` |
| 3 | stale evidence | AG `consequence_time_stale_observation_and_revoked_standing_do_not_spend` |
| 4 | denied standing | same witness; `standing_resolver_unavailable_at_decide_or_authorize_fails_closed` |
| 5 | reuse authorization | `normal_path_is_closed_and_one_shot`; concurrent-spend witness |
| 6 | work A/B substitution | Nightshift `submitted_work_other_than_the_prepared_binding_is_rejected`; AG `record_proposal_rejects_unbound_work_before_any_resolution` |
| 7 | historical authorization/later occurrence replay | `each_occurrence_binds_its_own_expected_work`; store uniqueness/replay tests |
| 8 | basis changes before consequence | `a_changed_basis_between_record_and_decide_keeps_the_proposal_unjudged`; `tightened_catalog_before_spend_refuses_and_preserves_state` |
| 9 | crash before spend | `restart_at_each_consequence_boundary_preserves_pc_and_never_recreates_authority` |
| 10 | crash after spend, before custody | same witness; `custody_crash_recovers_to_reconciliation_without_respend_or_repeat` |
| 11 | crash after dispatch, before receipt | same witnesses |
| 12 | effect possible, receipt missing | `indeterminate_attempt_blocks_repeat_until_exact_settlement` |
| 13 | reconciliation says occurred | `exact_reconciliation_and_settlement_replay_are_idempotent_but_substitution_refuses` |
| 14 | reconciliation says not occurred/unknown | `unknown_outcome_can_only_reconcile_or_halt_and_never_repeat`; Docket process suite |
| 15 | two workers race | `concurrent_authorization_consumes_exactly_one_ag_spend`; concurrent settlement and human-resume witnesses |
| 16 | process restart/reopen | `restart_at_each_consequence_boundary_preserves_pc_and_never_recreates_authority`; store reopen/tamper suite |
| 17 | unchanged-precondition retry | `retry_is_a_distinct_occurrence_with_fresh_unchanged_preconditions` |
| 18 | changed preconditions | `changed_preconditions_cannot_be_laundered_as_retry` |
| 19 | repeated failure bounded | `durable_budget_fact_is_nonauthorizing_and_exhaustion_halts` |
| 20 | budget exhaustion | same witness |
| 21 | residual prevents completion | `residual_disposition_refuses_wrong_basis_and_partial_accounting`; `program_replacement_is_authority_empty_and_unresolved_attempt_blocks_resume_or_termination` |
| 22 | refusal retains provenance, mints nothing | Nightshift `ag_refusal_cannot_be_resurrected_by_docket`; AG policy/standing refusal witnesses |
| 23 | result requires fresh observation | Nightshift healthy chain reaches `SettledObservationRequired`, then only an independently sealed fresh cycle opens the distinct successor occurrence at `ProposalRecorded`; AG `production_path_spends_once_settles_and_requires_a_new_occurrence` |

The mechanical gate `scripts/check-governed-loop-authority-surface.sh` also
fails if spend construction leaves the pure kernel, CampaignDriverNG enters
the authority-bearing product graph, the Docket adapter gains an operation,
the genesis-bound profile disappears, or database occurrence/spend fences are
removed.

## Nonclaims and environmental assumptions

This loop does not prove source or resolver honesty, external-world truth,
timely revocation, clock adequacy, filesystem/power-loss behavior on an
unqualified host, cryptographic collision impossibility, Docket/executor host
integrity, or successful execution absent a receipt. NQ admission,
observation currentness, catalog admissibility, standing, AG authorization,
Docket custody, execution, and later observation remain distinct predicates.
