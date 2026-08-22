# Phosphor-ng governed-loop read contract

Status: canonical read-only presentation contract. The operator UI projects
the governed runtime described by `governed-loop-c1.md`; it is not a campaign
state machine and has no mutation surface.

The package/binary remains `ag-operator-ui`; its product identity is
Phosphor-ng. Semantic navigation is versioned as
`phosphor-ng.deep-link/v1` and contains only campaign, occurrence, and optional
proposal identities.

## Source map

| Displayed fact | Canonical owner and read interface | Presentation rule |
|---|---|---|
| campaign, current occurrence, program counter, state digest | AG `inspect` and `status` | show both source results; disagreement is visible |
| runtime-profile schema/digest | AG `inspect` | identity only; it is not authorization |
| replay/accounting totals | AG `replay` and the replay embedded in `inspect` | show exact counts, never a health score |
| ordered transitions and causal evidence | AG `history` | render the verified journal sequence and full successor snapshots |
| refusal and human-required provenance | AG `refusals` | show the typed refusal at its exact state; refusal never becomes authority |
| intervention submission custody/result | AG `intervention-submissions` | distinguish received, custody-refused, governed-refused/accepted, and unknown; none is authorization |
| program, expected work, residuals, budgets | AG occurrence snapshot | show exact values and used/limit pairs |
| observation identity/currentness/basis | AG occurrence snapshot | historical resolver judgment; never external-world truth |
| exact proposal and work binding | AG occurrence snapshot | show typed schema, subject, scope, work, and proposal identity |
| standing and admissibility | AG occurrence snapshot | show retained resolution/decision and policy basis; neither is a spend |
| spend and issuance | AG occurrence snapshot | absence, pending PC, consumed spend, and persisted issuance remain distinct |
| Docket custody/attempt | AG occurrence snapshot; optional Docket `governed-loop inspect` | show both independently; never synthesize agreement |
| indeterminate/settlement/receipt | AG occurrence snapshot; optional Docket inspection | missing receipt is `unknown`, not `failed` |
| Nightshift lineage and NQ admission provenance | optional Nightshift `cycle export-observation` for the AG-bound observation | display propagated provenance verbatim; AG/UI do not reinterpret NQ admission |
| Maude authoring-context lineage | optional Nightshift `cycle export-authoring-context` for exact campaign + occurrence | require owner self-digest plus exact proposal/work agreement; show lineage, never authority |
| Maude handoff custody | optional Nightshift `cycle export-authoring-custody` for exact campaign + occurrence | require owner self-digest, exact lineage/proposal/work join, and retain distinct session-issuer/producer identities; show authentication at ingress, never authority |
| halt/completion/human disposition/intervention history | AG snapshot and transition evidence | show exact halt reason, terminal witness, authenticated request, or human artifact when present; request evidence is not authority |

The supported source schemas are:

- `ag.governed-loop.operational-snapshot/v1`;
- `ag.governed-loop.transition-history/v1`;
- `ag.governed-loop.refusal-history/v1`;
- the typed `OccurrenceSnapshotV1` and `CampaignReplayReportV1` wire shapes;
- `nightshift.observation_export.v1`;
- `nightshift.authoring_context_export.v1` and
  `nightshift.authoring_context_provenance.v1`;
- `nightshift.authoring_context_custody_export.v1` and
  `nightshift.authoring_context_custody_provenance.v1`;
- `docket.governed-loop.inspection/v1`.

An unknown schema is an incompatible source, not a best-effort input.

The optional presentation-only corpus uses
`ag.operator-ui.demo-corpus/v1`. It contains complete instances of the same
campaign index/detail types; it does not define a parallel fixture model. Its
manifest retains the represented owner schema names. Loading checks exact
schemas, snapshot integrity, raw/typed equality, and index/detail locator
correspondence before any page is rendered.

## Typed transport model

Every command result is represented as either:

```text
available { source, command, captured_at, raw, typed value }
unavailable { source, command, captured_at, error kind, detail, exit status }
```

The backend runs only an enum-defined allowlist of canonical read commands.
It separately invokes AG `inspect`, `status`, `replay`, `history`, `refusals`,
and `intervention-submissions`, compares
their campaign/current-state coordinates, and reports exactly one transport
classification:

```text
exact | partial | disagreement
```

This classification describes source correspondence only. It is not a
governance, safety, readiness, or health judgment.

## Epistemic display

The UI labels facts as:

1. canonical persisted fact — journal entries, spends, issuances, custody,
   settlements, residuals, and exact identities;
2. canonical projection — current program counter, replay, and source
   correspondence;
3. external/unavailable — Nightshift/Docket source absent, command refusal,
   clock/world truth, or facts not represented by the canonical contracts.

`unknown` is rendered explicitly. In particular, absent settlement after
dispatch is not displayed as failure, and a consumed spend is never displayed
as available authorization.

## Read-only boundary

The backend accepts only HTTP `GET`/`HEAD`. Its process adapter can construct
only these command forms:

```text
ag-loopctl inspect --database DB
ag-loopctl status --database DB
ag-loopctl replay --database DB
ag-loopctl history --database DB
ag-loopctl refusals --database DB
ag-loopctl intervention-submissions --database DB
nightshift --store STORE cycle export-observation --observation-id ID
nightshift --store STORE cycle export-authoring-context --campaign-id ID --occurrence-id UUID
docket governed-loop inspect --state STATE --issuance ID
```

Campaign database paths are discovered as bounded regular files immediately
beneath one configured root. Request paths select a previously discovered
opaque locator token; they cannot supply a filesystem path or executable.
There are no mutation routes, forms, buttons, generic subprocess arguments,
database queries, or runtime libraries that expose campaign transitions.
Demo-corpus mode executes no owner command and opens no runtime database. It
reads one bounded regular capture file and is visibly identified as demo data.

## Nonclaims

The UI does not prove resolver or source honesty, physical-world truth,
freshness beyond a recorded canonical judgment, deployed host isolation,
receipt delivery, or execution success. It does not authorize, consume,
dispatch, reconcile, retry, continue, halt, complete, or apply a human
disposition.
Authenticated governed-intervention records are likewise display-only facts
from `history`/`refusals`; they add no Phosphor-ng command or HTTP method.
