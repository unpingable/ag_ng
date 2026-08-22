# Maude / Phosphor-ng operator-surface contract

Status: convergence contract for the current canonical runtime. It changes no
governance or authority semantics.

## Surface roles

| Surface | Owns or presents | Does not own |
|---|---|---|
| Maude | mutable pre-governed PlanDocument artifacts, typed edit/check/diff/lock operations, bounded-plan ingress, supervised-session driving, intent/plan context, intervention and promotion requests routed to its Governor authority, run testimony and review context | AG-NG currentness, standing, authorization, campaign continuation, Docket execution, or independent governed-proposal authorship |
| Phosphor-ng `/design` | Maude-owned browser workbench over the same pre-governed Plan Core revision boundary | workflow compilation from prose, governed handoff, AG/Nightshift/Docket mutation, or authority |
| Phosphor-ng `/inspect` | read-only Nightshift → AG-NG → Docket campaign/occurrence provenance, authority lifecycle, execution custody, settlement/reconciliation, refusal, and terminal facts | plan/proposal authoring, authorization, dispatch, reconciliation decisions, retries, human disposition, or any runtime mutation |

Current Maude doctrine owns mutable plan artifacts before governed handoff.
Its headless Plan Core, TUI/CLI lane, and separate `/design` service all use
the same typed revision boundary. Maude is the intent/plan-side desk, not a
second AG-NG office. `ag-operator-ui` remains the Rust package and binary name
for `/inspect`, while the operator-facing product family is **Phosphor-ng**.
This preserves the qualified read-only inspector as a separate trust domain.

The interaction boundary is artifact-first: Maude presents exact intent,
plan, and request artifacts for inspection and review; canonical runtime
owners check those artifacts and own every judgment; Phosphor-ng traces the
resulting facts and witnesses. The shared operator grammar is `inspect`,
`trace`, `propose`, `compare`, `reconcile`, `provide disposition`, `open
successor`, `halt`, and `follow provenance`. Similar presentation must never
collapse these distinct contracts, and a shared theme is not required for the
surfaces to belong to one system.

## Shared vocabulary

Canonical runtime terms are not replaced with friendly aliases:

| Term | Operator meaning |
|---|---|
| campaign | durable governed program identity |
| occurrence | independently allocated, authority-isolated continuation unit |
| observation | Nightshift evidence identity cited by an occurrence |
| proposal | immutable AG exact-work proposal identity; not authorization |
| exact work | immutable work payload identity bound to the occurrence |
| DecisionBasis | normalized Nightshift precondition vocabulary bound by digest |
| standing | present-tense external authority fact; not an AG spend |
| admissibility | positive AG policy decision; authorization is still pending |
| authorization | one exact consequence-time permission for one occurrence/work |
| spend | durable one-use consumption of that authorization |
| issuance | deterministic AG instruction persisted after spend |
| custody | Docket acceptance of the issuance and its one attempt |
| attempt | Docket-owned exact execution attempt identity |
| dispatch | custody/effect handoff; not proof of outcome |
| outcome unknown | mechanics may have occurred; absence of receipt is not failure |
| reconciliation | exact classification required before any repeat path |
| settlement | known Docket outcome; does not authorize continuation |
| fresh observation | independent Nightshift evidence required for continuation |
| successor occurrence | new authority-empty occurrence after the required boundary |
| refusal | durable explanation that did not create authority |
| halted | durable non-effecting terminal-for-now state |
| human-required | explicit refusal/disposition boundary, never a generic error |
| completed | terminal campaign state with its retained witness |
| residual work | explicit unresolved obligations preventing false completion |

The family preserves these distinctions: pending ≠ consumed; accepted ≠
settled; unknown ≠ failed; unavailable ≠ refused; settlement ≠ continuation
authorization; retry ≠ a second dispatch or inherited successor authority.

## Shared visual semantics

Both surfaces use exact identifiers, explicit source/provenance labels, honest
empty/error states, and progressive disclosure from orientation to detail to
raw law/facts. `unknown`, `unavailable`, `refused`, `authority consumed`,
`human-required`, and `terminal` keep distinct labels. Maude remains an
authoring/executor desk; Phosphor-ng remains a dense trace inspector. Family
resemblance does not require a shared theme or runtime library.

## Read-only deep-link contract

Schema: `phosphor-ng.deep-link/v1`.

```text
/phosphor-ng/campaigns/{campaign-id}/occurrences/{occurrence-id}
/phosphor-ng/campaigns/{campaign-id}/occurrences/{occurrence-id}/proposals/{proposal-id}
```

Path segments use RFC 3986 percent encoding. Campaign and proposal IDs are
canonical `sha256:<64-lower-hex>` identities. Occurrence IDs are canonical
lowercase hyphenated UUIDs. Extra segments, malformed encodings, and
noncanonical identifiers refuse. The proposal-bearing form additionally
requires that the selected occurrence's retained proposal matches exactly.

The route selects the latest verified journal snapshot of that exact
occurrence. Therefore a historical occurrence remains historical and is not
redirected to the campaign's current occurrence. A successor is addressed by
its own occurrence and, when recorded, its own proposal; it never inherits a
predecessor link. The operational database filename/locator token is not part
of this contract.

Deep links carry no signature, capability, spend, issuance, secret, or standing
material. URL possession grants nothing. The API form is the same path under
`/api/v1`; it returns the independently sourced campaign read model.

## Current cross-surface correspondence

Nightshift now owns `nightshift.authoring_context_provenance.v1` at its exact
proposal-preparation handoff. The immutable record binds Maude `plan_ref` and
session identity to the exact Nightshift intent and AG campaign, occurrence,
proposal, and work identities. Its self-digest is validated again against the
independently prepared AG request; the relation is not sent to AG and supplies
no authority input.

- Maude queries `nightshift.authoring_context_export.v1` by exact plan and
  session before constructing a Phosphor-ng URL.
- Phosphor-ng queries the same owner by exact campaign and occurrence, then
  requires proposal/work equality with the selected AG snapshot before showing
  context.
- Phosphor-ng separately queries
  `nightshift.authoring_context_custody_export.v1` and shows a handoff as
  authenticated only when its session issuer, delivery producer, lineage,
  campaign, occurrence, proposal, and work bindings validate. Custody is an
  ingress fact, not authority.
- an authored plan with an available-empty owner response is `not handed off`;
- a historical/runtime-generated occurrence with no record is `authoring
  context not recorded`;
- historical records are not backfilled, and successors never inherit a
  predecessor relation.

No timestamps, filenames, titles, prose, or digest similarity participate in
linking. Maude has no stable browser-addressed plan/session view today, so
Phosphor-ng displays exact Maude identities but does not fabricate a backlink.
The historical cut line and remaining host/key/executable assumptions are
documented by Nightshift's separate authoring-lineage and handoff-custody
contracts.

## Legacy Phosphor disposition

| Legacy concept | Disposition |
|---|---|
| compact receipt/identity strips, readable raw records, deep links, restrained status badges, narrow-window layout | retain as presentation ideas |
| exact provenance visible beside human-readable context | retain conceptually |
| supervised run/session review | superseded by Maude |
| campaign/occurrence/runtime trace inspection | superseded by Phosphor-ng |
| generic chat, unconstrained builder/wizard, artifact promotion, direct runtime imports, client-side semantic interpretation | obsolete |
| direct write/action routes, local receipt minting, authority or reconciliation controls | forbidden under current authority doctrine |

The `gov-webui` repository should remain frozen historical evidence. It is not
a compatibility target and should not be deployed as part of the canonical
surface family. “Phosphor-ng” now names the product family: Maude-owned mutable
`/design` and mechanically read-only `/inspect` remain distinct processes and
trust domains. It is not a revival of the old cockpit.

## Governed intervention seam

A future operator action may begin in Maude as an exact request and may be
oriented from Phosphor-ng by navigation to a separately authenticated ingress.
The canonical request taxonomy, exact target law, authentication boundary, and
replay/refusal semantics are now defined by
[`governed-intervention-contract.md`](governed-intervention-contract.md).
The separately qualified non-browser loading dock is
[`governed-intervention-ingress.md`](governed-intervention-ingress.md): Maude
may prepare, inspect, and package exact bytes for AG-owned submission, while
Phosphor-ng `/inspect` displays the immutable receipt history. Navigation
remains neither the workflow nor approval/authority. `/design` mutates only
pre-governed Plan Core artifacts; no browser governed-intervention mutation
surface is implemented.
