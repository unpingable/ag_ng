# Phosphor read-only governed-runtime inspector

**Phosphor** is the operator-facing identity of the existing
`ag-operator-ui` Rust package and binary. It is a loopback-only
campaign/occurrence inspector. It renders
canonical AG, Nightshift, and Docket read projections; it is not a runtime
state machine and cannot change governed state. The exact typed source map is
[`operator-ui-read-model.md`](operator-ui-read-model.md). Its relationship to
Maude and legacy Phosphor is fixed by
[`operator-surface-convergence.md`](operator-surface-convergence.md).

The public name is Phosphor. Existing `/phosphor-ng` routes, Rust package and
executable names, and persisted read-model schemas remain unchanged for
compatibility. A product-name change is not a protocol migration.

## Build and launch

Build the three owner CLIs and UI from their existing workspaces. Then point
the UI at a directory whose immediate regular `.sqlite` files are AG campaign
stores:

```bash
cargo build --locked -p ag-app --bin ag-loopctl -p ag-operator-ui

target/debug/ag-operator-ui \
  --campaign-root /absolute/path/to/ag-campaigns \
  --ag-loopctl /absolute/path/to/constellation-ag/target/debug/ag-loopctl \
  --nightshift-bin /absolute/path/to/constellation-nightshift/target/debug/nightshift \
  --nightshift-store /absolute/path/to/nightshift/store.sqlite \
  --docket-bin /absolute/path/to/constellation-docket/target/debug/docket \
  --docket-state /absolute/path/to/docket/state
```

Open `http://127.0.0.1:8417/phosphor-ng`. Nightshift and Docket coordinates are optional;
when omitted or unavailable, the campaign remains inspectable and the source
is labeled `unknown`/`unavailable`. The bind address is loopback-only. JSON
read models are available at `/api/v1/campaigns` and
`/api/v1/campaigns/LOCATOR_TOKEN`.

Stable navigation uses canonical semantic identities rather than locators:

```text
/phosphor-ng/campaigns/{campaign}/occurrences/{occurrence}
/phosphor-ng/campaigns/{campaign}/occurrences/{occurrence}/proposals/{proposal}
```

The proposal form refuses a mismatch. Historical occurrence links remain
pinned to the latest verified journal state of that occurrence. These URLs are
navigation only and carry no authority. Operational locator-token routes remain
an internal compatibility surface for source-error and demo captures.

The UI invokes only these owner commands:

```text
ag-loopctl inspect|status|replay|history|refusals|intervention-submissions --database DB
nightshift --store STORE cycle export-observation --observation-id ID
nightshift --store STORE external-observation export --campaign-id ID \
  --occurrence-id UUID --evaluated-at-unix-ms DISPLAY_TIME \
  --evidence-ttl-ms DISPLAY_WINDOW
docket governed-loop inspect --state STATE --issuance ID
maude-observation-acquisition export-occurrence --ledger LEDGER \
  --campaign-id ID --occurrence-id UUID
```

All source programs must be absolute paths with their canonical executable
name. Commands have bounded runtime and output. Campaign URL tokens select one
already-discovered root child and cannot supply paths.

The intervention-submission projection contains immutable ingress custody
receipts. Phosphor keeps `received`, `governed_accepted`,
`governed_refused`, `custody_refused`, and `outcome_unknown` distinct and does
not present any of them as authorization or execution. It exposes no
submission command, form, or browser write path.

## Deterministic lifecycle demo

The presentation corpus is generated from the production `CampaignEngineV1`
fixtures and serialized through the same typed read model used in live mode:

```bash
scripts/run-operator-ui-demo.sh
```

The script writes only to a temporary directory, builds 20+ browsable campaign
snapshots, launches the loopback UI, and removes the capture at exit. The
corpus covers every program counter plus human-required, budget exhaustion,
partial sources, malformed/refused owner output, projection disagreement, and
a multi-occurrence successor with its own exact work and proposal. The page
header says `deterministic demo corpus`. It is never presented as live runtime
state.

The capture schema is `ag.operator-ui.demo-corpus/v1`. Loading is bounded to
64 MiB / 512 campaign entries. Typed values must correspond exactly to their
retained raw JSON, index/detail locators must match, and current owner schemas
and integrity checks must pass. These checks make fixture drift visible.
Because the corpus intentionally retains several time-slice captures of one
lifecycle, its `semantic_link_targets` manifest selects the complete-history
capture for historical links and a production-engine-derived successor capture
for the successor's own proposal link. Those selectors are explicitly
fixture-only and are not runtime provenance or a source-reconciliation rule.

## Reading the display

- `persisted fact` marks journal, spend, issuance, custody, refusal, settlement,
  and exact identity records.
- `projection` marks owner-computed current state, replay, or transport
  correspondence. It does not mean healthy, safe, approved, or ready.
- `unknown`/`unavailable` marks a fact the canonical source did not establish or
  a source that could not be queried.

The campaign detail follows observation → proposal → standing/admissibility →
AG spend/issuance → Docket custody → dispatch → settlement/reconciliation →
fresh-observation requirement → successor occurrence. The transition timeline
uses AG's verified journal. Raw structured owner output remains available under
each source.

A Docket `accepted` record means custody exists and the outcome is unknown.
It is not displayed as failure. An AG spend is always displayed as consumed;
the UI never represents it as available authority. Propagated NQ admission is
shown only as part of Nightshift's raw canonical observation and is not
re-evaluated by AG or this UI.

The index is ordered by most recent durable transition by default. Read-only
links can filter exact projected facts (`nonterminal`, `reconciliation`,
`human required`, `terminal`, or `source problem`) or order by campaign/state.
These are display selections over canonical values, not saved views or new
classifications.

The index uses the campaign store's basename as its scan label and renders a
canonical `sha256` campaign identity in shortened typography. The link target,
accessible label, hover text, campaign detail, and raw projection retain the
full exact identity. The store name remains an operational locator and never
becomes campaign identity or authority.
Campaign-grid cells wrap long terminal witnesses and identifiers. In
particular, a `Completed` witness remains inside the program-counter column at
narrow desktop widths rather than colliding with the last durable fact.

Detail pages use three disclosure layers borrowed from the established Maude
operator convention: immediate orientation, exact typed detail, and raw owner
facts. Occurrence boundaries and predecessor links come from the verified AG
journal. A timeline never fills a missing transition. Long raw values scroll
inside their own region, and every raw source labels its owner, command,
schema, capture time, and exact diagnostic.

The detail heading leads with the human-distinguishing campaign-store label;
the canonical campaign digest remains directly available in secondary,
selectable typography and raw owner data. A compact **Available inspections**
area anchors the current occurrence case to authority, execution, history,
evidence, refusal, submitted-intent, and raw-source views. Every item is
navigation within this GET/HEAD-only instrument. It is not an intervention or
runtime-action menu.

The HTML timeline renders at most the most recent 500 verified transitions and
states the shown/total count when truncated. The complete bounded owner history
remains available in raw canonical data; truncation is never silent. Canonical
command output remains capped at 16 MiB.

## Error behavior

Missing stores, failed commands, malformed output, unsupported schemas,
projection disagreement, and optional-source loss remain separate visible
diagnostics. The UI never merges disagreeing results. A missing campaign is a
404; an unreadable campaign root is a visible 503. All responses are `no-store`
and use a restrictive content-security policy.

Run the structural and automated checks with:

```bash
scripts/check-operator-ui-read-only.sh
cargo test --locked -p ag-operator-ui
cargo test --locked -p ag-app --test governed_loop_engine \
  operator_views_render_every_canonical_counter_from_real_persisted_history
```

## Explicit non-goals and environmental limits

There are no forms, mutation routes, arbitrary subprocess arguments, direct
SQLite reads, authorization APIs, dispatch controls, retry controls,
reconciliation submission, or human-disposition controls. The UI does not
prove source/resolver honesty, external-world truth, physical executor
correspondence, abrupt-power-loss behavior, host-principal isolation, or backup
correctness. Those remain deployment/environment qualification concerns.

## Governed intervention contract and remaining browser questions

The runtime meanings are now fixed by
[`governed-intervention-contract.md`](governed-intervention-contract.md): exact
reconciliation, bounded read-only probe intent, authority-empty successor,
safe continuation halt, and the pre-existing closed human disposition are
separate records. Phosphor renders their journal provenance but still has no
submission path.

The remaining questions concern a future browser write service, not runtime
semantics:

1. Which authenticated browser/session transport may deliver request bytes to
   the genesis-pinned verifier without URL or cookie possession becoming a
   mandate?
2. Which deployment-owned principal/mandate scopes may originate each narrow
   class, and how are revocation and expiry presented before submission?
3. Which owner produces admissible reconciliation evidence? An operator note
   is not automatically a Docket settlement.
4. Should Maude author all request classes, or should reconciliation use a
   separate evidence-review desk while preserving the shared wire schema?
5. Which refusal classes can share review ergonomics without sharing an
   authority path or disposition contract?
6. What exact predecessor evidence must remain pinned onscreen before a human
   signs a successor or disposition request?

Any future write surface must be designed as a separate governed campaign. It
must not be added to this package by placing buttons over existing commands.

## Maude / Phosphor convergence

Maude is the bounded-plan/supervised-session desk. Phosphor is the durable
governed-runtime inspector. They share exact vocabulary, identity display,
honest absence, and the versioned read-only link contract—not authority or a
runtime library. Nightshift's immutable authoring-context projection supplies
exact plan/session ↔ occurrence/proposal/work lineage where newly recorded.
Phosphor checks that relation against the selected AG state; absent
historical or runtime-generated context remains visibly unlinked. See the
convergence contract for the full legacy disposition and future intervention
boundary.

For newly authenticated handoffs, Phosphor also reads Nightshift's separate
`export-authoring-custody` projection. It displays the independently pinned
Maude session issuer and delivery producer, session/handoff receipts, target
runtime, and caller-sealed cycle time only after the custody record agrees with the exact
lineage and AG proposal/work. `custody not recorded` remains valid historical
absence. Producer authentication is never presented as standing or authority.

For occurrences with workflow-specific application/world evidence,
Phosphor also reads Nightshift's exact `external-observation export`
projection. It shows authenticated producer custody, candidate/source
identities, exact PlanNode claims, and whether the source time falls inside an
explicit configured display window. That arithmetic age label is not
Nightshift currentness. Docket settlement remains an attempt outcome rather
than proof of present health; absent candidates remain honestly unrecorded.

When `--maude-acquisition-bin` and `--maude-acquisition-ledger` are configured,
Phosphor also renders the exact occurrence-scoped acquisition trigger,
request, adapter, settlement, evidence candidate, and immutable event stages.
This source is mechanics provenance. `scheduled`, `adapter failed`, `custody
outcome unknown`, `custody accepted`, and a separately rendered Nightshift
currentness result are not collapsed into a monitoring status. The only Maude
verb reachable from the inspector is the exact read-only `export-occurrence`
shown above.

The external-evidence panel now separates historical authenticated custody,
display-only arithmetic evidence age, Nightshift composition/profile, and the
owner-produced currentness result at the selected governed evaluation. A
historical observation that was current at one evaluation is not labelled
current now by the UI. See Maude's
`docs/OBSERVATION-ACQUISITION-ORCHESTRATION.md` for trigger/recovery law.

For Nightshift v4 decision-relative observations, the panel keeps effectful
qualification and read-only steady-state evidence separate. It leads with the
historical qualification's exact compiled-artifact binding, then shows the
independently timed passive acquisition and Nightshift-owned currentness
horizon. The UI states explicitly when no new fault test occurred. A new
passive acquisition may refresh steady-state evidence; it neither renews the
qualification timestamp nor creates a failure-survival claim.

The PlanDocument shown in that panel is labelled as an owner-established exact
qualification match. Nightshift admits the composition only after binding the
proposal's target PlanDocument to Q at both admission and consequence time;
the UI does not calculate or carry qualification between design revisions.
Qualification occurrence, exact work, compilation, and PlanDocument remain
visible together so a stable PlanNode cannot lose its artifact-generation
context during cross-probing.

For the closed local-Compose V1 workflow, deployment/effect and qualification
of the exact artifact are one authorized workflow boundary. The retained
lifecycle therefore contains no pre-Q2 passive C2 observation and the
inspector must not imply one. S3 follows settled C2 qualification; the hostile
Q1+S3 view proves only that passive freshness cannot make Q1 applicable to C2.
The UI renders Q as evidence of a particular governed qualification occurrence,
not as a mutable `qualified` attribute on an artifact. A future deploy-only,
canary, or staging lifecycle would require a separate owner contract.
