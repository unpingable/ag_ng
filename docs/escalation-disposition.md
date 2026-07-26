# Escalation — disposition record

Status: **intentionally absent, with no scaffolding.** This record states the finding
and the criteria for any future work. Nothing here is an implementation order.

## What exists now

Nothing. A whole-repository search for `escalat*` returns **zero hits in code**. There
is no escalation type, verdict, wire field, refusal kind, or test. There is no dead
scaffolding to remove and no partial implementation to finish. (In documentation the
term appears only in the records that state its absence — this file,
`docket-issuance.md`, and the README pointer — which is the intended shape; an earlier
revision of this sentence claimed "zero in documentation," which those records
themselves falsified.)

The sixteen `BreakGlass` references in `docs/` are a **different concept** — an
exceptional *authority family*, not an escalation channel. BreakGlass is likewise
absent by decision: it has no runtime schema, catalog entry, mandate, or execution path,
and its exclusion is tracked in `docs/formal-calculus-crosswalk.md` and the release
checklist. Do not conflate the two.

An earlier revision of this record added that "the runtime refuses it as an unsupported
authority family." That was wrong, and it is corrected here rather than quietly dropped.
`BrokerError::UnsupportedAuthorityFamily` exists and maps to an API error code, but
nothing in the workspace constructs it — the refusal is declared, not reachable.
`docs/release-checklist.md:183` records the absence of a BreakGlass path as **checked**;
line 231, "BreakGlass and every unsupported authority family refuse before burn", is
**unchecked**. The earlier sentence merged the two. BreakGlass is absent, which is
stronger than refused, but no runtime witness demonstrates the refusal.

## What the current outcome vocabulary is

Every non-admitted outcome is one of:

- a **refusal** — attributable to the intent, closed vocabularies per layer,
  accumulated losslessly (all families evaluated, every failure retained);
- a **typed indeterminacy** — operationally unknown, deliberately not observable as an
  admission;
- for proposals, the lifecycle state `ReconciliationRequired`, which routes to a human
  operator but is a terminal-uncertainty state with no automatic retry — **not** an
  escalation channel and not an output an upstream consumer receives.

## Is refusal being overloaded?

**No.** The refusal vocabulary is closed per layer and each variant names an
attributable cause; the `is_semantic_compilation_refusal` allow-list explicitly
separates intent-attributable refusal from operationally-indeterminate causes, so
"refused" is not being used as a catch-all for "someone else must decide". What is
missing is not a distinction inside refusal — it is a *third speech act* that does not
exist: a typed demand for a higher authority.

## Where escalation would belong

An AG escalation, if it is ever earned, would establish:

> This office cannot decide this proposal under the authority it holds; deciding it
> requires *this named* higher authority.

That is a statement about **this office's own competence and the authority required** —
not a grant, not a deferral, and not a weak admission. It belongs upstream, in the
office that owns the authorization question.

It does **not** belong in the consuming runtime. That runtime's intake accepts an
authenticated *admitted* decision and mints local standing; an escalation is by
definition not an admission, so it must never arrive there as authorization. If a
future orchestration layer wants to act on escalations, it should consume them from the
authorizing office directly, and its notion of "what to do next" is a fourth office's
concern with its own vocabulary — not the same object under the same name.

## Acceptance criteria for future work

Escalation should only be built when all of these can be satisfied:

1. **A typed required-authority object.** `Escalate` must carry *which* authority is
   required, in a closed vocabulary bound to the decision context — not a free-text
   reason. An escalation whose required authority is a string is a refusal wearing a
   hat.
2. **A real second authority to escalate to.** Today there is one authority tier per
   decision context. An escalation with no reachable higher authority is ceremony;
   the tier must exist and be nameable before the outcome does.
3. **Distinct downstream handling, or none.** Either a consumer can act on an
   escalation in a way it cannot act on a refusal, or the escalation stays internal to
   the authorizing office. If no consumer behaves differently, it is a refusal.
4. **No weakening of the admitted path.** An escalation must not become a route by
   which a proposal is later admitted without the full decision path, the catalog, and
   the authority burn.
5. **Wire consequences stated first.** `ag.docket-issuance:v1` carries admitted
   decisions only. An escalation must not be squeezed into it; it needs its own record
   or no wire form at all.

## Verdict

**Left explicitly unresolved, leaning "owned by a future orchestration layer".** It is
not retired — the concept is coherent and AG classic had it in several faces — but it
is not owed by any current contract, nothing depends on it, and inventing it now would
produce criterion-3 ceremony. Revisit when a second authority tier or an orchestration
consumer actually exists.
