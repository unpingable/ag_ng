# Governed Admissibility Calculus crosswalk

## Status and fence

This crosswalk is pinned to the clean public Lean revision
`ff491b808ebeab2a132d9ade46d234cf85dcfbe9` (release 14.0.0, 2026-07-18).
It is an implementation-obligation map, not a runtime dependency or a proof of
Rust conformance.

> A Lean theorem may justify an adapter contract. It never confers runtime
> authority.

Lean proves properties of its declared objects and assumptions. Rust must
separately survive parsing, canonicalization, persistence, concurrency, stale
state, partial writes, hostile inputs, and version drift. The adapter is the
membrane where those different failure surfaces are made explicit. The
machine-readable companion is `formal-calculus-obligations.json`; no daemon
loads it as authority.

## Promoted surface map

| Lean v14 rung | Lean claim | AG-ng surface | Disposition |
| --- | --- | --- | --- |
| Domains and `Located` | Domain transport and carried locations do not repair or authenticate evidence | `ag-kernel::PathVerdict`, `LocatedObstruction`, and ordered traces | Structural only. Rust locations are operational identifiers; their authenticity comes from daemon/store custody, not the Lean carrier. |
| `GovernedFamily` | Claim-indexed witness/refusal data, separate standing/custody/obligation books, exclusivity, total decision | Concrete AG-ng family claims, witnesses, refusals, books, and `NativeJudgment` | Partially correspondent. Rust has four fixed books, fallible observation around a total native decision, and no claim that its types instantiate the Lean structure. |
| Weathering and bounded paid reachability | Two reviewed governed-family inhabitants | No runtime family | Unmapped. These examples constrain interpretation but do not authorize adding weathering, payment, settlement, or reachability APIs. |
| `SpineEncoding` / `LosslessEncoding` | Exact claim-indexed refusal packets round-trip through the selected encoding | Typed Rust refusals plus `CalculusDecisionV1` digest binding | Structural only. JCS round-trip and substitution tests preserve Rust evidence; no theorem establishes a Lean/Rust encoding isomorphism. |
| Indexed comparison | A kind cannot be stored without its law; loss receipts and nonclaims remain attached to the selected map | Proposal/effect/evaluator identities and the obligation ledger | Unmapped as a comparison engine. Runtime digests name bytes; they do not prove a declared comparison law or source shape. |
| Stored-decision crossing | Each native family is evaluated once and all downstream views derive from the stored pair | Existing concrete crossing evaluators plus the non-authorizing stored decision adapter | Partially correspondent. The adapter binds and consumes one stored result; durable daemon integration and correspondence evidence remain future work. |
| Origin/history-bound BreakGlass | Exceptional lifecycle instance retains exact origin, ordinary denial, and audit history under explicit assumptions | No schema, effect, mandate, or execution path | Deliberately absent. BreakGlass remains fail-closed until an independently reviewed model-only campaign and later operator decision. |

## Runtime obligations

The correspondence membrane keeps four claim classes separate:

1. **Formal evidence:** what the pinned Lean theorem proves under its declared
   assumptions and axiom footprint.
2. **Adapter evidence:** what Rust types, canonical encodings, and hostile tests
   preserve.
3. **Runtime evidence:** what authenticated peers, committed stores, clocks,
   executables, and observed host state establish.
4. **Authority:** what a closed reconstruction function may create from exact
   committed runtime evidence.

The first adapter binds domain, epoch, lifecycle origin, evaluator identity,
input digest, adapter schema, Lean release, and Lean revision to the complete
native outcome. It distinguishes semantic refusal from operational
indeterminacy, retains native evidence, and provides a one-use projection
ledger. It cannot create `Authority`, does not authenticate the evaluator, and
cannot prevent rollback to a copied older store without the existing
store/epoch ceremonies.

## Explicit non-correspondence

The v14 corpus makes no runtime-conformance, cryptographic, attestor-honesty,
origin-allocation, unconditional state-change, general transition-universe,
or payment/settlement lifecycle claim. AG-ng does not infer any of those.
Likewise, AG-ng's successful canonicalization, signature verification, durable
write, or effect receipt proves an operational fact—not a Lean theorem.

The promoted BreakGlass instance includes accepted `Quot.sound` and
`Classical.choice` footprints over its opaque substrate. It must not be
described as axiom-free, and its existence does not weaken AG-ng's current
BreakGlass exclusion.

## Campaign disposition

- Campaign 1: this crosswalk, the machine-readable obligations, and the clean
  public-source/license pin.
- Campaign 2: pure non-authorizing adapter in `ag-kernel`; no daemon or effect
  catalog consumer.
- Campaign 3: hostile serialization, baseline drift, replay, restart, foreign
  origin, and concurrent-consumption qualification.
- Deferred: durable daemon consumption and a model-only BreakGlass campaign.
