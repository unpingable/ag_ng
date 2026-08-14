# Canonical governed repair R4: pre-spend scope discovery

This R4 correction is being constructed under explicit external human
development authorization.  The governed loop does not authorize or review
its own construction, and this document is not standing, qualification, or
operational authority.

## Correction design

R4 adds two disjoint product transitions:

1. A typed pre-spend insufficiency halt is accepted only from an exact
   `ProposalRecorded` cut.  It persists a Store-verifiable marker binding the
   proposal, immutable original scope, diagnostic basis, caller state, and
   idempotency identity.  The generic halt transition cannot create this
   marker.
2. An exact discovery transition is accepted only from that typed halt.  In
   one committing transaction it checks the caller cut, derives the strict
   original-plus-delta scope, records `PreSpendScopeDiscoveryV1`, and creates
   one distinct `ObservationRequired` occurrence.  The predecessor is never
   rewritten.  The new occurrence carries only a nonauthorizing constraint on
   the exact revised proposal; it must obtain a fresh observation, Standing,
   admissibility, spend, issuance, and Docket custody through ordinary law.

The pre-spend artifact and constraint are separate from the externally
approved post-spend successor basis.  No Docket wire, custody, or result law
changes in R4.

Exact replay may return the one committed discovery/successor relationship.
Changed bytes under a reused idempotency identity, stale caller cuts, generic
halts, post-spend states, and conflicting concurrent deltas refuse before a
durable consequence.

Checkpoint-bound post-spend successors and expired proposals are ineligible
at both the product projection and kernel boundary.  The exact revised
proposal retains the original expiry, so an expired authority-empty revised
occurrence cannot advertise or execute proposal recording.

## Final source-path census

The causal implementation surface is:

- `crates/ag-campaign/src/governed.rs`: canonical artifacts, constraints, and
  kernel transition, replay, expiry, and anti-laundering laws.
- `crates/ag-campaign/tests/governed_loop.rs`: pure-kernel hostile specimens.
- `crates/ag-app/src/governed_loop.rs`: canonical application-engine entry.
- `crates/ag-app/src/governed_store.rs`: transactional persistence, replay,
  artifact indexing, and caller-cut CAS.
- `crates/ag-app/src/governed_product.rs`: versioned product DTOs, projections,
  operations, and service entry points.
- `crates/ag-app/src/bin/ag-loopctl.rs`: product-service CLI adapter.
- `crates/ag-app/src/governed_product_tests.rs`: public product, laundering,
  CAS, replay, concurrency, refusal preservation, checkpoint-route, and expiry
  coverage.
- `crates/ag-app/tests/governed_pre_spend_discovery.rs`: external-crate public
  service and CLI specimens for exact revision, strict decoding, reopen,
  replay, stale callers, and concurrent creation.
- `crates/ag-app/tests/public_api_exclusivity.rs`: one production-capable
  pre-spend revision path.
- `docs/canonical-governed-repair.md`: canonical product-operation and artifact
  vocabulary.
- this document: ownership, semantics, and scope record.

No Docket source or shared wire corpus changed.

## Bounded hostile-review disposition

The bounded R4 review found and closed three material seams before freeze:

- checkpoint-bearing post-spend successor proposals could enter a typed
  pre-spend halt;
- a nonauthorizing refusal record could strand an otherwise advertised
  discovery; and
- proposal expiry could leave typed or revised occurrences advertising an
  operation that the kernel could not execute.

No critical or high R4 defect remains.  Two Store-corruption specimens remain
nonblocking hardening backlog: directly re-chained duplicate pre-spend
idempotency rows, and an evidence/transition timestamp divergence.  Reopen
code rejects both classes, while product collision and strict replay tests
cover their ordinary reachable forms.
