# NQ C1 immutable repair-boundary bootstrap

This document defines only the bootstrap boundary by which AG can inspect the
historical NQ C1 repair specimens under
`crates/ag-campaign/tests/fixtures/nq-c1/`. It does not declare that AG or
Docket governed those historical events.

## Identity boundary

Each fixture has three deliberately separate identities:

1. SHA-256 of the exact LF-terminated file bytes, pinned in `DIGESTS.txt`;
2. AG's domain-separated digest over the strict RFC 8785 JCS body; and
3. if Docket consumes the record, Docket's own versioned transcript digest.

AG validates its typed body. Docket records the AG digest opaquely and derives
its own digest from its own typed transcript. Neither side recomputes or
substitutes the other's identity.

## Authority boundary

Parsing proves canonical representation and internal consistency. It does not
construct a proposal, standing, authorization, permit, execution context, or
effect. The closed specimen classification distinguishes:

- an immutable rejected candidate;
- pre-spend scope discovery;
- a consumed repair hard stop; and
- architectural readjudication required.

Those meanings cannot be combined. In particular, the pre-spend record cannot
erase the later spend, the consumed checkpoint cannot authorize another path,
and the architectural census cannot be relabeled as bounded source repair.

The former Docket campaign-stage `exact_repair` proposal/adjudication/standing
chain is historical and cannot bootstrap a new repair. Any future governed
occurrence must start from current AG observation and enter Docket's distinct
governed-repair custody protocol through its exact current inputs. Historical
fixture possession is never one of those authority premises. Neither this
document nor the fixtures constitute AG standing, Docket custody,
qualification, certificate authority, or evidence that AG/Docket governed the
recorded NQ occurrences.
