# Canonical governed repair R2 correction basis

Status: **self-produced development correction; operational qualification is
`not_assessed`; awaiting independent review after completion**.

R2 is a bounded correction of the rejected R1 development candidate.  It is
being constructed under explicit external human development authorization.
The governed loop did not authorize or review its own correction, and no R2
record retroactively creates authority for R1 or for an NQ repair.

## Closed correction design

AG remains the owner of governance state and canonical issuance production.
Docket remains the owner of execution custody and sealed execution results.
The cross-repository seam uses one versioned contract and conformance corpus:
AG owns the issuance semantics and canonical scope/delta identities; Docket
strictly authenticates, decodes, recomputes, and compares those identities
before Standing resolution or custody.  Both repositories pin the same corpus
identity, and the cross-process development test passes actual AG product
bytes to actual Docket intake.

| Correspondence | AG producer | Docket consumer | Identity owner | Refusal cut |
| --- | --- | --- | --- | --- |
| issuance | `AgIssuanceV2` | strict issuance-v2 wire | AG | before Standing/custody |
| starting checkpoint | successor proposal and issuance | checkpoint evidence wire | AG; Docket verifies content correspondence | before Standing/custody and again before reconciliation |
| canonical effect scope | structured closed scope | same structured scope | AG RFC-8785 domain identity | before Standing/custody |
| requested delta | sealed requirement input | sealed/replayed requirement | AG RFC-8785 domain identity; Docket reproduces | seal, read, restart, and replay |
| labels | lowercase ASCII alphanumeric segments separated singly by `-._/:`, nonempty, at most 128 bytes; mutable-ref exclusion additionally applies to resource labels | identical grammar | shared contract corpus | strict decode/semantic validation |
| effect journal | issuance-scoped ordered entries | cumulative durable attempt journal | Docket | before result sealing/replay |
| governed result | typed Docket reference consumed by AG | sealed custody result | Docket | Docket seal then AG exact adaptation |
| expiry/time | JSON safe integers only | identical bound | shared contract | before identity, persistence, or effect |

Absent optional checkpoint members are omitted; explicit JSON `null` is not an
alternate spelling.  A present work checkpoint always has a content-manifest
identity.  Every consequence-bearing JSON integer must be in the exact
RFC-8785 interoperable interval
`[-9_007_199_254_740_991, 9_007_199_254_740_991]` before canonicalization.

The canonical AG product service is the only production-rooted application
path.  Lower mutable application engines, issuance signing, and the retired
human-disposition mutation are not externally callable.  Issuance
authentication consumes a Store-produced, process-local, one-use witness of
the exact durable spend.  Test clocks, executors, and fixture verifiers remain
clearly non-production.

Docket freshly verifies the exact immutable checkpoint before unknown-outcome
reconciliation and never repeats normal execution.  Its terminal result binds
the cumulative ordered effect journal, including observations made before an
indeterminate cut.  The ordinary executor path claims only that no
unauthorized effect was reported in the journal Docket validated; executor
completeness and physical containment remain operational premises.

Absent optional members are omitted at the effect-executor boundary as well as
the AG/Docket issuance boundary; explicit JSON `null` is refused rather than
accepted as an alternate spelling.  Replaying an already sealed settlement is
an exact read-only Docket reconciliation and cannot repeat executor mechanics.
AG Store startup/replay holds one SQLite read snapshot across the transition
journal, materialized occurrence, and accounting tables, so a concurrent legal
winner cannot be misclassified as store corruption.

External verification receipt references are one-store unique bindings to one
complete canonical verification record.  Exact replay is idempotent; changed
complete bytes under the same reference refuse.  Durable nested variants
refuse unknown fields, and requested-delta identity is rechecked at seal,
read, restart, and replay.

The Maude-facing surface remains AG-only and versioned: exact occurrence,
state/legality, cursor-stable lists/events, closed artifact inventory and
retrieval, decision request, verified disposition, and successor progression.
Allowed operations are a closed enum derived from the same state, expiry,
budget, Docket-availability, and verifier-availability predicates enforced by
the mutation methods.  Docket-backed operations are advertised only after a
fresh non-authorizing measurement of every pinned adapter coordinate;
disposition submission additionally requires fresh verifier-executable
correspondence.  The consequence boundary rechecks the same correspondence,
so projection never becomes inherited authority.  Historical lifecycle links
survive terminal-state replacement, including completion evidence and
historical dispositions.
No Maude, Phosphor, Docket-client, NQ, or Gen4 implementation is changed by R2.

## Nonclaims

R2 development tests are not independent review, qualification, a controlled
fixture campaign, certificate readiness, deployment, activation, physical
effect containment, executor completeness, global verifier-receipt uniqueness,
or operational fitness.  The NQ historical records remain immutable fixtures,
not AG or Docket authority.  Operational qualification remains
`not_assessed`.
