# Canonical governed repair R5 reconciliation rounds

## Bootstrap and scope

This correction is constructed under external human development authorization.
The governed loop does not govern its own construction.  This document records
development semantics only; it is not operational standing, qualification,
certification, or NQ repair authority.

## Decision

The accepted R3 contracts permit multiple legitimate reconciliation polls for
one indeterminate Docket attempt.  Docket's cumulative effect journal preserves
an ordered sequence of indeterminate observations followed by a possible
terminal observation.  A one-call-per-attempt implementation would therefore
be a semantic regression.

Each intentional poll is instead represented by a strict
`ReconciliationRoundRequestV1`.  AG creates and persists the request under the
caller's exact state compare-and-swap, and issues a one-use signing permit for
those exact bytes.  The wire request directly binds the issuance, attempt,
caller state, optional immediately preceding round/result, and an explicit
idempotency identity.  Campaign and occurrence correspondence are durable
Store invariants reached transitively through that exact issuance; they are
not duplicated as wire fields.  Retrying the same product request reuses the
same round.  A later poll requires a new product request and a predecessor
round that AG has already durably observed as completed indeterminate.

Docket verifies the authenticated request with the pinned AG issuer boundary,
derives the exact current attempt source cut, and commits its reservation before
executor entry.  Its response binds the round and durable reservation state.
AG records each completed round even when the executor evidence is otherwise
unchanged, so the next round is based on a new exact durable cut.

Recovery and reopen never allocate a reconciliation round.  They return the
current durable observation or reconciliation requirement.  Only the explicit
product reconciliation operation may request a new round.  A claimed round
left by a crash is unresolved and is never silently reinvoked.  Neither
checkpoint evidence nor a round request is standing or execution authority.
An unresolved or crash-unknown round cannot enable a later poll; it requires a
separate recovery or adjudication path.

One narrow first-round case performs no external poll.  If the initial attempt
has already durably sealed a settlement or governed-repair result before AG
could retain that response (including the concurrent-dispatch custody race),
Docket atomically records the authenticated first-round reservation and
completion from that exact terminal source cut.  It returns the pre-existing
result without invoking the executor.  After any round has completed, a lost
terminal response must replay that same round; it cannot create another
terminal-observation round.  Raw terminal reconciliation remains retired.

Physical exactly-once effects across process, host, database-copy, or executor
boundaries remain outside the earned claim.  The Docket reservation establishes
local single-flight and exact replay for one configured durable store.

The AG V6 migration stores requests and responses separately from occurrence
authority.  Reopen compares the complete `sqlite_schema` representation of
both tables—including table DDL, automatic unique indexes, foreign keys,
`STRICT`, and the response timestamp `CHECK`—with a schema freshly derived
from the pinned V6 migration SQL.  A complete-looking but weakened table is a
Store-identity refusal, not a compatible migration.  Row replay then validates
the canonical request/response bytes and their transition correspondence.

The sibling consequence-boundary census is closed: initial execution crosses
the external executor boundary only after Docket commits custody, while each
reconciliation crosses it only after Docket commits the exact round claim.
Standing, checkpoint, and executor-plan probes are read-only correspondence
premises and may be repeated; they cannot record an effect, custody, or round.

## Wire ownership and ordinary conformance gate

AG owns the intentional request, its two deterministic identities, and its
distinct Ed25519 signature domain. Docket owns the pre-executor reservation,
completion, and flattened durable response. The executor envelope contains
only exact Docket custody coordinates and existing attempt mechanics; its
executor-local registration is replay evidence, never authority.

The normative R5 extension is
`conformance/governed-repair-r2/reconciliation-rounds.v1.json`. The older
directory name deliberately preserves the R2 base corpus instead of rewriting
historical vectors. The extension pins schemas, identity basis fields and
domains, canonical positive vectors, the signature prefix, closed statuses,
completed public-result correspondence, multi-round law, and hostile
mutations. `manifest.v1.json` closes the complete corpus at
`sha256:74c429d8d32341fc31fba45e4cdd1a0b6d994bace4c7d4d8ccfccfc9dad8aded`.

The ordinary offline gate is:

```sh
python3 scripts/run_governed_repair_r3_contract_gate.py \
  --docket-root /path/to/docket/runtime
```

Despite its historical filename, that gate now requires the R5 manifest,
byte-identical consumer mirror, actual AG serializers/signature verification,
actual Docket validators, executor-envelope semantics, and every pinned
hostile refusal. A copied directory with no behavioral correspondence is not
a pass.
