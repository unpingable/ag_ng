# Operator-beta AG immutable store-cut audit checkpoint

Status: **CORRECTION CANDIDATE / INDEPENDENT RE-AUDIT REQUIRED**

The first checkpoint `20cca23bfe2b9bc92c9165c00a498e6db8f890b1`
was not accepted because an adjacent WAL could contribute unbound bytes and
the process/path substitution matrix was incomplete. This non-rewriting child
binds the main-store bytes and closes those cases; acceptance is not carried
forward from either the M1A result or the rejected checkpoint.

This bounded checkpoint adds one AG-owned query-only interface needed by the
NQ-ng operator-beta M1B lane. It does not create a new authority record,
receipt family, evidence model, execution path, or campaign. The accepted M1A
result remains attached to its exact original subjects.

## Owner boundary

AG already owns the Systemd V2 attempt store, the canonical Docket outcome
receipt, and the content-addressed D-Bus evidence record. NQ-ng must not
reimplement those validation rules. `ag-effectd audit-store` therefore accepts:

- the original canonical Systemd V2 plan;
- the original exact Docket dispatch on stdin; and
- one absolute path to a copied, stable SQLite store cut, its exact byte
  length, and its exact raw SHA-256.

The command returns the existing canonical Docket executor outcome only after
AG reopens the exact attempt and validates dispatch identity, plan/work,
receipt identity and canonical bytes, evidence identity and canonical bytes,
receipt/evidence agreement, and terminal state. Missing, nonterminal,
malformed, internally disagreeing, or substituted custody refuses.

The store cut must be a regular non-symlink file no larger than 64 MiB, with no
adjacent WAL. Its length, SHA-256, and pathname identity must remain stable
across the read. SQLite reopens the already acquired no-follow file descriptor
in immutable, read-only mode and evaluates one read transaction; auxiliary WAL
state cannot contribute to the result. The command does not acquire the live
execution lock, use the live
store path from the plan, invoke mechanics, reconcile an unterminated attempt,
or mutate the copied bytes. The copied store remains evidence custody only; it
does not become an authoritative live attempt store.

The M1B harness must retain a stable cut under its existing WAL-absent boundary,
record its exact digest and length, and invoke the pinned AG binary with the
original plan and dispatch. A successful audit proves that AG can reopen its
own retained terminal receipt/evidence relationship. It does not prove current
target state, AG authorization consumption, Docket admission beyond the exact
dispatch, or an NQ finding.

## Qualification boundary

The owner checkpoint must directly qualify:

- exact successful query-only reopen with byte-for-byte store preservation and
  functional process-bound CLI replay;
- receipt/evidence/dispatch/plan substitution refusal;
- missing and nonterminal attempt refusal;
- symlink, relative, oversized, nonempty/present WAL, same-inode content
  mutation, and pathname-replacement refusal;
- the explicit CLI surface and existing canonical outcome vocabulary; and
- the absence of any mechanics, retry, approval, authority, or aggregate result.

After independent acceptance and package qualification, NQ-ng may pin the new
AG package and use this interface to close its owner-preimage gap. NQ-ng's
separate recovery run/attempt cross-binding blocker is not closed by this AG
checkpoint and remains an NQ-owned correction.
