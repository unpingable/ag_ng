# Docket issuance producer

AG-ng produces authenticated **authorization issuances** for an external governed-work
runtime (Docket). This is the only AG-ng surface that speaks to that runtime, and it is
deliberately narrow.

The wire contracts themselves — `gwr:authz-request:v1` and `ag.docket-issuance:v1` —
are owned and versioned by the Docket product repository, which is their authoritative
home and ships the conformance vectors. AG-ng owns the **producer** implementation
only; the consumer implementation and the downstream testimony consumer are separate
offices with separate repositories.

## What this surface does

`crates/ag-app/src/docket_issuance.rs`:

1. strictly decodes a `gwr:authz-request:v1` request (unknown fields are refused — an
   unknown field means it is not that schema);
2. decides through this office's own path: supported effect class, a validated
   principal chain, a root-owned target-catalog match on repository, reference, and
   effect class, actor admission, and containment of every requested path within the
   target's admitted prefixes;
3. burns this office's decision authority **exactly once** through
   `IssuanceDecisionLedger`; a second issuance for the same decision refuses;
4. emits one immutable `ag.docket-issuance:v1` envelope for an admitted decision only.

A refusal produces no issuance and burns nothing.

## Authenticity

The envelope carries the exact canonical body bytes (base64url, unpadded) plus an
Ed25519 signature over `"ag-ng\0docket-issuance-signature\0v1\0" ‖ body`. The prefix is
distinct per statement kind, so a signature made for another AG-ng statement cannot be
replayed as an issuance. Signing reuses the repository's existing Ed25519 material
handling (ring, PKCS#8 v2, canonical base64url); no new cryptography and no shared
secret were introduced.

`verify_envelope` verifies the signature over those exact bytes. The consumer performs
the same check independently, against its own configured trusted-issuer list — a record
never nominates its own verifier.

## What an issuance establishes — and does not

**Establishes**: that this exact proposal was admitted under a named decision context;
that this office's decision authority was consumed under its own law; and that the
record is authentic.

**Does not establish**: that the downstream runtime executed anything, that any
repository reached any state, or that any downstream claim is admissible. Execution and
settlement are the consuming runtime's; admissibility is a third office's.

## No serialized authority

`Authority<F>` is not serializable, not clonable, and has no public constructor; it is
reconstructed only by full semantic replay against committed evidence. **An issuance is
not authority.** It carries no capability, no key material, no witness, no commit
digest, and no downstream standing — nothing in it can reconstruct an `Authority`, and
the consuming runtime mints its own local, single-use standing after verifying the
record. Tests assert the absence of those shapes.

## Digest domains

Three digests are kept deliberately distinct and none is derived from another:

- the consumer's plain byte digest of the request (`raw_sha256`);
- this office's domain-separated canonical digest of the same bytes
  (`ag_canonical_digest`);
- the consumer's own prepared-attempt transcript digest, which this office **echoes and
  never recomputes**.

## Supported versions

| role | schema | status |
|---|---|---|
| consumed | `gwr:authz-request:v1` | supported; unknown schema refuses |
| produced | `ag.docket-issuance:v1` | current |
| consumed effect class | `git-ref-update:v1` | the only class this office authorizes |

## Residual obligations and escalation

Issuances carry a residual-obligation **status** that distinguishes *no residuals
recorded* from *residuals unrepresented*. This office currently emits `unrepresented`:
it has no live mechanism that produces a meaningful residual obligation, and that
absence is reported as a producer limitation rather than as a finding about the
decision. See `docs/residual-obligations-disposition.md`.

**Escalation does not exist in AG-ng** — not as a type, a verdict, or a wire field.
Every non-admitted outcome is a refusal or a typed indeterminacy. Nothing downstream
receives an escalation, and none is inferred. See
`docs/escalation-disposition.md`.

## Durability limit

`IssuanceDecisionLedger` is an in-memory, caller-owned record. Within one ledger
instance a decision's authority burns exactly once. It is **not** a durable authority
ledger and claims no protection across process restarts or store rollback — the same
limit the kernel's decision ledger states for itself. A durable issuance burn is
deferred work, not a current property.
