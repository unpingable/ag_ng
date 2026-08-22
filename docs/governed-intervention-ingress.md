# Governed-intervention ingress v1

Status: canonical deployment contract for authenticated, non-browser delivery
of the already-frozen governed-intervention vocabulary.

> Submission authenticates delivery of intent. It does not authorize the
> requested intervention.

> Transport replay is not intervention retry.

## Owner and deployment shape

AG-NG owns ingress because `GovernedLoopKernelV1` and `CampaignEngineV1`
already own intervention verification, program-counter applicability, and
canonical transition/refusal persistence. Maude may author/package a request;
Nightshift, Docket, and Phosphor-ng do not accept intervention writes.

The qualified local shape remains one-shot and file based:

```text
typed request draft
  -> ag-loopctl prepare-intervention-request
  -> exact canonical request file
  -> ag-loopctl inspect-intervention-request
  -> ag-loopctl package-intervention-submission
  -> exact Ed25519-authenticated submission file
  -> ag-loopctl submit-intervention
  -> append-only ingress receipt + existing AG transition/refusal
  -> ag-loopctl intervention-receipt / intervention-submissions
  -> Phosphor-ng read-only projection
```

There is no HTTP writer, daemon, queue, message bus, or second intervention
state machine.

## Identities and exact bytes

`ag.governed-loop.intervention-submission/v1` contains one signed
`ag.governed-loop.intervention-submission-body/v1`. The body binds:

- content-derived submission ID;
- exact canonical intervention request ID;
- digest and base64url encoding of the exact request-file bytes;
- submitting-service principal and key ID;
- target genesis runtime-profile digest;
- creation time and exclusive custody expiry.

The request bytes may contain exactly canonical JCS or canonical JCS followed
by one LF. Packaging preserves those bytes byte-for-byte; submission decodes
and compares them rather than regenerating equivalent JSON. Both the exact-byte
digest and Ed25519 signature bind the presentation. Recomputing untrusted
content digests after substitution does not recreate the signature.

The request's `principal`/`mandate` and the envelope's submitting service are
different identities. The submitter signature proves which configured service
delivered the bytes. The genesis-pinned human/intervention verifier separately
decides whether the requesting principal and mandate are recognized now.
Transport authentication never supplies standing.

## Runtime-profile binding and credentials

An optional `ag.governed-loop.intervention-ingress/v1` entry in the sealed
runtime profile pins exactly one submitting principal, key ID, and raw Ed25519
public key. Enrollment reads the 32-byte public-key file and embeds only its
public bytes. The private PKCS#8 submitter key remains operator-side, must be a
nonsymlink single-link regular file inaccessible to group/other, and is never
written to a receipt, campaign store, AG spend, or Docket record.

The complete sealed runtime-profile digest is the target runtime identity. A
submission packaged for runtime A is a custody refusal at runtime B even when
campaign identifiers happen to match. Runtime identity is routing/custody
evidence, not authority.

The minimal local filesystem split is:

```text
/etc/agent-governor/governed-loop/       deployment-owned, read-only
  runtime-profile-enrollment.json
  runtime-profile.json
  intervention-submitter.pub
/var/lib/agent-governor/governed-loop/   AG-owned, mode 0700
  campaign.sqlite
  campaign.sqlite.intervention-receipts
/run/credentials/maude-intervention/     submitter-owned, not readable by AG
  submitter.pk8                          mode 0600
```

Coordinates are locators rather than identity; the sealed bytes and profile
digest are authoritative. The AG process needs the public key and both AG
stores, but never the submitter private key. The submitting process needs the
private key and sealed public profile, but no AG issuer or Docket credential.

The v1 profile pins one submitter key. It has no implicit overlap or in-place
key rotation. Changing that key changes the sealed profile; existing campaign
genesis therefore refuses the drift. Until a separately reviewed overlap law
exists, deployment rotation means provisioning a new profile/campaign cut and
retaining the old public profile for historical receipt verification. Revoking
a live v1 submitter without such a cut is a deployment stop, not permission to
accept an unenrolled replacement.

## Receipt model

The non-campaign sidecar `<campaign-db>.intervention-receipts` is an AG-owned,
mode-0600 SQLite append-only receipt ledger. Its distinct application/schema
identity binds it to one runtime-profile digest. It is deliberately not named
`*.sqlite`, so the operator UI cannot mistake it for a campaign database.

Every `ag.governed-loop.intervention-submission-receipt/v1` is content-derived
and chained per exact submission/presentation. Stages remain distinct:

| Receipt | Meaning | Nonmeaning |
|---|---|---|
| `received` | exact bytes and configured submitter authenticated; custody is durable | intervention legal/authorized |
| `governed_accepted` | existing AG kernel committed the cited exact transition | reusable AG authority or execution |
| `governed_refused` | governed evaluation refused the exact request | custody failure |
| `custody_refused` | bytes/schema/target/submitter/signature failed before evaluation | AG policy/standing refusal |
| `outcome_unknown` | custody is durable but no exact durable governed result can yet be established | failure, nonexecution, or permission to repeat |

An unsafe, unreadable, or oversized file locator fails before AG has accepted
any exact presentation bytes, so it cannot truthfully produce a submission
receipt. Once bounded exact bytes have been read, pre-governance schema,
binding, target, submitter, expiry, and authentication failures are durably
receipted by presentation digest. A structurally decodable envelope's claimed
submission/request IDs are retained only as untrusted lookup selectors; they
cannot join or alter an authenticated receipt chain.

Verified state/applicability refusals reference the canonical AG refusal where
one exists. Requester-verifier refusal is retained in the ingress ledger but is
not promoted into trusted verified-request provenance. Accepted transitions
continue to live only in the existing hash-chained campaign journal.

## Timeout, replay, restart, and concurrency

`submit-intervention` takes a single-writer fence for the receipt sidecar,
durably records `received`, and searches AG transition/refusal history for the
exact request ID before evaluation. Therefore:

- exact resend after a lost response returns the already recorded result;
- a state-changing request is not applied twice;
- a new submission wrapper around the same already-applied request converges
  on the canonical event rather than treating transport as intervention retry;
- a new request targeting the predecessor is governed-refused as stale;
- a refused request does not become eligible by retransmission;
- concurrent identical submissions serialize and converge;
- concurrent conflicting requests still use AG's authoritative predecessor
  compare-and-swap, so at most one legal transition wins.

Crash before `received` leaves no canonical submission. Crash after `received`
leaves a visible pending receipt. Crash after an AG transition/refusal but
before its ingress result receipt is repaired by exact journal lookup on resend.
If neither result can be established, the ledger says `outcome_unknown`; the
operator must query the exact submission before creating anything new.

## Operational start, backup, and rollback

There is no ingress daemon to order. Provision and verify the sealed runtime
profile, initialize the campaign, then permit one-shot submissions. A useful
readiness check is `verify-runtime-profile` followed by `status`, `replay`, and
`intervention-submissions`; none mutates the campaign. Shutdown is ordinary
process completion. Killing a process before `received` leaves no submission;
killing it after `received` leaves a lookup-visible custody fact.

The campaign database and intervention receipt sidecar are separate owners of
different facts. A backup procedure must capture coherent SQLite backups of
both (including their WAL state) and label the pair with the sealed profile
digest. Copying only main database files is not a qualified backup. After
restore, verify the profile and replay the campaign, then inspect the receipt
ledger. A missing or older receipt ledger does not prove that an intervention
was never applied; the campaign journal remains authoritative for accepted
transitions/refusals, and uncertainty must remain visible.

Rollback never means restoring an earlier writable authority snapshot and
continuing from it. Retain old binaries/profiles for read verification, stop
new submissions, and reconcile exact campaign/receipt facts before any
cutover. Live-WAL backup, cross-office restore, abrupt power loss, filesystem
ownership, and service-principal isolation remain designated-host gates.

## Class-specific routing

- `ReconcileAttempt` uses only the existing read-only Docket reconciliation
  port. It cannot accept custody or dispatch.
- `RequestProbe` records only the existing bounded probe fact. Packaging and
  submission perform no probe mechanics.
- `OpenSuccessor` invokes only the existing authority-empty successor law. It
  creates no proposal, standing, spend, or Docket custody.
- `HaltContinuation` invokes only the existing safe-boundary halt law. It is
  not physical containment.

`HumanDispositionV1` remains on its existing separate verifier/application
path. It has a distinct one-use decision identity and disposition-specific
semantics; sharing the transport envelope would not justify merging those
contracts.

## Read surfaces and future browser boundary

`intervention-receipt --submission ID` and `intervention-submissions` are
canonical read-only commands. Phosphor-ng may invoke only the latter closed
read verb and labels submitter custody separately from governed acceptance,
authorization, and execution. Maude may call the request preparation,
inspection, and packaging commands from a future non-browser adapter; it does
not infer the intervention class or governed eligibility.

A future browser writer may submit only an already prepared, inspected, signed
envelope through an authenticated service that preserves this receipt law. It
may not receive submitter private keys, call AG transition methods directly,
or replace lookup-before-repeat with a generic retry button.

No such browser writer is currently justified by the identity model. Maude's
supervised-session receipts authenticate a service-produced session/plan fact,
and the intervention envelope authenticates a submitting service. Neither
authenticates a browser user or binds a browser session to the request's exact
`HumanPrincipalRefV1` and `MandateRefV1`. A local keystroke or loopback
connection is not that missing proof.

Before a browser mutation surface can exist, deployment owners must choose and
configure a browser-session verifier and an exact principal/mandate mapping,
including session expiry and revocation behavior. The narrower current default
is therefore: Phosphor-ng remains GET/HEAD-only, Maude remains a local
supervised-session desk, and intervention mutation remains the authenticated
one-shot ingress. This is an identity decision, not a frontend implementation
detail.

## Nonclaims

This contract does not prove designated-host principal separation, private-key
custody, operator mandate honesty, revocation timeliness, filesystem/power-loss
durability, clock adequacy, Docket/executor honesty, or external-world outcome.
It introduces no new standing, authorization, settlement, or execution rule.
