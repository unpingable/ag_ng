# Governed-loop deployment qualification

Status: canonical deployment companion to
[`governed-loop-c1.md`](governed-loop-c1.md). This document qualifies the
smallest local one-shot-process deployment surface and identifies the premises
that still require a designated host or physical fault environment. It changes
no authorization rule.

## Minimal deployment shape

The qualified local shape has one `ag-loopctl` binary, one deployment-owned
runtime-profile enrollment, one sealed runtime profile, one AG campaign SQLite
database, one Docket state directory, and the exact resolver, catalog, trust,
executor, and signing-key files named by the profile. Suggested ownership is:

```text
/etc/agent-governor/governed-loop/       root/deployment controlled, read-only
  runtime-profile-enrollment.json
  runtime-profile.json                   mode 0600
  exact-work-catalog.json
  docket-trust.json
/var/lib/agent-governor/governed-loop/   AG runtime controlled, mode 0700
  campaign.sqlite                        mode 0600
/var/lib/docket/governed-loop/           Docket controlled
/run/credentials/ag-loop/issuer.pk8      deployment-injected signer, mode 0600
```

These are example coordinates, not authority-bearing names. A deployment may
choose other absolute paths. The profile binds exact file bytes, stable
resolver identities, the Docket root, and the signer identity. The Docket
state directory is an intentionally mutable locator; per-occurrence executor
configuration is exact authorized work rather than a global deployment grant.

`ag-loopctl` is a one-shot controller. Each invocation opens and verifies the
authoritative campaign store; there is no in-memory authority to reconstruct
after process exit. A service manager may invoke the controller, but must not
add a second transition owner, cache a spend, or translate recovery into a new
authorization.

When governed intervention ingress is enabled, the sealed profile additionally
pins one submitting-service principal, key ID, and Ed25519 public key. The
operator-side private key is not an AG or Docket key. Exact submission custody
receipts live in the adjacent non-campaign
`<campaign-db>.intervention-receipts` ledger described by
[`governed-intervention-ingress.md`](governed-intervention-ingress.md).
That ledger is part of the coherent operational backup set even though the AG
campaign journal remains the authority for governed transitions. A partial
restore must surface uncertainty rather than infer non-submission.

## Provisioning and startup

The deployment prepares an
`ag.governed-loop.runtime-profile-enrollment/v1` document containing absolute
paths and non-secret identities. It is strict canonical JSON (optionally one
final LF) with no unknown keys. Its top level names `schema`, `profile_label`,
the observation and standing resolver paths/IDs, `max_standing_ttl_ms`, the
exact-work catalog, optional controlling review, optional human verifier, and
one Docket enrollment. The Docket enrollment names its own schema, executable,
mutable state directory, trust and standing files, executor adapter, issuer
principal/key ID, and private-key path. The deployment then seals it while all
enrolled files are present:

```sh
ag-loopctl seal-runtime-profile \
  --enrollment /etc/agent-governor/governed-loop/runtime-profile-enrollment.json \
  --output /etc/agent-governor/governed-loop/runtime-profile.json

ag-loopctl verify-runtime-profile \
  --runtime-profile /etc/agent-governor/governed-loop/runtime-profile.json

ag-loopctl init \
  --database /var/lib/agent-governor/governed-loop/campaign.sqlite \
  --genesis /run/agent-governor/campaign-genesis.json \
  --runtime-profile /etc/agent-governor/governed-loop/runtime-profile.json
```

Sealing measures bounded regular files without following a final symlink,
validates the catalog and signing key, publishes a canonical create-once file
at mode `0600`, and emits only profile/schema digests and stable public labels.
It does not emit private-key bytes. Genesis atomically stores the sealed
profile with the authority-empty occurrence. A second seal cannot overwrite
the first profile.

Before accepting work after startup, run:

```sh
ag-loopctl verify-runtime-profile --runtime-profile PROFILE
ag-loopctl inspect --database DATABASE
```

`inspect` is a machine-readable projection containing the current occurrence,
deterministic replay counts, and the genesis-bound profile schema/digest. It is
read-only and deliberately does not require access to live signing material.
`status` and `replay` remain narrower machine-readable projections. Command
JSON is written to standard output; refusal diagnostics go to standard error.
Operators must collect both without treating logs as transition inputs and
must never log enrollment secret contents or signing-key bytes.

## Identity and custody

| Item | Owner | Meaning |
|---|---|---|
| campaign and occurrence IDs | AG | durable governed-loop identity and one exact authority boundary |
| observation/resolver identity | Nightshift/deployment | exact evidence and expected resolver binding; not authority |
| standing resolver identity | standing authority/deployment | exact current standing source expected at each live gate |
| runtime-profile digest | AG genesis/deployment | exact deployment-root binding; not a locator or authorization |
| AG issuer principal/key ID | AG deployment | stable signer identity trusted by Docket |
| AG issuer private key | deployment credential custodian | signs only an already-spent exact issuance; possession alone must not expose a second minting path |
| Docket attempt/receipt | Docket | custody, dispatch, and outcome evidence for the exact issuance |
| executor attempt marker | executor | physical idempotency/reconciliation evidence, not permission |
| intervention submitter identity | deployment / operator-side service | authenticates exact request delivery; never standing or authorization |
| intervention ingress receipt | AG ingress | immutable custody/evaluation evidence; never a spend or execution receipt |

The local process qualification proves file pinning and missing-key refusal. It
does **not** establish OS-principal separation between a caller, AG signer, and
Docket. In the current direct process composition, a Nightshift operator that
invokes `ag-loopctl` must not thereby be granted unrestricted read access to
the AG private key. A deployment claiming separated custody needs a trusted
launcher/credential injection boundary that exposes only the exact canonical
command, not the key. Adding such a service protocol is outside this
qualification campaign and must not become an alternate transition API.

## Restart matrix

A restart recovers facts and never creates permission.

| Durable program counter | Persisted fact after restart | Authority after restart | Legal continuation |
|---|---|---|---|
| `ObservationRequired` | authority-empty occurrence | none | obtain a fresh independent observation and exact proposal |
| `ProposalRecorded` | exact proposal and observation reference | none | enter standing-required; then resolve fresh currentness/standing |
| `StandingRequired` | proposal awaits live judgment | none | resolve fresh currentness, standing, and catalog admissibility |
| `AdmissiblePendingAuthorization` | positive prior decision only | none | re-resolve every consequence-time premise before one spend |
| `AuthorizationConsumed` | one spend and exact issuance | consumed historical spend only | present the same issuance to Docket or reconcile; never remint |
| `Dispatched` | exact accepted Docket attempt | no reusable authority | poll/reconcile the exact attempt; never dispatch mechanics again |
| `ReconciliationRequired` | exact attempt has unknown outcome | no reusable authority | exact settlement, read-only probe, human disposition, or halt |
| `SettledObservationRequired` | durable exact receipt/settlement | no successor authority | fresh independent Nightshift cycle before a distinct occurrence |

The restart witness drops and reopens the store at every row and checks the
same program counter and spend count. `Halted` and `Completed` are terminal;
restart cannot reopen them into an authority-bearing state.

## Crash, receipt, and reconciliation law

- Before `AuthorizationConsumed`, process/database/configuration/resolver
  failure leaves no spend and no execution attempt. Reevaluation is allowed.
- The spend and exact issuance commit atomically. A crash after that commit but
  before Docket custody leaves the spend consumed. Recovery presents the same
  issuance; it does not create a replacement.
- Once Docket has accepted an attempt, a missing or delayed receipt means the
  effect may have occurred. Repeat dispatch is forbidden. Exact polling or
  reconciliation is mandatory.
- Duplicate byte-identical facts are idempotent. A receipt, settlement,
  issuance, occurrence, work, or attempt substitution refuses.
- A conflicting or unknown outcome remains reconciliation-required. An
  operator may use bounded read-only evidence or halt/escalate; absence of a
  receipt is never evidence of non-execution.
- Settlement records an outcome but does not establish current posture. Only a
  fresh Nightshift observation can open governed continuation.

SQLite transaction/replay and deterministic logical crash-cut tests establish
this state-machine law. They do not establish controller, filesystem,
disk-cache, or physical power-loss durability.

## Concurrency and event ordering

SQLite predecessor/version fences allow one competing occurrence transition
to win. Independent-process contention, concurrent authorization, concurrent
settlement, and concurrent human-resume witnesses establish that losers
refuse and replay remains exact. Delayed exact duplicate facts are idempotent;
reordered or substituted facts cannot skip the program counter. There is no
queue/message acknowledgment protocol in this local shape, so deployment
middleware must preserve exact records and may not reinterpret delivery as
authorization.

## Backup, restore, and hostile environment

Back up a coherent stopped cut of the Nightshift store, AG campaign database,
Docket state, executor attempt journal/artifacts, sealed runtime profile, and
the deployment configuration needed to verify them. Do not copy a live SQLite
database while omitting its WAL, restore one office independently and infer
the others, or infer non-execution from a missing restored receipt. After
restore, verify each store independently and reconcile every consumed or
accepted attempt before continuation. A cleanly closed AG database copy is
covered by the local reopen test; a truncated copy refuses. Cross-office and
live-WAL restore remain deployment exercises.

Fail-closed operational expectations are:

| Condition | Required behavior / remaining premise |
|---|---|
| disk full or filesystem unavailable | transaction/file operation fails; no success may be inferred; physical atomicity needs designated-host qualification |
| clock skew/rollback | currentness/standing boundary refuses when contract limits fail; clock adequacy and cross-service relation remain environmental |
| network loss or service restart order | unavailable resolver/Docket/executor refuses or leaves exact reconciliation state; never bypass a gate |
| stale configuration or changed binary/key bytes | profile verification refuses before invocation |
| missing secret | facts remain inspectable; signing/dispatch fails; no spend is recreated |
| revoked identity | propagation/timeliness belongs to the standing/trust deployment; historical records remain historical |
| partial restore | refuse corruption or treat cross-office outcome as unknown; never infer success or non-execution |

The locally runnable operational harness records exact command identities and
results under `qualification/operational/`. Its overall status remains
`not_assessed` because real power loss, OS isolation, deployed currentness,
revocation, and physical executor behavior require declared environments.

## Operator projection and intervention

Future UI must project `inspect`, replay journals, Nightshift evidence
references, Docket attempt/settlement records, and executor reconciliation
evidence. It must visibly distinguish: no authority; admissible pending fresh
authorization; consumed issuance not yet accepted; dispatched outcome unknown;
reconciliation required; settled but fresh observation required; terminal
halt/completion; and human disposition required. It must not calculate a
parallel program counter or infer authorization from proposal, receipt, or
service reachability.

Human action is required when exact reconciliation cannot establish an
outcome, bounded probes/budgets are exhausted, residual work is unresolved,
the deployment profile cannot be reverified, or environmental premises cannot
be restored safely. Automation may inspect, re-resolve, present the same
issuance, poll, and record exact duplicate facts; it may not remint authority,
repeat mechanics, or synthesize a fresh observation.

## Qualification boundary

Runtime-controlled facts are the campaign program counter, proposals,
decisions, spends, issuances, Docket attempt/settlement references, residuals,
and budgets. Deployment-controlled facts are file placement and ownership,
profile enrollment, process identities, credential injection, service order,
backup coordination, clocks, trust/revocation distribution, and log custody.

Browser-originated mutation remains unqualified. The current Maude and ingress
credentials authenticate supervised-session and submitting-service custody,
not a human browser session or its mandate. Until a deployment selects that
identity mapping, the only production intervention write path is the one-shot
authenticated `submit-intervention` command; Phosphor-ng remains read-only.
Environmental assumptions remain resolver/source honesty, standing-authority
honesty and timeliness, filesystem and clock adequacy, signer and host
integrity, digest collision resistance, executor idempotency, and physical
world correspondence.
