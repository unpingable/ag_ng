# AG-ng + Docket operational kit

This is the operational index for the [deterministic Linux quickstart](ag-ng-docket-adoption.md),
not a new daemon, SDK, package promise, or production installation qualification.
It requires no model provider or credential. The four-case example is an embedding
harness using `CampaignEngineV1`; it is not the complete Constellation operator beta.

## Responsibility map

| Owner | Supplies | Does not establish |
|---|---|---|
| Integrating harness | Exact proposal, enrolled catalog, truthful/current resolvers, durable driving | Authorization merely by calling a tool |
| AG-ng | Exact-work decision, durable one-use spend, signed issuance, continuation state | Provider answer correctness or executor settlement |
| Docket | Issuer authentication, separate execution standing, attempt/custody and settlement/reconciliation | A fresh authorization or current postcondition |
| Effect adapter | Pinned plan and mechanics, attempt evidence, reconcile-only readback | Permission to change work, re-execute an uncertain attempt, or select another target |
| Model transport, if independently integrated | Requested/reported model and provider, bounded output/usage testimony | Any AG-ng authorization, Docket custody, or accepted worker result |

The beta Switchyard/Codex/Foreman model-work route is separate from this example.
`ag-providerd` is also a separate credential-isolated broker. At source
`41578147d97d337f1018675faec74ede2d2c4a76`, the [deployment contract](deployment.md#workers-and-admitted-checks)
still records the missing live worker/session/peer proof immediately before that section.
Do not activate it as a substitute beta worker route or infer OpenRouter qualification
from a configurable HTTPS endpoint. Offline generic-worker support is not live inference.

## Revisions and environment

The quickstart names the historical witnessed AG-ng `837de287497942c79966aa05c083acee9c312261`
and Docket `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` pair, Ubuntu 24.04.4 x86-64,
Rust/Cargo 1.94.0, C toolchain and Python 3. Its
[reconciliation record](../qualification/ag-ng-docket-adoption-reconciliation-20260908.md)
is the evidence for those exact binaries and four cases. This kit was reconciled against
the later beta AG source `41578147d97d337f1018675faec74ede2d2c4a76`; documentation changes
do not transfer that witness to changed runtime/package pins. Record source/tree and
binary hashes, environment and exact dependency pair for each new showing.

Use the quickstart's two explicit clones, locked builds and fresh absolute run root.
With no network authority, use previously acquired exact source/dependency objects;
missing dependencies are a prerequisite, not permission to fetch. Before a long build,
use the campaign's existing durable launcher and checkpoint. Record host/cwd, run/unit
and execution identity, all source/protocol revisions, logs, artifacts, expected terminal
record and inspection command. Reserve aggregate storage with the campaign storage owner.

## Install, restart, upgrade, rollback and uninstall

The quickstart installs no service or package: binaries remain in the selected build
directories and state remains below the fresh `RUN_ROOT`. Invoking the four-case harness
on an existing root is intentionally refused. A new root creates new fixture work; it is
not recovery of an old occurrence.

For actual daemon installation, read [deployment](deployment.md),
[systemd packaging](../packaging/systemd/README.md), and the
[release checklist](release-checklist.md). Example configurations and units do not supply
keys, enroll an authority domain, or qualify production principal separation. Installation,
credential enrollment and activation require their own exact authority; this kit performs none.

| Operation | Required custody rule |
|---|---|
| Restart/recover | Inspect original AG/Docket/executor state and process identity first. Retain exact issuance and attempt. Never rerun mechanics because acknowledgment is missing. |
| Upgrade | Quiesce the exact producer, retain coherent state plus configuration/keys under their existing protection, record old/new source and binary hashes, and qualify the changed pair before activation. No general cross-version migration is promised. |
| Rollback | Restore only a reviewed compatible binary/configuration pair. Never restore an older authorization database to make a spent authorization available. Partial/incoherent restore stays uncertain and needs same-attempt reconciliation. |
| Uninstall | Stop only enrolled services under explicit authority. Removing binaries is not permission to remove catalogs, keys, databases, WAL files or recovery evidence. Obtain exact cleanup scope after dependency/quiescence checks. |

Use [backup/restore](backup-restore.md) and
[governed-loop deployment qualification](governed-loop-deployment-qualification.md) for
their actual surfaces. Copying a live SQLite file without its WAL is not a coherent backup.
The example's acknowledgment-loss case itself closes/reopens AG and reconciles Docket's
same attempt; no command in this kit adds a general resume API for the fixture harness.

## Adapter author boundary

An adapter implements Docket's existing `plan-id`, `execute` and reconcile-only process
operations. Bind the exact admitted work, executor identity and immutable plan; pin
executable/configuration bytes and restrict OS access to enrolled mechanics. Keep all
effecting routes behind AG and Docket. A shell route available to the proposing process
is outside this guarantee, even if the regular tool route uses the adapter.

Test refusal before effects, duplicate delivery, changed request/plan/executor,
acknowledgment loss, process interruption and insufficient retained evidence. Local
process exit is not proof an external operation was cancelled. Reconciliation may
remain indeterminate. Do not invent successful settlement from a file's existence or
reuse one-use authorization for new work. Model authentication, quota and transport
failures belong to the model transport owner, not this effect adapter.

## Five-minute showing after the locked build

1. Show the exact revisions and binaries, environment and fresh run root. State that
   this is a deterministic local-file example, without a model provider or production target.
2. Run the quickstart once. Display `summary.json`: one spend/attempt/settlement for
   permitted work; no spend/effect for refusal; one retained custody for the duplicate.
3. Show that the acknowledgment-loss effect existed while the outcome was indeterminate,
   then settled through same-attempt reconciliation without another spend or attempt.
4. Use `docket governed-loop inspect` with the summary's exact issuance. Do not use
   `ag-loopctl inspect` on this library-created database; it is a different ingress.
5. Retain the entire run root and summary with the checkpoint. Record whether an actual
   human observed the showing; a script completing is not a human usability trial.

Missing artifacts, uncertain completion, lack of principal separation, and unqualified
new adapter/provider pairs remain explicit limitations. No exactly-once external-effect,
power-loss, production, or arbitrary-platform guarantee is added here.
