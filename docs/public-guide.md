# Constellation AG newcomer guide

AG-ng decides whether a specific piece of automated work may run now. It checks
the proposal against current observations, the relevant mandate, and policy.
If allowed, it records a permission that can be used only once for that run.
Docket manages the execution attempt; a separate executor does the work.

Use AG when proposing work must be separate from granting permission to do it.
A recorded permission is not proof that the work happened, and success on one
run does not grant permission for the next. The detailed contracts call a run
an *occurrence* and the permission decision an *admissibility judgment*.

The public repository is **constellation-ag**. `AG-ng` and `ag_ng` are earlier
names for this Rust implementation, not additional products. Existing crate,
executable, service, configuration, and protocol names are unchanged. The
classic Python Agent Governor is a predecessor, not a compatible installation.

## Current status

This tree is qualification-ready development code, not a production-deployment
claim. Its canonical path is `ag-loopctl` through the durable C1 campaign
engine and store. The older standalone producer and vertical examples are
bounded historical or conformance surfaces; they are not alternate current
installation paths. Start with the [C1 loop contract](governed-loop-c1.md) and
the [deployment qualification contract](governed-loop-deployment-qualification.md),
not an older vertical in isolation.

The present implementation still has explicit qualification gaps. The release
checklist is open; production worker qualification and several host,
filesystem, package, and power-loss matrices remain pending. The development
worker launcher is rejected by the `production` and `high_assurance` profiles.
The [deployment guide](deployment.md) describes the intended host shape but is
not permission to deploy AG over a governed host.

## Build and inspect from source

This guide describes the governed-loop development source containing it. The
default branch and qualified development revisions may expose different
commands; use the source revision linked by your tutorial, not a mixture of
branches. From that repository root:

```sh
cargo build --locked --workspace
./target/debug/ag-loopctl --help
./target/debug/agctl --help
./target/debug/ag-operator-ui --help
```

These commands build and display the implemented surfaces; they do not create
an authority domain or operate a campaign. A production-shaped loop requires a
reviewed genesis document and runtime profile:

```sh
./target/debug/ag-loopctl init \
  --database /absolute/path/ag-loop.sqlite \
  --genesis /absolute/path/genesis.jcs.json \
  --runtime-profile /absolute/path/runtime-profile.jcs.json
```

The profile binds the observation and standing resolvers, exact-work catalog,
and Docket coordinates. Use the read-only `inspect`, `status`, `replay`,
`history`, and `refusals` subcommands documented by `ag-loopctl --help`; the
local read-only UI consumes only those projections. See the
[operator UI contract](operator-ui.md) and
[read model](operator-ui-read-model.md).

The daemon-oriented `agctl` surface is separately role-scoped. Its proposer
profile can submit intent, while its effect-admin profile can inspect and
ratify effect records. The exact commands and configuration separation are in
the [`agctl` guide](agctl.md). Do not infer daemon readiness from a source build
or substitute one role profile for the other.

## Standalone and composed use

The pure crates are useful independently for typed judgments, occurrence law,
and deterministic transition tests. AG can also retain and inspect durable C1
campaign state without a browser. A real governed effect is composed: an
observation/currentness owner and standing resolver supply present-tense
inputs, AG decides and spends authority, Docket custodies the attempt, and an
executor performs only the bound mechanics. Nightshift is the current
recurrence and observation-cycle integration; NQ owns diagnostic evaluation.

AG does not become a workflow scheduler, evidence authority, execution
runtime, or generic shell when composed with those systems. The complete
ownership split is in [architecture](architecture.md).

## Authority and trust boundary

AG owns admissibility judgment, the exact occurrence binding, and the durable
one-use spend. `ag-effectd` owns the narrow privileged effect plane for its
configured catalog. Docket owns custody and settlement. Resolvers remain
trusted for the facts they report, and deployment owns their identities,
credentials, clocks, files, and process placement.

Remaining bypasses and premises are material:

- root or another principal able to alter deployed binaries, configuration,
  credentials, stores, resolver output, or governed targets remains outside
  AG's in-process guarantees;
- the system does not prove external truth, resolver honesty, timely
  revocation, clock adequacy, host integrity, or filesystem/power-loss
  behavior on an unqualified host;
- the development Bubblewrap worker path is not production containment;
- an issuance record is neither proof of execution nor authority for a later
  occurrence, and a browser has no write surface.

Review [deployment](deployment.md),
[managed-pointer activation readiness](managed-pointer-activation-readiness.md),
and the [release checklist](release-checklist.md) before relying on a host.

## Formal claims

The pure kernel has a non-authorizing crosswalk to Governed Admissibility
Calculus v14 at the pinned Lean revision. Lean proves properties of its stated
objects and assumptions. It does not prove Rust runtime conformance,
cryptographic behavior, daemon honesty, persistence, host behavior, or an
unconditional state transition. The adapter cannot create authority and is
not loaded by a daemon as authority. The exact correspondences and deliberate
non-correspondences are in the
[formal calculus crosswalk](formal-calculus-crosswalk.md).

## Recovery

Restart reconstructs durable state and historical spends; it never recreates
authority. A dispatch with an unknown result must be reconciled against the
same issuance and attempt, never mechanically repeated. Settlement requires a
fresh observation before another consequence. See the C1
[crash and recovery law](governed-loop-c1.md#crash-and-recovery-law) and the
[coherent backup/restore protocol](backup-restore.md). The backup coordinator
is currently an embedding surface: there is no complete privileged system
coordinator or live backup command.
