# Constellation AG on `main`

Constellation AG decides whether one exact piece of prepared automated work may
receive authority. The decision is deliberately separate from proposing,
executing, settling, and evaluating the work. Docket owns execution custody;
other Constellation components own observation, recurrence, and evaluation.

Use AG when that separation and an inspectable one-use decision matter. For a
small local edit or read-only task, the ordinary repository workflow is clearer
and AG is usually unnecessary overhead. An issuance record is not proof that an
effect ran, and it cannot authorize another occurrence.

## Which revision is this?

The public repository is **constellation-ag**. `AG-ng` and `ag_ng` are earlier
names for this Rust implementation, not separate products. Existing crate,
executable, service, configuration, and protocol names remain unchanged.

The default branch at the time of this guide is the older daemon/library
workspace. It contains `agctl`, `agd`, `ag-effectd`, and `ag-providerd`. It does
not contain the newer `ag-loopctl` or `ag-operator-ui` binaries.

The newer governed-loop and read-only inspection surface is published as a
qualification-ready development revision, not silently presented as default
`main`:

- [newcomer guide at exact revision `32f10101c4a93bad77d00803bad3031dd6847698`](https://github.com/unpingable/constellation-ag/blob/32f10101c4a93bad77d00803bad3031dd6847698/docs/public-guide.md)
- [operator UI contract at that revision](https://github.com/unpingable/constellation-ag/blob/32f10101c4a93bad77d00803bad3031dd6847698/docs/operator-ui.md)
- [complete source tree at that revision](https://github.com/unpingable/constellation-ag/tree/32f10101c4a93bad77d00803bad3031dd6847698)

Use one exact revision's source and documentation together. Relative C1 and UI
links in the development guide name files that are absent from this older
`main` tree.

## Inspect this `main` source

From this repository root:

```sh
cargo build --locked --workspace
./target/debug/agctl --help
```

These commands build the source and display its implemented client surface.
They do not create an authority domain or establish deployment readiness. The
[`agctl` guide](agctl.md) describes the mutually exclusive proposer and
effect-administrator profiles, exact inspection and ratification commands,
offline managed-pointer enrollment, and reconciliation evidence. The command
is not a shell or generic effect launcher.

Before configuring daemons, read the [architecture](architecture.md),
[deployment guide](deployment.md), and [release checklist](release-checklist.md).
The tree is explicitly not production deployable until its open qualification
work closes. Its historical three-office and four-office runs demonstrate only
the bounded paths recorded in the README; they do not establish the newer
governed-loop/UI surface on `main` or qualify an arbitrary deployment.

## Trust and recovery limits

AG's in-process law does not prove resolver honesty, external truth, host
integrity, credential custody, clock adequacy, or filesystem and power-loss
behavior on an unqualified host. Root or another principal able to replace the
deployed binaries, configuration, credentials, stores, or governed targets
remains outside those guarantees.

Restart must not recreate authority. An attempt with an unknown result requires
reconciliation against the same exact record, not an automatic repeat. See the
[backup and restore protocol](backup-restore.md) and the reconciliation section
of the [`agctl` guide](agctl.md). The current backup coordinator is an embedding
surface, not a complete live backup command.
