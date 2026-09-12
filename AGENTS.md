# Agent guidance

Follow applicable workspace instructions. This guide describes this
repository's supported paths. Use the ordinary Git workflow for bounded edits.

Use AG's governed loop when work needs durable exact-occurrence judgment,
one-use authority, restart-safe custody, or evidence-backed reconciliation;
do not route every task through it. Build and inspect the supported surface
with `cargo build --locked --workspace` and `./target/debug/ag-loopctl --help`.
Production-shaped state requires an owner-reviewed genesis and runtime profile;
follow [`docs/governed-loop-c1.md`](docs/governed-loop-c1.md) and
[`docs/governed-loop-deployment-qualification.md`](docs/governed-loop-deployment-qualification.md).

For prolonged work, use the campaign-approved durable producer and checkpoint,
which may be a named transient user-systemd service when that campaign records
it. After supervisor loss, inspect the original producer and AG/Docket state;
reconcile an indeterminate attempt before opening successor work. Never infer
authorization from tool availability, a proposal, an issuance, or a receipt.
If the governed path is unavailable, record the reduced claim and use the
campaign's documented fallback. Pre-alpha design tooling remains opt-in.
