# Agent guidance

Follow applicable workspace instructions and use the ordinary Git workflow for
bounded edits. Constellation AG is useful when work needs a separate exact-work
decision, one-use authority, and inspectable custody. It is usually unnecessary
for a small local edit, documentation change, or read-only check.

This default-branch snapshot is the older daemon/library workspace. Build and
inspect only the commands present here:

```sh
cargo build --locked --workspace
./target/debug/agctl --help
```

The `ag-loopctl` and `ag-operator-ui` commands belong to the separately
published development revision linked from [`docs/public-guide.md`](docs/public-guide.md);
do not claim that they exist on this revision. For daemon operation, use the
role-separated profiles and commands in [`docs/agctl.md`](docs/agctl.md), and
read [`docs/deployment.md`](docs/deployment.md) before relying on a host.

For prolonged work, use the campaign-approved durable producer and persist its
recovery checkpoint before waiting. After supervisor loss, reconcile the
original producer and any indeterminate state before opening successor work.
Tool availability, a proposal, an issuance, or a receipt does not grant
authority. If the governed path is unavailable, record the reduced claim and
use the campaign's documented fallback.
