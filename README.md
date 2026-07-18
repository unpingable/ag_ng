# Agent Governor NG

Agent Governor NG is a Rust hard successor to the classic Python Agent
Governor. Its authority boundary is deliberately narrow:

> Workers propose. `ag-effectd` alone compiles, ratifies, and executes exact
> effects.

The workspace is organized around non-convertible judgment-family types, an
unprivileged governor daemon, a credential-isolated provider daemon, and a
minimal privileged effect broker. The initial production target is a
single-host Linux service for contained batch work, Git managed-ref promotion,
managed files, and systemd units.

This repository does not preserve the classic command, API, database, or
authority-token surfaces. The Rust-only frozen archive verifier treats classic
files as bounded opaque evidence and never imports them as runtime authority.

See `docs/architecture.md` and `docs/source-baseline.md` for the implementation
contract and source custody. Operational reviewers should also read
`docs/deployment.md`, `docs/backup-restore.md`, and
`docs/release-checklist.md`, and `docs/migration-m8.md`; the current tree is
explicitly not production deployable until that checklist closes.
