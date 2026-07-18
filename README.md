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

The current tree also contains one deliberately bounded live-worker slice. In
the `development` security profile, `agd` can launch an offline worker selected
from a root-reviewed fixed executable/argv catalog inside a private Bubblewrap
proposal workspace. The worker receives a non-transferable session identity
and may return only authenticated candidate material; `agd` reconstructs the
reviewed mapping and `ag-effectd` still owns compilation and persistence of the
canonical proposal. Session authority is durably bound and tombstoned rather
than recreated after exit or restart. This slice admits exactly one live worker
at a time; while it is live, `agd` refuses other blocking proposal/launch work
so deadline supervision cannot be starved.

That development path can now carry one strict, self-contained Git bundle into
an independently ratified managed-pointer proposal. `ag-effectd` alone derives
the exact base/post trees and target bindings, durably arms a one-shot commit,
and compare-and-swaps one configured, existing loose ref that is not checked
out under the target owner. Success requires independent ref/tree readback;
ambiguity requires reconciliation. This is a managed-ref lifecycle only: it
does not synchronize or write a live checkout, and a packed-ref-only target
refuses.

This is not a production containment claim. `production` and
`high_assurance` configurations reject the development launcher, and the
packaged `agd.service` namespace restrictions are not a host for it. Provider
adapters, typed systemd effects, admitted check launch, production activation
of managed-pointer execution, and production worker qualification remain
pending.

See `docs/architecture.md` and `docs/source-baseline.md` for the implementation
contract and source custody. Operational reviewers should also read
`docs/deployment.md`, `docs/backup-restore.md`, and
`docs/release-checklist.md`, and `docs/migration-m8.md`; the current tree is
explicitly not production deployable until that checklist closes.
