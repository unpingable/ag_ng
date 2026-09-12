# Constellation AG

Constellation AG is the authority office for exact automated-work decisions. It
decides whether one prepared action may proceed and records that decision; it
does not schedule work, execute it, or turn a receipt into reusable authority.
For an ordinary bounded repository edit, AG is usually unnecessary overhead.

New here? Start with the [main-branch guide](docs/public-guide.md). This `main`
revision preserves the older daemon/library workspace and its `agctl` command.
The newer governed-loop inspection guide and read-only operator UI are published
separately at exact revision
[`32f10101c4a93bad77d00803bad3031dd6847698`](https://github.com/unpingable/constellation-ag/blob/32f10101c4a93bad77d00803bad3031dd6847698/docs/public-guide.md).
That revision contains `ag-loopctl` and `ag-operator-ui`; this `main` tree does
not. Do not mix commands or relative documentation links between the revisions.

## Status (2026-07-26)

Constellation AG (called AG-ng in this historical implementation) is the
**canonical exact-work admissibility and issuance
implementation** — the authority-bearing decision of a four-office governed
constellation: it decides whether exact prepared work may receive authority
and burns one-use decision authority; **Docket** executes and settles;
**NQ** evaluates testimony, claims, and consumer reliance; **Nightshift**
proposes and holds read-only orchestration posture. It is not a universal
authority office: mandate custody (delegation, revocation, lineage — the
`standing` repository's jurisdiction) and spendability accounting (the
`linearaccountant` jurisdiction) are separately defined offices that AG-ng
neither owns nor absorbed, and which the current vertical does not
exercise. AG-ng owns its decision law and the issuance producer;
it does **not** own the authorization wire contracts (`gwr:authz-request:v1`
and `ag.docket-issuance:v1` are Docket-owned, with Docket's conformance
vectors), execution, settlement, repository state, claim admissibility, or
orchestration.

Maturity: part of an **operationally reusable governed vertical** — its
issuance path authorized both the three-office vertical (2026-07-25) and the
four-office pilot (2026-07-26). That is not a production claim: the issuance
surface is a library face exercised by harness, the decision-burn ledger is
in-memory per process, and the tree remains explicitly **not production
deployable** until its own checklist closes ("not production deployable" is a
deployment-maturity statement, not a statement about which office is
canonical). New authority features land here; the classic Python
implementation (`agent_gov`) is legacy-historical, retained for its
diagnostic drill helpers and archives, and receives no new authority work.

Agent Governor NG is a Rust hard successor to the classic Python Agent
Governor. Its authority boundary is deliberately narrow:

> Workers propose. `ag-effectd` alone compiles, ratifies, and executes exact
> effects.

The workspace is organized around non-convertible judgment-family types, an
unprivileged governor daemon, a credential-isolated provider daemon, and a
minimal privileged effect broker. The initial production target is a
single-host Linux service for contained batch work, Git managed-ref promotion,
managed files, and systemd units.

The pure kernel is crosswalked against the public Governed Admissibility
Calculus v14 through an explicit, non-authorizing adapter. The adapter binds
native Rust decisions to a reviewed specification revision and operational
context; it cannot deserialize or convert them into runtime authority. See
`docs/formal-calculus-crosswalk.md` for correspondence and non-correspondence
claims.

AG-ng also produces authenticated authorization issuances for an external
governed-work runtime. That producer is deliberately narrow: it decides through
this office's own catalog and principal checks, burns its own decision authority
once, and emits an immutable authenticated record. The record is not authority —
`Authority` remains non-serializable and process-local — and it makes no claim
that anything executed or that any downstream claim is admissible. See
[`docs/docket-issuance.md`](docs/docket-issuance.md).

Residual obligations and escalation are both deliberately absent from the live
surface today, and both say so where it matters rather than being silently
missing: see [`docs/residual-obligations-disposition.md`](docs/residual-obligations-disposition.md)
and [`docs/escalation-disposition.md`](docs/escalation-disposition.md).

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
packaged `agd.service` namespace restrictions are not a host for it. The
managed-pointer broker now has code-level live activation gating and a
complete inspectable activation receipt, but its host/Git/filesystem,
power-loss, and package matrices remain unqualified. Provider adapters, typed
systemd effects, admitted check launch, and production worker qualification
remain pending.

See `docs/architecture.md` and `docs/source-baseline.md` for the implementation
contract and source custody. Operational reviewers should also read
`docs/deployment.md`, `docs/managed-pointer-activation-readiness.md`,
`docs/clean-host-activation-qualification.md`, `docs/backup-restore.md`,
`docs/release-checklist.md`, `docs/worker-qualification.md`, and
`docs/migration-m8.md`; the current tree is explicitly not production
deployable until that checklist closes.

The live worker ingress substrate has its own qualified gate,
`scripts/run-worker-qualification.sh`, described in
`docs/worker-qualification.md`. It exercises the ingress path end to end against
a feature-gated fixture worker under real bubblewrap confinement, and it is
separate from the packaged test step because it needs host prerequisites a
package builder cannot guarantee. It qualifies the **ingress substrate**, not a
production worker; production worker qualification remains pending as stated
above.
