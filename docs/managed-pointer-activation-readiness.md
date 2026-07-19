# Managed-pointer activation/readiness campaign

Status: bounded implementation complete under local hostile qualification,
implemented at `24efeef` from frozen baseline `fe0bb86`; packaged-host
qualification remains open.

This campaign closes the existing managed-pointer path from exact ratification
to an inspectable durable activation. It does not introduce another pointer,
authority family, deployment framework, or interpretation of the formal
calculus. The managed Git ref remains the sole active selector. The frozen
preparation/ratification specimen at `fe0bb86` and
`docs/preparation-ratification-kernel.md` retains its vocabulary and scope.

## Implemented outcome

`ManagedPointerActivationReceiptV1`
(`ag.managed-pointer.activation-receipt/v1`) is created only after the final
post-fsync exact readback. It is carried only by a verified successful
`ag.effect-record/v3`; legacy v2 records fail closed rather than acquiring the
new custody interpretation. A reconciled `applied` outcome retains its exact
reconciliation evidence and does not forge a success receipt or claim that the
original attempt returned through its durability-confirmation boundary.

`EffectdLiveActivationV1` is a non-cloneable, non-serializable process value.
On each production/high-assurance start, effectd constructs it from the
activated store; running build/config/catalog/profile; process capabilities;
the checked effective-unit cut; current mounts; and static pinned-helper,
staging, and repository custody. `EffectBrokerV1::apply_live_activation` then
repeats the static target preflight, reconstructs the exact governed head from
genesis and terminal history, and compares every live managed ref with that
head. Only then can health report ready or the broker burn new authority. The
resulting `EffectdActivationReceiptV1` remains process-memory diagnostic
evidence. It is not stored as authority, and restart cannot load it as
standing.

## Acceptance model

The existing proposal lifecycle remains authoritative:

```text
Ready
-> AuthorizationBurned
-> Preparing
-> Executing(commit-may-proceed)
-> Succeeded | Failed | ReconciliationRequired
-> Reconciled (only from reconciliation-required)
```

For managed-pointer execution, the exact `git update-ref --no-deref` compare
and swap is the externally visible commit point. Its expected old object is the
stale-current fence. Candidate objects are imported and synced before that
boundary. Success may be recorded only after exact post-object and post-tree
readback, ref and directory durability sync, and a second exact readback.

The activation binds all of the following without rediscovery or “latest”
selection:

- activation domain, epoch, catalog, security profile, target, repository,
  owner, ref, and helper/launch-profile identities already in canonical bytes;
- exact prepared candidate, artifact and pack digests, complete inputs,
  preparation receipt, exact basis, and candidate-specific ratification;
- accepted independent authorization, one-shot operation and execution attempt;
- durable commit-may-proceed checkpoint;
- exact previous object/tree and exact installed object/tree;
- full commit and post-state evidence, including the durability assertion.

The governed-head machine starts from the configured effectd-v2 genesis
object, tree, and descriptor-derived state identity. A verified `Succeeded`
record advances it to the activation receipt's exact post-state identity. A
verified reconciled `NotApplied` record must preserve it exactly. An unresolved
armed attempt, `Foreign` reconciliation, or reconciled `Applied` result without
the original durability-confirmation receipt blocks readiness; observation
does not backfill success.

The implementation adds a typed activation receipt only after the final
durable readback. The receipt is evidence and explanation, not standing. It is
retained in broker custody and projected on the direct effectd inspection
plane. A retained receipt never makes a currently divergent ref active and never
re-enables broker authority after restart.

## Failure and recovery contract

- Failure proven before ref CAS preserves the previous active object.
- Any doubt at or after the CAS boundary is indeterminate and requires fresh
  reconciliation; it is never safe automatic retry.
- Restart abandons an authorization that never began execution, proves an
  interrupted reversible preparation unchanged or marks it indeterminate, and
  marks every commit-armed attempt reconciliation-required.
- Reconciliation observes only the exact ratified pre-state, exact ratified
  post-state, or foreign state. It does not select by recency or convenience.
- A stale expected old object cannot overwrite a different newer activation.
- One effectd actor serializes local attempts; the store writer fence excludes
  a second writer for the same authority store; Git CAS resolves external
  contention without a last-writer-wins path.

Git's lock-and-rename ref transaction supplies the atomic old/new reader
primitive; AG never writes a loose ref in place. A success receipt additionally
establishes that the selected object graph was already durable and the new ref
survived the declared sync/readback contract. Simultaneous external readers
under every supported filesystem remain a qualification gap rather than an
inference from this primitive.

## Live production readiness

Production/high-assurance authority remains disabled unless the current
effectd process constructs fresh, non-serializable readiness standing. That
standing must bind the current store activation, catalog, profile and build to
current process and effective-unit evidence. At minimum it proves:

- root effectd identity with no supplementary groups;
- exact required effective, permitted and bounding capabilities, empty
  inheritable/ambient capabilities, and `NoNewPrivileges`;
- `ProtectSystem=strict`, private network, AF_UNIX-only operation, exact
  `ReadWritePaths`, empty ambient/supplementary unit settings, and exact
  executable role;
- writable-root equality for broker state/socket custody, managed-file
  parents, managed-pointer repositories, and managed-pointer staging roots;
- exact configured Git bytes/launch profile plus descriptor-bound repository,
  owner, ref and staging preflight.

Every child launch first marks all descriptors above stdio close-on-exec and
clears that flag only for its exact admitted descriptor set. Fixed Git
mutations additionally require Landlock ABI 3 or newer. Candidate inspection
has no filesystem write grant; quarantine creation/indexing is confined to the
exact stage root; target object import is confined to the exact
`objects/pack` directory; and ref CAS is confined to the exact Git directory
because Git may transact `HEAD.lock` when a bare repository's `HEAD` selects
the managed ref. The handled Landlock rights cover open/write/truncate,
create/remove, rename and refer operations; this is not a claim that Landlock
mediates every Linux metadata operation. The pinned fixed Git binary remains
part of the trusted execution cut.

An external `agctl doctor` report is diagnostic evidence only. It is not
bearer authority and cannot reconstruct the live readiness value. Restart must
perform the checks again. A failed or unavailable check keeps authenticated
health live but not ready and refuses before ratification burn.

## Rollback boundary

There is no direct pointer-edit or privileged rollback path. The current
bundle contract also cannot simply rewind the ref: its candidate must have the
live basis as its sole parent. Restoring earlier content therefore requires a
new candidate commit on the then-current basis, a new independent
ratification, and a new exact activation. Any future direct object rollback is
a separately governed effect and is outside this campaign.

## Hostile acceptance cases

The local suite covers exact success explanation; stale predecessor; artifact,
candidate, ratification, receipt and post-state substitution; pre-CAS failure;
post-CAS ambiguity; restart recovery; replay; broad, missing or optional
writable roots; missing or excess capabilities; disabled `ProtectSystem`;
helper/repository/staging substitution; exact child-FD inheritance; Landlock
write and symlink escape refusal; repository filter/hook command surfaces; and
absence of fixture/development artifacts from release output. The
same-predecessor contention specimen exercises the serialized broker rule:
the first activation wins and the stale candidate refuses on current-basis
mismatch before authorization burn. It is not a simultaneous multi-process
contention test. A mixed-catalog specimen replaces the managed-ref inode while
preserving its object bytes and proves that the shared activation gate blocks
a managed-file ratification before authority burn; readiness drift cannot be
bypassed by selecting another effect family.

## Qualification limits

This campaign does not claim real power-loss or torn-write survival, disk-full
or WAL/fsync fault coverage, every supported filesystem/storage-cache
combination, simultaneous client/reader qualification, external-writer
historical provenance, distro Git/systemd/Landlock matrix qualification,
package install/upgrade behavior, or target resource quotas. The live unit has
not yet been installed and activated in a clean disposable host, the expanded
`SystemCallFilter` set is packaged but not compared by live attestation, and no
packaged operator tool yet measures and enrolls the genesis state identity.
`agctl doctor` also lacks a subprocess deadline.

The current state identity detects same-byte loose-ref inode replacement, but
does not bind file timestamps. An external target-owner writer can therefore
perform an in-place same-value ABA that leaves the currently expected bytes
and recorded inode metadata. A coherent copied store-plus-target snapshot also
has no external anti-rollback anchor. Git's object-ID CAS proves the current
comparison and exclusivity of its own update, not complete unobserved history.
Applied reconciliation cannot restore readiness without a separately governed
durability-confirmation transition, which is outside this campaign. Historical
head reconstruction is also an unbounded scan pending a later non-authorizing
cache/scale qualification. These are release blockers, not reasons to invent a
second mutable truth.

## Scope fence

No Lean or NQ changes, provider ingress, worker/check wrapper, mandate,
systemd effect, new effect family, UI, direct-checkout mode, generic command
effect, or informal rollback belongs in this campaign.
