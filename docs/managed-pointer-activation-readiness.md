# Managed-pointer activation/readiness campaign

Status: bounded implementation campaign, based on `fe0bb86`.

This campaign closes the existing managed-pointer path from exact ratification
to an inspectable durable activation. It does not introduce another pointer,
authority family, deployment framework, or interpretation of the formal
calculus. The managed Git ref remains the sole active selector. The frozen
preparation/ratification specimen at `fe0bb86` and
`docs/preparation-ratification-kernel.md` retains its vocabulary and scope.

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

The implementation adds a typed activation receipt only after the final
durable readback. The receipt is evidence and explanation, not standing. It is
retained in broker custody and projected on the direct effectd inspection
plane. A stored receipt never makes a currently divergent ref active and never
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

Readers of the loose ref observe the old or new complete ref value, never a
partially written object name. A success receipt additionally establishes that
the selected object graph was already durable and the new ref survived the
declared sync/readback contract.

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

The campaign must cover exact success explanation; stale predecessor;
artifact, candidate, ratification, receipt and post-state substitution;
pre-CAS failure; post-CAS ambiguity; restart recovery; replay; concurrent
attempts; broad, missing or optional writable roots; missing or excess
capabilities; disabled `ProtectSystem`; helper/repository/staging substitution;
and absence of fixture/development artifacts from release output.

## Qualification limits

This campaign does not claim real power-loss or torn-write survival, disk-full
or WAL/fsync fault coverage, every supported filesystem/storage-cache
combination, external-writer historical provenance, distro Git/systemd matrix
qualification, LSM policy, package install/upgrade behavior, or target resource
quotas. In particular, an external target-owner writer can perform a
same-value ABA that leaves the exact currently expected ref bytes; Git's
object-ID CAS proves the current comparison and exclusivity of its own update,
not the complete unobserved history. Those are release blockers, not reasons
to invent a second mutable truth.

## Scope fence

No Lean or NQ changes, provider ingress, worker/check wrapper, mandate,
systemd effect, new effect family, UI, direct-checkout mode, generic command
effect, or informal rollback belongs in this campaign.
