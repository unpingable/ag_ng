# Coherent three-store backup and restore

An agd database backup, an effectd database backup, and a providerd database
backup taken independently are not a system backup. A supported backup is one
sealed `BackupCutV1` that proves those component states jointly existed behind
one durable quiescence barrier.

No live backup command is currently exposed by `agctl`. The implemented v1
surface is deliberately offline: all three units must be stopped, and a caller
must open all three stores and therefore acquire all three exclusive writer
fences before `OfflineBackupCoordinatorV1::seal` will accept exact
`OfflineServicesStopped` barrier attestations. There is no code path that calls
this a live distributed quiescence handshake.

The store crate implements the durable cut state machine, verified blob
catalog, per-store sealed capture, complete database/object publication format,
strict offline verification, no-replace atomic publication, and immutable
evidence restoration. `ag-backup verify`, `ag-backup publish`, and
`ag-backup restore-evidence` expose the non-authority-bearing parts as an
operator tool. The coordinator and capture APIs remain an embedding surface;
there is not yet a privileged system coordinator that stops units, discovers
effective config/profile/build identities, obtains independent attestations,
materializes a bundle, performs a second-principal verification, and releases
all three barriers.

`capture_sealed_database` uses SQLite's online-backup API only while the cut is
sealed, normalizes the copy to standalone rollback-journal form, refuses
replacement, runs a post-copy quick check, fsyncs and makes the snapshot
read-only, and returns a `SealedDatabaseCaptureV1` bound to the manifest plus
post-seal chain/blob facts. `CoherentBackupBundleV1` rejects individually valid
captures from non-joint states. `BackupPublicationV1` additionally binds every
cataloged immutable object and the capture-tool identity. Verification reopens
each database read-only, checks its exact store identity and event chain, and
rejects missing, additional, writable, linked, or digest-inconsistent files.

## Bound facts

The canonical cut binds at least:

- authority domain and epoch;
- the agd, effectd, and providerd component identities;
- each component event-chain head and immutable-blob root;
- config, schema, security-profile, executable-build, and launch-profile
  identities;
- one quiescence-barrier identity;
- an exact per-component `QuiescenceBarrierAttestationV1`, including the
  attesting principal and digest of every in-flight cross-daemon operation's
  declared terminal, indeterminate, or reconciliation boundary.

Exactly those three participants are required. A missing, duplicated, stale,
or additional participant makes the cut unsealable. An object root without its
database checkpoint, or a database without its object root, is incomplete.

## Backup protocol

### 1. Prepare

The currently implemented offline coordinator allocates a unique cut ID and
barrier ID and records the same domain/epoch and exact participant
registrations only after it owns all three store writer fences. It accepts only
the explicit `OfflineServicesStopped` boundary mechanism. Once any participant
records begin, ordinary mutation is fenced. Retries use the same exact request;
reuse of an ID with different bytes is a conflict. Any partial coordinator
failure is fail-closed: already-written barriers remain active and must be
resumed with the exact request or explicitly aborted.

Quiescence does not mean merely “no effect is executing.” Before acknowledging
its checkpoint, each participant must stop admitting new mutation and account
for all work that crossed a daemon boundary:

- no worker is still producing mutable session state;
- no provider request or response handoff is unaccounted for;
- no proposal compilation, ratification burn, or effect execution is between
  durable boundaries;
- any uncertain external outcome is durably `Indeterminate` and attached to a
  reconciliation record rather than relabeled refused or retried;
- all event/materialized-view commits and blob installations have reached
  their declared durable boundary.

Each participant then persists its checkpoint: chain head, blob root,
identities, and full barrier attestation. “Prepared” is true only after all
three checkpoints are durable and mutually bound to the same barrier.

### 2. Seal

The coordinator constructs the manifest only from those durable checkpoints,
canonicalizes it, verifies all bound facts, and commits the exact manifest
digest as `sealed` at every participant. No participant may resume mutation
after sealing. A coordinator or daemon crash in `preparing`, `prepared`, or
`sealed` state leaves the fence active after restart.

The only safe recovery choices are to resume the exact cut or explicitly abort
it with a durable reason. Never clear the fence by editing SQLite, removing a
WAL, changing an epoch file, or starting a daemon against a copied store.

### 3. Physical capture

Capture into a new root-owned staging directory on the same publication
filesystem. While every participant remains sealed:

1. Invoke each participant store's `capture_sealed_database` and retain its
   `SealedDatabaseCaptureV1`. Never use a naked copy of a live database/WAL
   pair, even while the higher-level coordinator believes the host quiesced.
2. Construct and validate `CoherentBackupBundleV1` from exactly those three
   captures before treating their database bodies as a joint cut.
3. Enumerate each store's verified `blob_catalog()`, capture its immutable
   object root, and verify every filename, byte length, and content digest.
4. Capture the sealed canonical manifest, config identities, effective systemd
   unit properties and drop-ins, build identities, enrollment metadata, and
   supported restore-tool identity. Secrets remain in their separate recovery
   system; include only credential enrollment references, never plaintext.
5. Build a bundle inventory with sizes and SHA-256 digests, fsync every file,
   then fsync every directory from leaf to staging root.
6. Independently reopen the three staged databases read-only, verify SQLite
   integrity, event-chain continuity, materialized-view revisions, blob roots,
   cut IDs, manifest digest, domain, and epoch.

Any capture or verification failure keeps the daemons sealed. Discard the
staging tree or retain it as failed evidence; it is not a backup.

### 4. Atomic publication

Publish only the completely verified staging directory. On a local filesystem,
`ag-backup publish --staging PATH --destination PATH` requires sibling paths,
uses `renameat2(RENAME_NOREPLACE)`, fsyncs the publication parent, and re-verifies
the final name. Existing destinations are never replaced. For remote/object
storage, upload immutable objects first and create one conditional final commit
object containing the exact bundle digest last; that remote publisher remains
unimplemented.

Never publish a mutable “latest” directory. A convenience pointer may be
updated by compare-and-swap only after the immutable bundle is committed. The
published receipt binds bundle digest to cut manifest digest and capture-tool
identity.

### 5. Release

Only after publication is durable and a second verifier reproduces the exact
bundle digest may the coordinator commit `released(bundle_digest)` to every
participant and lift the mutation fence. Release is idempotent only for that
same digest. A different digest is a conflict, not another candidate.

If the coordinator crashes after publication but before release, verify the
existing immutable bundle and resume the same release. Do not take another cut
or allow mutation first. If an operator aborts a sealed cut, the unpublished
capture must be discarded and the durable abort reason retained.

## Restore protocol

Restore is fail-closed and offline. It never combines component directories
from different bundles, even when their individual integrity checks pass.

1. Keep all AG-ng units disabled and stopped. Isolate the host from governed
   targets and provider egress.
2. Run `ag-backup verify --publication PATH` to verify the full bundle digest,
   sealed cut,
   all three checkpoints, event chains, blob roots, component/config/schema/
   profile/build identities, and restore-tool compatibility before copying.
3. `ag-backup restore-evidence --publication PATH --destination PATH` can make
   a verified, immutable, no-replace evidence copy through a sibling staging
   directory. It deliberately does not install live component roots. A future
   recovery coordinator must restore each component with its original owner and
   mode, reopen databases read-only, and repeat all logical checks.
4. Create and fsync a root-owned activation journal. With services still down,
   rename any existing live component roots to unique quarantine names and
   install all three staged roots. Record and fsync each rename. A crash during
   this sequence is recovered from the journal while services remain stopped;
   no partially installed set may start.
5. Start a recovery-only coordinator. The restored `sealed` barrier must still
   reject ordinary mutation. Reconcile external target state, provider custody,
   and any indeterminate operation against the cut.
6. Advance to a new nonzero authority epoch through a single durable recovery
   transition shared by all three stores. This invalidates capabilities and
   ratification state created after the backup. Never edit epoch fields by
   hand.
7. Verify effective units, target catalog/sandbox equality, peer enrollments,
   executable bytes, credential references, and direct effect inspection.
   Publish a restore receipt binding the old cut, new epoch, installed store
   roots, and reconciliation result.
8. Lift the recovery fence and enable ordinary startup only after all checks
   admit. Retain quarantined roots until an independently verified post-restore
   coherent backup exists.

The live recovery activation journal, recovery-only coordinator, and shared
epoch transition are not implemented. `restore-evidence` is therefore valuable
disaster-recovery input, not authorization to make restored stores live by
manual database surgery.
