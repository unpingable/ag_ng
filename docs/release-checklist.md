# Release checklist and support matrix

## Current verdict

**Not production deployable.** The repository has authority-bearing kernel,
protocol, store, session, and effect components under construction, plus a
reviewable service/package skeleton. A release tag, package, successful unit
start, or passing crate test does not override the gates below.

Known blockers in the current tree include:

- managed-file execution and a development-qualified managed-ref CAS path are
  wired, but typed systemd D-Bus backends remain deliberately unavailable;
  managed-pointer production activation is still blocked on effective-unit
  sandbox parity, target-owner capability packaging, host/Git qualification,
  and the power-loss matrix;
- offline three-writer-fence coordination, sealed SQLite/object capture,
  hostile coherence validation, atomic local publication, and immutable
  evidence restore exist, but there is no live cross-daemon coordinator,
  independent release ceremony, activation journal, or recovery-only epoch
  transition;
- effectd does not yet prove that every configured target equals the effective
  systemd `ReadWritePaths` sandbox before readiness;
- a development-only, offline, fixed-profile Bubblewrap worker ingress now
  mints and tombstones durable `WorkerSessionPrincipal` records and accepts
  only authenticated candidate material; it enforces one live worker, checked
  reaping, typed refusal tombstones, exact dynamic-key proof, and durable broker
  outcomes, but it is deliberately rejected by
  production/high-assurance configuration; the packaged agd unit cannot host
  it, and production worker/check wrappers, sandbox attestation, and one-shot
  launch-record consumption do not exist, so both templates remain withheld;
- providerd is signed-agd-proxy-only, while the session ingress/proxy path does
  not yet prove the live `WorkerSessionPrincipal` before spending its committed
  provider capability; the implemented worker slice is offline rather than a
  provider-capability workaround;
- `agctl doctor` implements a fail-closed configuration/custody/effective-unit
  audit, but kernel-feature attestation, a daemon activation-level readiness
  contract, and watchdog heartbeats are not implemented (`Type=exec`
  intentionally claims only exec);
- package install, upgrade, rollback, and removal tests have not run on every
  supported distribution/architecture pair;
- Debian maintainer/distribution metadata are placeholders because no release
  remote or signing authority has been enrolled;
- source-license evidence is recorded, but the private `skunkworks`
  formalization has no license declaration at its pinned revision or current
  tree; reuse permission and release treatment remain unresolved;
- audited Ed25519 generation, independent public-key enrollment, rotation, and
  recovery tooling is not packaged.
- daemon stores durably bind authority, exact configuration, security profile,
  and running executable bytes, but the offline activation transition needed
  for an authorized upgrade, key rotation, catalog change, or epoch change is
  not implemented.

## Support matrix

| Surface | Release target | Current status |
| --- | --- | --- |
| Debian 12, Linux >= 6.1, systemd >= 252, amd64 | Tier 1 | unqualified |
| Debian 12, Linux >= 6.1, systemd >= 252, arm64 | Tier 1 | unqualified |
| Ubuntu 24.04, Linux >= 6.1, systemd >= 252, amd64 | Tier 1 | unqualified |
| Ubuntu 24.04, Linux >= 6.1, systemd >= 252, arm64 | Tier 1 | unqualified |
| Other Linux/systemd distributions | none | unsupported until qualified |
| Containers as a security boundary | none | unsupported |
| FreeBSD | roadmap only | no production claim |
| Hostile multi-tenancy | excluded | no security claim |

The v1 product is one authority domain on one host, batch-only workers, Unix
sockets, SQLite/WAL with one authoritative writer per component, and a closed
effect/provider catalog. Public TCP APIs, PTYs, arbitrary shell/root commands,
plugins, wildcard policy, BreakGlass, Python runtime fallback, linked
worktrees, and classic command/API/database compatibility are out of scope.

## Freeze gates

- [ ] The architecture, threat model, exclusions, protocol versions, support
  matrix, and M1 anti-bloat rule are frozen and reviewed.
- [ ] The classic AG, calculus/formalization, NQ-ng, verifier, Nightshift, and
  other source baselines have immutable receipts and license review.
- [ ] All wire/config schemas reject unknown fields and versions, duplicate
  keys, floats, implicit defaults, invalid UTF-8, oversized frames, appended
  frames, and noncanonical identifiers.
- [ ] Authority-domain and epoch agreement is checked at every daemon boundary.
- [ ] Principal-chain independence, session nonce/lifecycle, executable bytes,
  launch profile, service/unit identity, and live peer binding have hostile
  tests. Recycled UID/PID cannot replay authority.
- [ ] Every local RPC uses mutually enrolled Ed25519 keys with signed random
  challenge, caller nonce, audience, direction, canonical request/response
  digest, bounded skew, and durable/in-memory replay defense as appropriate.
  The signed leaf principal is bound into its enrolled chain root. A valid
  signature does not weaken domain, epoch, role, socket, or capability checks;
  UID/PID observations do not replace the signature.
- [ ] No serialized witness, capability, digest, or receipt is accepted as
  runtime authority without reconstruction from committed local state.

## Build and supply-chain gates

- [ ] `cargo build --locked --offline --release --workspace` succeeds from a
  reviewed vendored dependency set using the pinned Rust toolchain.
- [ ] Unit, integration, hostile-specimen, fuzz, loom/concurrency where
  applicable, and end-to-end tests pass on amd64 and arm64.
- [ ] Binaries are stripped according to policy, carry build/source identities,
  and have reproducible-build comparison receipts and an SBOM.
- [ ] Package signatures, repository metadata, provenance, vulnerability
  review, license notices, and rollback artifacts are verified independently.
- [ ] Distinct daemon/operator RPC keys are generated as accepted PKCS#8 v2,
  independently enrolled, sealed with a reviewed host/TPM and recovery policy,
  rotated without identity collapse, and never persisted plaintext.
- [ ] No Python module, classic database library, network-capable code, shell,
  generic command runner, or plugin loader is linked into effectd.
- [ ] `scripts/verify-effectd-isolation.sh` succeeds. This builds the exact
  release broker offline and rejects provider, HTTP, and TLS crates in its
  dependency graph or provider-network symbols in its ELF artifact.

## Authority-membrane gates

The development managed-pointer slice exercises exact bundle custody,
broker-owned canonicalization, independent exact ratification, target-owner
managed-ref CAS, verified poststate, single-use consumption, and explicit
reconciliation. It supports only an existing loose ref in a bare repository or
a loose managed ref not checked out in any attached worktree. A packed-ref-only
target refuses. It does not synchronize a live worktree and does not close the
production gates below.

- [ ] `agd` can submit only intent plus admitted artifact references; only
  effectd compiles and persists canonical proposal bytes.
- [ ] `agctl effect show` and ratification submission terminate directly at
  effectd and display/submit the same digest-bound bytes.
- [ ] Proposal, admin, governor, and provider sockets have the expected owner,
  SGID parent, mode, SELinux/AppArmor label, and exact peer policy after every
  install/restart/upgrade.
- [ ] Every production listener uses signed transport plus its exact enrolled
  `SO_PEERCRED` UID/GID as a separate fail-closed lifecycle check; no daemon
  entry point imports or calls legacy cross-UID `/proc` peer authentication,
  and no unit has `CAP_SYS_PTRACE`.
- [ ] Proposer and ratifier chains are independent; a role string, distinct UID,
  reused dynamic UID, or Nightshift alias cannot manufacture independence.
- [ ] Human exact ratification, bounded host mandates, and derived code
  promotion are distinct paths. Code promotion cannot use an ordinary mandate.
- [ ] BreakGlass and every unsupported authority family refuse before burn or
  effect.
- [ ] Ratification burns durably before execution; timeout/crash/uncertain
  external outcome becomes indeterminate/reconciliation and never auto-retry.
- [ ] Managed-pointer promotion admits only the exact self-contained Git
  bundle contract and binds its artifact/pack, base and post trees, repository
  and Git-directory device/inode identity, owner, ref, catalog/profile, pinned
  Git executable/launch profile, expiry, and one-shot operation ID into the
  broker-owned proposal.
- [ ] The promotion adapter runs only fixed Git plumbing under the target
  owner with isolated configuration, no hooks/filters/helpers/protocols or
  implicit `PATH`; it revalidates immediately before mutation and issues
  success only after independent ref/tree readback.
- [ ] A durable commit-may-proceed checkpoint precedes the ref CAS. Crash and
  power-loss specimens prove known unchanged failure before that boundary and
  reconciliation-required uncertainty at an ambiguous boundary; live
  observation distinguishes exact `not_applied`, exact `applied`, and
  `foreign` state without automatic retry.

## Worker and provider gates

The development Bubblewrap slice exercises fixed-profile launch, authenticated
candidate custody, durable transient-principal binding, terminal tombstones,
checked process cleanup, typed refusals, and broker-owned canonical
compilation. A reviewed profile may now classify candidate material as the
exact managed-pointer Git bundle contract, but the worker still cannot choose
the target or acquire promotion authority. Neither development slice closes
any production gate below; those gates require the production wrapper,
sandbox/host attestation, provider relation, and full qualification matrix.

- [ ] Worker source/artifact/delta custody uses independent repositories or
  snapshots and contains no governed target mount or hidden checkout sync.
- [ ] Batch workers have no interactive input, PTY, pause/resume, reusable
  identity, unintended inherited descriptor, ambient credential, or egress.
- [ ] Every admitted helper is exact executable bytes plus an exact fixed launch
  profile; path substitution and descriptor smuggling specimens fail.
- [ ] Provider capabilities bind domain, epoch, session, worker principal,
  live peer, endpoint/model/method/protocol envelope, policy digest, budgets,
  expiry, and revocation state and burn at session termination.
- [ ] Providerd retains no plaintext after acknowledged custody transfer; agd
  holds exact credential-free request, sanitized headers, and complete response
  stream. Digest-only custody is visibly weaker.
- [ ] Redirects, arbitrary CONNECT, endpoint/model drift, secret logging,
  environment/argv secrets, and peer/capability replay are denied and tested.

## Storage, backup, and recovery gates

- [ ] Each SQLite store has one fenced authoritative writer; concurrent clients
  serialize, a second writer fails, and event/materialized state commit in one
  transaction.
- [ ] Event chains, immutable blobs, orphan cleanup, corruption detection,
  schema migration, disk-full, fsync, WAL/checkpoint, and power-loss tests pass.
- [ ] Prepare accounts for all cross-daemon work; seal keeps all stores fenced;
  each database capture returns a verified `SealedDatabaseCaptureV1`, blob
  catalogs verify object roots, `CoherentBackupBundleV1` rejects non-joint
  captures, publication is atomic, and release binds the exact three-store
  database/object bundle digest.
- [ ] Crashes at every prepare/seal/capture/publish/release boundary resume the
  same cut or require an explicit durable abort. No restart silently unquiesces.
- [ ] Restore installs exactly one three-store bundle offline, preserves the
  sealed fence, reconciles targets, advances epoch durably, and produces a
  restore receipt before ordinary mutation resumes.

## Operations and packaging gates

- [ ] `agd`, `ag-effectd`, `ag-providerd`, and `agctl` implement `--version` and
  config validation; daemons expose authenticated health/readiness without
  overstating systemd activation.
- [ ] Operator `agctl` runs in a fixed-name, hardened, short-lived service with
  its own enrolled encrypted credential; direct display/ratification bytes are
  not altered by a wrapper, terminal, pager, or agd projection.
- [ ] Effective units pass `systemd-analyze security` review and do not require
  undocumented capabilities, writable roots, address families, namespaces, or
  descriptors.
- [ ] Debian install creates users/directories only, installs no live config,
  initializes no store, enables/starts no service, and removal deletes no data.
- [ ] Fresh install, upgrade, failed upgrade, downgrade refusal, package remove,
  purge-with-explicit-confirmation, and disaster restore pass on every Tier 1
  matrix cell.
- [ ] Journald retention/forwarding and audit-export custody are documented and
  tested; no nonexistent file-log rotation policy is installed.
- [ ] A real release exercise proves the entire membrane on a disposable host,
  including refused, indeterminate, reconciliation, backup, restore, and
  managed-target drift paths—not just one successful service restart.
