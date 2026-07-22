# Clean-host package and activation qualification

Status: campaign contract and genesis enrollment implementation present; one
immutable bounded `BLOCKED` receipt exists, but no exact package has passed the
clean-host matrix. The repository remains not production deployable.

## Claim boundary

This campaign asks whether an operator with no developer checkout knowledge
can install the exact package on a pristine supported host, create a reviewed
initial managed-pointer enrollment through packaged tooling, start the
packaged effect broker under its effective systemd sandbox, and recover the
same live governed head after restart. A passing local Rust suite is a
prerequisite, not evidence for this claim.

Qualification is deliberately split into three layers:

1. **Package lifecycle.** The exact binary package installs inertly. Its
   payload, owners, modes, sysusers, tmpfiles, disabled units, dependency
   ordering, removal, retained operator state, and identical-package reinstall
   match the package contract.
2. **Live effectd activation.** Given reviewed disposable enrollment fixtures,
   the packaged `ag-effectd` starts from an absent store, reaches authenticated
   `ready = true`, reconstructs genesis or a durable activation after restart,
   and fails closed under the named unit/process/filesystem mutations.
3. **Shipped stranger workflow.** A stranger installs the package and performs
   enroll -> submit candidate -> ratify -> activate using only shipped
   production interfaces.

Only layers 1 and 2 are presently implementable. Layer 3 remains blocked:
production `agd` has no packaged artifact/admission ingress, while the only
implemented candidate-custody route is the development-only worker launcher.
A qualification-only signed proposal forwarder may exercise the real effectd
socket for layer 2, but its executable, public key, cgroup, inputs, and receipt
must be recorded and the result must not be described as production ingress
qualification.

The campaign does not qualify `agd` or `ag-providerd` application readiness;
both retain narrower conservative health behavior. Unit start and
`Type=exec` are never treated as readiness.

## Genesis ceremony

Genesis enrollment is an offline root ceremony because the final genesis is
part of the exact effectd config/store activation identity. It cannot be an RPC
to a daemon which already needs that config to start.

Begin from the inert, uncompressed packaged examples:

```text
install -d -o root -g root -m 0755 /etc/agent-governor
install -o root -g root -m 0600 \
  /usr/share/doc/agent-governor-ng/examples/effectd.example.toml \
  /etc/agent-governor/effectd.template.toml
install -o root -g root -m 0600 \
  /usr/share/doc/agent-governor-ng/examples/managed-pointer-genesis-request.example.toml \
  /etc/agent-governor/genesis-request.toml
```

Replace every placeholder identity, key, numeric custody value, socket peer,
path, repository owner, authority domain, and epoch under independent review;
copying the examples is not enrollment. Keep the effectd template
managed-pointer-free. It may contain managed-file targets, but v1 refuses a
pre-existing managed-pointer target. The effectd database and SQLite
sidecars/writer lock must be absent,
and its object store must exist with exact configured custody and be empty. The
package's tmpfiles policy pre-creates the example object and promotion-staging
directories as `root:root` mode `0700`; the package also creates the local
`ag-effectd.service.d` output parent as `root:root` mode `0755`.

Measure without mutating the repository or managed ref:

```text
agctl managed-pointer measure-genesis \
  --request /etc/agent-governor/genesis-request.toml \
  --effectd-config-template /etc/agent-governor/effectd.template.toml \
  > /etc/agent-governor/genesis-measurement.json
```

The command requires effective UID/GID 0, clears supplementary groups, pins
and seals the exact Git bytes, and reuses effectd's descriptor-bound repository
and state observer. Its canonical measurement binds the authority domain,
epoch, exact template bytes, absent-store destinations, selected target,
helper/launch profile, repository layout/config/custody, loose-ref inode and
bytes, commit, tree, cleanliness, checked-out state, and staging custody. It is
read-only with respect to the repository/ref and creates no standing. For a
non-bare repository, cleanliness observation creates and removes one private
`.ag-promotion-*` scratch directory under the enrolled staging root. Normal
success and fresh-measurement refusal paths must leave that root free of
ceremony residue. A cleanup failure leaves a non-authorizing quarantined
directory, fails the command, and must fail qualification rather than being
mistaken for repository mutation or standing.

After independent review, enroll through a second complete live measurement:

```text
agctl managed-pointer enroll-genesis \
  --request /etc/agent-governor/genesis-request.toml \
  --effectd-config-template /etc/agent-governor/effectd.template.toml \
  --measurement /etc/agent-governor/genesis-measurement.json \
  --receipt-output /etc/agent-governor/genesis-enrollment-receipt.json \
  --unit-drop-in-output /etc/systemd/system/ag-effectd.service.d/50-managed-pointer.conf \
  --output /etc/agent-governor/effectd.toml
```

The reviewed JSON must be canonical JCS followed by exactly one LF, root-owned,
regular, single-link, bounded, and not group/other writable. Enrollment refuses
unless the fresh measurement equals the complete reviewed measurement. It
derives the complete final `EffectdConfigV1` and exact effective
`CapabilityBoundingSet=`/`ReadWritePaths=` drop-in; no target fragment or
manual digest transcription is left to the operator.

Publication uses root-owned nonsymlink ancestry, sibling staging files, file
fsync, `renameat2(RENAME_NOREPLACE)`, parent fsync, and exact readback. The
non-authorizing receipt is published first, the unit drop-in second, and the
final effectd config last as the ceremony's commit point. A failure can leave
any complete published prefix: receipt only, receipt plus drop-in, or all three
complete files when a post-rename sync/readback step reports failure. It cannot
leave a partial published file and never overwrites. V1 has no prefix-aware
packaged recovery command: an incomplete prefix requires exact out-of-band
custody/digest review and archive/removal, or restoration of the pristine VM
snapshot, before retry. If all three files exist, run the verifier below even
when enrollment returned failure. Command status alone never authorizes
deletion.

Before service start, verify all artifacts and repeat the live measurement:

```text
agctl managed-pointer verify-genesis-enrollment \
  --measurement /etc/agent-governor/genesis-measurement.json \
  --effectd-config-template /etc/agent-governor/effectd.template.toml \
  --receipt /etc/agent-governor/genesis-enrollment-receipt.json \
  --effectd-config /etc/agent-governor/effectd.toml \
  --unit-drop-in /etc/systemd/system/ag-effectd.service.d/50-managed-pointer.conf

systemctl daemon-reload
systemd-analyze verify ag-effectd.service
systemctl show ag-effectd.service \
  -p DropInPaths -p CapabilityBoundingSet -p ReadWritePaths
```

The qualification harness must compare those effective properties with the
generated artifacts before it starts the unit; writing a drop-in does not
reload systemd's manager state. On the first actual start, `ag-effectd` repeats
the complete pristine-store cut and configured genesis check before creating
its immutable authority store. The ordinary post-store live activation check
remains mandatory because the target owner can race any pre-store observation.
Same-inode in-place ABA and coherent store-plus-target rollback remain explicit
release gaps; two equal observations do not prove uninterrupted history.

## Required clean-host matrix

Run full VMs, not containers, from pinned images:

| Guest | Architecture | Minimum runtime |
| --- | --- | --- |
| Debian 12 | amd64 | Linux 6.1, systemd 252, Landlock ABI >= 3 |
| Debian 12 | arm64 | Linux 6.1, systemd 252, Landlock ABI >= 3 |
| Ubuntu 24.04 | amd64 | distribution kernel/systemd, Landlock ABI >= 3 |
| Ubuntu 24.04 | arm64 | distribution kernel/systemd, Landlock ABI >= 3 |

Every case starts from a named pristine or activated snapshot and has a bounded
controller deadline. Record the image digest, `/etc/os-release`, architecture,
kernel, systemd, Git, Landlock ABI, active LSMs, cgroup mode, filesystem and
mount options, installed package set, source tree, `Cargo.lock`, toolchain,
package digest, and harness digest.

Mandatory case families are:

- clean build and package payload/control/maintscript inspection;
- install, reboot, exact sysusers/tmpfiles, disabled/inactive units, and no
  config/key/store/target side effects;
- measure -> review -> enroll -> verify -> daemon-reload -> effective-unit
  comparison -> daemon start from an absent store;
- authenticated effectd readiness at genesis, restart, and reboot;
- one real effectd activation through an explicitly qualification-only signed
  proposal fixture, durable record inspection, restart, and reconstruction;
- missing/excess/ambient capabilities, supplementary groups,
  `NoNewPrivileges`, `ProtectSystem`, network/address-family, `ExecStart`,
  missing/extra/broad writable roots, protected-root and mount drift;
- repository/ref/staging/helper/config/object/store custody and substitution;
- removal while active, strict observed stop before payload removal, retained
  state, empty drop-in-directory removal versus nonempty operator-content
  retention, identical-package reinstall, preserved prior enablement, and
  explicit-start reconstruction;
- packaging-only revision upgrade with identical executable bytes after a
  strict observed stop, followed by explicit-start reconstruction; plus safe
  refusal on the explicit start after a real changed-binary/config upgrade
  until the offline store activation transition exists.

Every hostile case must distinguish `active_not_ready` from
`failed_before_listener`, prove refusal before authorization burn where a ready
proposal exists, and prove the target and prior receipts unchanged. Removing a
required Landlock syscall must make the actual promotion fail safely. Adding an
unapproved syscall is currently an external qualification failure only: the
daemon does not yet attest systemd's expanded effective `SystemCallFilter=`.

## Package-build gates exposed by this campaign

The checked-in Debian skeleton currently invokes Cargo with `--locked --offline`.
That invocation can use a deliberate Cargo home already containing
the locked dependencies, but it is not a claim that this repository carries an
independently sealed compiler, registry, or native-tool closure. A separately
enrolled, hash-complete Rust compiler closure and byte-for-byte reproducible
second build are not gates for this stage.

The builder may be a controlled development or build environment distinct from
the runtime VM. Before building, record the exact source commit and tree,
worktree state, verbose Rust and Cargo versions, target triple, `Cargo.lock`
digest, relevant native compiler/linker/packaging versions, material environment
variables, network availability, and exact build command. Use a clean Cargo
target directory and a deliberate Cargo home, or otherwise demonstrate that no
stale output can be selected. The resulting package is admissible only by its
exact path, size, and SHA-256 and must pass on a genuinely clean supported
runtime host. Rust and Cargo remain build-time tools and must not become package
runtime dependencies. If the current offline invocation prevents an otherwise
admissible clean build, that is a concrete build or packaging defect to repair,
not a reason to expand this campaign into compiler-provenance research.

The package now declares the Git and development-only Bubblewrap runtimes used
by shipped command paths,
limits binary architectures to amd64/arm64, keeps Markdown documentation
uncompressed so unit `Documentation=file:` targets resolve, honors `DPKG_ROOT`
in sysusers/tmpfiles setup, and refuses removal or upgrade unless systemd
explicitly reports every daemon stopped with `MainPID=0`. Fresh install leaves
units disabled/inactive; reinstall preserves an administrator's prior enable
state, and `--no-start` leaves upgrade/reinstall activation explicit. A
host-root-only post-install manager reload refreshes unit definitions without
starting them and is skipped under `DPKG_ROOT`. Those
changes still require the VM package lifecycle matrix; source text is not a
receipt.

## Qualification receipt

The aggregate is canonical `ag.clean-host-package-qualification-receipt/v1`,
non-authorizing, and committed separately from the implementation it qualifies.
The checked-in source scaffold deliberately uses the distinct
`ag.clean-host-package-qualification-receipt-template/v1` schema and cannot be
promoted by editing its verdict. It binds the target receipt schema, frozen
blockers and exclusions, all four guest cells, and every mandatory case as
`not_run`. The rootless validator in `qualification/clean-host/validate.py`
enforces those relationships and exact canonical JSON.

A materialized receipt binds source/package/image/harness identities, every
matrix cell, exact expected and observed daemon/authority/target states,
before/after evidence, reboot/snapshot boundaries, and bounded artifacts by
SHA-256 and byte length. Each case is `pass`, `fail`, `blocked`, or `not_run`;
any mandatory result other than `pass` prevents a `qualified` verdict. Even
after every runnable case passes, the aggregate remains `blocked` while the
required shipped-stranger-workflow layer is blocked.

The immutable historical receipt at
`qualification/receipts/clean-host/20260720-debian12-amd64-9a5f140/receipt.v1.json`
has verdict `BLOCKED` and `authority_use = evidence_only`. It records successful
Debian 12 runtime-prerequisite exercise through the package-build boundary, then
the absence of a package because the guest repository Rust/Cargo versions were
too old. Installation and every later runtime gate remain `not_run`. The
continuation campaign incorporates that receipt by reference and resumes at the
package-build boundary; documentation cannot promote the historical result or
reinterpret it as activation readiness.

## Exclusions

This campaign does not claim real power-loss/torn-write behavior, disk-full or
WAL/fsync fault injection, filesystem/cache combinations beyond the named VM,
simultaneous clients/readers, same-inode ABA prevention, external anti-rollback,
TPM-backed key ceremony, production worker/provider readiness, package signing
or repositories, successful changed-binary/config upgrade, or confirmed
decommission/purge. Those remain separate gates.
