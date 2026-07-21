# Clean-host qualification fixtures

This directory is the source-side controller contract for the campaign in
`docs/clean-host-activation-qualification.md`. It is not a qualification
receipt and contains no passing host evidence.

`claim.v1.json` is the frozen claim/exclusion split. `matrix.toml` names the
mandatory guests and case families. `receipt.template.v1.json` uses a distinct
`receipt-template/v1` schema, carries all four guest cells and every mandatory
case result as `not_run`, and names the eventual `receipt/v1` target schema. It
is intentionally not a valid final receipt.

`phase1-starting-candidate.v1.json` freezes the clean starting source cut,
rejects the stale unbound package found in `/tmp`, inventories prior receipts,
and separates the four known campaign blockers from four undeclared ambient
host dependencies. It binds `phase1-host-contract.v1.json`, which records the
exact supported-host assumptions and activation/readiness argv before any VM
is created. Each entry also records its exact stdout destination, including
the genesis measurement file. The two `ENROLLED_OPERATOR` tokens are explicit
site parameters: they must be resolved to one numeric operator UID/GID before
that later command is executed, and are not evidence that such an identity has
already been enrolled. `bundle.py` is the standard-library-only evidence
controller. It
initializes every guest/case directory, records exact argv with an explicit
child environment, descriptor-pinned executable identity, expected terminal
outcome, and bounded deadlines, seals all evidence, and strictly reopens a
final receipt. The first command in a case starts an immutable
`CLOCK_BOOTTIME` boundary; later commands are refused after 1,800 seconds, so
idle gaps cannot evade the case deadline. Initialization also copies every
starting-commit contract input
from Git, the host contract, the executing controller, VM fixture, and receipt
publisher bytes, and the measured candidate identity so an omitted or
substituted contract byte refuses reopen. Campaign commands use those copied,
manifest-covered helper bytes after initialization.

`vm_fixture.py` renders deterministic NoCloud inputs, records bounded SSH/QMP
operations, and persists a real `CLOCK_BOOTTIME` case deadline. It never
launches QEMU itself; QEMU, image, ISO, archive, SSH, and guest operations still
go through `bundle.py record` so their exact argv and executable identities are
sealed.

The controller fixture requires Python 3, QEMU/KVM, `qemu-img`, `xorriso`,
OpenSSH `ssh` and `scp`, and coreutils `tail`. The clean guest needs a reachable
configured Debian package mirror while `/usr/bin/apt-get update`, Debian's
implicit `build-essential` build baseline, and the exact source-build
dependency set declared by `debian/control` are installed. These are
qualification-controller or clean-image prerequisites, not runtime
dependencies of the binary package. The repository contains no policy that
authorizes a release-wide guest upgrade, so this campaign pins the published
image and performs only that dependency preparation; it does not run `apt
full-upgrade` or infer an updated-image claim.

Validate the source contract without root or third-party Python packages:

```text
python3 qualification/clean-host/validate.py
python3 qualification/clean-host/bundle.py validate-phase1 \
  qualification/clean-host/phase1-starting-candidate.v1.json
python3 qualification/clean-host/bundle.py validate-host-contract \
  qualification/clean-host/phase1-host-contract.v1.json
python3 -m unittest discover -s qualification/clean-host -p 'test_*.py'
```

Initialize a new evidence root, then route every hypervisor and guest command
through `record` (the executable in argv must be absolute):

```text
python3 qualification/clean-host/bundle.py init /tmp/ag-clean-host-run
python3 /tmp/ag-clean-host-run/inputs/bundle.py record \
  --root /tmp/ag-clean-host-run \
  --guest debian-12-amd64 --case package_build_and_payload \
  --command-id host-preflight --cwd / --env LC_ALL=C -- \
  /usr/bin/uname -a
```

Exit zero is the default expected outcome. A hostile case which expects a typed
nonzero refusal must say so, for example `--expect-exit-code 1`; timeout,
signal, and launch-error expectations are separate mutually exclusive flags.
A case cannot pass when any assigned command differs from its recorded
expectation, and every passing case must contain at least one command record.

After copying all pre-result evidence out of the guests, seal it before writing
the final receipt. The seal excludes only the exact bundle-root paths
`manifest.v1.json`, `receipt.v1.json`, and `verification-result.v1.json`;
nested files with those basenames remain ordinary covered evidence. The final
receipt binds the manifest's recomputed digest and length. This exact frozen
claim is deliberately blocked-only: its required shipped-stranger-workflow
layer has no production ingress case. `QUALIFIED`, `REQUALIFIED`, and
`UNSUPPORTED` therefore refuse under this schema even if arbitrary files claim
all matrix cells passed; qualifying that layer requires a new claim and test
gate. The accepted bounded receipt stops at the first Debian 12 amd64 clean
package-build counterexample, leaves later cases `not_run`, and binds the
unexpected real SSH build command, exact defect, and residual gate. Evidence
roles remain in distinct exact subdirectories below `mandatory/`.

The bounded first build gate requires four canonical typed records before
sealing. `mandatory/test_results/guest-facts.v1.json` has schema
`ag.clean-host-guest-facts-binding/v1`; it binds the raw
`ag.clean-host-guest-facts/v1` stdout produced by the fixed in-guest probe.
`ag.clean-host-candidate-archive/v1` also belongs below
`mandatory/test_results/`; `ag.clean-host-image-provenance/v1` belongs below
`mandatory/image_provenance/`; and
`ag.clean-host-snapshot-boundary/v1` belongs below
`mandatory/snapshot_boundaries/`. The archive record references a nonempty
manifest-covered, uncompressed Git archive, fixes its extraction root at
`/home/agqual/agent-governor-ng-0.1.0`, and binds the exact starting and final
source objects. Reopen reconstructs the Git tree directly from tar members,
then requires the guest to measure the transferred tar, extract it, and run
the fixed Git `init --bare`, `add --all --force`, and `write-tree` sequence
before either build command. The final `write-tree` stdout must be the exact
candidate tree. Every SSH step uses byte-identical identity and known-host
inputs. The snapshot binds those same source objects and the image SHA-256.
Receipt metadata must equal the typed records exactly.

The receipt also requires one real, ordered first-gate VM chain. Record the
copied fixture rendering exact NoCloud `meta-data` and `user-data` from a
manifest-covered public key, the exact `xorriso` ISO creation, and a fresh
qcow2 overlay creation from the manifest-covered base image. Then record the
fixed daemonized KVM/QEMU launch, copied-fixture authenticated readiness,
exact `apt-get update` and build-dependency installation, archive transfer,
source and guest-facts measurements, both build refusals, copied-fixture QMP
`quit`, a wait for the launched QEMU PID to disappear, and conversion, check,
and info of a nonempty standalone qcow2 failure snapshot. The fixture public
key, rendered inputs and their typed identity, QEMU PID, serial log, NoCloud
ISO, readiness result, and QMP result are mandatory hypervisor evidence. The
private SSH key, mutable overlay, and live QMP socket stay outside the sealed
evidence tree. `qemu-img info --backing-chain` must report exactly one qcow2
image with no backing filename, and `qemu-img check --output=json` must report
zero check errors. Controller `CLOCK_BOOTTIME` records must order the whole
chain; overlapping or reversed synthetic records refuse.

The `vm-launch` record uses this order-sensitive argv, with every placeholder
expanded to one absolute run-local path or concrete value:

```text
/usr/bin/qemu-system-x86_64 -name ag-ng-debian-12-amd64 -uuid <UUID> -machine q35,accel=kvm -cpu host -smp 4 -m 8192 -display none -serial file:<SEALED_SERIAL_LOG> -monitor none -no-reboot -daemonize -pidfile <SEALED_PIDFILE> -qmp unix:<EXTERNAL_QMP_SOCKET>,server=on,wait=off -drive if=virtio,format=qcow2,file=<EXTERNAL_OVERLAY>,cache=none -drive if=virtio,format=raw,readonly=on,file=<SEALED_NOCLOUD_ISO> -netdev user,id=net0,hostfwd=tcp:127.0.0.1:<PORT>-:22 -device virtio-net-pci,netdev=net0
```

Use the fixed command IDs in `FIRST_GATE_COMMAND_IDS`. In particular,
`fixture-render-nocloud` uses the copied deterministic renderer;
`nocloud-iso-create` uses exactly `xorriso -as mkisofs -output ... -volid
cidata -joliet -rock user-data meta-data`; `vm-overlay-create` is the exact
`qemu-img create -f qcow2 -F qcow2 -b` operation; `vm-shutdown` is
copied-fixture QMP `quit`; `vm-exit-wait` is the fixed `tail --pid ...
--follow=name --sleep-interval=0.1 /dev/null` boundary; and
`snapshot-convert`, `snapshot-check`, and `snapshot-info` are the exact
qemu-img operations enforced by the verifier. Keep the external QMP socket
path short enough for the platform Unix-domain socket limit.

The canonical `inputs/blocked-receipt-metadata.v1.json` object has these exact
required fields: `schema` set to
`ag.clean-host-blocked-receipt-metadata/v1`; `authority_use` set to
`evidence_only`; `controller_host` containing exactly `architecture`,
`distribution`, `hypervisor`, `kernel`, and nonempty `evidence_paths`;
`terminal_image` containing exactly `bytes` (`length` and `sha256`), `source`,
`source_digest`, and `provenance_path`; `terminal_observed` containing exactly
`active_lsms`, `architecture`, `cgroup`, `distribution`, `filesystem`,
`kernel`, `landlock_abi`, `release`, and `systemd`; and the path collections
`terminal_guest_evidence_paths`, `terminal_snapshot_paths`, and
`mandatory_evidence_paths`. The observed identity is exactly Debian 12 on
`amd64`. `mandatory_evidence_paths` has one key for each controller role:
`activation_and_receipt_identities`, `command_ledger`, `hostile_case_results`,
`hypervisor_and_host`, `image_provenance`, `installed_file_inventory`,
`reboot_and_recovery`, `service_process_security_attestation`,
`snapshot_boundaries`, `test_results`, and
`user_group_permission_inventory`. Optional fields are `additional_defects`,
`additional_residual_gates`, `repairs`, and `receipt_inventory_paths`.
The six roles not reached after the first build gate remain empty arrays; they
must not contain placeholder success evidence.

The three typed path collections must include these exact paths:

```text
terminal_guest_evidence_paths = mandatory/test_results/guest-facts.v1.json, mandatory/test_results/candidate-archive.v1.json
terminal_image.provenance_path = mandatory/image_provenance/image.v1.json
terminal_snapshot_paths = mandatory/snapshot_boundaries/snapshot.v1.json
```

Before rendering, the canonical metadata, candidate archive, raw guest-probe
stdout, actual base-image artifact, and actual preserved failure snapshot must
all exist. The image, snapshot, and archive artifacts themselves must appear
in their corresponding `mandatory_evidence_paths` arrays alongside their typed
records. The nine hypervisor artifacts named above must appear in
`mandatory_evidence_paths.hypervisor_and_host`. Render the records with the
copied publisher before sealing. The renderer recomputes the image identity,
measures the archive, checks the raw probe, derives both source identities from
copied inputs, and creates each record exclusively.

```text
python3 /tmp/ag-clean-host-run/inputs/blocked_receipt.py \
  --prepare-evidence \
  --archive mandatory/test_results/candidate-source.tar \
  --guest-facts-observation guests/debian-12-amd64/cases/package_build_and_payload/commands/guest-facts.stdout \
  --image-artifact mandatory/image_provenance/base-image.qcow2 \
  --snapshot-artifact mandatory/snapshot_boundaries/failure.qcow2 \
  --snapshot-id debian-12-amd64-first-gate-failure \
  /tmp/ag-clean-host-run
```

The source/build chain requires these exact remote tails after literal
`agqual@127.0.0.1`:

```text
/usr/bin/sudo /usr/bin/apt-get update
/usr/bin/sudo /usr/bin/apt-get --yes --no-install-recommends install build-essential debhelper bubblewrap cargo git python3 rustc
/usr/bin/sha256sum /home/agqual/agent-governor-ng-0.1.0.tar
/usr/bin/tar --extract --file=/home/agqual/agent-governor-ng-0.1.0.tar --directory=/home/agqual
/usr/bin/git init --bare /home/agqual/ag-ng-source-measure.git
/usr/bin/git --git-dir=/home/agqual/ag-ng-source-measure.git --work-tree=/home/agqual/agent-governor-ng-0.1.0 add --all --force
/usr/bin/git --git-dir=/home/agqual/ag-ng-source-measure.git write-tree
/usr/bin/sudo /usr/bin/python3 /home/agqual/agent-governor-ng-0.1.0/qualification/clean-host/guest_probe.py debian-12-amd64
/usr/bin/env --chdir=/home/agqual/agent-governor-ng-0.1.0 LC_ALL=C /usr/bin/dpkg-checkbuilddeps
/usr/bin/env --chdir=/home/agqual/agent-governor-ng-0.1.0 LC_ALL=C /usr/bin/dpkg-buildpackage --build=binary --no-sign
```

The SSH prefix is also exact: ambient configuration is disabled; batch,
public-key-only authentication and strict host-key checking are mandatory; and
one absolute run-local known-hosts file, one external identity file, and one
numeric forwarded port precede the literal target. The archive transfer uses
the equivalent exact SCP options and is byte-bound to the sealed archive.
Exactly one readiness record must be produced by a successful terminal-case
record of `/usr/bin/python3 <root>/inputs/vm_fixture.py wait-ssh --output
<absolute-readiness-path> ...`; its known-hosts file must initially be absent,
and its accepted key, identity bytes, target, and forwarded port must be reused
by every SSH/SCP record.

The bounded receipt requires both build commands to retain the default
expected exit zero while observing mismatches: `dpkg-checkbuilddeps` exits 1
and `dpkg-buildpackage` exits 3. Do not pass `--expect-exit-code 1` or `3` for
those commands. Every other recorded command must match its expected outcome,
and all command records for this bounded stop remain assigned to the first
Debian 12 amd64 `package_build_and_payload` case.

```text
python3 /tmp/ag-clean-host-run/inputs/bundle.py seal /tmp/ag-clean-host-run
python3 /tmp/ag-clean-host-run/inputs/blocked_receipt.py \
  /tmp/ag-clean-host-run
python3 /tmp/ag-clean-host-run/inputs/bundle.py verify \
  --write-result /tmp/ag-clean-host-run
```

`validate-receipt` checks only canonical receipt shape. The semantic boundary
is `verify`: it reopens the evidence seal, typed records, exact command
outcomes, guest archive measurement, and executing copied tool identities.

A controller implementation must create a fresh VM or restore the named
snapshot for each hostile case, enforce bounded deadlines, and copy evidence
out before destroying the guest. Containers are not acceptable substitutes
for the systemd, mount, capability, Landlock, and package-lifecycle boundary.

Receipts belong under `qualification/receipts/clean-host/` after either every
mandatory cell has run or an exact earlier gate has produced the bounded
`BLOCKED` stop. The aggregate must be a separate receipt-only commit whose
source/harness/package/image digests refer backward to immutable inputs.
Private fixture signing keys must never be copied into evidence.

## Debian 12 amd64 continuation

`continuation-claim.v1.json` is a new, narrower claim; it does not amend the
immutable blocked receipt or make the frozen four-guest claim succeed. It
qualifies all eleven case families only for Debian 12 amd64. Debian 12 arm64
and both Ubuntu cells remain structurally empty `not_run_not_claimed` cells,
and the shipped submit/ratify workflow and compiler-closure/reproducibility
work remain explicit roadmap exclusions.

Initialize with the committed continuation tool, record commands through the
copied `bundle.py`, add the canonical continuation metadata and typed build
record, then seal, publish, and reopen:

```text
python3 qualification/clean-host/continuation_receipt.py init /tmp/ag-continuation
python3 /tmp/ag-continuation/inputs/bundle.py record ...
python3 /tmp/ag-continuation/inputs/bundle.py seal /tmp/ag-continuation
python3 /tmp/ag-continuation/inputs/continuation_receipt.py publish /tmp/ag-continuation
python3 /tmp/ag-continuation/inputs/continuation_receipt.py verify --write-result /tmp/ag-continuation
```

The continuation bundle copies and binds the tracked predecessor receipt,
manifest, verification result, and evidence locator. `REQUALIFIED` requires
one exact final amd64 package and every scoped case to pass; it does not invent
a pre-repair package generation where the predecessor produced none. A
`BLOCKED` continuation stops at the first exact scoped obstruction and leaves
all later scoped cases `not_run`.
