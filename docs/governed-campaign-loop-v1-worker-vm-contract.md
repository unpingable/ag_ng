# Governed Campaign Loop V1 worker-VM contract

Status: frozen implementation contract, 2026-08-28.

This contract adds one production executor mechanism to the frozen Governed
Campaign Loop V0. It does not change AG authority, Docket attempt or settlement
semantics, C1/C2, NQ qualification, Nightshift applicability, or AG
continuation. The complete V0 authority chain remains:

```text
factual evidence
  -> NQ deterministic qualification
  -> Nightshift current applicability
  -> AG continuation decision
```

## Adjudicated placement

The selected architecture is `WORKER-VM-PREFERRED`:

```text
AG authorization -> Docket exact attempt -> worker-VM executor adapter
  -> Porter exact SSH endpoint -> persistent Linux worker VM
  -> Codex parent + guest-local Bubblewrap command boundary
```

VM creation, session selection, and lifecycle are caller-owned. Porter is a
factual courier. Docket is unaware of campaign-loop semantics and does not
manage VMs. The VM and its agent carry no authority.

## W0 live prerequisite

The live Crow preflight on 2026-08-28 established `KVM-AVAILABLE`:

- execution user `jbeck` (uid 1000) is a member of gid 109 (`kvm`) and has
  read/write access to `/dev/kvm`;
- `kvm_amd` and `kvm` are loaded;
- `/usr/bin/qemu-system-x86_64` 8.2.2 launched with `-accel kvm`, and QMP
  `query-kvm` returned `enabled=true,present=true` before a clean QMP quit;
- unified cgroup v2 exposes `cpu`, `memory`, `pids`, `io`, and `cpuset`
  under systemd 255;
- Crow's Mellanox identity is NetworkManager profile `crow-mellanox`, UUID
  `5a0cc298-0f9f-3039-b41b-6d4be111c0f8`, MAC
  `24:8a:07:f8:1d:91`, currently named `enp4s0`. The interface name is not an
  identity input.

H0/AppArmor and prior TCG-only archaeology are superseded fallback evidence
and are outside this contract.

## One exact coding-worker profile

The only admitted worker architecture is x86-64 Ubuntu 24.04 LTS, independently
derived for this campaign from one downloaded official cloud-image object.
The build receipt freezes the downloaded object's URL, official checksum
manifest, observed SHA-256, derived immutable root-image SHA-256, installed
package inventory, and provisioning transcript. No fixed-function Docket VM
guest image, protocol, journal, source, or device is reused.

The frozen executable and device profile is:

- QEMU: `/usr/bin/qemu-system-x86_64`, version 8.2.2, exact executable hash in
  the session manifest;
- machine: `q35`, KVM acceleration, host CPU, one virtio-net-pci device on a
  QEMU user network, virtio-blk devices only, no shared filesystem, no USB,
  no graphics, no host repository device;
- immutable root: the derived worker qcow2 is attached read-only; the guest
  boots with a read-only root and volatile `/var` state;
- writable devices: one raw ext4 `GCL_STATE` device and one separate raw ext4
  `GCL_CREDENTIALS` device. Their filesystem UUIDs, host file identities, and
  sizes are session inputs. They are never repository artifacts;
- transport: OpenSSH through exactly one loopback-only QEMU host-forward,
  with a dedicated client key and a pinned guest host key. W2 binds the exact
  endpoint profile and observed guest/session identities;
- guest agent: `/usr/local/libexec/gcl-worker-agent`, immutable with the root
  image, exposing only identity, execute, reconcile, and candidate-custody
  mechanics;
- Codex: `/usr/local/libexec/gcl/codex`, `codex-cli 0.147.0`, native x86-64
  package object SHA-256
  `cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40`;
- model: exactly `gpt-5.6-sol`, reasoning effort `medium`, noninteractive
  `codex exec`, no model routing and no model-selected successor;
- Bubblewrap: guest-local immutable executable; each model-controlled shell
  receives a fresh user, pid, ipc, uts, and network namespace, a read-only
  selected system tree, a private `/tmp`, and exactly one writable bind: the
  admitted attempt repository;
- capacity: one measured boot/session, three reserved attempt ordinals, three
  Codex invocation slots, and an unconditional refusal for any fourth slot.

Exact derived hashes replace descriptive identities in the W1 build receipt
and every W3 session manifest. A changed launch is a different session.

## Authentication and credential law

Codex is authenticated inside the guest by `codex login` using ChatGPT. No
`OPENAI_API_KEY` is created, requested, copied, or stored. Crow's
`~/.codex/auth.json` is never read or copied.

Credential bytes live only on the guest-local `GCL_CREDENTIALS` device beneath
`/var/lib/gcl-credentials/codex`. The directory is accessible to the Codex
parent and absent from the Bubblewrap filesystem presented to model-controlled
shell commands. It is not pushed or pulled by Porter, named as an artifact,
included in a campaign packet, stored in a host repository, or copied into a
transcript. Authentication evidence is limited to the exit status and redacted
method reported by `codex login status`.

The parent agent and its Git custody mechanics own the attempt workspace as
guest UID 2000. Every model-controlled shell command crosses the immutable
Bubblewrap wrapper and runs as UID 2001 inside a private user, PID, IPC, UTS,
cgroup, and network namespace. Only the one attempt workspace is writable in
that namespace. The credential device is not mounted there, so the workload
cannot use DAC or a filesystem path to reach it. Parent-side Git operations
after model completion create the candidate bundle but make no qualification
claim.

## Network law

The QEMU host-forward binds only to `127.0.0.1`. Guest firewall policy permits
DHCP/DNS needed by QEMU user networking, established SSH traffic, and outbound
TLS for the Codex parent. New guest connections to the QEMU host gateway are
refused. Bubblewrap model-command namespaces have no network interface other
than loopback. No inbound listener other than the pinned SSH endpoint is part
of the profile.

## Resource and lifecycle profile

The production transient unit is named `gcl-v1vm-<session-id>.service` and
binds, at minimum:

- `MemoryMax=8G`;
- `CPUQuota=400%`;
- `TasksMax=512`;
- `KillMode=control-group`;
- `TimeoutStartSec=120s` and `TimeoutStopSec=30s`;
- an explicit three-attempt session deadline in the caller manifest.

Qualification uses deliberately smaller harmless profiles to prove memory,
CPU, task-count, descendant containment, timeout, and whole-tree termination.
Those test profiles do not become the production resource profile.

## Workspace and candidate custody

Crow repositories are never mounted or exported into the guest. Each attempt
begins from a host-created content-addressed Git bundle for the exact declared
predecessor. Porter sends it to a fresh attempt-private guest directory. The
guest clone has every remote removed. Codex works only there.

The returned candidate is a Git bundle plus factual metadata and hashes. It is
pulled by Porter into a new host quarantine. A trusted host validator rejects
wrong bases, stale predecessors, path traversal, symlinks, non-regular entries,
unexpected paths/files, out-of-scope changes, missing objects, substitutions,
and malformed bundles. Only the trusted Docket executor may apply the exact
admitted candidate to the qualification repository.

Worker prose and a zero exit status are never qualification evidence.

## Explicit nonclaims

This profile does not provide a general VM manager, worker pool, scheduler,
parallel campaign support, dynamic planning, dynamic stage generation, model
routing, production HA, UI, fixed-function VM integration, a second worker
architecture, a fourth stage, or V2. Porter does not admit, qualify, schedule,
settle, reconcile, select work, or mint any domain verdict. Guest persistence
does not create standing or authority.
