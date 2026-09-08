# Deployment contract

This document governs the existing daemon/effect-plane packaging. The
canonical `ag-loopctl` governed-loop deployment companion is
[`governed-loop-deployment-qualification.md`](governed-loop-deployment-qualification.md);
neither surface may be used as an alternate authority-bearing path for the
other.

AG-ng is a single-host, systemd-managed authority service. Installation and
production enrollment are separate operations: the package may place binaries,
units, examples, users, and empty directories, but it must not create an
authority domain, choose an epoch, enroll a principal, initialize a database,
admit a target, install a secret, enable a service, or start a daemon.

The current implementation is not yet releasable. Use this document to review
the intended host shape together with `release-checklist.md`, not as permission
to deploy it over a governed host.

## Host and file custody

The production baseline is Linux 6.1 or newer with systemd 252 or newer. A
catalog containing a managed-pointer target additionally requires the running
kernel to report Landlock ABI 3 or newer; the version number alone is not
treated as proof of a distribution backport. The
supported package targets are Debian 12 and Ubuntu 24.04 on amd64 and arm64.
SELinux/AppArmor policy, filesystem features, cgroup v2 delegation, and D-Bus
policy still require a host-specific preflight.

Managed-pointer enrollment and activation, together with the relevant
development-only worker-launch paths, also have four exact host prerequisites
which are not satisfiable through Debian package dependencies. They are
mandatory operator preflight inputs, not optional fallbacks:

- `/dev/null` must be a nonsymlink character device with device number `1:3`,
  owner `root:root`, one link, and mode `0666`;
- the filesystem containing the pinned `/usr/bin/git` must support descriptor
  queries for the `security.capability` extended attribute, and an absent
  attribute must be reported as `ENODATA` (an unsupported query is refusal,
  not evidence that the capability is absent);
- the kernel and active LSM policy must permit creation, sealing, and execution
  of executable memfds through `/proc/self/fd/N`; and
- procfs must be mounted so the effective service sandbox can read
  `/proc/self/exe`, `/proc/self/status`, `/proc/self/cgroup`, and
  `/proc/self/mountinfo`.

The daemon and genesis tooling check these properties through their real
descriptor-bound paths. A missing property is a typed startup, measurement, or
readiness refusal; an operator must not replace it with a copied helper,
unsealed executable, guessed process identity, or manually transcribed
measurement.

Live configuration belongs in `/etc/agent-governor` and is created by an
operator from measured enrollment data:

| File | Owner and mode | Purpose |
| --- | --- | --- |
| `agctl.toml` | `root:ag-admin 0640` | effect-admin signer and effectd enrollment only |
| `agctl-proposer.toml` | `root:ENROLLED_PROPOSER 0640` | proposer signer and agd enrollment only |
| `agd.toml` | `root:ag-governor 0640` | governor/store/peer limits |
| `providerd.toml` | `root:ag-provider 0640` | closed endpoints and caller identity |
| `effectd.toml` | `root:root 0600` | effect peers and target catalog |

The three daemon files carry the same canonical authority-domain identifier
and nonzero epoch. Each CLI file is a tagged, single-plane profile: the strict
schema rejects an `agd` peer in the effect-admin profile and an effectd peer in
the proposer profile. The two CLI files must use separately held keys and
service identities. The packaged examples are syntactically valid but contain
conspicuous fake digests and site IDs; copying them unchanged is a deployment
failure.

Resolve dynamic service IDs with `getent passwd`/`getent group` only after
`systemd-sysusers` has run. Numeric UID/GID values are live observations. An
enrolled Ed25519 RPC key establishes the stable local peer; authority domain,
epoch, stable enrollment root, signed nonce/challenge/audience/direction, and
freshness bind its principal chain. Exact executable digest, cgroup, UID/GID,
PID/start time, and boot facts are defense in depth. Group membership alone
never establishes identity.

`/var/lib/agent-governor` is `0711 root:root`: service users may traverse to
their named component root but cannot list the parent. Component roots and
object stores are `0700` under their owning daemon (`effectd` remains root),
and the backup root is `0700 root:root`. A common `0750 root:ag-admin` parent
would strand both unprivileged daemons and is not an admitted layout.

Each daemon configuration repeats the enrolled numeric UID, GID, and exact
mode for its database parent, object root, database, writer lock, socket
parent, and final socket node. These values are resolved after sysusers and
tmpfiles setup; the daemon never substitutes its effective IDs or umask as a
default. Startup requires every ancestor to be an absolute, normalized,
non-symlink path, requires pre-created state/socket directories to match the
configured custody, and verifies database/lock/socket metadata again after
creation. Startup logs say `listening`; authenticated health remains the only
application-level readiness claim.

On first daemon open, the store atomically enrolls its authority domain,
epoch, digest of the exact descriptor-read configuration, security profile,
and a build identity containing the bytes and size of `/proc/self/exe` actually
running. Enrollment is allowed only through an opaque, retained-descriptor
token proving that startup exclusively created that exact empty database
inode. A pre-existing empty file, unrelated SQLite database, replaced inode,
or legacy/unactivated AG store is never enrolled online. Effectd additionally
binds the compiler catalog identity produced by the same normalization and
pinned-helper-byte verification used by broker startup. Every later daemon
open must reproduce the complete activation identity before claiming the
writer fence. With its durable activation record intact, a generic store
opener cannot open an activated daemon store. This is deliberately fail-closed
across binary, configuration, profile, catalog, or epoch changes; the offline
upgrade/rotation ceremony needed to authorize such a transition is not
implemented yet.
The executable digest does not attest dynamically loaded system libraries;
the qualified distribution package set and its loader/library state remain
part of the host TCB and supply-chain gates.

## Socket membrane

Run `systemd-tmpfiles --create agent-governor-ng.conf` after creating service
users and before starting daemons. Expected socket nodes after each daemon has
bound are:

| Socket | Expected ownership/mode | Accepted role |
| --- | --- | --- |
| `agd/control.sock` | `ag-governor:ag-users 0660` | exact enrolled proposer peer |
| `effectd/proposal/proposal.sock` | `root:ag-governor 0660` | exact `agd` identity |
| `effectd/admin/admin.sock` | `root:ag-admin 0660` | exact inspection/ratifier peer |
| `providerd/provider.sock` | `ag-provider:ag-governor 0660` | exact configured provider caller |

The effectd parent directory is traversal-only. `agd` can reach proposal bytes
but cannot reach inspection/ratification. An operator sees and ratifies the
canonical bytes directly on effectd's admin socket; an agd projection is never
a ratification input.

Production daemon listeners use signed transport and additionally require the
exact configured `SO_PEERCRED` UID/GID. The kernel credential is a fail-closed
lifecycle fence, never the stable identity and never a replacement for the
enrolled Ed25519 signature. They do not open a peer's `/proc` entries. Do not
restore the legacy process-observation path or grant
`CAP_SYS_PTRACE`—not even to effectd, because ptrace would be a second generic
effect surface.

The effect-admin CLI is run in a fixed-name, short-lived operator service so
its signing key exists only in a systemd credential mount. A site-owned wrapper
may make this ergonomic, but it must preserve the exact properties. A
representative effect-plane invocation is:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --unit=agctl-operator --service-type=exec \
  --uid=ENROLLED_OPERATOR --gid=ENROLLED_OPERATOR \
  --property=SupplementaryGroups=ag-admin \
  --property=LoadCredentialEncrypted=rpc-ed25519-pkcs8:/etc/credstore.encrypted/agctl-operator-rpc-ed25519-pkcs8.cred \
  --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
  --property=PrivateDevices=yes --property=PrivateNetwork=yes \
  --property=PrivateTmp=yes --property=ProtectHome=yes \
  --property=ProtectProc=invisible --property=ProtectSystem=strict \
  --property=RestrictAddressFamilies=AF_UNIX \
  /usr/bin/agctl --config /etc/agent-governor/agctl.toml \
  effect show sha256:0000000000000000000000000000000000000000000000000000000000000000
```

`--collect` releases the fixed unit name after the command; concurrent operator
commands fail instead of sharing a credential context. The same effect-admin
unit may run `effect show`, `effect record`, `effect list`, `effect ratify`,
`effect reconcile-draft`, `effect reconcile`, and `health ag-effectd`; its
profile cannot address `agd`. A reconciliation invocation additionally admits
exactly one evidence file into the transient unit with `BindReadOnlyPaths=` and
passes it as `effect reconcile --evidence /admitted/path/evidence.json`. There
is no standard-input or receipt-digest shortcut.

Intent submission uses a distinct fixed unit, OS identity, credential, and
single-plane configuration. For example, after admitting the exact input path
to the unit's read-only filesystem view:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --unit=ag-proposer --service-type=exec \
  --uid=ENROLLED_PROPOSER --gid=ENROLLED_PROPOSER \
  --property=SupplementaryGroups=ag-users \
  --property=LoadCredentialEncrypted=rpc-ed25519-pkcs8:/etc/credstore.encrypted/ag-proposer-rpc-ed25519-pkcs8.cred \
  --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
  --property=PrivateDevices=yes --property=PrivateNetwork=yes \
  --property=PrivateTmp=yes --property=ProtectHome=yes \
  --property=ProtectProc=invisible --property=ProtectSystem=strict \
  --property=RestrictAddressFamilies=AF_UNIX \
  --property=BindReadOnlyPaths=/srv/agent-governor/intents/change.json \
  /usr/bin/agctl --config /etc/agent-governor/agctl-proposer.toml \
  intent submit --file /srv/agent-governor/intents/change.json
```

Never use one enrolled unit identity for both profiles, enroll one signing key
on both daemon listeners, or invoke `agctl` with a persistent plaintext
private-key path. Direct effect commands connect only to effectd's admin
socket; proposer commands connect only to agd.

## Effect catalog and sandbox

Effectd accepts only opaque target IDs from `ProposalIntentV1`. Root-owned
configuration resolves an ID to one closed target definition. For a managed
pointer, “pinned helper” means the digest of exact Git executable bytes plus
the digest of the built-in fixed operation, argv, environment, descriptor, and
security-profile contract—not a pathname or an operator-supplied command.

The code-enforced managed-pointer target also names one normalized
repository strictly beneath an allowed root, one exact `refs/heads/` ref, the
repository identity, expected non-root owner UID/GID, a broker-controlled
staging root outside the allowed target root, a bounded promotion lifetime,
and the pinned Git identities. The candidate semantic is exactly
`git_bundle_promotion_v1`. The candidate itself is a strict, self-contained Git
bundle v2 with one `refs/heads/ag-candidate`, no prerequisites, one commit whose
sole parent is the live base, and no gitlinks. The target repository is not
selected from candidate bytes.

Effectd config schema v2 also requires
`activation_genesis_object`, `activation_genesis_tree`, and
`activation_genesis_state` for each managed pointer. They are reviewed
enrollment facts for the exact loose ref before the authority store has any
successful history; they are never populated by “latest,” directory order, or
daemon startup observation. The state value is the digest of AG's
descriptor-derived repository-state evidence, not the object ID repeated in a
different field. The packaged offline `agctl managed-pointer` ceremony now
measures, independently remeasures, and emits the complete final effectd config
plus its exact target-derived unit drop-in and non-authorizing receipt. It
requires an absent database and empty object store and never selects “latest”
or silently edits an activated config. See
`clean-host-activation-qualification.md`. Schema v1 and records unable to prove
the new bindings fail closed.

Effectd stages and inspects the bundle outside the governed repository, then
compiles canonical bytes that bind the exact artifact and pack, base commit and
tree, candidate commit and post-tree, target ref, repository and Git-directory
device/inode observations, repository identity and owner, activation/catalog/
profile identities, exact Git executable/launch profile, expiry, and a
proposal-scoped single-use operation ID. An independently authenticated human
ratifier sees and ratifies those effectd-owned bytes on the admin socket. The
ratifier is necessarily absent from the proposal it has not yet ratified; the
signed authorization, durable burn, and one-shot attempt bind the exact
proposal to the broker-reconstructed independent ratifier principal before
preparation begins.

After durable authority burn, effectd performs reversible preparation: the
closed adapter re-opens and revalidates the target, drops the Git subprocess to
the configured target owner, imports and durably syncs the exact staged pack as
unreachable objects, and proves the managed ref remains at the exact prestate.
Effectd then persists a commit-may-proceed checkpoint, after which the adapter
compare-and-swaps only the configured ref. It clears and rebuilds the
environment, bypasses implicit `PATH`, isolates
Git configuration, disables hooks and interactive helpers, and disables Git
protocols. It issues success only after independently reading back the exact
post-ref and tree. Ambiguity at the commit boundary requires reconciliation;
it is never converted into success or a safe automatic retry. Reconciliation
distinguishes exact prestate, exact poststate, and foreign state.

Git is executed from a sealed exact-byte descriptor. In the child,
`close_range(CLOEXEC)` first closes the ambient inheritance channel and only
reviewed descriptors are re-admitted. Candidate PACK stdin is read-only.
Command-bearing repository filters and config indirection refuse enrollment;
hooks, external diff/text conversion, helpers, reflogs, and protocols are
disabled. Landlock ABI 3 mediates handled write/truncate/create/remove/rename
rights: quarantine operations receive the exact stage root, target import the
exact `objects/pack` directory, and ref CAS the exact Git directory (needed for
Git's possible `HEAD.lock` transaction). This prevents redirected writes into
another target for the handled rights; it does not turn Landlock into proof
about unmediated metadata syscalls or remove the pinned Git and dynamic-loader
package set from the host TCB.

Version 1 supports one existing, descriptor-validated loose ref in a bare
repository or a managed ref not checked out in any attached worktree. A target
available only through `packed-refs`, a dirty non-bare repository, or a
checked-out target ref refuses. Promotion does not update an index or working
tree and there is no hidden checkout synchronization or direct-checkout
compatibility mode. A site that needs a live checkout must perform that
synchronization through a future, separately specified governed effect; it
must not point this effect at the live branch and assume Git will update files.

Every configured repository, staging root, managed-file parent, broker state
root, and socket parent appears exactly in effective `ReadWritePaths=`.
Effectd requires exact equality between the effective unit's `ReadWritePaths`
property and that closed set before readiness, and refuses optional, missing,
extra, or broad entries. It separately proves every required root writable in
the current namespace and the protected `/usr`, `/boot`, `/etc`, and `/srv`
roots read-only; this is not a claim that Linux exposes no other writable API
or private temporary mounts. Do not grant a common parent such as `/etc`,
`/srv`, or `/var/lib` merely to make enrollment convenient. Unit actions are
escaped exact systemd unit names with a closed action list.

The base effectd unit is networkless and has no shell or generic command
surface. A target drop-in may add only exact target-derived filesystem paths
and, for managed pointers, the exact `CAP_SETUID`/`CAP_SETGID` delta documented
below. It must not add an IP address family, network namespace access, shell,
interpreter, any other capability, or writable executable search path.

The checked-in base unit grants the exact four capabilities used by a
managed-file-only catalog. A managed-pointer deployment installs a root-owned
drop-in which resets the bound and adds exactly `CAP_SETUID` and `CAP_SETGID`
so the fixed Git child can enter the configured non-root target owner. Fresh
in-process activation checks permitted, effective and bounding masks, empty
inheritable/ambient masks, empty supplementary groups, `NoNewPrivileges`, the
effective unit contract, current mount exceptions, helper bytes/profile,
staging custody, repository identity/owner/ref, and a harmless target-owner Git
observation. Missing or excess privilege refuses readiness. This closes the
code-level activation gate, not the host/Git/filesystem or power-loss
qualification matrix. The packaged unit permits the three Landlock syscalls,
but live readiness does not yet compare systemd's expanded
`SystemCallFilter=` set; exact host parity is a release qualification gap.

## Provider credentials and custody

Every daemon has a distinct Ed25519 PKCS#8 v2 signing key sealed with
`systemd-creds` into a host/TPM-bound file under `/etc/credstore.encrypted`.
The base unit maps it to the exact `private_key_credential` path in TOML. The
configured leaf principal, public key, and key ID must match; a substituted
credential prevents readiness. Plaintext key files are destroyed after
enrollment and never enter a backup bundle.

The enrollment pipeline must produce Ed25519 PKCS#8 v2 bytes accepted by the
installed build and independently derive the public-key enrollment. Seal each
distinct key with `systemd-creds encrypt`, using the credential name
`rpc-ed25519-pkcs8` and a reviewed `--with-key=host+tpm2` (or
recovery-compatible) policy, into the exact encrypted source named by its unit.
Do not reuse one signing key across
agd, effectd, providerd, or an operator. A packaged generation/rotation command
does not exist yet and is a release gate; ad hoc key conversion is not an
enrollment procedure.

Every provider endpoint selects exactly one tagged transport/authentication
variant in root-owned policy:

- `credentialed_https_api` requires an exact HTTPS URL, a protected
  credential filename, and one closed credential header. Credentials are not
  optional for this variant.
- `local_http` requires an exact cleartext HTTP URL, an operator-owned origin
  allowlist containing that URL's origin, and `redirect_policy = "deny"`.
  Providerd never follows a redirect, so a local endpoint cannot redirect a
  request to an unenrolled origin.
- `command` requires one absolute executable, fixed working directory,
  closed environment, and a built-in `codex`, `claude-code`, or `kimi-code`
  structured-argument adapter. Provider request bytes can supply only the
  already capability-bound model and prompt; they cannot supply argv or a
  shell command.

The endpoint ID, protocol adapter, and method/model set remain closed for all
variants. Install an HTTPS API secret outside the repository and map it with a
root-owned unit drop-in:

```ini
[Service]
LoadCredentialEncrypted=provider-api-key:/etc/credstore.encrypted/provider-api-key.cred
```

The encrypted source is root-custodied; decrypted bytes exist only in the
service credential mount. The secret never appears in TOML, an environment
variable, argv, logs, SQLite, or an audit export. Providerd may use the secret
and network, but it owns no governed-effect authority and cannot authorize AG
effects. It may retain bounded provider-access capability, usage,
dispatch/custody, lifecycle, and revocation state; it holds no governed-effect
standing, ratification, effect, or target state.

Providerd opens the credential directory and named credential with bounded
descriptor traversal. It uses `openat2` with beneath/no-symlink resolution
when admitted. If a service sandbox returns `ENOSYS` for `openat2`, as
`RestrictSUIDSGID=yes` does so creation modes remain seccomp-inspectable, it
falls back to one normalized, no-follow `openat` per component. The fallback
rejects empty, absolute, dot, parent, and symlink components and keeps every
ancestor anchored by its opened descriptor. The reader accepts only a
single-link regular file owned by root or its own effective UID. Group/other
permissions, empty or non-UTF-8 content, a read race, and content above 64 KiB
all fail closed.

Credentialless local HTTP and command routes never load the provider credential
directory. Command-provider authentication is the enrolled executable's
separately mounted login state; its child environment is cleared before the
closed root-owned environment is installed. Output and diagnostics are drained
without unbounded retention. Timeout or ambiguous pipe/wait failure kills and
reaps the process group but remains operationally indeterminate: cleanup does
not prove that provider execution or billing did not occur.

Before acknowledging a provider result, the complete credential-free request,
sanitized transport headers, and complete response event stream must have
crossed into agd custody. Digest-only custody is explicitly weaker and cannot
support exact replay evidence. Exact custody and provider-protocol terminality
establish neither semantic truth nor testimonial sufficiency, proposal
admission, effect authority, or execution success. Providerd deletes plaintext
after confirmed delivery and burns the peer/session-bound capability when the
session ends.

The provider socket enrolls one exact signed daemon or fixed-service proxy
identity. Dynamic workers and humans remain inadmissible. Every dispatch is
bound to the authenticated caller, capability, provider/model/method/protocol,
exact request custody, and root policy digest.
Provider inference is therefore a release blocker; do not substitute “request
came from agd” for the missing worker/session/peer relation or expose the
provider socket directly to a group.

## Workers and admitted checks

The current implementation has one development-only offline worker path. A
root-owned `agd` configuration defines a closed profile ID, exact executable
bytes, fixed argv, semantic type, candidate effect family and target mapping,
runtime limit, and output budget. The candidate may be managed-file content or
the exact managed-pointer Git bundle described above; the caller and worker
cannot switch the configured family or target. The caller selects the profile
ID only. `agd` creates an independent proposal workspace, durably mints the bound
`WorkerSessionPrincipal`, and launches the executable under Bubblewrap with an
empty ambient environment, a private network namespace, read-only `/usr`, and
the proposal workspace as its only writable host-filesystem bind. There is no
shell string, implicit `PATH`, worker-selected executable or target,
governed-target working directory, PTY, or provider route.

The development catalog is deliberately single-worker: configuration requires
`max_active_sessions = 1`, and `agd` refuses another launch or an external
proposal submission while that worker is live. This is a deadline-isolation
fence, not a claim of multi-worker scheduling. The worker executable must be a
native ELF image; shebang/startup scripts and implicit interpreter lookup are
rejected. Exact retained-descriptor bytes, inode metadata, and launch profile
are rechecked immediately before spawn.

The only per-session credential delivered to the worker is its ephemeral
candidate-ingress signing key and public bootstrap. That key is bound to the
session, workspace, launcher lineage, expiry, budget, and activation context;
it conveys no authority to create canonical proposals, ratify, admit, or
execute an effect. Candidate output is accepted only through the authenticated
protocol and then mapped from durable reviewed state. Effectd—not the worker
and not a worker-supplied record—compiles and persists canonical proposal
bytes. Exit, timeout, cancellation, budget failure, and restart recovery leave
a durable terminal tombstone; inspection cannot silently recreate authority.
Cleanup is marked complete only after confirmed process reaping. The governor
challenge enrollment and skew policy travel in the authenticated ingress proof
and must exactly match effectd's enrolled `agd` policy; a worker profile cannot
outlive that window. Candidate bytes are transferred to effectd once, inside
the proof, and all three broker terminal outcomes are recorded durably.

This path is enabled only by `security_profile = "development"`.
Configuration validation rejects it in `production` and `high_assurance`.
The packaged `agd.service` also has `RestrictNamespaces=yes`, so it
intentionally cannot host this in-process Bubblewrap launcher. Do not weaken
that unit to make the development path run and do not interpret a manual
development launch as systemd, cgroup, LSM, or distribution qualification.

The source-side `ag-worker@.service` remains the intended production-shaped
DynamicUser design, but it is withheld from packages until a separately
attested wrapper and root-owned one-shot launch-record protocol exist. The
`ag-check@.service` design is likewise withheld: admitted check launch is not
implemented by this slice. Future wrappers must resolve one opaque instance,
reject replay, verify exact executable and launch-profile bytes, pass only
declared helper descriptors, and close every unintended inherited descriptor.

## Startup and observability

Services are disabled on pristine installation. Package bookkeeping preserves
an administrator's prior enable state across reinstall/upgrade, while package
transactions do not start the services. After configuration validation and the entire
release checklist succeed, start effectd and providerd before agd. Current
units use `Type=exec`: systemd activation means only that the daemon executable
was entered. Effectd constructs fresh non-serializable activation standing
before reporting authenticated health ready; a prior doctor or activation
receipt cannot recreate it. The remaining daemons still have their narrower
authenticated health contracts, and no unit implements `sd_notify` or watchdog
heartbeats.

Logs go only to journald. Set retention, forwarding, sealing, rate limits, and
disk quotas in host journal policy. Audit exports are protocol artifacts, not a
replacement for journal transport diagnostics; the journal is not an authority
store.

Removal disables no effects and deletes no state automatically. Preserve all
three stores, object roots, configuration, credential enrollment, effective
unit definitions, and the last coherent backup receipt until an explicit,
audited decommission procedure completes.
