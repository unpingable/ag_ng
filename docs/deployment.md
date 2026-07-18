# Deployment contract

AG-ng is a single-host, systemd-managed authority service. Installation and
production enrollment are separate operations: the package may place binaries,
units, examples, users, and empty directories, but it must not create an
authority domain, choose an epoch, enroll a principal, initialize a database,
admit a target, install a secret, enable a service, or start a daemon.

The current implementation is not yet releasable. Use this document to review
the intended host shape together with `release-checklist.md`, not as permission
to deploy it over a governed host.

## Host and file custody

The production baseline is Linux 6.1 or newer with systemd 252 or newer. The
supported package targets are Debian 12 and Ubuntu 24.04 on amd64 and arm64.
SELinux/AppArmor policy, filesystem features, cgroup v2 delegation, and D-Bus
policy still require a host-specific preflight.

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
pointer, “pinned helper” means the digest of exact executable bytes plus the
digest of its fixed argv, environment, descriptor, namespace, resource, and
seccomp launch profile—not a pathname.

Every configured repository or managed-file parent also appears in an
effectd unit drop-in as `ReadWritePaths=`. Before readiness, effectd must compare
the effective unit sandbox with its target catalog and refuse any mismatch.
Do not grant a common parent such as `/etc`, `/srv`, or `/var/lib` merely to
make enrollment convenient. Unit actions are escaped exact systemd unit names
with a closed action list.

The base effectd unit is networkless and has no shell or generic command
surface. A target drop-in may add filesystem access only; it must not add an IP
address family, network namespace access, shell, interpreter, broad capability,
or writable executable search path.

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

Each provider endpoint is an exact HTTPS URL, endpoint ID, protocol adapter,
closed method/model set, credential header/prefix, and systemd credential
filename. Install the API secret outside the repository and map it with a
root-owned unit drop-in:

```ini
[Service]
LoadCredentialEncrypted=provider-api-key:/etc/credstore.encrypted/provider-api-key.cred
```

The encrypted source is root-custodied; decrypted bytes exist only in the
service credential mount. The secret never appears in TOML, an environment
variable, argv, logs, SQLite, or an audit export. Providerd may use the secret
and network but holds no standing, ratification, effect, or target state.

Providerd opens the credential directory and named credential with bounded
`openat2` descriptor traversal, rejects symlinks and traversal, and reads a
single-link regular file only from root or its own effective UID. Group/other
permissions, empty or non-UTF-8 content, a read race, and content above 64 KiB
all fail closed.

Before acknowledging a provider result, the complete credential-free request,
sanitized transport headers, and complete response event stream must have
crossed into agd custody. Digest-only custody is explicitly weaker and cannot
support exact replay evidence. Providerd deletes plaintext after confirmed
delivery and burns the peer/session-bound capability when the session ends.

The current v1 provider socket enrolls only agd's signed proxy identity. The
session ingress/proxy path does not yet prove the live
`WorkerSessionPrincipal` before spending its committed provider capability.
Provider inference is therefore a release blocker; do not substitute “request
came from agd” for the missing worker/session/peer relation or expose the
provider socket directly to a group.

## Workers and admitted checks

Workers are one-shot, noninteractive systemd instances with `DynamicUser=yes`,
a private network namespace, no capabilities, no device access, a closed system
call envelope, bounded time/tasks/memory/CPU, and an independent repository or
snapshot. There is no PTY, pause/resume, arbitrary input, linked worktree,
governed target mount, or direct checkout synchronization.

The worker/check templates are source artifacts only until their Rust wrappers
and root-owned launch-record protocol exist. When admitted, each wrapper must
receive a single opaque instance identifier, resolve it once, reject replay,
verify exact executable and launch-profile bytes, pass only declared helper
descriptors, and close every unintended inherited descriptor.

## Startup and observability

Services are installed disabled. After configuration validation and the entire
release checklist succeed, start effectd and providerd before agd. Current
units use `Type=exec`: systemd activation means only that the daemon executable
was entered. It does not mean the database, backup fence, peer policies, target
catalog, or sockets are ready. Production release requires an authenticated
readiness probe or a correctly implemented `sd_notify` contract.

Logs go only to journald. Set retention, forwarding, sealing, rate limits, and
disk quotas in host journal policy. Audit exports are protocol artifacts, not a
replacement for journal transport diagnostics; the journal is not an authority
store.

Removal disables no effects and deletes no state automatically. Preserve all
three stores, object roots, configuration, credential enrollment, effective
unit definitions, and the last coherent backup receipt until an explicit,
audited decommission procedure completes.
