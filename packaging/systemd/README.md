# systemd deployment contract

These files are packaging inputs, not evidence that a host satisfies the
production contract. `agctl doctor` now checks strict daemon configuration,
enrolled store/socket custody, fixed effective unit properties, target-root
drop-ins, credential-unit bindings, and configured installed executable
digests. Kernel-feature attestation, socket ACL interpretation beyond enrolled
numeric custody, providerd self-executable enrollment, and the remaining gates
in `docs/release-checklist.md` are still absent, so the units remain a
reviewable deployment skeleton rather than a production-readiness claim.

## Socket custody

Daemon units deliberately do not use `RuntimeDirectory=`. That directive would
re-own a shared directory to the service's primary group and collapse the
proposal/admin separation. `systemd-tmpfiles` instead creates:

| Path | Mode and owner | Intended peer |
| --- | --- | --- |
| `/run/agent-governor/agd` | `2750 ag-governor:ag-users` | enrolled control caller |
| `/run/agent-governor/effectd` | `0711 root:root` | traversal only |
| `/run/agent-governor/effectd/proposal` | `2750 root:ag-governor` | `agd` only |
| `/run/agent-governor/effectd/admin` | `2750 root:ag-admin` | direct inspection/ratification |
| `/run/agent-governor/providerd` | `2750 ag-provider:ag-governor` | provider caller |

The SGID bit makes a socket created with mode `0660` inherit the directory's
peer group. Filesystem access is only the first gate; signed challenge/request/
response proofs bind the enrolled key, leaf principal, chain root, audience,
direction, nonce, timestamp, and exact canonical bytes. Every daemon listener
also requires the configured `SO_PEERCRED` UID/GID as a fail-closed lifecycle
fence; it never substitutes for the signature. In particular, `agd` cannot
traverse the effectd admin directory and an admin cannot submit intent through
the proposal policy.

Run `systemd-sysusers` before `systemd-tmpfiles --create`. Installed production
configuration is root-owned, not group/other writable, and uses the numeric
IDs resolved on that host. The example IDs and digests are placeholders.

## Readiness and process observation

The current daemons do not call `sd_notify` and do not emit watchdog
heartbeats. Their units therefore use `Type=exec` and have no `WatchdogSec=`.
This reports successful `execve`, not application readiness. Dependents and
operators must treat a successful authenticated socket probe as readiness once
such a probe exists.

The stable local-RPC identity is an enrolled Ed25519 key; service private keys
arrive through the base unit's encrypted `rpc-ed25519-pkcs8` credential. The
production listeners pair signed transport with the exact enrolled
`SO_PEERCRED` UID/GID; they never open the peer's `/proc` entries. Daemon units can therefore
use `ProtectProc=invisible` and `ProcSubset=pid`. The legacy process-observation
module remains test/bootstrap code and must not re-enter a production listener.
No unit receives `CAP_SYS_PTRACE`—not even effectd, because ptrace would be a
second generic effect surface.

## Effects, provider credentials, and workers

For every managed repository or file parent, install a root-owned effectd
drop-in such as:

```ini
[Service]
ReadWritePaths=/srv/agent-governor/repos/service.git
ReadWritePaths=/etc/example-service
```

Effectd must compare the effective sandbox to its target catalog before
production readiness. A config entry alone never grants a writable target.

Each base daemon unit maps a distinct host/TPM-bound blob from
`/etc/credstore.encrypted` to the runtime ID `rpc-ed25519-pkcs8`. Provider API
secrets arrive through additional `LoadCredentialEncrypted=` entries in a
root-owned local drop-in, with one runtime ID matching each configured
`credential_name`. Decrypted bytes exist only in the service credential mount;
they do not belong in TOML, environment variables, command lines, or unit
metadata.

Provider credential names are canonical single path components. Providerd
opens the credential mount and file through bounded no-symlink descriptors and
accepts only a protected, single-link regular file owned by root or the daemon
UID; group/other permissions and reads above 64 KiB are rejected.

The current generic-worker ingress is an in-process, offline Bubblewrap launch
inside `agd`, accepted only by the `development` security profile. It does not
use `ag-worker@.service`, and it is not a production deployment path. In
particular, the packaged `agd.service` has `RestrictNamespaces=yes`, which
intentionally prevents that development launcher from creating its namespaces.
Do not relax the packaged unit and then describe the result as qualified
containment.

`ag-worker@.service` and `ag-check@.service` remain source-side descriptions of
future dynamic, batch-only containment. They are not in the package install
manifest until their separately admitted wrappers exist. A production worker
wrapper must resolve `%i` through a root-owned one-shot launch record, pin exact
executable bytes and launch profile, pass only named file descriptors, close
all unintended descriptors, and make replay fail. Admitted check launch is not
implemented by the development worker slice.

All service output goes to journald. No file log is created, so installing a
logrotate policy would be misleading; journal retention is configured through
the host's `journald.conf` policy.
