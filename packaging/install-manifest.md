# Package install manifest

This table names the authority-relevant intended payload. Debhelper also adds
ordinary package metadata and lifecycle documentation; qualification compares
the complete built archive rather than treating this table as an exhaustive
`dpkg-query -L` oracle. Entries marked “withheld” are source-side designs and
must not enter a package until their named release gates pass.

| Source | Installed path | Mode/policy |
| --- | --- | --- |
| `target/release/agd` | `/usr/bin/agd` | `0755 root:root` |
| `target/release/ag-effectd` | `/usr/bin/ag-effectd` | `0755 root:root` |
| `target/release/ag-providerd` | `/usr/bin/ag-providerd` | `0755 root:root` |
| `target/release/agctl` | `/usr/bin/agctl` | `0755 root:root` |
| `target/release/ag-backup` | `/usr/bin/ag-backup` | `0755 root:root`, offline coherent-backup verifier/publisher only |
| `target/release/ag-migrate` | `/usr/bin/ag-migrate` | `0755 root:root`, offline classic retirement/archive verifier only |
| three daemon unit files | `/usr/lib/systemd/system/` | `0644 root:root`, disabled on pristine install; prior admin enablement is preserved |
| `sysusers.d/agent-governor-ng.conf` | `/usr/lib/sysusers.d/` | `0644 root:root` |
| `tmpfiles.d/agent-governor-ng.conf` | `/usr/lib/tmpfiles.d/` | `0644 root:root` |
| package-created local unit directory | `/etc/systemd/system/ag-effectd.service.d/` | `0755 root:root`; generated enrollment drop-in destination |
| selected `docs/*.md` listed by the package skeleton, `README.md` | `/usr/share/doc/agent-governor-ng/` | operator and campaign documentation |
| `packaging/systemd/README.md` | `/usr/share/doc/agent-governor-ng/systemd-deployment.md` | effective-unit deployment contract |
| `config/*.example.toml` | `/usr/share/doc/agent-governor-ng/examples/` | examples only |
| `migration/` | `/usr/share/doc/agent-governor-ng/migration/` | immutable-source manifest, partial disposition ledger, receipts, and hostile specimens |
| Debian copyright/changelog/`README.Debian` | `/usr/share/doc/agent-governor-ng/` | ordinary package metadata and installed-path guidance |

The package does **not** install `/etc/agent-governor/*.toml`, an RPC signing
key, provider credential, encrypted credential blob, target drop-in file, authority
domain, epoch, enrollment root, database, object, backup, managed target,
policy decision, ratification, or fresh-install service-enable state. The empty
package-owned drop-in directory is inert. Authority-bearing post-install setup
is limited to sysusers/tmpfiles creation; debhelper also performs systemd
manager and enable-state bookkeeping, and a host-root-only daemon reload
refreshes unit definitions without starting a service. Removal never
deletes `/var/lib/agent-governor` or operator-created enrollment/configuration
content.

`agctl` includes the offline root-only managed-pointer genesis ceremony. Its
request example is documentation, never an active enrollment. The package has
a runtime dependency on Git because the ceremony and effect broker both pin
and execute exact `/usr/bin/git` bytes; the enrolled digest still decides
whether those installed bytes are accepted.

Withheld from packages:

- `ag-worker@.service` until a production-attested one-shot worker wrapper
  exists; the development-only in-process Bubblewrap launcher does not use or
  qualify this unit;
- `ag-check@.service` until the separately owned verifier wrapper exists;
- any production worker/check helper binary until its exact-byte,
  launch-profile, and one-shot admission path is wired and qualified;
- compatibility aliases named `ag` or `governor` (permanently excluded);
- logrotate configuration because services emit only to journald.
