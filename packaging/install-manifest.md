# Package install manifest

This is the intended binary package payload. The Debian skeleton enforces the
same list. Entries marked “withheld” are source-side designs and must not enter
a package until their named release gates pass.

| Source | Installed path | Mode/policy |
| --- | --- | --- |
| `target/release/agd` | `/usr/bin/agd` | `0755 root:root` |
| `target/release/ag-effectd` | `/usr/bin/ag-effectd` | `0755 root:root` |
| `target/release/ag-providerd` | `/usr/bin/ag-providerd` | `0755 root:root` |
| `target/release/agctl` | `/usr/bin/agctl` | `0755 root:root` |
| `target/release/ag-backup` | `/usr/bin/ag-backup` | `0755 root:root`, offline coherent-backup verifier/publisher only |
| `target/release/ag-migrate` | `/usr/bin/ag-migrate` | `0755 root:root`, offline classic retirement/archive verifier only |
| three daemon unit files | `/usr/lib/systemd/system/` | `0644 root:root`, disabled |
| `sysusers.d/agent-governor-ng.conf` | `/usr/lib/sysusers.d/` | `0644 root:root` |
| `tmpfiles.d/agent-governor-ng.conf` | `/usr/lib/tmpfiles.d/` | `0644 root:root` |
| selected `docs/*.md` listed by the package skeleton, `README.md` | `/usr/share/doc/agent-governor-ng/` | operator and campaign documentation |
| `config/*.example.toml` | `/usr/share/doc/agent-governor-ng/examples/` | examples only |
| `migration/` | `/usr/share/doc/agent-governor-ng/migration/` | immutable-source manifest, partial disposition ledger, receipts, and hostile specimens |

The package does **not** install `/etc/agent-governor/*.toml`, an RPC signing
key, provider credential, encrypted credential blob, target drop-in, authority
domain, epoch, enrollment root, database, object, backup, managed target,
policy decision, ratification, or service-enable state. Post-install runs only
sysusers/tmpfiles creation. Removal never deletes `/var/lib/agent-governor` or
operator-created enrollment/configuration content.

Withheld from packages:

- `ag-worker@.service` until a production-attested one-shot worker wrapper
  exists; the development-only in-process Bubblewrap launcher does not use or
  qualify this unit;
- `ag-check@.service` until the separately owned verifier wrapper exists;
- any production worker/check helper binary until its exact-byte,
  launch-profile, and one-shot admission path is wired and qualified;
- compatibility aliases named `ag` or `governor` (permanently excluded);
- logrotate configuration because services emit only to journald.
