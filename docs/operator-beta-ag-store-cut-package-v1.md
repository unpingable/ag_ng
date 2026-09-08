# Operator-beta AG store-cut package V1

Status: **PACKAGE CANDIDATE / INDEPENDENT REVIEW REQUIRED**

This bounded checkpoint packages the independently accepted AG-ng owner subject
`837de287497942c79966aa05c083acee9c312261` so NQ-ng can later invoke the
read-only `ag-effectd audit-store` interface without copying AG receipt or
evidence semantics into its controller.

The package remains the existing inert
`agent-governor-ng-systemd-executor` family. Version
`0.1.0-1+m1a4` contains exactly one feature-enabled executable at
`/usr/libexec/agent-governor-ng/ag-effectd`. It installs no service, unit,
configuration, authority state, target definition, mutable store, or
maintainer script. The default featureless `/usr/bin/ag-effectd` package is
unchanged.

## Exact candidate custody

- accepted owner subject: `837de287497942c79966aa05c083acee9c312261`;
- accepted owner tree: `20023de0b8299fa125ed5f9fcaf63383a4978e30`;
- source timestamp / `SOURCE_DATE_EPOCH`: `1788830784`;
- package version: `0.1.0-1+m1a4`;
- archive length: `2649438` bytes;
- archive SHA-256:
  `98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279`;
- executable length: `8489480` bytes;
- executable SHA-256:
  `668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068`.

The campaign-owned archive and staging tree are retained under
`.campaign-local/operator-beta-store-audit/package-001/`. They are evidence,
not a live installation or deployment source of authority.

## Qualification boundary

The package test must reopen the archive rather than trust the staging tree. It
checks the closed control fields, exact root-owned `0755` directory and binary
inventory, absence of control scripts, exact embedded executable bytes, and
the executable's `audit-store` argument surface. A second archive assembled
from the retained stage at the same source epoch must be byte-identical.

The package gate also replays the accepted AG owner store-cut gate and its
query-only functional CLI cases. It does not install the archive, contact a
guest, call D-Bus, run systemd mechanics, reopen an NQ run, or qualify the
future two-VM composition.

## Next lawful transition

Independent review must accept this exact package checkpoint. Only then may
NQ-ng pin the exact archive and executable identities, retain a stable copied
AG store cut, and call the AG-owned `audit-store` interface during M1B
recovery/terminal verification. Acceptance does not publish, install, deploy,
or authorize an effect.
