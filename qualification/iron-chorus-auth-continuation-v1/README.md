# IRON-CHORUS authorization-continuation qualification

Implementation pair:

- AG `625f1d8` on
  `campaign/iron-chorus-ag-codex-exact-occurrence-authorization-continuation-v1`
- Codex `6e21836d37` on the same branch name
- Docket contract `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` on
  `campaign/c2-governed-loop-layering`

Observed host-supported results:

- `cargo test -p ag-external-authz`: 41 passed across five test binaries
- `cargo test -p ag-campaign --test governed_loop`: 40 passed
- `cargo test -p ag-app --test governed_loop_engine`: 41 passed, one explicit
  corpus-writer fixture ignored
- `cargo test -p ag-app --test governed_docket_process`: one host-dependent
  adjacent-process case ignored by default
- the same Docket process case with exact pinned binaries and `--ignored`: one
  passed
- Docket executor-transport corpus: three checksums passed; AG conformance
  runner one passed
- `scripts/check-governed-loop-authority-surface.sh`: passed

The sealed `host-qualification-packet.v1.json` contains qualification cases
that require host capabilities or protected service custody. These commands
were not run here and must not be recorded as passing without the stated raw
evidence. A host that cannot create a user namespace or bubblewrap namespace
is `host_unsupported`, not a failed semantic substitute and not a reason to
weaken the authority boundary.

No production activation, protected approval, service mutation, or live
effect was performed. The adjacent-process test writes only to its temporary
local fixture and proves the already-existing AG/Docket/effectd seam.
