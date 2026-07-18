# Classic AG replacement and retirement ledger

`ag-migrate` makes the M8 rule executable: an inventoried classic surface is
exactly `replaced`, `retired`, or `blocked`. There is no `compatible`,
`deferred`, fallback, import, or mixed-runtime state.

The initial ledger is intentionally **not** a whole-classic parity claim. Its
machine-bound scope is `classic.authority-critical-runtime.v1` with
`partial_authority_critical` completeness. It inventories thirteen source-
substantiated entry, runtime, receipt, and store surfaces from classic commit
`5d7089b1fd26510adddab808a7322e8ada4bf8bd`. One is evidenced as replaced, six
are deliberately retired, and six remain explicitly blocked with objective
exit criteria. Expanding the claim requires expanding both the source manifest
and inventory; merely adding a disposition is rejected.

## Verify the ledger

From the repository root:

```console
cargo run --locked --offline -p ag-migrate -- \
  ledger \
  --ledger migration/classic-authority-ledger.v1.json \
  --evidence-root .
```

The verifier requires exact canonical JSON payloads (a single POSIX terminal
line feed is permitted), rejects duplicate keys, floats, unknown fields,
trailing data, duplicate IDs, missing or extra dispositions, path traversal,
and any claim that classic bytes are AG-ng runtime authority. A replacement
must bind an AG-ng schema and exact passed test receipt. A retirement must bind
a rationale and exact hostile absence specimen. A blocker must have a stable
code and concrete exit criterion.

The shipped evidence files are:

- `migration/classic-authority-ledger.v1.json` — closed-world disposition
  ledger for the declared scope;
- `migration/classic-authority-source.manifest.v1.json` — exact classic source
  file digest/length inventory;
- `migration/receipts/ag-kernel-authority-replacement.v1.json` — passed test
  receipt for the currently replaced authority-decision surface;
- `migration/specimens/classic-runtime-authority-forbidden.v1.json` — hostile
  claim that every retirement must reject.

## Verify a frozen classic archive

Place the ten files named by the source manifest under a read-only archive root,
preserving relative paths, then run:

```console
cargo run --locked --offline -p ag-migrate -- \
  archive \
  --manifest migration/classic-authority-source.manifest.v1.json \
  --archive-root /srv/archive/agent-gov-5d7089b1
```

The reader opens the root and every listed file with no-follow descriptor
semantics, rejects traversal, symlinks, non-regular files, hard links, size and
digest drift, read races, duplicate paths, and fixed file/aggregate limit
exhaustion. It reads databases as opaque bytes. It never opens SQLite, decodes
classic receipts, starts Python, reconstructs an authority book, or returns
classic content to a daemon.

## Current disposition summary

| Disposition | Surfaces |
| --- | --- |
| Replaced | classic authority-role gate receipt semantics, by separated AG-ng effect judgment/authority reconstruction |
| Retired | fiction/nonfiction/ops CLI entry points; gate-receipt and receipt-v1 JSONL as live authority; receipt-kernel SQLite as live state |
| Blocked | primary governor CLI, daemon RPC inventory, plan approval, operational promotion, session supervisor, workspace promotion |

The ledger is the normative detail. This summary is explanatory and cannot
widen its scope.
