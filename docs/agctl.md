# `agctl` role-separated control paths

`agctl` is a closed, mutually authenticated local client. It is not a shell,
plugin host, worker console, or generic effect launcher. One invocation loads
one root-owned role profile and one signing identity. The two profiles are
mutually exclusive:

- `proposer` contains only the `agd` socket/enrollment and authorizes `health
  agd` plus `intent submit`;
- `effect_admin` contains only the `ag-effectd` admin socket/enrollment and
  authorizes `health ag-effectd` plus the closed `effect` command family.

The tagged configuration schema rejects fields from the opposite plane, and
command dispatch rejects a role mismatch before loading a credential or
reading an intent file. The two private keys are delivered to distinct fixed,
hardened services (or equivalently constrained fixed-name transient units)
through `LoadCredentialEncrypted=`; neither key is stored in TOML.
`deployment.md` gives separate launch profiles.

`doctor` is the one deliberate exception to the single-role config flag. It
does not connect to an authority plane or load any private key. Instead it
requires all three public daemon configurations explicitly:

```text
agctl doctor \
  --agd-config /etc/agent-governor/agd.toml \
  --effectd-config /etc/agent-governor/effectd.toml \
  --providerd-config /etc/agent-governor/providerd.toml
```

Doctor strictly loads and validates the root-custodied files, checks their
domain/epoch and opposite-plane enrollments, then inspects the enrolled store
and socket nodes. It hashes installed `/usr/bin/agd` and
`/usr/bin/ag-effectd` bytes when an opposite-plane executable digest is
configured. Providerd has no self-executable enrollment in the current schema,
so no providerd byte check is fabricated.

Effective unit evidence comes from one environment-cleared, fixed invocation
of `/usr/bin/systemctl show`. Both the property names and unit arguments
(`agd.service`, `ag-effectd.service`, and `ag-providerd.service`) are compiled
in; no TOML or command-line value becomes a command surface. Doctor requires
the exact service user/group, `ExecStart`, network/address-family envelope, and
capability bound. It also requires every effectd managed-file parent to be
covered by effective `ReadWritePaths=` and rejects writable entries broader
than the enrolled state/target roots.

Standard output is one integer-only canonical JSON `ag.doctor-report/v1`.
Every check is `pass`, `fail`, or `unavailable`; missing or unparseable host
evidence is never promoted to a pass. The process exits nonzero unless every
emitted required check passes. Doctor is an operational diagnostic, not daemon
readiness: it does not change the deliberately conservative health responses.

The effect authority boundary is visible in the command routing:

- `agctl --config .../agctl-proposer.toml health agd` and `intent submit`
  terminate at `agd` under the proposer identity;
- `agctl --config .../agctl.toml health ag-effectd`, `effect show`, `effect
  record`, `effect list`, `effect ratify`, `effect reconcile-draft`, and
  `effect reconcile` terminate directly at `ag-effectd` under the independent
  effect-admin identity.

There is no governor projection of proposal bytes or ratification. Provider
health is not exposed to either CLI identity in v1: `ag-providerd` enrolls its
service caller separately, so adding a convenient CLI route would broaden
credential-proxy access.

## Exact inspection and ratification

```text
agctl --config /etc/agent-governor/agctl.toml effect show sha256:<digest>
agctl --config /etc/agent-governor/agctl.toml effect record sha256:<digest>
agctl --config /etc/agent-governor/agctl.toml effect ratify sha256:<digest> \
  --challenge <challenge-from-show>
```

`effect show` verifies that the returned object recomputes to the requested
digest. Standard output is exactly the broker-owned proposal encoded as JCS,
followed by one line feed, so redirecting it produces a proposal export. The
one-time, peer-bound challenge is printed separately on standard error. A
ratification command always requires that challenge explicitly; inspection
and ratification are never collapsed into one action.

`effect record` is a separate read-only operational view. It returns the
strict `ag.effect-record/v1` projection directly from effectd: the canonical
proposal, durable lifecycle state, accepted authorization when present,
terminal and ordered step receipts, execution attempt, and full reconciliation
record when present. Effectd validates all entity, canonical, lifecycle,
authorization, attempt, terminal-receipt, and reconciliation bindings before
returning it. The response contains no store revision, event query, arbitrary
JSON, or challenge and cannot be ratified in place.

All successful machine-readable output is integer-only canonical JSON. Daemon
errors, authentication failures, and terminal-safe diagnostics go to standard
error with a non-zero exit status. Intent and reconciliation-evidence inputs
must be bounded regular files; symlinks, duplicate keys, unknown fields,
floats, trailing JSON, and oversized documents fail before a signed request is
sent. Standard input is not an input mode. `agd` reconstructs the caller's
principal chain from its root-owned proposer enrollment and requires the
intent's proposer/domain/epoch to match it exactly; editing proposer bytes in
the input file cannot select another identity.

## Exact reconciliation evidence

Reconciliation does not accept a proposal digest plus an operator-invented
receipt digest. The operator supplies the complete strict
`ReconciliationEvidenceV1` document:

```text
agctl --config /etc/agent-governor/agctl.toml effect reconcile-draft \
  sha256:<digest> \
  > /run/agent-governor/reconciliation/evidence.json

agctl --config /etc/agent-governor/agctl.toml effect reconcile \
  --evidence /run/agent-governor/reconciliation/evidence.json
```

`effect reconcile-draft` is permitted only while the exact proposal is in
`reconciliation_required`. Effectd first validates its complete durable record,
then freshly observes the path or target embedded in the canonical effect and
derives the closed `applied` or `not_applied` classification. Standard output
is the complete strict evidence object, including the broker-custodied
uncertainty envelope, attempt, and ordered step receipts. Creating this draft
does not mutate broker state, consume a challenge, or submit reconciliation;
an independent operator must review and send it with the separately signed
`effect reconcile` command. Effectd observes and classifies the target again
when accepting that submission, so a stale draft fails closed.

The document binds the proposal, one-shot execution attempt, uncertainty
envelope, ordered broker step receipts, observed target poststate, and the
operator's closed `applied` or `not_applied` classification. The CLI opens that
one path with no symlink following, requires a regular file, bounds the read by
the configured control-frame limit, and strictly decodes the typed object. It
then sends the complete evidence directly to `ag-effectd` under the independent
effect-admin identity. Effectd—not the CLI—checks those fields against broker
custody, independently observes the target again, and creates the final
operator-authenticated reconciliation record and receipt.

Proposal submission uses the separate profile and service identity:

```text
agctl --config /etc/agent-governor/agctl-proposer.toml \
  intent submit --file /run/agent-governor/intent.json
```

Copying an effect-admin key into the proposer service, enrolling one principal
on both listeners, or placing both daemon peers in one CLI configuration
collapses proposer/ratifier separation and is invalid.

The command grammar intentionally has no BreakGlass, PTY, arbitrary command,
path-based effect, or generic execution operation.
