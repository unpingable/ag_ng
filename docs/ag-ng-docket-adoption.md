# AG-ng + Docket adoption quickstart

This guide is for a developer who already has an agent harness or orchestrator and wants
tool effects to cross an explicit authorization and execution-custody boundary. It uses
AG-ng, not the classic Python Agent Governor. No model subscription, Nightshift, NQ,
Marginalia, ABSD/civild, or monitoring operator is required.

The example creates only disposable non-Git files. It demonstrates an admitted action, a
policy refusal before the effect, an exact duplicate converging on retained custody, and a
simulated acknowledgement loss that is visibly indeterminate before read-only
reconciliation. It is a development integration example, not a production deployment.

## Integrated validation coordinates

The current operator-beta integration witness exercised this exact pair:

| Component | Repository | Immutable revision |
| --- | --- | --- |
| AG-ng | `https://github.com/unpingable/ag_ng.git` | `837de287497942c79966aa05c083acee9c312261` |
| Docket | `https://github.com/unpingable/docket.git` | `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` |

The AG-ng subject is the accepted query-only store-audit owner and a non-rewriting
descendant of accepted adoption integration result
`a05f7410cee0cca262d95ea198099f811091cc0f`. That result records the merge of accepted
operator-beta M1A result `92d274c299478a65121f2d8e1b93a2d00383a828` with adoption
validation result `549d1c446ea401456c286fba1d0885d00b72ec32`. The latter retains the
original guide witness at `7c350012507fac4f6d8f854cd697dcdc19a4fadd`, based on
`cb85d363e2495a75f78c28fb8ce9b46af1f289c0`. Those earlier qualifications remain attached
to their original subjects; ancestry alone does not qualify a successor. The fresh
successor witness is recorded in
`qualification/ag-ng-docket-adoption-reconciliation-20260908.md`.

Docket is used without source changes. Both source repositories must be available because
neither component currently promises a published package.

The demonstrated clean environment is Ubuntu 24.04.4 on x86-64 Linux with Rust/Cargo
1.94.0. A C toolchain and network or pre-populated Cargo cache are needed for the locked
Rust dependency closure. Python 3 is needed only for the example's deterministic Docket
standing resolver. SQLite is bundled by Docket; Git and Bubblewrap are not used by this
managed-file path.

## Build and run

Start with this AG-ng guide checkout in `ag-ng`. Fetch Docket's published campaign ref and
detach at the exact dependency revision:

```sh
git clone https://github.com/unpingable/docket.git docket
git -C docket fetch origin campaign/c2-governed-loop-layering
git -C docket checkout --detach c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b
test "$(git -C docket rev-parse HEAD)" = c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b

rustup toolchain install 1.94.0 --profile minimal
rustup override set 1.94.0
cargo build --locked --manifest-path docket/Cargo.toml -p gwr-local --bin docket
cargo build --locked --manifest-path ag-ng/Cargo.toml \
  -p ag-app --bin ag-effectd --example docket_file_harness

RUN_PARENT="$(mktemp -d)"
RUN_ROOT="$RUN_PARENT/ag-ng-docket-example"
ag-ng/target/debug/examples/docket_file_harness \
  "$(pwd)/docket/target/debug/docket" \
  "$(pwd)/ag-ng/target/debug/ag-effectd" \
  "$RUN_ROOT"
```

Run those commands from the parent of `ag-ng` and `docket`. `RUN_ROOT` must be an absent
absolute path; the example creates it mode `0700` and refuses an existing or relative
path. It prints and retains `summary.json`. A passing summary contains these facts:

```json
{
  "result": "passed",
  "scenarios": {
    "permitted": {"ag_spends": 1, "docket_attempts": 1, "settlements": 1},
    "refused_before_effect": {"ag_spends": 0, "effect_exists": false},
    "duplicate": {"same_custody": true, "docket_attempts": 1},
    "acknowledgement_loss": {
      "docket_status_before_reconcile": "indeterminate",
      "effect_existed_while_uncertain": true,
      "ag_spends": 1,
      "docket_attempts": 1,
      "settlements": 1
    }
  }
}
```

Inspect the effect file and machine-readable summary first:

```sh
python3 -m json.tool "$RUN_ROOT/summary.json"
```

The example uses `CampaignEngineV1`, as an embedding harness would, and records the AG replay
cardinality in the summary. The `ag-loopctl inspect` command applies only to campaigns created
through its genesis-bound runtime-profile surface; it intentionally refuses this library-created
example database.

The summary includes each accepted issuance digest. Copy the permitted digest from
`summary.json` into this read-only Docket inspection command:

```sh
ISSUANCE=sha256:replace-with-summary-value
docket/target/debug/docket governed-loop inspect \
  --state "$RUN_ROOT/permitted/docket-state" --issuance "$ISSUANCE"
```

The AG, Docket, and executor SQLite files under `RUN_ROOT` are persistence artifacts, not
a documented raw-query API. Preserve them together for restart/reconciliation; use the
summary and Docket command above for this example.

When finished, confirm `RUN_ROOT` contains this example summary, then remove only that
directory and its empty campaign-created parent:

```sh
test -f "$RUN_ROOT/summary.json"
python3 -m json.tool "$RUN_ROOT/summary.json" >/dev/null
rm -rf -- "$RUN_ROOT"
rmdir -- "$RUN_PARENT"
```

The example enrolls and writes no resource outside `RUN_ROOT`.

## Integration contract

The harness-to-effect path is:

```text
harness proposes exact work/subject/scope
  -> harness observation and standing resolvers return current judgments
  -> AG-ng matches the exact catalog and durably spends one authorization
  -> AG-ng signs the exact issuance and invokes Docket
  -> Docket authenticates it and resolves fresh Docket execution standing
  -> Docket persists one attempt, marker, executor binding, and custody
  -> ag-effectd checks its sealed plan and performs the managed-file mechanics
  -> Docket persists settlement or indeterminate evidence
  -> AG-ng consumes that exact outcome and requires a fresh observation for continuation
```

Ownership is deliberately split:

- AG-ng owns the occurrence, exact proposal, observation/standing checks, catalog decision,
  durable one-use authorization spend, signed issuance, and continuation program counter.
- Docket owns issuer authentication, its separate execution-standing consumption, executor
  binding, one attempt/marker, pre-delivery custody, settlement, and exact-attempt
  reconciliation.
- The executor owns the sealed effect plan, mechanics, local attempt journal, evidence, and
  evidence-sensitive outcome. `ag-effectd` is the supplied adapter for AG-ng managed-file,
  managed-pointer, and systemd effect types. A different tool action needs a separately
  qualified adapter implementing Docket's `plan-id`, `execute`, and reconcile-only process
  operations.
- The integrating harness owns proposal construction, the meaning and freshness of both AG
  resolvers and Docket standing, catalog enrollment, durable driving/recovery, and the
  application decision made after settlement.

The enforcement points are therefore not permission prompts. The harness must send every
effecting tool path through the AG-ng decision and Docket custody path, keep direct execution
unavailable to the proposing process, and configure the executor with only its enrolled
mechanics. A user routinely clicking “allow” is only prompt policy; it does not create these
authority and custody boundaries. Any direct tool route that bypasses this integration is
outside its guarantees.

## Persistence, restart, and credentials

Persist AG's campaign SQLite database, Docket's state directory, the executor plan and
attempt database/artifacts, and the exact configuration needed to verify all three. Back up
a coherent stopped cut; do not copy a live SQLite database without its WAL and then infer
non-execution from missing records. After a partial restore, treat consumed or accepted
work as uncertain and reconcile the original attempt.

The example generates an in-memory disposable Ed25519 issuer key and writes only Docket's
public-key trust file. A deployment must instead inject and restrict the AG signing key,
enroll the matching Docket trust root, pin resolver/executor/configuration bytes, and separate
the proposing principal from effect mechanics as required by its authority boundary. The
one-shot local process composition does not itself establish OS-principal separation.

Restart reconstructs facts, never authorization. Before the spend, current gates may be
evaluated again. After the spend but before Docket custody, present or reconcile the same
issuance. After custody, reconcile the same attempt and never repeat mechanics. Settlement
does not authorize a successor; it returns AG-ng to fresh-observation-required state.

## What the four cases establish

- **Permitted:** one catalog-admitted proposal produces one AG spend, one Docket attempt,
  one managed-file effect, and one settlement.
- **Refused:** a proposal absent from the exact catalog is refused before authorization;
  there is no spend, Docket invocation, or effect file.
- **Duplicate:** the identical signed issuance is presented again. Docket returns the exact
  retained custody and does not call the standing resolver or executor again. This is
  duplicate suppression, not a claim that arbitrary external effects are exactly once.
- **Acknowledgement loss:** a clearly labeled shell substitution fixture delegates real
  execution to `ag-effectd`, then suppresses its valid outcome. Docket records
  `indeterminate` even though the file exists. The harness drops and reopens AG state, then
  Docket invokes only `ag-effectd reconcile`; retained executor evidence settles the original
  attempt without another effect.

## Limits

This path establishes one durable AG authorization spend and one Docket-custodied attempt
under the named local premises. It does not establish exactly-once external effects,
distributed atomic commit, resolver truth, semantic correctness of a proposal, current
posture after settlement, global replay prevention, disk-cache or power-loss behavior,
production credential isolation, or Windows support. A missing acknowledgement means “may
have occurred,” never “did not occur.” Reconciliation can remain indeterminate when retained
evidence is insufficient.

AG-ng's Lean crosswalk relates the pure authorization calculus to selected Rust types; it
does not prove this deployed process composition, Docket, the executor, the filesystem, or
the harness. Marginalia Gate 3A is compatible-revision and clean-VM evidence, not a runtime
dependency and not observed adoption by an external developer.

For protocol detail, see Docket's `docs/governed-runtime/executor-transport-v1.md` and
`docs/governed-runtime/governed-loop-c2-layering.md`; for AG restart and state ownership, see
[`governed-loop-c1.md`](governed-loop-c1.md) and
[`governed-loop-deployment-qualification.md`](governed-loop-deployment-qualification.md).
