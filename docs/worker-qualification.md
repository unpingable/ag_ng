# Worker ingress qualification

The live worker ingress suite is a **qualified gate**, not part of `cargo test
--workspace` and not part of the packaged test step. This document states what it
covers, why it is separate, and how to run it.

## Running it

```sh
scripts/run-worker-qualification.sh
```

| exit | meaning |
|---|---|
| 0 | qualified |
| 1 | the suite failed |
| 2 | a prerequisite is unmet, so the suite was not run |

Expected runtime is roughly **45 seconds** on a warm build tree, dominated by the
managed-pointer lifecycle test. The suite is deterministic: repeated runs from clean
state produce identical results, and it leaves no residue outside `TMPDIR`.

## Prerequisites

| prerequisite | why |
|---|---|
| `/usr/bin/bwrap` | the tests launch a real worker under real bubblewrap confinement |
| unprivileged user namespaces | bubblewrap is not setuid here, so it needs them; the script probes the mechanism rather than reading a sysctl, because containerised builders can report the sysctl enabled and still refuse the clone |
| `/usr/bin/git` | the managed-pointer tests build and read a real Git repository |
| `TMPDIR` at most 57 bytes | the suite binds Unix sockets under `TMPDIR`, the kernel bounds `sun_path` at 108 bytes, and the longest path the suite builds adds 50 |

`bubblewrap` and `git (>= 1:2.39.0)` are already `Build-Depends` in `debian/control`.
The user-namespace and `TMPDIR` requirements are host properties, not packages.

## What it covers

Five tests in `crates/ag-app/tests/worker_live_ingress.rs`, all behind the
`worker-fixture` feature:

| test | what it establishes |
|---|---|
| `real_fixed_elf_enters_only_through_signed_candidate_ingress` | a real ELF worker under confinement can deliver material **only** as a signed candidate; activation is descriptor-only |
| `agd_core_recovers_custodied_fixture_into_broker_owned_canonical_proposal` | custody survives the governor→broker hop over signed local RPC, and canonicalization alone does **not** execute the effect |
| `live_worker_bundle_closes_the_managed_pointer_lifecycle` | the managed-pointer lifecycle closes against a real repository, with exact object/tree/ref identities and loose-ref custody |
| `wrong_live_semantic_is_fenced_before_candidate_custody` | a wrong-semantic worker is refused **before** custody is taken, and the governor stays usable |
| `supervisor_timeout_tombstones_reaps_and_releases_fresh_capacity` | a hung worker is tombstoned with an attributable reason, reaped, and its slot released — the liveness half of the one-live-worker rule |

Together these are the only coverage of the ingress path end to end: external input →
confinement → descriptor-only activation → single-frame candidate emission → exact
decode → signature verification with replay guard → principal construction → catalog
resolution → authority boundary → dispatch → refusal → persistence → reap and cleanup.
Every governor-side entry point they drive is live in `agd`.

## The `worker-fixture` feature

The feature gates two things and nothing else:

- `crates/ag-app/tests/worker_live_ingress.rs` (whole-file `cfg`);
- `crates/ag-app/src/bin/ag-worker-fixture.rs`, the fixture worker.

**No production source file in the workspace contains `cfg(feature = …)`.** The feature
cannot change production behaviour; it only adds test surface.

The fixture worker is the only implementation of the *worker side* of the ingress
protocol — this repository ships no worker. Keeping it behind a feature is what stops it
becoming a shipped command surface: `override_dh_auto_build` builds without the feature,
and `debian/agent-governor-ng.install` is an explicit allowlist of six release binaries
that does not include it.

## Why it is not in the packaged test step

`override_dh_auto_test` deliberately does **not** enable the feature. The packages are
available at build time, but Debian build environments — sbuild, pbuilder, containerised
builders — frequently disallow unprivileged user namespaces. Enabling it there would make
package builds fail for a reason unrelated to the package.

This is a stated limit, not an oversight: **the qualified suite is a developer and
operator gate, not a packaging gate.** If this repository gains CI whose runner
guarantees user namespaces, the suite belongs there.

## Full verification

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace --all-targets
python3 qualification/clean-host/validate.py
python3 -m unittest discover -s qualification/clean-host -p 'test_*.py'
scripts/verify-effectd-isolation.sh
scripts/run-worker-qualification.sh
cargo run --locked --offline -p ag-migrate -- ledger \
    --ledger migration/classic-authority-ledger.v1.json --evidence-root .
```

The first five lines are what `debian/rules` runs. The last three are gates that a bare
`cargo test` cannot express.

## Known limit outside this suite

Six `ag-effect` `executor::tests::*` cases validate ancestor custody against `TMPDIR`'s
parent chain and assume it is root-owned, as `/tmp` is. Under a `TMPDIR` nested inside a
user-owned directory they fail, because the executor correctly refuses the ancestor
custody. This is unrelated to the worker suite and is recorded rather than changed.
