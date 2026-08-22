# AG governed-loop operational qualification harness

Status: harness preparation only. Nothing in this directory is a qualification
claim, certificate, or authority artifact.

This harness separates deterministic development evidence from the operational
premises that require a trusted host, deployed services, or a fault-injection
environment. It does not alter the governed-loop law or any production path.

## Gate classification

| Gate | Required environment | Safe local evidence available here |
| --- | --- | --- |
| local process provisioning/reopen | runnable locally now | create-once profile seal, genesis binding, independent-process inspect/replay, coherent closed-copy restore, partial-copy and missing-custody refusal |
| SQLite/WAL crash and power-loss recovery | fault-injection environment | transactional replay, logical crash cuts, reopen tests |
| multi-process contention | runnable locally now | independent `ag-loopctl` writers contend for one predecessor |
| authenticated intervention ingress | runnable locally now | exact signed bytes, runtime targeting, receipt durability, timeout resend, owner read projection, and structural read-only checks |
| service-currentness behavior | deployed service | deterministic current/stale/mismatch contract tests |
| clock/expiry behavior | deployed service | exact boundary and noninheritance tests |
| process isolation | trusted host | release-binary structural isolation scan |
| executor physical idempotency | fault-injection environment | logical duplicate-delivery and attempt-identity tests |
| deployed Standing/Docket correspondence | deployed service | command-port binding and refusal tests |

`gates.json` is the machine-readable version of this matrix. The three plan
files define the additional evidence that would be needed to close the
non-local premises honestly.

## Local development evidence

Run from the repository root, writing evidence outside the source tree:

```sh
python3 qualification/operational/run_local.py \
  --output /tmp/ag-operational-local-$(date -u +%Y%m%dT%H%M%SZ)
```

The runner refuses a dirty source tree by default. During development of the
harness itself, `--allow-dirty-development` permits the run while recording the
exact dirty-status digest and marking the bundle as development evidence.

The local runner executes focused kernel/store/engine tests, the production
profile provisioning/reopen test, the authenticated intervention ingress and
operator read projection, a real multi-process SQLite contention scenario,
executor-adapter tests, both authority/read-only structural checks, and the
existing release-binary isolation scan. Its aggregate result remains
`qualification_status: not_assessed`: it closes only the explicitly local
development gate and does not turn proxies into host or physical qualification.

## Environment preflight

Preflight only inventories prerequisites and exact identities. It does not run
the operational experiment and cannot close a gate.

```sh
python3 qualification/operational/preflight.py \
  --profile trusted-host \
  --output /tmp/ag-trusted-host-preflight

python3 qualification/operational/preflight.py \
  --profile deployed-service \
  --output /tmp/ag-deployed-preflight

python3 qualification/operational/preflight.py \
  --profile fault-injection \
  --output /tmp/ag-fault-preflight
```

The deployed-service profile recognizes these path-valued environment
coordinates without executing them:

- `AG_QUAL_OBSERVATION_RESOLVER`
- `AG_QUAL_STANDING_RESOLVER`
- `AG_QUAL_DOCKET_BIN`
- `AG_QUAL_DOCKET_STANDING_RESOLVER`
- `AG_QUAL_EXECUTOR`
- `AG_QUAL_EXECUTOR_CONFIG`
- `AG_QUAL_DEPLOYMENT_MANIFEST`

The trusted-host profile additionally requires `AG_QUAL_HOST_DECLARATION`.
The fault-injection profile requires `AG_QUAL_FAULT_VM_IMAGE`,
`AG_QUAL_FAULT_CONTROLLER`, and `AG_QUAL_DISPOSABLE_EXECUTOR_TARGET`. These
explicit declarations prevent the mere presence of systemd or QEMU tools from
being mistaken for a designated qualification environment.

Secrets, signing keys, and bearer artifacts are intentionally not captured.
Path records larger than 32 MiB are not hashed by preflight, and every path
hash is labeled as an unlocked read rather than a coherent service snapshot.

## Evidence discipline

- Every output directory is create-once.
- Every command log records argv, UTC bounds, exit status, and byte hashes.
- Source HEAD, branch, dirty-status hash, harness hashes, executable hashes, and
  host identity are captured before an experiment.
- Local fixtures grant no standing, authorization, or qualification status.
- Filesystem and SQLite logical tests are not represented as power-loss tests.
- A deployed service response is required for deployed-currentness and
  Standing/Docket correspondence.
- Physical effect idempotency requires a disposable target and a declared
  crash/fault boundary.
