# BRASS-RABBIT qualification

TRACK: Governed Campaign Loop V1

CAMPAIGN: BRASS-RABBIT

SLUG: gcl-v1-production-antecedent-issuance-lifecycle

## Result

The versioned production antecedent-issuance lifecycle is qualified for its declared V1 scope. Frozen V0 remains byte-for-byte unchanged. The implementation adds no authorization primitive and changes no Docket wire, custody, executor, Porter, NQ, or Nightshift authority semantics.

## Exact lifecycle law

The new closed schema is `ag.governed-campaign.production-lifecycle/v1`. It binds the frozen V1 reservation packet, one content-addressed verified campaign-start basis, three exact logical stages, three independently allocated occurrences, three W5 executor-plan templates, the ordinary AG program/subject/scope/mandate/resolver coordinates, and one terminal `HUMAN_REQUIRED` law.

The root basis schema is `ag.governed-campaign.verified-start-basis/v1`; AG observes it only through the exact typed basis `ag.governed-campaign.verified-start/v1`. It retains the explicit human decision, human principal, external verification record, verification profile, exact packet, Stage 1 logical work, subject, scope, initial occurrence, mandate, observation, and pinned observation/standing resolvers. It explicitly establishes none of execution, qualification, standing, authorization, issuance, Docket custody, or continuation. Packet, reservation, worker session, repository, or controller possession cannot substitute for the pinned current observation plus standing path.

The exact production chain is:

```text
verified start -> ordinary AG spend S1 -> issuance S1 -> Docket Stage 1
current R1 -> authority-empty Stage 2 occurrence -> ordinary AG spend/issuance S2 -> Docket Stage 2
current R2 -> authority-empty Stage 3 occurrence -> ordinary AG spend/issuance S3 -> Docket Stage 3
settled Stage 3 + current R3 -> durable HUMAN_REQUIRED receipt
```

The terminal receipt creates zero spends, zero issuances, and zero successor occurrences. The contract contains exactly three stages and no Stage 4 representation.

## Logical work and exact Docket plan linkage

The packet's logical stage work is not misrepresented as Docket's executable plan identity. Before execution, each stage freezes its exact W5 plan template and reservation. After the exact predecessor exists, the existing VELVET-PIGEON materializer deterministically constructs the runtime plan. `executor_plan_identity` uses W5's exact `ag-effectd.docket-executor-plan/v2` domain and canonical bytes. The authority-empty occurrence and ordinary AG proposal/issuance bind that exact plan identity.

The resulting chain is exact:

```text
frozen logical stage + template + R + exact predecessor
  -> materialized W5 plan
  -> AG issuance.work
  -> signed Docket custody
  -> exact attempt
```

No Stage 2 or Stage 3 runtime plan identity is predicted before its predecessor realization. No wildcard catalog entry or post-runtime successor selection was introduced.

## Deterministic production specimen

Canonical evidence is under `qualification/governed-campaign-loop-v1/brass-rabbit/evidence/`.

- lifecycle: `sha256:f2e6e81c677336729c292c60dda0d8272334da28524da75fd0869c89eaaf13a0`
- verified root basis: `sha256:bcef216451b1fd3f5f0ec82e4b58ac55f38f60634b119da7c4540ee4083820ac`
- materialized W5 plans:
  - `sha256:7165a915d299109c08edd23174b4841da4e89e1e2c9ebc43acea859240fc4ca9`
  - `sha256:754d73fac41a94c35688d1480a100faca96e0def711c06d8e5cae59ab4fdc679`
  - `sha256:3df6efc1c4f5beb9b5de16f297c0853d663dc329358d2cb7d1f2002413618df8`
- AG spends:
  - `sha256:c4168e88f2143242c13e9f219ef78250603af69df205509218c8c3c7010d1fb2`
  - `sha256:486e99cce641e56ec8075700cc124fe264718bc97836544d7c28d013595482c3`
  - `sha256:811a6e4eed0865a876f1011560ff8fd930fb3b16e7b3c093c3c71d58170e5db1`
- AG issuances:
  - `sha256:f68d9536bec532ef5aadda6c5a6e6b02fe1a62fab16032c2392bd011c9074e21`
  - `sha256:66ddd9279f3cbd697a3a14a8913340361ede41abaf47e6607f057715ec2a0c57`
  - `sha256:173afc848aa085cc1baf158d23657884cf486ad3b52ce553226be2a6dce9abf5`
- Docket attempts:
  - `sha256:fde55fb4b8b484646ebdc64982ea4307e721e7a3d2a8a02b885a0a3e13717277`
  - `sha256:98d2b2d09ec21db1c454d20ed8ec8ef285c63d9891faf6aad4d1a07727127dc3`
  - `sha256:0016e2e74f0ce922b2386eed291a6a5b140ee309a5099ca9c67461d8c65e7f4e`
- terminal receipt: `sha256:4e796eddeb015cc6b71cfe29e6b9661a70d6ed7bd3e0b2b8e70dff55210665d6`

Cardinality is exactly one verified start, three executable occurrences, three AG spends, three issuances, three Docket attempts, three current reservation realizations, one HUMAN_REQUIRED receipt, zero Stage 4, and zero terminal spends.

## Hostile authority matrix

| Case | Result |
|---|---|
| Stage 1 dispatch without S1 | canonical AG dispatch refuses |
| packet or wrong verified-start record | lifecycle recorder refuses; zero issuance |
| reservation used as Stage 1 root | exact root typed-basis requirement mismatches |
| S2/S3 before current predecessor R | lifecycle order and exact AG basis refuse |
| wrong/stale R or resolver | exact typed-basis/currentness gates refuse |
| wrong subject, scope, work, plan, or reservation | contract/plan/AG binding refuses |
| replay S1/S2/S3 | canonical state and durable journal are idempotent; no second spend |
| duplicate Docket custody | production Docket retains one attempt/delivery |
| restart after spend or custody | exact AG/Docket state is reopened and reconciled |
| R3 executable successor | structurally absent from the three-stage contract |
| R3 terminal replay | exact receipt replay returns existing event, zero spend |
| fabricated HUMAN_REQUIRED | evidence-validating terminal method refuses absent settled Stage 3 + current R3 |

## Restart matrix

The deterministic specimen reopens authoritative AG and lifecycle storage after verified root recording, root observation/proposal, standing, admission, each S1/S2/S3 issuance, each Docket custody, each settlement, each R1/R2/R3 realization, each authority-empty successor occurrence, and HUMAN_REQUIRED. Replay reports remain exactly three spends, attempts, and settlements. Existing AG and Docket concurrency/reconciliation tests independently prove no duplicate spend, issuance, custody, executor delivery, or settlement.

## Regression gates

All commands exited zero:

- `cargo test -p ag-app --test governed_campaign_v0 --test governed_campaign_v1 --test governed_campaign_production_v1 --test governed_loop_engine --no-fail-fast`: 58 passed, 1 explicitly unrelated ignored fixture writer.
- exact signed production Docket process gate: 1 passed.
- Docket governed-loop gates: 17 passed.
- W5 executor/custody gates: 20 passed.
- Porter suite: 28 passed.
- NQ campaign-stage realization V2 gates: 5 passed.
- Nightshift reservation realization gates: 3 passed.

Frozen V0 source SHA-256 remains `f33864aa36f52069ce25fd5edeeeb0428e82fcdd27e10d7ea421d3edfc45f1de`. VELVET-PIGEON packet identity remains `sha256:02b89310808fdc09f8949e57d60ff9692f02316212ee985d2952f840daf67e85`. Docket, campaign-driver-ng, Porter, NQ, and Nightshift product worktrees remained unchanged and clean.

## Implementation and artifacts

Implementation commits:

- `2af93fe3cb52160ff2843f2c1f6a7efe0315b46d` — versioned lifecycle, root basis, exact W5 linkage, terminal law, cardinality and hostile tests.
- `7c0d8023fdf9041bd09d2c79582240c1883a791e` — restart coverage and canonical specimen artifacts.

Artifact SHA-256:

- `production-lifecycle.v1.json`: `03941946a0d48d3fb1427cd40d8d73e64196cf4c5be4277a0ac9343d19bd005e`
- `lifecycle-events.v1.json`: `6cb40b137b0d9e76ad7563a3f64c511c197daf804267b6c0999054d698bcd74c`
- `human-required-receipt.v1.json`: `9afd8b59299de8d8eafb6c353d447cf1c180194b8a2258960213c6d6b52e448a`
- `specimen-summary.v1.json`: `24d43d43a476d75523613191f20884e38dfda88795bcecc3e4384a0ebe7d52fa`
- production Docket binary: `69909d371528a3820e9d2a9c029d7064237e5d4c3a133a04d80b16f6058f1a40`
- AG effectd binary: `3d0785f9bcec10065f2c6dba096340bfe9c9d71ef50645798e860c4505ec908b`

TURNSTILE-COMET was a read-only controlling-run adjudication and had no repository artifact at starting custody; no nonexistent revision is claimed.

PRODUCTION-ANTECEDENT-ISSUANCE-LIFECYCLE-QUALIFIED
