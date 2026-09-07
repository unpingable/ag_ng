# AG-ng + Docket adoption integration checkpoint — 2026-09-07

## Exact custody

- Integrated AG-ng subject: `651d7178ef4a8950b9d9ac25c7d3fe496ed55f96`.
- Tree: `71cc65fadfd662349485c9f61ab263415386d398`.
- Parents: accepted/published operator-beta M1A result
  `92d274c299478a65121f2d8e1b93a2d00383a828` and local adoption result
  `549d1c446ea401456c286fba1d0885d00b72ec32`.
- Docket dependency: accepted/published C2
  `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`.
- Branch:
  `campaign/constellation-operator-beta-ag-docket-adoption-integration-v1-20260907`.

The merge is non-rewriting and retains both component histories. The original adoption
validation remains evidence for `7c350012507fac4f6d8f854cd697dcdc19a4fadd` on base
`cb85d363e2495a75f78c28fb8ce9b46af1f289c0`; it was not transferred to this subject by
ancestry. Docket's operator-beta systemd composition contract
`2be939c744f5cbd94a9047b61e9322b23750c79a` remains a separate documentation successor and
was not treated as Docket C2 runtime qualification or merged into AG-ng.

## Observed integrated witness

Fresh locked builds of AG-ng `ag-effectd` plus `docket_file_harness` and Docket C2 `docket`
passed locally. The harness used only a campaign-owned disposable directory and reached:

- permitted: one AG spend, one Docket attempt, one settlement, effect present;
- refusal: zero AG spends and no effect;
- duplicate: identical custody and one Docket attempt;
- acknowledgement loss: effect present while Docket was indeterminate, followed by AG
  restart and same-attempt reconcile to `SettledObservationRequired`, with cardinality
  remaining one spend, one attempt, one settlement.

The query-only Docket inspection reopened the exact permitted issuance, authentication,
custody, executor binding, attempt, marker, and settlement. Local retained evidence:

- `/tmp/ag-ng-docket-integrated-witness.CMZcm6/run/summary.json`: 1,245 bytes, SHA-256
  `2029b74e03e209fd0034ff792a8086e56e34dc93ccc3dbb91c0d8dacc52bed87`;
- `/tmp/ag-ng-docket-integrated-witness.CMZcm6/docket-inspect.json`: 3,022 bytes, SHA-256
  `6a8f81147e5c3d77e435fd5f971364f7aea89c9346e94377f88eec8cb9c98a02`.

## Proportional regression

- AG governed-loop engine: 42 passed, 1 intentional fixture-writer ignore.
- AG real-process test target: compiled; its environment-dependent case remained ignored.
- Docket governed-loop filter: 17 passed.
- Operator-beta systemd owner gate: 24 Rust passed, 1 ignored; 1 CLI test passed; 13 Python
  tests passed; boundary gate passed.
- Locked AG and Docket builds passed.

This checkpoint demonstrates that the adoption example still composes with exact Docket C2
after the M1A systemd history is integrated. It does not transfer either predecessor's
qualification, qualify the pending Docket systemd composition, establish production
placement, or prove a current postcondition. Independent review is required before this
candidate is accepted or published.
