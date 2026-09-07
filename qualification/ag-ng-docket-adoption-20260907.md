# AG-ng + Docket adoption validation — 2026-09-07

## Source and environment

- AG-ng guide/example commit tested: `7c350012507fac4f6d8f854cd697dcdc19a4fadd`
  (based on `cb85d363e2495a75f78c28fb8ce9b46af1f289c0`).
- Docket dependency: `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`.
- Fresh detached clones, both clean before build; no development-tree imports.
- Ubuntu 24.04.4, x86-64 Linux 6.5.0, Rust/Cargo 1.94.0, Python 3.12.3,
  Git 2.43.0, system C compiler.
- Fresh empty Cargo home fetched the locked dependency closures. No existing credential,
  model provider, LLM subscription, or pre-existing service was used.

Run `adoption-clean-20260907-02` used a detached producer and persisted recovery checkpoint.
The failed predecessor `adoption-clean-20260907-01` stopped before build because it named an
unreadable Rustup home; it was retained and not treated as evidence.

## Results

The guide's two locked build commands passed. The example then passed all asserted cases:

| Case | Observed result |
| --- | --- |
| permitted | effect present; 1 AG spend, 1 Docket attempt, 1 settlement |
| refusal | exact work not admissible; 0 spends; no effect |
| duplicate | identical issuance returned identical custody; Docket remained settled; 1 attempt |
| acknowledgement loss | file existed while Docket was `indeterminate`; AG reopened; reconcile-only path reached `SettledObservationRequired`; cardinality remained 1/1/1 |

The documented Docket read command returned the exact issuance, custody, executor binding,
and successful settlement. Cleanup validated the recorded output root, removed only that
example run, and preserved a sibling sentinel.

Retained local evidence (campaign-owned, not published):

- `/tmp/ag-ng-docket-clean-validation-20260907-02/checkpoint` — SHA-256
  `694882465f5ddb3aed0e6faeac0b2358dd1d85019d4012456a4b58d5056ec99c`
- `run.log` — `5b51a25226e49f50eeaae1d6a50e3a5d2f2b71dd986794b87398f05812fd5762`
- `retained-summary.json` — `289372a4d62f98927c6e657b7df4961c060a24ab997d9f341bf0edcedae4035c`
- `docket-inspect.json` — `41cac2d3f43cc3fac2107eff48d25e43a4ac01deb078e2bb8b91e049d7dd2645`

Focused regression evidence also passed at the pinned revisions:

- Docket governed-loop filter: 17 passed.
- AG-ng governed-loop engine: 42 passed, 1 ignored fixture writer.
- Exact real-process AG-ng → Docket → `ag-effectd` witness: 1 passed.
- New example `cargo check --locked`: passed.

## Gate qualifications

`cargo fmt --all --check` is not green at the AG-ng baseline: it reports pre-existing
formatting drift in three governed-campaign test files untouched by this campaign.
Warning-denied Clippy likewise stops on pre-existing documentation and large-enum findings
in `governed_campaign_production_v1.rs` and `governed_campaign_v1.rs`. The new example emitted
no Rust compiler warnings. These unrelated baseline findings were not modified or made an
adoption blocker.

Independent review reproduced all four cases and Docket inspection. It found and prompted a
documentation fix so cleanup also removes the empty `mktemp` parent. The retained validation
used local no-local clones and an already-installed, explicitly selected Rust 1.94.0 toolchain;
it did not establish public-remote retrieval or fresh Rustup installation.

This validation establishes the clean source-tree build and local managed-file integration
experience. It does not establish production credential separation, physical power-loss
durability, exactly-once external effects, or observed adoption by an external developer.
