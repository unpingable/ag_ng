# Source baseline receipt

Captured 2026-07-17 while AG-ng implementation began. A source revision is an
input witness, not a runtime dependency. Implementations never chase these
repositories automatically.

| Source | Revision | Worktree state |
| --- | --- | --- |
| classic Agent Governor | `5d7089b1fd26510adddab808a7322e8ada4bf8bd` | clean |
| transition-kernel | `543dfc504c837443ecb20b8f166dd539b1bfc15a` | clean |
| NQ-ng | `18e0b35da2c2aad1a8c41c92ee61a3e19319b808` | clean |
| verifier | `902111b38860b34a883dcc4b81adadde6a5c9c31` | clean |
| Nightshift | `e71303fb7dc744ae352078c12a7db08f89682366` | clean |
| Standing | `a5120add32a5ce12fe302b67f1c9bce4f691930a` | clean |
| Wicket | `049309398e13be793806ed2a856fc082e19e108a` | clean |
| Linear Accountant | `2975500dfdf92841e69ded3c51ac4d3dbfcfe8dc` | clean |

The formalization source is the `skunkworks` repository at
`7c3de3ada5e42066c61224e3fc135cb01e8659eb`, plus a dirty-tree witness whose
binary diff digest was
`sha256:0f6c6aa403a9ded5d35ef80e94ea08698ad1310b781f1f692f674e3a00ae7cfb`.
The untracked files consumed by the design had these exact byte digests:

- rung-1 transfer receipt: `sha256:2646597e793708a8ba6cfe127c4eb246e1c9391b8b0d34896f7bcbd394b85f18`
- rung-2 GovernedFamily candidate: `sha256:0a822f5b103f94097102c7402721d94527e2732f2469d111ac4db97abf5b5f75`
- signature-promotion audit: `sha256:c9ba003703fb8a5a865ca7d8e54621bfd3eae8eec12ed3186ae840a0906b282e`

NQ-ng is separately pinned above even though its nested repository appears as
an untracked directory from the `skunkworks` worktree. Scratch and candidate
Lean names are not AG-ng public APIs.

## License evidence

This is a source-audit receipt, not legal advice. It records the declarations
present in the exact local source baselines; it does not itself grant reuse
permission or establish release compliance.

| Source | Declared/root license evidence | NOTICE evidence |
| --- | --- | --- |
| classic Agent Governor | package SPDX `Apache-2.0`; `LICENSE` `sha256:0cffb64e7c0813e4db2091aa55528d9844d80d8a7bbed8b25a27d946cc14e2c5` | `sha256:77db7ce5135cc3ea350613b2004b676bc5ee279d1751ca31e9b6516235e1aa7d` |
| transition-kernel | package SPDX `Apache-2.0`; `LICENSE` `sha256:0cffb64e7c0813e4db2091aa55528d9844d80d8a7bbed8b25a27d946cc14e2c5` | `sha256:778c298aaded45c0c518210318b7df3b8685e7b63b0e956befa92084763b07e2` |
| NQ-ng | workspace SPDX `Apache-2.0`; `LICENSE` `sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` | absent |
| verifier | root Apache License 2.0; `LICENSE` `sha256:f8c96bf1a1e2b2e6f57d8ae035d6207de5fa64ba92428c1e822569e11a071405`; root package metadata omits a license field | `sha256:bc75efe2c7bd87092b44be4c5ebbacc2686b382d9d64339d3448c1c4f49a3705` |
| Nightshift | Cargo and Python package SPDX `Apache-2.0`; `LICENSE` `sha256:f8c96bf1a1e2b2e6f57d8ae035d6207de5fa64ba92428c1e822569e11a071405` | `sha256:cb5df5c62749e1000fec84afe3de4d0755ebf454679dbbba2e22617c269a6860` |
| Standing | root Apache License 2.0; `LICENSE` `sha256:f8c96bf1a1e2b2e6f57d8ae035d6207de5fa64ba92428c1e822569e11a071405`; virtual-workspace metadata omits a license field | `sha256:c1a3562abd370620cc35b1c1c33cfe21b25fba923fc8450562b7cf6ad9a37517` |
| Wicket | package SPDX `Apache-2.0`; `LICENSE` `sha256:fbb1b63a7394ac58d4f9cd6906528a1c7674c2b364b381c494b15d15fdcb3b7e` | `sha256:f87887cbd1c531b47d246bc1e5d760591f2bfee4e7cf5021350466582a38c8df` |
| Linear Accountant | package SPDX `Apache-2.0`; `LICENSE` `sha256:43a93bc3f5afd26caa1cebc6c9c665e974a8229e3cfbaa1f4c30e8f9b2dd9c83` | `sha256:610bcc6c86cdecbbef7e6fee302f832259b8d8f5f57bb01edb96cb310816aac9` |

The `skunkworks` repository and its `formalization` component have no root
`LICENSE`, `COPYING`, or `NOTICE`; `formalization/lakefile.toml` has no license
field. The same was true at the pinned `7c3de3a` revision. Permission to reuse
that material is therefore unresolved and remains a release blocker. AG-ng's
implementation uses the formalization as a private behavioral cross-check; no
Lean source is copied into this repository.

The audit rechecked all eight separately pinned revisions as clean exact
matches. The parent `skunkworks` repository was at
`506b13e1a6eb5372c94e48a120a58cdfbff18d4f` during the audit; the pinned
revision remains an ancestor, and the only observed dirt was the four expected
untracked formalization/rung-source and `nq-ng` paths.
