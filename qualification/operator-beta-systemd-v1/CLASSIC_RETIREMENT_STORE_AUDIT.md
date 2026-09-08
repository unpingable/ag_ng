# CLASSIC-RETIREMENT package store-audit evidence

This additive record supplies the AG-owned evidence pointer for the derivative
composition witness. It does not replace the original package/M1/M2 records or
claim their acceptance for new revisions. Runtime source remains
`bf6adde2792a886d1ba75d97ca77efb8e914f4f5`, tree
`31b3b15437baffcaa41ae31020f4570599304019`. Later test/documentation descendants
do not change that packaged runtime subject.

Observed local occurrence `composition-local-003` used the newly constructed
AG executor package SHA256
`80ea7ad067da9d5ed1f07b39fb7ee41eef58680f3af15fad64c6b1bf05c1045c`
and the AG/Docket composition package SHA256
`45a18d7c0d7a70933c6a7e2f6c56c190203d1a4afee9b1ec5097065d848d168e`
(Docket runtime `6c57926d2560c47c681691e006fbbfe244c6993e`). Each package
has separate reproducible two-build and archive-inspection evidence.

The existing local composition driver exercised a deliberately wrong machine
identity. It reached SETTLED with a failed/no-effect executor outcome, not
successful service execution: no StartUnit was sent. It retained exactly one
AG spend, one Docket attempt and one settlement, same-custody duplicate behavior,
exact AG restart reconstruction and executor reconciliation. The newly packaged
AG executable independently audited the retained store cut. Source-owned audit
output and raw cut are retained; this is not the older PASS_7_OWNER_3_CLI result.

Evidence root:
`/data/git/.campaign-artifacts/classic-retirement-full-20260908/`.

| Evidence | SHA256 |
|---|---|
| `composition-local-003.log` | `fd106882fb35f028d337ef07035b5026863954a1cf0200495e63cba92f2c085d` |
| `composition-local-003/result/composition-result.json` | `210b89adadfcea90f0a4bbb1b19895450fe182b2435f2a3df5d49885afb8e4c7` |
| `composition-local-003/result/executor-outcome.json` | `cc01a966d296cd45ea2b4ed007e0f1d7c703c796434846d12a16cab73bb80bfe` |
| `composition-local-003/result/systemd-evidence.json` | `caff8675162fecb47a46f8ecdde30628a555cb54a1c07fb0d9b0a4fc9880832b` |
| `composition-local-003/result/docket-inspection.json` | `e88cd77e68a5d6129861d39e275fd14e9038928c4196109d5df0a6becdc63438` |
| Retained store cut, indexed by occurrence recovery | `c315909322a76e9211e1289aba1189752e839cae39a8927af26efd93a973a967` |

Assessment: sufficient new-package local store-audit evidence to proceed to the
separately enrolled two-VM composition witness. VM installation, positive service
effect, terminal composed qualification, publication and production deployment
are **not established by this local record**. Inspect the exact occurrence
recovery and independent package review for commands and operating assumptions.
