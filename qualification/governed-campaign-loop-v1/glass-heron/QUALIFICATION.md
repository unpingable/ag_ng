# GLASS-HERON closeout

TRACK: Governed Campaign Loop V1
CAMPAIGN: GLASS-HERON
SLUG: gcl-v1-w7-w8-real-codex-specimen-reconcile

BRASS-RABBIT passed its hard gate as `PRODUCTION-ANTECEDENT-ISSUANCE-LIFECYCLE-QUALIFIED`. GLASS-HERON then froze a fresh session-009 packet and began Stage 1 through an antecedent signed AG issuance and production Docket.

## Exact stop

Stage 1 stopped after Docket custody and before a guest attempt reservation. The W5 adapter built a nonempty local package containing:

- predecessor bundle SHA-256 `9372e61725151b5e6547a3e8dafc3882718b5b2a4c7292bbf18c62399b02e4c0`;
- prompt SHA-256 `dd08aa9f67ebdb1e284e138ca02e2df54e89dd20afaf056fcd01f8ef9578b58e`;
- request SHA-256 `f8850c971fee8699f5df7e2b97e10f780ce6b63964b03ab6de4e8e7efae70bf3`.

Porter run `2026-08-29T07-09-43Z-07b9e9` recorded its push as exit 0, but the transferred tar was empty. The next exact guest invocation failed because `/var/lib/gcl-state/inbox/fdfbe0ddbe761e294d31ac985dd1a2188e6507fd704bfad20bd757ff1b7f8e87/request.json` did not exist. Porter record SHA-256 is `dc66ed31fda92736c9335e8c1ab5aaf678429b63f5b631a7fd8851b5951b6682`; the guest execution transcript SHA-256 is `88f0522f409536a8f6c294b49412f53ea55d6413e0aa7bc1c08ea717f0a91764`.

Docket retained S1 attempt `sha256:fdfbe0ddbe761e294d31ac985dd1a2188e6507fd704bfad20bd757ff1b7f8e87` as indeterminate. Reservation R1 was consumed. The executor has no lawful retry under R1, the guest journal has zero attempts, and Codex was never invoked.

## Cardinality at stop

- 1 worker VM launch, 1 AG spend/issuance, 1 Docket attempt, 1 Porter campaign run.
- 1 reservation consumed.
- 0 guest attempts, Codex invocations, candidates, applications, NQ receipts, Nightshift realizations, or HUMAN_REQUIRED terminal receipts.
- W8 was not started.
- The fixture remains unchanged at HEAD `829f77118aef25ac818c78a24dee3071ee48562e`, tree `1929b1a11994b7c152af616e19c4b37d4180873b`.
- The stale session was closed; its unit is inactive/dead with no QEMU PID.

This is not a model-quality failure. It is a real Porter-to-guest workspace custody failure in the deployed W5 path. The one-use law forbids repairing and retrying this frozen campaign reservation.

WORKER-VM-CUSTODY-NOT-BOUNDED
