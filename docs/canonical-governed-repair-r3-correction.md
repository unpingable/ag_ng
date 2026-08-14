# Canonical governed repair R3 correction

R3 is a local development correction constructed under explicit external
human development authorization. The governed loop did not authorize its own
construction. R3 is not independently reviewed, operationally qualified,
certificate-ready, active, or deployed.

The correction preserves the accepted R2 wire, custody, reconciliation,
journal, replay, verifier-receipt, strict-decoding, and truthful-effect laws.
It closes four bounded product defects:

1. `GovernedCampaignServiceV1` is the only production-rooted AG issuance
   application path. Retired V1 issuance machinery is not a production Cargo
   target or consequence-bearing Docket intake.
2. Every durable AG counter and timestamp is within the interoperable RFC 8785
   integer interval before it can participate in persistence, replay, event
   identity, cursor projection, or retrieval.
3. Every product mutation carries the caller's expected state into the first
   consequence-bearing Store transaction. That transaction compares the
   durable campaign head with the caller cut before any write; subsequent
   writes in the same product operation are chained from the exact committed
   predecessor. An early product check is diagnostic only.
4. The ordinary governed-repair conformance gate verifies both the pinned
   AG-owned corpus and the actual AG producer/Docket consumer serializers and
   validators. Matching copied corpus files alone is insufficient.

These are development claims only. They do not claim physical effect
containment, executor completeness, cross-database verifier-receipt
uniqueness, operational deployment correspondence, NQ repair authority, or
qualification.
