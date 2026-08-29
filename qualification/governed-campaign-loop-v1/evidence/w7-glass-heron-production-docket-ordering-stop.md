# GLASS-HERON production-Docket ordering stop

Campaign: `GLASS-HERON`
Slug: `gcl-v1-w7-w8-real-codex-specimen-reconcile`
Track: Governed Campaign Loop V1
Boundary: G0 complete; W7 stopped before Stage 1 admission, reservation claim,
Docket custody, Porter campaign run, Codex invocation, candidate application,
NQ evaluation, Nightshift realization, or AG spend.

## Frozen predecessor and G0

The VELVET-PIGEON predecessor was verified exactly: AG commit
`1a4cc8e0ac01098f63bf2d76176200a982c0418f`, AG tree
`71a935b60c4c9d8e5142cadd72d924ba3bfdae37`, NQ predecessor-proof commit
`a14d1962cda187317393fdb73ad76a1dcf939ef8`, qualification-record SHA-256
`ed22b578926f56a574cf2c5b550d929d7181cbb97c03e8f58f42659e3a285de6`, and
frozen packet identity
`sha256:02b89310808fdc09f8949e57d60ff9692f02316212ee985d2952f840daf67e85`.

Retained session `gcl-v1-20260828-007` was not silently reused. Its exact
Porter profile differed from the VELVET-PIGEON packet template, and its
manifest bound the pre-reservation Porter predecessor. It was explicitly
closed. The controller's session measurement constant was advanced only to
the qualified reservation-aware Porter commit in
`e5996778979bf6d2ed9d9138b7a8c9530a5176e7`.

Exactly one replacement session, `gcl-v1-20260828-008`, was launched and
measured. Its manifest SHA-256 is
`5ca4acdb71e78c5b3d39c235f17dd761e999efcea429cd0249d28287a6cee83a`;
its exact Porter endpoint profile SHA-256 is
`8165ce927bbe8197a524b4ca9fffc30faa5f46fa0921df0dedf52710cb84a22e`.
The measured root remained
`00afb09883966d2f1cfdcf133eac14b010f0ae8651ebf153105428f3ee90bb8b`,
Codex remained `0.147.0`, the guest boot ID was
`b3cd61f7-68d6-4c40-b62a-729553cd392a`, and campaign capacity remained three
with no attempts consumed. The one Porter run in the manifest,
`2026-08-29T00-33-02Z-7f2296`, is the session-measurement identity probe, not
a campaign run or reservation claim.

After the stop decision, the exact user-systemd unit was stopped. QEMU PID
`858844` terminated, the unit is inactive/dead, its cgroup is empty, and TCP
endpoint `127.0.0.1:23022` is no longer listening.

## Newly exposed ordering conflict

VELVET-PIGEON lawfully closes the future-evidence identity cycle. It does not
close a different temporal composition gap between the frozen V0 driver and
production Docket:

1. Frozen V0 orders `admit_stage` -> `dispatch_exact_attempt` ->
   `reconcile_exact_attempt` -> factual qualification/NQ/Nightshift -> AG
   successor or terminal disposition. This is explicit in
   `governed_campaign_v0.rs` (`run_unattended_v0`, lines 803-823 at the stopped
   predecessor).
2. Production Docket's only governed-executor delivery path accepts a verified
   signed AG issuance, persists its custody, and only then calls the executor.
   This is explicit in Docket `governed_loop::accept`: the input is a
   `SignedIssuanceEnvelopeWireV1`; executor delivery occurs after that issuance
   is verified and custodied.
3. A stage reservation can be realized only after that stage's real Docket
   attempt and Porter run. It therefore cannot authorize the same already
   executed attempt without retroactive authority.
4. V0's post-settlement AG disposition authorizes only the enumerated
   successor. Stage 3 instead requires a terminal `HUMAN_REQUIRED` disposition
   and explicitly cannot authorize a successor.

Thus the real W5 worker-VM executor cannot be reached through production
Docket in the frozen V0 order unless some additional pre-execution AG issuance
law exists. No such bootstrap/current basis, spend mapping, or issuance is
present in the frozen three-reservation packet.

## Refused interpretations

- Calling the W5 adapter directly would bypass production Docket custody.
- Letting Docket accept a reservation or packet without a signed AG issuance
  would change Docket semantics.
- Treating the post-execution reservation realization as authorization for the
  already-completed attempt would create retroactive authority.
- Adding a bootstrap basis or an extra pre-execution AG spend would change the
  frozen V0 authority/continuation law and the required cardinality.
- Reinterpreting R1/R2/R3 as predecessor authorization slots would change the
  frozen reservation schema, which binds each R to its own stage realization.
- Spending AG authority after Stage 3 to represent `HUMAN_REQUIRED` would turn
  a terminal human boundary into authority and contradict V0.

These are materially different authority placements. Selecting one is human
architecture judgment, explicitly outside this resumed campaign's authority.
No W7 or W8 evidence can lawfully be manufactured while this ordering remains
unresolved.

## Cardinality at stop

All campaign cardinalities remain zero: reservations consumed, Docket
attempts, campaign Porter runs, Codex invocations, guest attempt workspaces,
candidate artifacts, host applications, NQ receipts, Nightshift realizations,
AG spends, and result commits. W8 was not started.

Classification: `HUMAN-JUDGMENT-REQUIRED`.
