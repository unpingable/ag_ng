# Retired Docket issuance V1

`ag.docket-issuance:v1` and `gwr:authz-request:v1` are retained as historical
names only. Their former producer used a caller-owned in-memory decision ledger,
caller-selected decision inputs, and caller-provided signing material. It was not
bound to the canonical governed-campaign Store spend and is therefore not a
production authorization surface.

R3 removes the producer module, its `vertical_issue` Cargo example, and its
integration producer tests. No AG library or binary can construct, decide, sign,
or issue this format. Docket likewise has no production intake that can turn the
format into standing or custody.

The sole consequence-bearing repair issuance root is
`GovernedCampaignServiceV1`, which commits durable spend before its private
issuance signer is usable and emits the closed governed-loop V2 contract.

Historical records may continue to name the V1 schemas. Those names and bytes are
evidence about prior development runs; decoding or displaying them grants no
standing, spend, custody, execution, successor, or current authorization.
