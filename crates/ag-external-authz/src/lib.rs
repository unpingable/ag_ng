//! External-occurrence authorization daemon for Agent Governor NG.
//!
//! `ag-external-authorizer` lets a separate same-host system (a Codex fork)
//! ask AG to authorize one exact external action occurrence. It drives
//! [`ag_app::governed_loop::CampaignEngineV1`] as a library with in-process
//! port fixtures and uses only shipped AG semantics: it introduces no new
//! kernel types and evaluates no policy inside AG beyond the root-owned
//! exact-work catalog admission the engine already owns.
//!
//! # Wire contract
//!
//! One short-lived Unix-socket connection per request; frames are JSON with a
//! big-endian u32 length prefix. Requests are
//! `ag.external-authorization-request:v1` (see [`protocol`]); responses are
//! exactly one of:
//!
//! - `ag.external-authorization:v1` — a real AG decision (`authorized`,
//!   `refused`, or `indeterminate`);
//! - `ag.external-authorization-error:v1` — **not a decision**: invalid input
//!   (action-digest mismatch, non-`continue` admissibility, stage/work-schema
//!   inconsistency, malformed frame) or daemon-internal failure (state-dir
//!   I/O, unreadable/malformed standing store, unexpected engine errors).
//!   Daemon-internal failures are never mapped to `refused` or
//!   `indeterminate`.
//!
//! # Custody of the exact-work catalog
//!
//! Per request the daemon builds an [`ag_app::governed_loop::ExactWorkCatalogV2`]
//! under its own custody containing exactly one entry —
//! `(work_schema, subject_digest, scope_digest, TypedBasis(basis))` — that
//! registers the exact occurrence class for this adjudication only. The
//! catalog derivation is adapter custody: it binds the request's own
//! digests verbatim and can never widen authority, because the independent
//! authority input is the root-owned standing mandate store
//! ([`ag_app::standing_authority::StandingMandateStoreV1`]), which the daemon
//! only reads.
//!
//! # Replay guard and parked occurrences
//!
//! Each `authorization_occurrence_id` is adjudicated at most once: the
//! campaign store lives at `<state-dir>/<occurrence-id>/campaign.sqlite` and
//! `CampaignStoreV1::create` refuses to reuse an existing path, so a replayed
//! occurrence id is refused with `occurrence_already_adjudicated` even across
//! daemon restarts. After a successful spend the occurrence parks in
//! `ProgramCounterV1::AuthorizationConsumed`: the spend is durably committed,
//! this deployment has no Docket custody, and the daemon deliberately never
//! dispatches, settles, or re-spends.
//!
//! # Deployment custody
//!
//! This deployment is same-UID local custody with **no cryptographic
//! authentication**: the socket, state directory, and standing store are
//! protected by filesystem ownership/mode checks only (see [`daemon`]). The
//! signed RPC transport in `ag-app` is intentionally not used here.
//!
//! # Determinism
//!
//! Given identical fixtures (standing store content, resolver identities,
//! TTLs) and identical wall-clock readings, adjudication is deterministic in
//! all decision-relevant fields: the decision, refusal code, content-derived
//! `mandate_ref`, and standing expiry. Fields that bind the occurrence
//! identity (`campaign_id`, `ag_occurrence_id`, `authorization_ref`,
//! `spend_ref`, `issuance_ref`, `standing_resolution_ref`) are derived over
//! the occurrence key and therefore differ across distinct occurrence ids.
//! The same occurrence id can never be adjudicated twice (replay guard), so
//! cross-occurrence comparison is the only meaningful determinism check.

pub mod adjudicate;
pub mod admissibility;
pub mod custody;
pub mod daemon;
pub mod framing;
pub mod lookup;
pub mod protocol;
pub mod standing;
