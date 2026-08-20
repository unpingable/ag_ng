#![allow(
    clippy::missing_errors_doc,
    reason = "StandingAuthorityErrorV1 is the closed error contract for the standing authority"
)]

//! The production standing authority: a read-only, present-tense answer over
//! a local mandate store.
//!
//! Standing answers exactly one question:
//!
//! > Does the designated external governance authority presently maintain a
//! > mandate under which this `(subject, scope)` relationship is eligible for
//! > AG authorization?
//!
//! The store is a deterministic canonical JSON document loaded fresh on
//! every invocation, so mandate changes are visible to the next resolution
//! with no cache machinery. There is no write API: mandates change out of
//! band by replacing the document.
//!
//! Standing is a revocable prerequisite to authorization, never authority:
//! nothing here is signed, and no answer can be presented to Docket or
//! substituted for AG's one-use spend. Mandate-store truthfulness is an
//! environmental/deployment assumption — the authority process is trusted by
//! deployment identity, and content addressing binds provenance to the exact
//! mandate content evaluated, not to its truth.

use std::collections::BTreeSet;

use ag_campaign::governed::{
    CurrentStandingResolutionV2, MandateRefV1, ObservationRefV1, OccurrenceKeyV1, ProposalRefV1,
    STANDING_RESOLUTION_SCHEMA_V2, StandingCurrentnessRefV1, StandingResolutionRefV1,
    StandingStatusV1,
};
use ag_primitives::{Digest, JcsDocument};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire schema for the standing request consumed from stdin. Mirrors the
/// exact request AG's standing port sends.
pub const STANDING_AUTHORITY_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.standing-request/v1";
/// Wire schema for the local mandate-store document.
pub const STANDING_MANDATE_STORE_SCHEMA_V1: &str = "ag.governed-loop.standing-mandate-store/v1";

const MANDATE_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.standing-mandate/v1";
const CURRENTNESS_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.standing-currentness/v1";
const RESOLUTION_DIGEST_DOMAIN_V1: &str = "ag.governed-loop.standing-resolution/v2";

/// Errors of the standing authority. These are process failures, never
/// encoded as standing statuses.
#[derive(Debug, Error)]
pub enum StandingAuthorityErrorV1 {
    /// The wire request is malformed.
    #[error("invalid standing request: {0}")]
    Request(String),
    /// The mandate store is malformed or ambiguous.
    #[error("invalid standing mandate store: {0}")]
    Store(String),
    /// Resolver configuration is invalid.
    #[error("invalid standing resolver configuration: {0}")]
    Configuration(String),
}

fn canonical_digest(domain: &str, value: &impl Serialize) -> Digest {
    let document = JcsDocument::canonicalize(value)
        .expect("standing authority values contain only strict JCS-compatible fields");
    Digest::hash_domain(domain, document.as_bytes())
}

/// The declared state of one mandate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatusV1 {
    /// Governance standing is presently maintained.
    Active,
    /// Governance standing is explicitly revoked.
    Revoked,
}

/// One mandate: the semantic content of a governance-standing declaration
/// for one exact `(subject, scope)` relationship. It has no identity field;
/// its identity is derived from this exact content.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingMandateV1 {
    /// Exact governed subject.
    pub subject: Digest,
    /// Exact governed scope.
    pub scope: Digest,
    /// Monotonic mandate generation within `(subject, scope)`.
    pub generation: u64,
    /// Declared mandate state.
    pub status: MandateStatusV1,
    /// Exclusive end of the mandate's own validity.
    pub valid_until_unix_ms: u64,
}

impl StandingMandateV1 {
    /// The content-derived mandate identity. Every semantic field
    /// participates; there is no caller-editable identity field to lie with.
    #[must_use]
    pub fn mandate_ref(&self) -> MandateRefV1 {
        MandateRefV1::from_digest(canonical_digest(MANDATE_DIGEST_DOMAIN_V1, self))
    }
}

/// The local read-only mandate store. Entries must be strictly ordered by
/// `(subject, scope, generation)`, which makes the document canonical and
/// makes duplicate/conflicting records a load error rather than a silent
/// "last one wins".
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingMandateStoreV1 {
    /// Exact schema.
    pub schema: String,
    /// Canonically ordered mandate records.
    pub mandates: Vec<StandingMandateV1>,
}

impl StandingMandateStoreV1 {
    /// Store validity: exact schema and strict `(subject, scope, generation)`
    /// ordering, which rejects duplicates and conflicting same-generation
    /// records.
    pub fn validate(&self) -> Result<(), StandingAuthorityErrorV1> {
        if self.schema != STANDING_MANDATE_STORE_SCHEMA_V1 {
            return Err(StandingAuthorityErrorV1::Store(format!(
                "unsupported mandate store schema {}",
                self.schema
            )));
        }
        if self
            .mandates
            .iter()
            .map(|mandate| {
                (
                    mandate.subject.clone(),
                    mandate.scope.clone(),
                    mandate.generation,
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
            != self.mandates.len()
        {
            return Err(StandingAuthorityErrorV1::Store(
                "duplicate mandate record for one subject/scope/generation".into(),
            ));
        }
        if !self.mandates.windows(2).all(|pair| {
            (&pair[0].subject, &pair[0].scope, pair[0].generation)
                < (&pair[1].subject, &pair[1].scope, pair[1].generation)
        }) {
            return Err(StandingAuthorityErrorV1::Store(
                "mandate records are not in canonical (subject, scope, generation) order".into(),
            ));
        }
        Ok(())
    }

    /// The present-tense mandate for one exact `(subject, scope)`: the
    /// highest declared generation, or none.
    fn current_mandate(&self, subject: &Digest, scope: &Digest) -> Option<&StandingMandateV1> {
        self.mandates
            .iter()
            .filter(|mandate| &mandate.subject == subject && &mandate.scope == scope)
            .max_by_key(|mandate| mandate.generation)
    }
}

/// The exact standing request, mirrored owned form of AG's standing-port
/// request. Only `subject`, `scope`, and `now_unix_ms` carry mandate
/// semantics; the remaining fields are exact decision-context bindings that
/// make the answer non-replayable across occurrences.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandingAuthorityRequestV1 {
    /// Exact request schema.
    pub schema: String,
    /// Occurrence being resolved.
    pub key: OccurrenceKeyV1,
    /// Exact observation basis.
    pub observation: ObservationRefV1,
    /// Exact proposal basis.
    pub proposal: ProposalRefV1,
    /// Exact subject.
    pub subject: Digest,
    /// Exact scope.
    pub scope: Digest,
    /// AG's consequence-time clock reading; the evaluation instant.
    pub now_unix_ms: u64,
}

impl StandingAuthorityRequestV1 {
    /// Strict syntactic validation.
    pub fn validate(&self) -> Result<(), StandingAuthorityErrorV1> {
        if self.schema != STANDING_AUTHORITY_REQUEST_SCHEMA_V1 {
            return Err(StandingAuthorityErrorV1::Request(format!(
                "unsupported standing request schema {}",
                self.schema
            )));
        }
        Ok(())
    }
}

/// Resolver configuration: deployment identity and the authority's own
/// maximum answer lease. AG independently enforces its kernel maximum on top.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingResolverConfigV1 {
    /// Exact identity AG is configured to expect.
    pub resolver_id: String,
    /// The authority's maximum answer lifetime.
    pub answer_ttl_ms: u64,
}

impl StandingResolverConfigV1 {
    /// Configuration validity; neither field may be a wildcard.
    pub fn validate(&self) -> Result<(), StandingAuthorityErrorV1> {
        if self.resolver_id.trim().is_empty() {
            return Err(StandingAuthorityErrorV1::Configuration(
                "resolver_id must be explicitly configured and nonempty".into(),
            ));
        }
        if self.answer_ttl_ms == 0 {
            return Err(StandingAuthorityErrorV1::Configuration(
                "answer_ttl_ms must be positive".into(),
            ));
        }
        Ok(())
    }
}

fn answer(
    request: &StandingAuthorityRequestV1,
    config: &StandingResolverConfigV1,
    mandate: MandateRefV1,
    status: StandingStatusV1,
    expires_at_unix_ms: u64,
) -> CurrentStandingResolutionV2 {
    #[derive(Serialize)]
    struct CurrentnessBasisV1<'a> {
        mandate: &'a MandateRefV1,
        status: StandingStatusV1,
        subject: &'a Digest,
        scope: &'a Digest,
        resolver_id: &'a str,
        resolved_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }
    #[derive(Serialize)]
    struct ResolutionBasisV1<'a> {
        key: &'a OccurrenceKeyV1,
        observation: &'a ObservationRefV1,
        proposal: &'a ProposalRefV1,
        currentness: &'a StandingCurrentnessRefV1,
    }
    let currentness = StandingCurrentnessRefV1::from_digest(canonical_digest(
        CURRENTNESS_DIGEST_DOMAIN_V1,
        &CurrentnessBasisV1 {
            mandate: &mandate,
            status,
            subject: &request.subject,
            scope: &request.scope,
            resolver_id: &config.resolver_id,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms,
        },
    ));
    let resolution = StandingResolutionRefV1::from_digest(canonical_digest(
        RESOLUTION_DIGEST_DOMAIN_V1,
        &ResolutionBasisV1 {
            key: &request.key,
            observation: &request.observation,
            proposal: &request.proposal,
            currentness: &currentness,
        },
    ));
    CurrentStandingResolutionV2 {
        schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
        resolution,
        currentness,
        mandate,
        key: request.key.clone(),
        observation: request.observation.clone(),
        proposal: request.proposal.clone(),
        subject: request.subject.clone(),
        scope: request.scope.clone(),
        resolver_id: config.resolver_id.clone(),
        status,
        resolved_at_unix_ms: request.now_unix_ms,
        expires_at_unix_ms,
    }
}

/// Resolve one standing request against the mandate store.
///
/// Status selection for the exact `(subject, scope)` of the request:
///
/// - no mandate at any generation → `Absent`;
/// - the highest generation is expired at `now` (`valid_until <= now`;
///   equality is expired) → `Expired`;
/// - the highest generation is declared revoked → `Revoked`;
/// - otherwise → `Current`, naming the content-derived mandate ref.
///
/// `Superseded` is intentionally never produced: the request does not name a
/// mandate generation, so the only honest present-tense answer concerns the
/// highest generation; older generations simply do not govern.
pub fn resolve_standing(
    store: &StandingMandateStoreV1,
    request: &StandingAuthorityRequestV1,
    config: &StandingResolverConfigV1,
) -> Result<CurrentStandingResolutionV2, StandingAuthorityErrorV1> {
    config.validate()?;
    request.validate()?;
    store.validate()?;
    let answer_expiry = request
        .now_unix_ms
        .checked_add(config.answer_ttl_ms)
        .ok_or_else(|| {
            StandingAuthorityErrorV1::Request("now_unix_ms + answer_ttl_ms overflows".into())
        })?;
    let Some(mandate) = store.current_mandate(&request.subject, &request.scope) else {
        return Ok(answer(
            request,
            config,
            // The empty-mandate sentinel: no mandate content exists to
            // address, so the identity is the domain-separated digest of the
            // absent marker. AG never consumes the mandate ref of a
            // non-Current resolution beyond recording it.
            MandateRefV1::from_digest(Digest::hash_domain(MANDATE_DIGEST_DOMAIN_V1, b"absent")),
            StandingStatusV1::Absent,
            answer_expiry,
        ));
    };
    if mandate.valid_until_unix_ms <= request.now_unix_ms {
        return Ok(answer(
            request,
            config,
            mandate.mandate_ref(),
            StandingStatusV1::Expired,
            answer_expiry,
        ));
    }
    if mandate.status == MandateStatusV1::Revoked {
        return Ok(answer(
            request,
            config,
            mandate.mandate_ref(),
            StandingStatusV1::Revoked,
            answer_expiry,
        ));
    }
    // A Current answer never outlives the mandate's own remaining validity.
    let expires_at = answer_expiry.min(mandate.valid_until_unix_ms);
    Ok(answer(
        request,
        config,
        mandate.mandate_ref(),
        StandingStatusV1::Current,
        expires_at,
    ))
}
