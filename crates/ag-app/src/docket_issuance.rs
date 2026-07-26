//! `ag.docket-issuance:v1` — authenticated issuance for an exact Docket
//! prepared attempt.
//!
//! Docket prepares an exact attempt and projects it as a
//! `gwr:authz-request:v1` request. This module evaluates that request through
//! AG's existing decision path and, for an admitted decision only, emits one
//! immutable authenticated issuance record.
//!
//! **What crosses the boundary.** An issuance record is an *authenticated
//! immutable fact about a decision*. It is not authority: `Authority<F>`
//! remains non-serializable and stays inside this process, exactly as
//! `crates/ag-kernel` requires. Nothing here can reconstruct it, and the
//! record deliberately carries no capability, no secret, no Docket standing,
//! and no execution or admissibility verdict. Docket mints its own local
//! single-use standing after verifying this record; that standing is Docket's,
//! not ours.
//!
//! **Authenticity** reuses the repository's existing Ed25519 stack (ring
//! Ed25519, PKCS#8 v2 credentials, canonical base64url encodings,
//! domain-separated signature prefixes over strict canonical JSON) with one
//! new prefix for this statement kind. No new cryptography, no shared secret.
//!
//! **The decision token is sealed.** [`DocketDecision`] has private fields and
//! no public constructor, so it can only come from
//! [`DocketIssuanceOffice::decide`]. A caller cannot fabricate one and reach
//! [`DocketIssuanceOffice::issue`] with the catalog, actor, scope, effect-class,
//! and principal-chain checks skipped.
//!
//! **Dual canonical domains.** The request's exact bytes are hashed two ways
//! and both travel: `raw_sha256` (plain SHA-256 over the exact transported
//! bytes, the domain Docket also computes) and `ag_canonical_digest` (this
//! repository's domain-separated digest). Neither is recomputed from the
//! other, and neither is presented as interchangeable with the other, nor
//! with Docket's own prepared-attempt transcript digest, which we echo but
//! never recompute.

use ag_primitives::Digest;
use ag_protocol::{ProtocolError, canonical_json, strict_json_from_slice};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// Wire schema of the request this office accepts.
pub const SUPPORTED_REQUEST_SCHEMA: &str = "gwr:authz-request:v1";

/// Wire schema of the issuance envelope this office emits.
pub const ISSUANCE_SCHEMA: &str = "ag.docket-issuance:v1";

/// The one Docket effect class this office authorizes today.
pub const SUPPORTED_EFFECT_CLASS: &str = "git-ref-update:v1";

/// Domain separation for the issuance-body digest.
const BODY_DIGEST_DOMAIN: &str = "ag.docket-issuance.body.v1";

/// Domain separation for the request digest in this repository's domain.
const REQUEST_DIGEST_DOMAIN: &str = "ag.docket-issuance.request.v1";

/// Domain separation for the authority-consumption use digest.
const CONSUMPTION_DIGEST_DOMAIN: &str = "ag.docket-issuance.consumption.v1";

/// Ed25519 signature prefix, in the same shape as the local-RPC prefixes.
/// Distinct per statement kind so a signature cannot be reflected between
/// message types.
const SIGNATURE_PREFIX: &[u8] = b"ag-ng\0docket-issuance-signature\0v1\0";

// ---------------------------------------------------------------------------
// The request, as Docket projects it. Strictly decoded: an unknown field
// means this is not a `gwr:authz-request:v1` document.
// ---------------------------------------------------------------------------

/// One Docket authorization request. Testimony about a prepared proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketAuthzRequestV1 {
    /// Exact request schema.
    pub authz_request_format: String,
    /// Docket attempt identity.
    pub attempt: String,
    /// Docket lifecycle version of that attempt at projection time.
    pub attempt_version: u64,
    /// Docket effect class and version.
    pub effect_class: String,
    /// Docket's own prepared-attempt transcript digest. Echoed, never
    /// recomputed here: it belongs to Docket's canonical domain.
    pub prepared_attempt_digest: String,
    /// Governed repository as Docket records it.
    pub repository: String,
    /// Governed target reference.
    pub target_ref: String,
    /// Exact basis commit.
    pub basis: String,
    /// Exact admitted paths.
    pub allowed_paths: Vec<String>,
    /// Docket's own settlement premises, declared for our information. They
    /// remain Docket's premises; this office neither adopts nor verifies them.
    pub settlement_premises: Vec<String>,
    /// The actor Docket proposes to authorize for ratification.
    pub requested_actor: String,
    /// Human-readable goal, as recorded by Docket.
    pub goal: String,
    /// Docket work-request identity.
    pub work_request: String,
    /// Docket preparation-run identity.
    pub preparation_run: String,
    /// Docket candidate identity.
    pub candidate: String,
    /// Docket candidate content digest.
    pub candidate_digest: String,
    /// Docket clock reading for request creation.
    pub request_created_at_ms: u64,
    /// Docket clock reading for attempt admission.
    pub admitted_at_ms: u64,
}

// ---------------------------------------------------------------------------
// Decision context and catalog.
// ---------------------------------------------------------------------------

/// The exact decision context an issuance is bound to. Mirrors the fields the
/// kernel's `LifecycleOrigin` and catalog identity carry, in wire form; a
/// foreign context cannot be silently accepted downstream because it is
/// signed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceDecisionContextV1 {
    /// Authority domain of this office.
    pub authority_domain: String,
    /// Epoch within the domain.
    pub epoch: u64,
    /// Lifecycle nonce, canonical lowercase hex.
    pub lifecycle_nonce: String,
    /// Digest identity of the root-owned target catalog consulted.
    pub catalog_identity: String,
}

/// One root-owned Docket target entry. Docket repositories and refs enter this
/// office only through catalog entries: a request naming an uncatalogued
/// repository or reference is refused, never authorized on the caller's word.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketTargetDefinitionV1 {
    /// Opaque catalog key.
    pub target_id: String,
    /// Exact repository this target admits.
    pub repository: String,
    /// Exact reference this target admits.
    pub target_ref: String,
    /// Effect class this target admits.
    pub effect_class: String,
    /// Actors admitted to ratify against this target.
    pub admitted_actors: Vec<String>,
    /// Path prefixes this target admits; every requested path must be
    /// covered by one of them.
    pub admitted_path_prefixes: Vec<String>,
}

/// The root-owned Docket target catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketTargetCatalogV1 {
    /// Digest identity of the catalog bytes, supplied by the operator that
    /// installed it.
    pub identity: String,
    /// Entries by catalog key.
    pub targets: BTreeMap<String, DocketTargetDefinitionV1>,
}

impl DocketTargetCatalogV1 {
    /// The one entry admitting this repository, reference, and effect class.
    fn match_request(&self, request: &DocketAuthzRequestV1) -> Option<&DocketTargetDefinitionV1> {
        self.targets.values().find(|t| {
            t.repository == request.repository
                && t.target_ref == request.target_ref
                && t.effect_class == request.effect_class
        })
    }
}

// ---------------------------------------------------------------------------
// Premises and residuals.
// ---------------------------------------------------------------------------

/// One authorization premise. These are *this office's* premises about its own
/// decision — deliberately a different kind of thing from Docket's settlement
/// premises, and never merged with them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPremiseV1 {
    /// Stable premise kind.
    pub kind: String,
    /// Exact statement of what is assumed, not verified.
    pub statement: String,
}

/// Whether the decision carried residual obligations, and honestly why not.
///
/// `NoneRecorded` and `Unrepresented` are deliberately distinct: the first
/// says the decision produced no residuals; the second says this office cannot
/// currently express residuals at all, so their absence is not evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualStatusV1 {
    /// The decision recorded no residual obligations.
    NoneRecorded,
    /// This office cannot represent residual obligations yet; absence here is
    /// a limitation of the producer, not a finding about the decision.
    Unrepresented,
    /// Residual obligations are present in `items`.
    Present,
}

/// Residual obligations carried with the decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualObligationsV1 {
    /// Status of the residual set.
    pub status: ResidualStatusV1,
    /// Exact residual entries, when `status == Present`.
    pub items: Vec<UpstreamResidualV1>,
}

/// One upstream residual obligation, in the shape a downstream office can
/// carry without coercing it into a native obligation variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamResidualV1 {
    /// Source system that owns this obligation.
    pub source_system: String,
    /// Source-owned obligation identity.
    pub obligation_id: String,
    /// What the obligation is about.
    pub subject: String,
    /// Stable kind tag.
    pub kind: String,
    /// Exact statement.
    pub statement: String,
}

/// The authority-consumption fact. This office burns its own decision
/// authority under its own law; the receipt below is a *record* of that burn,
/// never a re-usable authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConsumptionV1 {
    /// Ledger that recorded the burn.
    pub ledger: String,
    /// Digest of the consumption event.
    pub use_digest: String,
}

// ---------------------------------------------------------------------------
// The issuance record.
// ---------------------------------------------------------------------------

/// The signed body of an issuance. Every field here is authenticated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketIssuanceBodyV1 {
    /// Immutable issuance identity (digest over this body without this field).
    pub issuance_id: String,
    /// The decision this issuance reports.
    pub decision_id: String,
    /// Issuing principal.
    pub issuer_principal: String,
    /// Issuing key identity.
    pub issuer_key_id: String,
    /// Exact decision context.
    pub decision_context: IssuanceDecisionContextV1,
    /// Principal chain that carried the decision, verbatim.
    pub principal_chain: Vec<String>,
    /// Catalog key admitted for this request.
    pub target_id: String,
    /// Identity and digests of the source request.
    pub request_source: RequestSourceV1,
    /// Docket-owned facts, echoed for binding. Docket re-compares every one of
    /// these against its own stored attempt; they are not a yardstick.
    pub docket: DocketBindingV1,
    /// Issue time, this office's clock.
    pub issued_at_unix_ms: u64,
    /// Expiry, this office's clock.
    pub expires_at_unix_ms: u64,
    /// This office's authorization premises.
    pub premises: Vec<AuthorizationPremiseV1>,
    /// Residual obligations and their honest status.
    pub residual_obligations: ResidualObligationsV1,
    /// The authority-burn fact.
    pub consumption: AuthorityConsumptionV1,
    /// Always `"admitted"`: a refusal is never an issuance.
    pub decision: String,
}

/// Identity and both canonical digests of the source request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSourceV1 {
    /// Exact request schema.
    pub schema: String,
    /// Plain SHA-256 over the exact transported request bytes, `sha256:<hex>`.
    /// Docket computes the same value in its own domain.
    pub raw_sha256: String,
    /// This repository's domain-separated digest of the same bytes. Distinct
    /// from `raw_sha256`; neither is derived from the other.
    pub ag_canonical_digest: String,
}

/// The Docket facts this issuance is bound to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketBindingV1 {
    /// Docket attempt identity.
    pub attempt: String,
    /// Docket prepared-attempt transcript digest, echoed from the request.
    pub prepared_attempt_digest: String,
    /// Docket effect class.
    pub effect_class: String,
    /// Governed repository.
    pub repository: String,
    /// Governed reference.
    pub target_ref: String,
    /// Exact basis.
    pub basis: String,
    /// Exact admitted paths.
    pub allowed_paths: Vec<String>,
    /// Actor authorized to ratify.
    pub requested_actor: String,
}

/// Authentication over the exact body bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceAuthenticationV1 {
    /// Signing key identity.
    pub signer_key_id: String,
    /// Canonical base64url-no-pad Ed25519 public key.
    pub signer_public_key: String,
    /// Canonical base64url-no-pad Ed25519 signature over the prefixed body.
    pub signature: String,
}

/// The transported issuance envelope. The body travels as exact bytes so that
/// verification never depends on two canonicalizers agreeing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketIssuanceEnvelopeV1 {
    /// Exact envelope schema.
    pub schema: String,
    /// Base64url-no-pad encoding of the exact canonical body bytes.
    pub body_b64: String,
    /// Authentication over those bytes.
    pub authentication: IssuanceAuthenticationV1,
}

// ---------------------------------------------------------------------------
// Refusals. A refusal is never an issuance.
// ---------------------------------------------------------------------------

/// Why this office declined to issue. Refusals accumulate nothing downstream:
/// no issuance exists, so no Docket standing can be minted.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IssuanceRefusal {
    /// The document is not a supported Docket request schema.
    #[error("unsupported request schema: expected {expected:?}, found {found:?}")]
    UnsupportedRequestSchema {
        /// The schema this office accepts.
        expected: String,
        /// The schema the document declared.
        found: String,
    },
    /// The document declares the supported schema but is not well formed.
    #[error("malformed request: {detail}")]
    MalformedRequest {
        /// What made the document unusable.
        detail: String,
    },
    /// The effect class is outside what this office authorizes.
    #[error("unsupported effect class: {found:?}")]
    UnsupportedEffectClass {
        /// The effect class the request named.
        found: String,
    },
    /// No catalog entry admits this repository, reference, and class.
    #[error("no catalog target admits repository {repository:?} ref {target_ref:?}")]
    TargetNotInCatalog {
        /// Repository the request named.
        repository: String,
        /// Reference the request named.
        target_ref: String,
    },
    /// The requested actor is not admitted for the matched target.
    #[error("actor {actor:?} is not admitted for target {target_id:?}")]
    ActorNotAdmitted {
        /// Actor the request asked to authorize.
        actor: String,
        /// Catalog target consulted.
        target_id: String,
    },
    /// A requested path is outside the target's admitted prefixes.
    #[error("path {path:?} is outside the admitted scope of target {target_id:?}")]
    PathOutsideScope {
        /// The path outside the target's admitted prefixes.
        path: String,
        /// Catalog target consulted.
        target_id: String,
    },
    /// The principal chain is empty or malformed.
    #[error("malformed principal chain: {detail}")]
    MalformedPrincipalChain {
        /// What made the chain unusable.
        detail: String,
    },
    /// This office's own decision authority is unavailable or already spent
    /// for this decision.
    #[error("authority unavailable: {detail}")]
    AuthorityUnavailable {
        /// Why this office's decision authority could not be spent.
        detail: String,
    },
    /// Canonicalization or signing failed.
    #[error("issuance production failed: {detail}")]
    ProductionFailed {
        /// What failed while producing or verifying the record.
        detail: String,
    },
}

impl From<ProtocolError> for IssuanceRefusal {
    fn from(e: ProtocolError) -> Self {
        Self::ProductionFailed {
            detail: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// The one-use decision ledger.
// ---------------------------------------------------------------------------

/// Records that a decision's authority was burned exactly once. Mirrors the
/// kernel's decision-ledger law: a decision digest consumes once, and a second
/// consumption refuses rather than reissuing.
#[derive(Clone, Debug, Default)]
pub struct IssuanceDecisionLedger {
    consumed: BTreeMap<String, String>,
}

impl IssuanceDecisionLedger {
    /// A fresh, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Burn the authority for one decision. The second call for the same
    /// decision refuses; this office never mints a second issuance from one
    /// decision's authority.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityUnavailable` when the decision was already consumed.
    pub fn consume(
        &mut self,
        decision_id: &str,
        context: &IssuanceDecisionContextV1,
    ) -> Result<AuthorityConsumptionV1, IssuanceRefusal> {
        if self.consumed.contains_key(decision_id) {
            return Err(IssuanceRefusal::AuthorityUnavailable {
                detail: format!("decision {decision_id} already consumed"),
            });
        }
        let use_digest = Digest::hash_domain(
            CONSUMPTION_DIGEST_DOMAIN,
            &canonical_json(&(decision_id, context))?,
        )
        .to_string();
        self.consumed
            .insert(decision_id.to_string(), use_digest.clone());
        Ok(AuthorityConsumptionV1 {
            ledger: "ag-ng.docket-issuance.decision-ledger.v1".into(),
            use_digest,
        })
    }

    /// The prior consumption of a decision, if any. Returning a record does
    /// not recreate consumption authority.
    #[must_use]
    pub fn prior_use(&self, decision_id: &str) -> Option<&String> {
        self.consumed.get(decision_id)
    }
}

// ---------------------------------------------------------------------------
// The office.
// ---------------------------------------------------------------------------

/// What this office needs to decide and issue.
pub struct DocketIssuanceOffice<'a> {
    /// Root-owned target catalog.
    pub catalog: &'a DocketTargetCatalogV1,
    /// Exact decision context.
    pub context: IssuanceDecisionContextV1,
    /// Principal chain carrying the decision.
    pub principal_chain: Vec<String>,
    /// Issuing principal identity.
    pub issuer_principal: String,
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Decode the exact request bytes into a validated request value.
///
/// # Errors
///
/// Refuses an unsupported schema or a malformed document. A document with an
/// unknown field is not a `gwr:authz-request:v1` request.
pub fn decode_request(bytes: &[u8]) -> Result<DocketAuthzRequestV1, IssuanceRefusal> {
    let probe: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| IssuanceRefusal::MalformedRequest {
            detail: format!("not JSON: {e}"),
        })?;
    let found = probe
        .get("authz_request_format")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(absent)")
        .to_string();
    if found != SUPPORTED_REQUEST_SCHEMA {
        return Err(IssuanceRefusal::UnsupportedRequestSchema {
            expected: SUPPORTED_REQUEST_SCHEMA.into(),
            found,
        });
    }
    strict_json_from_slice::<DocketAuthzRequestV1>(bytes).map_err(|e| {
        IssuanceRefusal::MalformedRequest {
            detail: e.to_string(),
        }
    })
}

impl DocketIssuanceOffice<'_> {
    /// Evaluate one exact request through this office's decision path.
    ///
    /// The decision consults the root-owned catalog for target admission,
    /// actor admission, and scope containment, and requires a well-formed
    /// principal chain. It never rewrites the request, and it authorizes
    /// nothing outside the catalog.
    ///
    /// # Errors
    ///
    /// Returns the typed refusal for any inadmissible request. A refusal
    /// produces no issuance and burns no authority.
    pub fn decide(
        &self,
        request: &DocketAuthzRequestV1,
    ) -> Result<DocketDecision, IssuanceRefusal> {
        if request.effect_class != SUPPORTED_EFFECT_CLASS {
            return Err(IssuanceRefusal::UnsupportedEffectClass {
                found: request.effect_class.clone(),
            });
        }
        if self.principal_chain.is_empty()
            || self.principal_chain.iter().any(|p| p.trim().is_empty())
        {
            return Err(IssuanceRefusal::MalformedPrincipalChain {
                detail: "principal chain must be non-empty with non-empty nodes".into(),
            });
        }
        let target = self.catalog.match_request(request).ok_or_else(|| {
            IssuanceRefusal::TargetNotInCatalog {
                repository: request.repository.clone(),
                target_ref: request.target_ref.clone(),
            }
        })?;
        if !target
            .admitted_actors
            .iter()
            .any(|a| a == &request.requested_actor)
        {
            return Err(IssuanceRefusal::ActorNotAdmitted {
                actor: request.requested_actor.clone(),
                target_id: target.target_id.clone(),
            });
        }
        for path in &request.allowed_paths {
            if !target
                .admitted_path_prefixes
                .iter()
                .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            {
                return Err(IssuanceRefusal::PathOutsideScope {
                    path: path.clone(),
                    target_id: target.target_id.clone(),
                });
            }
        }
        // The decision identity binds the exact request content, the context,
        // and the matched target: a changed request is a different decision.
        let decision_id = Digest::hash_domain(
            "ag.docket-issuance.decision.v1",
            &canonical_json(&(request, &self.context, &target.target_id))?,
        )
        .to_string();
        Ok(DocketDecision {
            decision_id,
            target_id: target.target_id.clone(),
        })
    }

    /// Produce one authenticated issuance for an admitted decision, burning
    /// this office's decision authority exactly once.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the decision authority is unavailable or when
    /// canonicalization or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        request: &DocketAuthzRequestV1,
        request_bytes: &[u8],
        decision: &DocketDecision,
        ledger: &mut IssuanceDecisionLedger,
        signer: &IssuanceSigner,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        premises: Vec<AuthorizationPremiseV1>,
        residual_obligations: ResidualObligationsV1,
    ) -> Result<DocketIssuanceEnvelopeV1, IssuanceRefusal> {
        let consumption = ledger.consume(&decision.decision_id, &self.context)?;
        let request_source = RequestSourceV1 {
            schema: request.authz_request_format.clone(),
            raw_sha256: sha256_prefixed(request_bytes),
            ag_canonical_digest: Digest::hash_domain(REQUEST_DIGEST_DOMAIN, request_bytes)
                .to_string(),
        };
        let docket = DocketBindingV1 {
            attempt: request.attempt.clone(),
            prepared_attempt_digest: request.prepared_attempt_digest.clone(),
            effect_class: request.effect_class.clone(),
            repository: request.repository.clone(),
            target_ref: request.target_ref.clone(),
            basis: request.basis.clone(),
            allowed_paths: request.allowed_paths.clone(),
            requested_actor: request.requested_actor.clone(),
        };
        // The issuance identity is a digest over the body without it, so the
        // identity cannot disagree with the content it names.
        let identity_input = (
            &decision.decision_id,
            &self.issuer_principal,
            signer.key_id(),
            &self.context,
            &self.principal_chain,
            &decision.target_id,
            &request_source,
            &docket,
            issued_at_unix_ms,
            expires_at_unix_ms,
            &premises,
            &residual_obligations,
            &consumption,
        );
        let issuance_id =
            Digest::hash_domain(BODY_DIGEST_DOMAIN, &canonical_json(&identity_input)?).to_string();
        let body = DocketIssuanceBodyV1 {
            issuance_id,
            decision_id: decision.decision_id.clone(),
            issuer_principal: self.issuer_principal.clone(),
            issuer_key_id: signer.key_id().to_string(),
            decision_context: self.context.clone(),
            principal_chain: self.principal_chain.clone(),
            target_id: decision.target_id.clone(),
            request_source,
            docket,
            issued_at_unix_ms,
            expires_at_unix_ms,
            premises,
            residual_obligations,
            consumption,
            decision: "admitted".into(),
        };
        let body_bytes = canonical_json(&body)?;
        let signature = signer.sign(&body_bytes);
        Ok(DocketIssuanceEnvelopeV1 {
            schema: ISSUANCE_SCHEMA.into(),
            body_b64: URL_SAFE_NO_PAD.encode(&body_bytes),
            authentication: IssuanceAuthenticationV1 {
                signer_key_id: signer.key_id().to_string(),
                signer_public_key: signer.public_key_base64url(),
                signature,
            },
        })
    }
}

/// An admitted decision. Carries no authority: the issuance is produced only
/// by `issue`, and only after the decision authority is burned.
///
/// The fields are private and there is no public constructor, so a decision
/// token cannot be fabricated outside [`DocketIssuanceOffice::decide`]. This is
/// the same law the kernel applies to `Authority` and its book references: the
/// object that unlocks the next stage is unconstructable except through the
/// checked path. Without it, a caller of this crate could hand `issue` an
/// arbitrary `decision_id` and `target_id` and bypass effect-class, catalog,
/// actor, scope, and principal-chain validation entirely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocketDecision {
    decision_id: String,
    target_id: String,
}

impl DocketDecision {
    /// Identity of this decision over its exact inputs.
    #[must_use]
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    /// The catalog target admitted for this decision.
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// Ed25519 signing identity for issuances. Debug is unavailable, the key
/// material is never exposed, and this type signs exactly one statement kind.
pub struct IssuanceSigner {
    key_id: String,
    public_key: [u8; 32],
    key_pair: Ed25519KeyPair,
}

impl IssuanceSigner {
    /// Load a signer from Ed25519 PKCS#8 v2 bytes, as the local-RPC signer
    /// does.
    ///
    /// # Errors
    ///
    /// Returns a refusal for invalid key material.
    pub fn from_pkcs8(key_id: impl Into<String>, bytes: &[u8]) -> Result<Self, IssuanceRefusal> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| IssuanceRefusal::ProductionFailed {
                detail: "invalid Ed25519 PKCS#8 v2 key".into(),
            })?;
        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().map_err(|_| {
            IssuanceRefusal::ProductionFailed {
                detail: "invalid Ed25519 public key length".into(),
            }
        })?;
        Ok(Self {
            key_id: key_id.into(),
            public_key,
            key_pair,
        })
    }

    /// The non-secret key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The canonical base64url-no-pad public key.
    #[must_use]
    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    fn sign(&self, body_bytes: &[u8]) -> String {
        let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + body_bytes.len());
        message.extend_from_slice(SIGNATURE_PREFIX);
        message.extend_from_slice(body_bytes);
        URL_SAFE_NO_PAD.encode(self.key_pair.sign(&message).as_ref())
    }
}

/// Verify an issuance envelope's authentication over its exact body bytes and
/// return the decoded body.
///
/// Provided so this office's own tests, and any conformance harness, check the
/// same statement the consumer checks. It grants nothing: a verified issuance
/// is an authenticated fact about a decision, never authority.
///
/// # Errors
///
/// Returns a refusal for a bad encoding, an unknown schema, a malformed body,
/// or an invalid signature.
pub fn verify_envelope(
    envelope: &DocketIssuanceEnvelopeV1,
) -> Result<DocketIssuanceBodyV1, IssuanceRefusal> {
    if envelope.schema != ISSUANCE_SCHEMA {
        return Err(IssuanceRefusal::UnsupportedRequestSchema {
            expected: ISSUANCE_SCHEMA.into(),
            found: envelope.schema.clone(),
        });
    }
    let body_bytes = URL_SAFE_NO_PAD.decode(&envelope.body_b64).map_err(|_| {
        IssuanceRefusal::MalformedRequest {
            detail: "body_b64 is not canonical base64url-no-pad".into(),
        }
    })?;
    let public_key = URL_SAFE_NO_PAD
        .decode(&envelope.authentication.signer_public_key)
        .map_err(|_| IssuanceRefusal::MalformedRequest {
            detail: "signer_public_key is not canonical base64url-no-pad".into(),
        })?;
    let signature = URL_SAFE_NO_PAD
        .decode(&envelope.authentication.signature)
        .map_err(|_| IssuanceRefusal::MalformedRequest {
            detail: "signature is not canonical base64url-no-pad".into(),
        })?;
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + body_bytes.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&body_bytes);
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&message, &signature)
        .map_err(|_| IssuanceRefusal::ProductionFailed {
            detail: "issuance signature is invalid".into(),
        })?;
    strict_json_from_slice::<DocketIssuanceBodyV1>(&body_bytes).map_err(|e| {
        IssuanceRefusal::MalformedRequest {
            detail: format!("issuance body: {e}"),
        }
    })
}
