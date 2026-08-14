#![allow(
    clippy::missing_errors_doc,
    reason = "GovernedPortErrorV1 is the closed error contract for all concrete process ports"
)]
#![allow(
    clippy::wildcard_imports,
    reason = "the port module implements the governed kernel's complete external-boundary vocabulary"
)]

//! Concrete process boundaries for the canonical governed loop.
//!
//! Each invocation is a fresh request to an external owner.  Responses may be
//! retained as evidence, but this module never turns response bytes into a
//! reusable resolver, standing instrument, or campaign transition.  Docket
//! receives an authenticated exact AG issuance and remains the only process
//! permitted to invoke the configured executor adapter.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::governed_store::StoreIssuanceSigningPermitV1;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::JcsDocument;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Schema for the authenticated canonical AG issuance handed to Docket.
pub const SIGNED_AG_ISSUANCE_SCHEMA_V2: &str = "ag.governed-loop.signed-issuance/v2";
/// Schema for process observation-resolution requests.
pub const OBSERVATION_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.observation-request/v1";
/// Schema for process standing-resolution requests.
pub const STANDING_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.standing-request/v1";

/// Exact closed signature-domain prefix for the V2 issuance wire contract.
pub const SIGNATURE_PREFIX_V2: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v2\0";

fn deserialize_present_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Authentication metadata for one exact canonical issuance body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceAuthenticationV2 {
    /// AG principal trusted by the Docket deployment.
    pub issuer_principal: String,
    /// Exact configured signing-key identity.
    pub signer_key_id: String,
    /// Canonical base64url-no-pad Ed25519 public key.
    pub signer_public_key: String,
    /// Signature over the domain prefix followed by the exact body bytes.
    pub signature: String,
}

/// Authenticated immutable envelope for one already-spent AG issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgIssuanceEnvelopeV2 {
    /// Exact envelope schema.
    pub schema: String,
    /// Canonical `AgIssuanceV2` bytes, base64url-no-pad.
    pub body_b64: String,
    /// Exact authentication over `body_b64`'s decoded bytes.
    pub authentication: AgIssuanceAuthenticationV2,
}

/// AG's configured issuance signer.  It does not create or spend authority;
/// it authenticates an issuance that already exists in the spend journal.
pub(crate) struct AgIssuanceSignerV2 {
    issuer_principal: String,
    key_id: String,
    key_pair: Ed25519KeyPair,
}

impl AgIssuanceSignerV2 {
    /// Parses one explicit PKCS#8 v2 Ed25519 credential.
    pub(crate) fn from_pkcs8(
        issuer_principal: impl Into<String>,
        key_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, GovernedPortErrorV1> {
        let issuer_principal = issuer_principal.into();
        let key_id = key_id.into();
        if issuer_principal.is_empty() || key_id.is_empty() {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "issuer principal and key ID must be nonempty",
            ));
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| GovernedPortErrorV1::InvalidSigningKey)?;
        Ok(Self {
            issuer_principal,
            key_id,
            key_pair,
        })
    }

    /// Consumes the Store-owned one-use permission before authenticating the
    /// exact durable issuance. Raw issuance bytes are never a signing input.
    fn sign_permitted(
        &self,
        permit: StoreIssuanceSigningPermitV1,
    ) -> Result<(AgIssuanceV2, SignedAgIssuanceEnvelopeV2), GovernedPortErrorV1> {
        let issuance = permit.into_issuance();
        let body = JcsDocument::canonicalize(&issuance)
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V2.len() + body.as_bytes().len());
        signed.extend_from_slice(SIGNATURE_PREFIX_V2);
        signed.extend_from_slice(body.as_bytes());
        let signature = self.key_pair.sign(&signed);
        let envelope = SignedAgIssuanceEnvelopeV2 {
            schema: SIGNED_AG_ISSUANCE_SCHEMA_V2.to_owned(),
            body_b64: URL_SAFE_NO_PAD.encode(body.as_bytes()),
            authentication: AgIssuanceAuthenticationV2 {
                issuer_principal: self.issuer_principal.clone(),
                signer_key_id: self.key_id.clone(),
                signer_public_key: URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref()),
                signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
            },
        };
        Ok((issuance, envelope))
    }
}

/// Exact owned request sent to an observation owner on every live resolution.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationCommandRequestV1<'a> {
    schema: &'static str,
    key: &'a OccurrenceKeyV1,
    observation: &'a ObservationRefV1,
    subject: &'a ag_primitives::Digest,
    now_unix_ms: u64,
}

/// Exact owned request sent to Standing/Docket on every live resolution.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct StandingCommandRequestV1<'a> {
    schema: &'static str,
    key: &'a OccurrenceKeyV1,
    observation: &'a ObservationRefV1,
    proposal: &'a ProposalRefV1,
    subject: &'a ag_primitives::Digest,
    scope: &'a ag_primitives::Digest,
    now_unix_ms: u64,
}

const DOCKET_SCOPE_REQUIREMENT_SCHEMA_V1: &str =
    "docket.governed-repair.scope-expansion-required/v1";
const DOCKET_READJUDICATION_REQUIREMENT_SCHEMA_V1: &str =
    "docket.governed-repair.readjudication-required/v1";
const DOCKET_CHECKPOINT_SCHEMA_V1: &str = "docket.governed-repair.checkpoint/v1";
const DOCKET_SEALED_RESULT_SCHEMA_V1: &str = "docket.governed-repair.sealed-result/v1";

/// Strict private wire mirror of Docket's richer post-spend result.  AG never
/// deserializes this directly into authority-sensitive campaign types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketGovernedRepairBindingWireV1 {
    campaign: CampaignId,
    occurrence: String,
    proposal: ProposalRefV1,
    observation: ObservationRefV1,
    standing_resolution: StandingResolutionRefV1,
    admission_decision: AdmissionDecisionRefV1,
    spend: AgSpendRefV1,
    issuance: AgIssuanceRefV1,
    custody: DocketCustodyRefV1,
    attempt: DocketAttemptRefV1,
    executor_result: ag_primitives::Digest,
    executor_binding: ag_primitives::Digest,
    original_scope: CanonicalEffectScopeV1,
    original_scope_digest: ag_primitives::Digest,
    effect_journal_digest: ag_primitives::Digest,
    reported_authorized_effects_occurred: bool,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    idempotency: ag_primitives::Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketBlockedEffectWireV1 {
    effect_class: String,
    resource: String,
    path: String,
    operation: CanonicalEffectOperationV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketScopeExpansionWireV1 {
    schema: String,
    requirement_identity: ag_primitives::Digest,
    binding: DocketGovernedRepairBindingWireV1,
    requested_delta: CanonicalEffectScopeV1,
    requested_delta_digest: ag_primitives::Digest,
    blocked_effect: DocketBlockedEffectWireV1,
    reason: ag_primitives::Digest,
    dependency_evidence: Vec<ag_primitives::Digest>,
    no_unauthorized_effect_reported: bool,
    limitations: Vec<ag_primitives::Digest>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketReadjudicationWireV1 {
    schema: String,
    requirement_identity: ag_primitives::Digest,
    binding: DocketGovernedRepairBindingWireV1,
    question: ag_primitives::Digest,
    evidence_census: Vec<ag_primitives::Digest>,
    diagnostic_census: Vec<ag_primitives::Digest>,
    bounded_alternatives: Vec<ag_primitives::Digest>,
    unresolved_facts: Vec<ag_primitives::Digest>,
    adjudication_scope: CanonicalEffectScopeV1,
    no_unauthorized_effect_reported: bool,
    limitations: Vec<ag_primitives::Digest>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "requirement",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum DocketSealedRequirementWireV1 {
    ScopeExpansionRequired(DocketScopeExpansionWireV1),
    ReadjudicationRequired(DocketReadjudicationWireV1),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketImmutableCheckpointWireV1 {
    repository_identity: ag_primitives::Digest,
    commit: String,
    tree: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    diff_identity: Option<ag_primitives::Digest>,
    content_manifest_identity: ag_primitives::Digest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketCheckpointWireV1 {
    schema: String,
    checkpoint: DocketCheckpointRefV1,
    issuance: AgIssuanceRefV1,
    custody: DocketCustodyRefV1,
    attempt: DocketAttemptRefV1,
    executor_binding: ag_primitives::Digest,
    executor_result: ag_primitives::Digest,
    executor_receipt: ReceiptRefV1,
    requirement_kind: String,
    requirement_identity: ag_primitives::Digest,
    effect_journal_digest: ag_primitives::Digest,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_some"
    )]
    immutable_work_checkpoint: Option<DocketImmutableCheckpointWireV1>,
    idempotency: ag_primitives::Digest,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketSealedResultWireV1 {
    schema: String,
    sealed_result: DocketSealedResultRefV1,
    checkpoint: DocketCheckpointWireV1,
    outcome: DocketSealedRequirementWireV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DocketIssuanceRefusalClassWireV1 {
    IssuanceInvalid,
    IssuanceExpired,
    CheckpointInvalid,
    StandingInvalid,
    InstrumentSubstitution,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketIssuanceRefusalWireV1 {
    schema: String,
    refusal: ag_primitives::Digest,
    issuance: AgIssuanceRefV1,
    campaign: CampaignId,
    occurrence: OccurrenceId,
    refusal_class: DocketIssuanceRefusalClassWireV1,
    reason_code: String,
    evidence: ag_primitives::Digest,
    refused_at_unix_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum DocketAcceptanceWireV1 {
    Refused(DocketIssuanceRefusalWireV1),
    Custody(DocketCustodyV1),
    GovernedRepairRequired {
        custody: DocketCustodyV1,
        result: Box<DocketSealedResultWireV1>,
    },
}

/// Exact R2 Docket settlement wire. The cumulative journal is required on the
/// production boundary even though the campaign model retains a decoder-only
/// optional spelling for rejected-R1 historical Store rows.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketSettlementWireR2 {
    schema: String,
    settlement: SettlementRefV1,
    issuance: AgIssuanceRefV1,
    attempt: DocketAttemptRefV1,
    executor_marker: ExecutorAttemptMarkerRefV1,
    receipt: ReceiptRefV1,
    outcome: KnownOutcomeV1,
    cumulative_effect_journal_identity: ag_primitives::Digest,
    settled_at_unix_ms: u64,
}

impl DocketSettlementWireR2 {
    fn into_model(self) -> Result<DocketSettlementV1, GovernedPortErrorV1> {
        let value = DocketSettlementV1 {
            schema: self.schema,
            settlement: self.settlement,
            issuance: self.issuance,
            attempt: self.attempt,
            executor_marker: self.executor_marker,
            receipt: self.receipt,
            outcome: self.outcome,
            cumulative_effect_journal_identity: Some(self.cumulative_effect_journal_identity),
            settled_at_unix_ms: self.settled_at_unix_ms,
        };
        if value.settlement
            != value
                .expected_reference()
                .map_err(|_| malformed("Docket complete settlement identity is invalid"))?
        {
            return Err(malformed(
                "Docket complete settlement identity substitution",
            ));
        }
        Ok(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum DocketReconciliationWireV1 {
    NotAccepted,
    Refused(DocketIssuanceRefusalWireV1),
    Accepted(DocketCustodyV1),
    Settled {
        custody: DocketCustodyV1,
        settlement: DocketSettlementWireR2,
    },
    Indeterminate {
        custody: DocketCustodyV1,
        indeterminate: IndeterminateOutcomeV1,
    },
    GovernedRepairRequired {
        custody: DocketCustodyV1,
        result: Box<DocketSealedResultWireV1>,
    },
}

#[cfg(test)]
#[path = "governed_wire_conformance_tests.rs"]
mod governed_wire_conformance_tests;

/// Fresh process adapter for an external observation owner.
pub struct CommandObservationResolverV1 {
    program: PathBuf,
}

impl CommandObservationResolverV1 {
    /// Configures the exact executable invoked once per resolution.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl ObservationResolverV1 for CommandObservationResolverV1 {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<ObservationResolutionV1, ExternalBoundaryErrorV1> {
        run_json_program(
            &self.program,
            &[],
            &ObservationCommandRequestV1 {
                schema: OBSERVATION_REQUEST_SCHEMA_V1,
                key: request.key,
                observation: request.observation,
                subject: request.subject,
                now_unix_ms: request.now_unix_ms,
            },
        )
        .map_err(external_error)
    }
}

/// Fresh process adapter for the authoritative current-standing owner.
pub struct CommandStandingResolverV1 {
    program: PathBuf,
}

impl CommandStandingResolverV1 {
    /// Configures the exact executable invoked once per resolution.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl StandingResolverV1 for CommandStandingResolverV1 {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV1, ExternalBoundaryErrorV1> {
        run_json_program(
            &self.program,
            &[],
            &StandingCommandRequestV1 {
                schema: STANDING_REQUEST_SCHEMA_V1,
                key: request.key,
                observation: request.observation,
                proposal: request.proposal,
                subject: request.subject,
                scope: request.scope,
                now_unix_ms: request.now_unix_ms,
            },
        )
        .map_err(external_error)
    }
}

/// Concrete authenticated subprocess seam to Docket's custody service.
pub(crate) struct CommandDocketCustodyPortV1 {
    docket_program: PathBuf,
    state_directory: PathBuf,
    trust_config: PathBuf,
    standing_resolver: PathBuf,
    executor_adapter: PathBuf,
    executor_config: PathBuf,
    checkpoint_verifier: Option<PathBuf>,
    signer: AgIssuanceSignerV2,
    signing_permit: Option<StoreIssuanceSigningPermitV1>,
}

impl CommandDocketCustodyPortV1 {
    /// Binds the exact Docket deployment and its external execution boundaries.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn new(
        docket_program: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        trust_config: impl Into<PathBuf>,
        standing_resolver: impl Into<PathBuf>,
        executor_adapter: impl Into<PathBuf>,
        executor_config: impl Into<PathBuf>,
        checkpoint_verifier: Option<PathBuf>,
        signer: AgIssuanceSignerV2,
        signing_permit: Option<StoreIssuanceSigningPermitV1>,
    ) -> Self {
        Self {
            docket_program: docket_program.into(),
            state_directory: state_directory.into(),
            trust_config: trust_config.into(),
            standing_resolver: standing_resolver.into(),
            executor_adapter: executor_adapter.into(),
            executor_config: executor_config.into(),
            checkpoint_verifier,
            signer,
            signing_permit,
        }
    }

    fn arguments(&self, operation: &str) -> Vec<String> {
        let mut arguments = vec![
            "governed-loop".to_owned(),
            operation.to_owned(),
            "--state".to_owned(),
            self.state_directory.display().to_string(),
            "--trust".to_owned(),
            self.trust_config.display().to_string(),
            "--standing-resolver".to_owned(),
            self.standing_resolver.display().to_string(),
            "--executor".to_owned(),
            self.executor_adapter.display().to_string(),
            "--executor-config".to_owned(),
            self.executor_config.display().to_string(),
        ];
        if let Some(verifier) = &self.checkpoint_verifier {
            arguments.push("--checkpoint-verifier".to_owned());
            arguments.push(verifier.display().to_string());
        }
        arguments
    }
}

impl DocketCustodyPortV1 for CommandDocketCustodyPortV1 {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceAcceptanceV1, ExternalBoundaryErrorV1> {
        if issuance.governed_repair_checkpoint.is_some() && self.checkpoint_verifier.is_none() {
            return Err(ExternalBoundaryErrorV1::Unavailable {
                code: "checkpoint-verifier-not-configured".to_owned(),
            });
        }
        let permit =
            self.signing_permit
                .take()
                .ok_or_else(|| ExternalBoundaryErrorV1::Unavailable {
                    code: "store-issuance-signing-permit-absent".to_owned(),
                })?;
        let (permitted_issuance, envelope) =
            self.signer.sign_permitted(permit).map_err(external_error)?;
        if &permitted_issuance != issuance {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "store-issuance-signing-permit-substitution".to_owned(),
                evidence: None,
            });
        }
        let arguments = self.arguments("accept");
        let wire: DocketAcceptanceWireV1 =
            run_json_program(&self.docket_program, &arguments, &envelope)
                .map_err(external_error)?;
        adapt_docket_acceptance(issuance, wire).map_err(external_error)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV2,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
        }
        let arguments = self.arguments("reconcile-issuance");
        let wire: DocketReconciliationWireV1 = run_json_program(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &issuance.issuance,
            },
        )
        .map_err(external_error)?;
        adapt_docket_reconciliation(issuance, wire).map_err(external_error)
    }

    fn reconcile_attempt(
        &mut self,
        issuance: &AgIssuanceV2,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
            attempt: &'a DocketAttemptRefV1,
        }
        let arguments = self.arguments("reconcile-attempt");
        let wire: DocketReconciliationWireV1 = run_json_program(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &custody.issuance,
                attempt: &custody.attempt,
            },
        )
        .map_err(external_error)?;
        if issuance.issuance != custody.issuance {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "reconciliation-issuance-custody-substitution".to_owned(),
                evidence: None,
            });
        }
        adapt_docket_reconciliation(issuance, wire).map_err(external_error)
    }
}

struct DocketTranscriptV1(Sha256);

impl DocketTranscriptV1 {
    fn new(domain: &str) -> Self {
        let mut digest = Sha256::new();
        digest.update(
            u64::try_from(domain.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(domain.as_bytes());
        Self(digest)
    }

    fn field(mut self, label: &str, value: &[u8]) -> Self {
        self.0
            .update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.update(label.as_bytes());
        self.0
            .update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.update(value);
        self
    }

    fn text(self, label: &str, value: &str) -> Self {
        self.field(label, value.as_bytes())
    }

    fn finish(self) -> ag_primitives::Digest {
        ag_primitives::Digest::parse(&format!("sha256:{}", hex::encode(self.0.finalize())))
            .expect("SHA-256 output is always a canonical qualified digest")
    }
}

fn docket_digest_list(values: &[ag_primitives::Digest]) -> [u8; 32] {
    let mut transcript = DocketTranscriptV1::new("docket.governed-repair.digest-list/v1");
    for value in values {
        transcript = transcript.field("item", &value.raw_bytes());
    }
    transcript.finish().raw_bytes()
}

fn docket_scope_identity(
    scope: &CanonicalEffectScopeV1,
) -> Result<ag_primitives::Digest, GovernedPortErrorV1> {
    scope
        .validate()
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))?;
    let mut transcript = DocketTranscriptV1::new("ag.governed-loop.canonical-effect-scope/v1")
        .text("schema", CANONICAL_EFFECT_SCOPE_SCHEMA_V1)
        .text("effect_class", scope.effect_class());
    for resource in scope.resources() {
        transcript = transcript
            .text("resource", &resource.resource)
            .text("path", &resource.path);
        for operation in &resource.operations {
            transcript = transcript.text("operation", docket_operation_tag(*operation));
        }
    }
    Ok(transcript.finish())
}

fn docket_operation_tag(operation: CanonicalEffectOperationV1) -> &'static str {
    match operation {
        CanonicalEffectOperationV1::Read => "read",
        CanonicalEffectOperationV1::Create => "create",
        CanonicalEffectOperationV1::Modify => "modify",
        CanonicalEffectOperationV1::Delete => "delete",
        CanonicalEffectOperationV1::Execute => "execute",
    }
}

fn docket_requirement_transcript(
    domain: &str,
    binding: &DocketGovernedRepairBindingWireV1,
) -> DocketTranscriptV1 {
    DocketTranscriptV1::new(domain)
        .field("campaign", &binding.campaign.as_digest().raw_bytes())
        .text("occurrence", &binding.occurrence)
        .field("proposal", &binding.proposal.as_digest().raw_bytes())
        .field("observation", &binding.observation.as_digest().raw_bytes())
        .field(
            "standing_resolution",
            &binding.standing_resolution.as_digest().raw_bytes(),
        )
        .field(
            "decision",
            &binding.admission_decision.as_digest().raw_bytes(),
        )
        .field("spend", &binding.spend.as_digest().raw_bytes())
        .field("issuance", &binding.issuance.as_digest().raw_bytes())
        .field("custody", &binding.custody.as_digest().raw_bytes())
        .field("attempt", &binding.attempt.as_digest().raw_bytes())
        .field("executor_result", &binding.executor_result.raw_bytes())
        .field("executor_binding", &binding.executor_binding.raw_bytes())
        .field("original_scope", &binding.original_scope_digest.raw_bytes())
        .field("effect_journal", &binding.effect_journal_digest.raw_bytes())
        .text(
            "reported_authorized_effects_occurred",
            if binding.reported_authorized_effects_occurred {
                "true"
            } else {
                "false"
            },
        )
        .text(
            "created_at_unix_ms",
            &binding.created_at_unix_ms.to_string(),
        )
        .text(
            "expires_at_unix_ms",
            &binding.expires_at_unix_ms.to_string(),
        )
        .field("idempotency", &binding.idempotency.raw_bytes())
}

fn docket_scope_requirement_identity(value: &DocketScopeExpansionWireV1) -> ag_primitives::Digest {
    docket_requirement_transcript(DOCKET_SCOPE_REQUIREMENT_SCHEMA_V1, &value.binding)
        .field("requested_delta", &value.requested_delta_digest.raw_bytes())
        .text("blocked_effect_class", &value.blocked_effect.effect_class)
        .text("blocked_resource", &value.blocked_effect.resource)
        .text("blocked_path", &value.blocked_effect.path)
        .text(
            "blocked_operation",
            docket_operation_tag(value.blocked_effect.operation),
        )
        .field("reason", &value.reason.raw_bytes())
        .field(
            "dependency_evidence",
            &docket_digest_list(&value.dependency_evidence),
        )
        .text(
            "no_unauthorized_effect_reported",
            if value.no_unauthorized_effect_reported {
                "true"
            } else {
                "false"
            },
        )
        .field("limitations", &docket_digest_list(&value.limitations))
        .finish()
}

fn docket_readjudication_identity(
    value: &DocketReadjudicationWireV1,
) -> Result<ag_primitives::Digest, GovernedPortErrorV1> {
    Ok(
        docket_requirement_transcript(DOCKET_READJUDICATION_REQUIREMENT_SCHEMA_V1, &value.binding)
            .field("question", &value.question.raw_bytes())
            .field(
                "evidence_census",
                &docket_digest_list(&value.evidence_census),
            )
            .field(
                "diagnostic_census",
                &docket_digest_list(&value.diagnostic_census),
            )
            .field(
                "bounded_alternatives",
                &docket_digest_list(&value.bounded_alternatives),
            )
            .field(
                "unresolved_facts",
                &docket_digest_list(&value.unresolved_facts),
            )
            .field(
                "adjudication_scope",
                &docket_scope_identity(&value.adjudication_scope)?.raw_bytes(),
            )
            .text(
                "no_unauthorized_effect_reported",
                if value.no_unauthorized_effect_reported {
                    "true"
                } else {
                    "false"
                },
            )
            .field("limitations", &docket_digest_list(&value.limitations))
            .finish(),
    )
}

fn docket_checkpoint_identity(checkpoint: &DocketCheckpointWireV1) -> ag_primitives::Digest {
    let mut transcript = DocketTranscriptV1::new(DOCKET_CHECKPOINT_SCHEMA_V1)
        .text("issuance", checkpoint.issuance.as_str())
        .text("custody", checkpoint.custody.as_str())
        .text("attempt", checkpoint.attempt.as_str())
        .text("executor_binding", checkpoint.executor_binding.as_str())
        .text("executor_result", checkpoint.executor_result.as_str())
        .text("executor_receipt", checkpoint.executor_receipt.as_str())
        .text("requirement_kind", &checkpoint.requirement_kind)
        .text(
            "requirement_identity",
            checkpoint.requirement_identity.as_str(),
        )
        .text("effect_journal", checkpoint.effect_journal_digest.as_str())
        .text("idempotency", checkpoint.idempotency.as_str())
        .text(
            "created_at_unix_ms",
            &checkpoint.created_at_unix_ms.to_string(),
        )
        .text(
            "expires_at_unix_ms",
            &checkpoint.expires_at_unix_ms.to_string(),
        );
    if let Some(work) = &checkpoint.immutable_work_checkpoint {
        transcript = transcript
            .text("work_repository", work.repository_identity.as_str())
            .text("work_commit", &work.commit)
            .text("work_tree", &work.tree)
            .text(
                "work_diff",
                work.diff_identity
                    .as_ref()
                    .map_or("", ag_primitives::Digest::as_str),
            )
            .text(
                "work_content_manifest",
                work.content_manifest_identity.as_str(),
            );
    }
    transcript.finish()
}

fn docket_sealed_result_identity(checkpoint: &DocketCheckpointWireV1) -> ag_primitives::Digest {
    DocketTranscriptV1::new(DOCKET_SEALED_RESULT_SCHEMA_V1)
        .text("checkpoint", checkpoint.checkpoint.as_str())
        .text("issuance", checkpoint.issuance.as_str())
        .text("custody", checkpoint.custody.as_str())
        .text("attempt", checkpoint.attempt.as_str())
        .text("outcome_kind", &checkpoint.requirement_kind)
        .text("outcome_identity", checkpoint.requirement_identity.as_str())
        .text(
            "created_at_unix_ms",
            &checkpoint.created_at_unix_ms.to_string(),
        )
        .text(
            "expires_at_unix_ms",
            &checkpoint.expires_at_unix_ms.to_string(),
        )
        .finish()
}

fn malformed(detail: &'static str) -> GovernedPortErrorV1 {
    GovernedPortErrorV1::MalformedResponse(detail.to_owned())
}

fn validate_docket_binding(
    issuance: &AgIssuanceV2,
    custody: &DocketCustodyV1,
    binding: &DocketGovernedRepairBindingWireV1,
) -> Result<(), GovernedPortErrorV1> {
    if binding.campaign != issuance.key.campaign
        || binding.occurrence != issuance.key.occurrence.to_string()
        || binding.proposal != issuance.proposal
        || binding.observation != issuance.observation
        || binding.standing_resolution != issuance.standing_resolution
        || binding.admission_decision != issuance.admission_decision.decision
        || binding.spend != issuance.spend
        || binding.issuance != issuance.issuance
        || binding.custody != custody.reference()
        || binding.attempt != custody.attempt
        || binding.original_scope != issuance.effect_scope
        || binding.original_scope_digest != issuance.effect_scope_digest
        || binding.created_at_unix_ms >= binding.expires_at_unix_ms
    {
        return Err(malformed("Docket governed-repair binding substitution"));
    }
    Ok(())
}

fn validate_work_checkpoint(
    issuance: &AgIssuanceV2,
    work: Option<&DocketImmutableCheckpointWireV1>,
) -> Result<(), GovernedPortErrorV1> {
    match (issuance.governed_repair_checkpoint.as_ref(), work) {
        // An initial occurrence may begin without a checkpoint. Docket may
        // then seal the exact immutable checkpoint produced by that attempt;
        // the strict result type and Docket result authentication protect its
        // coordinates. A successor that already names a checkpoint must,
        // however, receive exactly that same checkpoint back.
        (None, _) => Ok(()),
        (Some(expected), Some(actual))
            if actual.repository_identity == expected.repository
                && actual.commit == expected.commit
                && actual.tree == expected.tree
                && actual.diff_identity == expected.diff_identity
                && actual.content_manifest_identity == expected.content_manifest =>
        {
            Ok(())
        }
        _ => Err(malformed("Docket immutable work checkpoint substitution")),
    }
}

fn adapt_docket_result(
    issuance: &AgIssuanceV2,
    custody: &DocketCustodyV1,
    result: DocketSealedResultWireV1,
) -> Result<DocketSealedGovernedRepairResultV1, GovernedPortErrorV1> {
    let (binding, kind, identity) = match &result.outcome {
        DocketSealedRequirementWireV1::ScopeExpansionRequired(value) => (
            &value.binding,
            "scope_expansion_required",
            &value.requirement_identity,
        ),
        DocketSealedRequirementWireV1::ReadjudicationRequired(value) => (
            &value.binding,
            "readjudication_required",
            &value.requirement_identity,
        ),
    };
    validate_docket_binding(issuance, custody, binding)?;
    validate_work_checkpoint(
        issuance,
        result.checkpoint.immutable_work_checkpoint.as_ref(),
    )?;
    if result.schema != DOCKET_SEALED_RESULT_SCHEMA_V1
        || result.checkpoint.schema != DOCKET_CHECKPOINT_SCHEMA_V1
        || result.checkpoint.issuance != issuance.issuance
        || result.checkpoint.custody != custody.reference()
        || result.checkpoint.attempt != custody.attempt
        || result.checkpoint.executor_binding != binding.executor_binding
        || result.checkpoint.executor_result != binding.executor_result
        || result.checkpoint.requirement_kind != kind
        || &result.checkpoint.requirement_identity != identity
        || result.checkpoint.effect_journal_digest != binding.effect_journal_digest
        || result.checkpoint.idempotency != binding.idempotency
        || result.checkpoint.created_at_unix_ms != binding.created_at_unix_ms
        || result.checkpoint.expires_at_unix_ms != binding.expires_at_unix_ms
        || result.checkpoint.checkpoint.as_digest()
            != &docket_checkpoint_identity(&result.checkpoint)
        || result.sealed_result.as_digest() != &docket_sealed_result_identity(&result.checkpoint)
    {
        return Err(malformed(
            "Docket governed-repair sealed result substitution",
        ));
    }
    let immutable_work_checkpoint = result
        .checkpoint
        .immutable_work_checkpoint
        .as_ref()
        .map(
            |work| -> Result<GovernedRepairCheckpointV1, GovernedPortErrorV1> {
                Ok(GovernedRepairCheckpointV1 {
                    repository: work.repository_identity.clone(),
                    commit: work.commit.clone(),
                    tree: work.tree.clone(),
                    diff_identity: work.diff_identity.clone(),
                    content_manifest: work.content_manifest_identity.clone(),
                    docket_checkpoint: Some(result.checkpoint.checkpoint.clone()),
                })
            },
        )
        .transpose()?;
    let outcome = DocketGovernedRepairOutcomeRefV1 {
        checkpoint: result.checkpoint.checkpoint.clone(),
        sealed_result: result.sealed_result,
        outcome: identity.clone(),
        issuance: issuance.issuance.clone(),
        custody: custody.reference(),
        attempt: custody.attempt.clone(),
        effect_journal: binding.effect_journal_digest.clone(),
        executor_binding: binding.executor_binding.clone(),
        executor_result: binding.executor_result.clone(),
        executor_receipt: result.checkpoint.executor_receipt.clone(),
        immutable_work_checkpoint,
        reported_authorized_effects_occurred: binding.reported_authorized_effects_occurred,
        created_at_unix_ms: binding.created_at_unix_ms,
        expires_at_unix_ms: binding.expires_at_unix_ms,
        idempotency: binding.idempotency.clone(),
    };
    match result.outcome {
        DocketSealedRequirementWireV1::ScopeExpansionRequired(value) => {
            adapt_scope_requirement(value, outcome)
        }
        DocketSealedRequirementWireV1::ReadjudicationRequired(value) => {
            adapt_readjudication_requirement(value, outcome)
        }
    }
}

fn adapt_scope_requirement(
    value: DocketScopeExpansionWireV1,
    outcome: DocketGovernedRepairOutcomeRefV1,
) -> Result<DocketSealedGovernedRepairResultV1, GovernedPortErrorV1> {
    if value.schema != DOCKET_SCOPE_REQUIREMENT_SCHEMA_V1
        || value.requirement_identity != docket_scope_requirement_identity(&value)
        || value.requested_delta_digest != value.requested_delta.digest()
        || value.blocked_effect.effect_class != value.requested_delta.effect_class()
    {
        return Err(malformed("Docket scope requirement identity substitution"));
    }
    let requirement = ScopeExpansionRequiredV1 {
        schema: SCOPE_EXPANSION_REQUIRED_SCHEMA_V1.to_owned(),
        original_scope: value.binding.original_scope,
        original_scope_digest: value.binding.original_scope_digest,
        requested_delta: value.requested_delta,
        requested_delta_digest: value.requested_delta_digest,
        blocked_operation: BlockedEffectOperationV1 {
            resource: value.blocked_effect.resource,
            path: value.blocked_effect.path,
            operation: value.blocked_effect.operation,
        },
        reason: value.reason,
        dependency_evidence: value.dependency_evidence,
        limitations: value.limitations,
        docket_outcome: Some(outcome.clone()),
        no_unauthorized_effect_reported: value.no_unauthorized_effect_reported,
    };
    requirement
        .validate()
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))?;
    Ok(DocketSealedGovernedRepairResultV1::ScopeExpansionRequired {
        outcome,
        requirement,
    })
}

fn adapt_readjudication_requirement(
    value: DocketReadjudicationWireV1,
    outcome: DocketGovernedRepairOutcomeRefV1,
) -> Result<DocketSealedGovernedRepairResultV1, GovernedPortErrorV1> {
    if value.schema != DOCKET_READJUDICATION_REQUIREMENT_SCHEMA_V1
        || value.requirement_identity != docket_readjudication_identity(&value)?
    {
        return Err(malformed(
            "Docket readjudication requirement identity substitution",
        ));
    }
    let requirement = ReadjudicationRequiredV1 {
        schema: READJUDICATION_REQUIRED_SCHEMA_V1.to_owned(),
        question: value.question,
        evidence_census: value.evidence_census,
        diagnostic_census: value.diagnostic_census,
        bounded_alternatives: value.bounded_alternatives,
        unresolved_facts: value.unresolved_facts,
        limitations: value.limitations,
        adjudication_scope: value.adjudication_scope,
        docket_outcome: Some(outcome.clone()),
        no_unauthorized_effect_reported: value.no_unauthorized_effect_reported,
    };
    requirement
        .validate()
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))?;
    Ok(DocketSealedGovernedRepairResultV1::ReadjudicationRequired {
        outcome,
        requirement,
    })
}

fn adapt_docket_acceptance(
    issuance: &AgIssuanceV2,
    wire: DocketAcceptanceWireV1,
) -> Result<DocketIssuanceAcceptanceV1, GovernedPortErrorV1> {
    match wire {
        DocketAcceptanceWireV1::Refused(refusal) => Ok(DocketIssuanceAcceptanceV1::Refused(
            adapt_docket_refusal(issuance, refusal)?,
        )),
        DocketAcceptanceWireV1::Custody(custody) => {
            Ok(DocketIssuanceAcceptanceV1::Custody(custody))
        }
        DocketAcceptanceWireV1::GovernedRepairRequired { custody, result } => {
            let result = adapt_docket_result(issuance, &custody, *result)?;
            Ok(DocketIssuanceAcceptanceV1::GovernedRepairRequired { custody, result })
        }
    }
}

fn adapt_docket_reconciliation(
    issuance: &AgIssuanceV2,
    wire: DocketReconciliationWireV1,
) -> Result<DocketIssuanceReconciliationV1, GovernedPortErrorV1> {
    match wire {
        DocketReconciliationWireV1::NotAccepted => Ok(DocketIssuanceReconciliationV1::NotAccepted),
        DocketReconciliationWireV1::Refused(refusal) => Ok(
            DocketIssuanceReconciliationV1::Refused(adapt_docket_refusal(issuance, refusal)?),
        ),
        DocketReconciliationWireV1::Accepted(custody) => {
            Ok(DocketIssuanceReconciliationV1::Accepted(custody))
        }
        DocketReconciliationWireV1::Settled {
            custody,
            settlement,
        } => Ok(DocketIssuanceReconciliationV1::Settled {
            custody,
            settlement: settlement.into_model()?,
        }),
        DocketReconciliationWireV1::Indeterminate {
            custody,
            indeterminate,
        } => Ok(DocketIssuanceReconciliationV1::Indeterminate {
            custody,
            indeterminate,
        }),
        DocketReconciliationWireV1::GovernedRepairRequired { custody, result } => {
            let result = adapt_docket_result(issuance, &custody, *result)?;
            Ok(DocketIssuanceReconciliationV1::GovernedRepairRequired { custody, result })
        }
    }
}

fn adapt_docket_refusal(
    issuance: &AgIssuanceV2,
    wire: DocketIssuanceRefusalWireV1,
) -> Result<DocketIssuanceRefusalV1, GovernedPortErrorV1> {
    let refusal_class = match wire.refusal_class {
        DocketIssuanceRefusalClassWireV1::IssuanceInvalid => {
            DocketIssuanceRefusalClassV1::IssuanceInvalid
        }
        DocketIssuanceRefusalClassWireV1::IssuanceExpired => {
            DocketIssuanceRefusalClassV1::IssuanceExpired
        }
        DocketIssuanceRefusalClassWireV1::CheckpointInvalid => {
            DocketIssuanceRefusalClassV1::CheckpointInvalid
        }
        DocketIssuanceRefusalClassWireV1::StandingInvalid => {
            DocketIssuanceRefusalClassV1::StandingInvalid
        }
        DocketIssuanceRefusalClassWireV1::InstrumentSubstitution => {
            DocketIssuanceRefusalClassV1::InstrumentSubstitution
        }
    };
    let refusal = DocketIssuanceRefusalV1 {
        schema: wire.schema,
        refusal: wire.refusal,
        issuance: wire.issuance,
        campaign: wire.campaign,
        occurrence: wire.occurrence,
        refusal_class,
        reason_code: wire.reason_code,
        evidence: wire.evidence,
        refused_at_unix_ms: wire.refused_at_unix_ms,
    };
    refusal
        .validate_for(issuance)
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))?;
    Ok(refusal)
}

/// Concrete-process boundary failures.  They never grant authority.
#[derive(Debug, Error)]
pub enum GovernedPortErrorV1 {
    /// Explicit configuration is malformed.
    #[error("invalid governed-port configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Signing key is not an Ed25519 PKCS#8 v2 key.
    #[error("invalid governed-loop issuance signing key")]
    InvalidSigningKey,
    /// Local filesystem/process I/O failed.
    #[error("governed-port I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict canonical request encoding failed.
    #[error("governed-port canonical encoding failed: {0}")]
    Canonical(String),
    /// External owner refused the request.
    #[error("external governed owner refused: {0}")]
    Refused(String),
    /// External owner returned a malformed response.
    #[error("external governed owner returned malformed output: {0}")]
    MalformedResponse(String),
}

fn run_json_program<I, O>(
    program: &Path,
    arguments: &[String],
    input: &I,
) -> Result<O, GovernedPortErrorV1>
where
    I: Serialize + ?Sized,
    O: DeserializeOwned,
{
    let body = JcsDocument::canonicalize(input)
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GovernedPortErrorV1::Io)?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            GovernedPortErrorV1::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "child stdin unavailable",
            ))
        })?
        .write_all(body.as_bytes())
        .map_err(GovernedPortErrorV1::Io)?;
    let output = child.wait_with_output().map_err(GovernedPortErrorV1::Io)?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(GovernedPortErrorV1::Refused(
            detail.chars().take(512).collect(),
        ));
    }
    JcsDocument::parse(&output.stdout)
        .and_then(|document| document.decode::<O>())
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))
}

fn external_error(error: GovernedPortErrorV1) -> ExternalBoundaryErrorV1 {
    match error {
        GovernedPortErrorV1::Refused(detail) => ExternalBoundaryErrorV1::Refused {
            code: format!("external-process:{detail}"),
            evidence: None,
        },
        other => ExternalBoundaryErrorV1::Unavailable {
            code: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn digest(label: &str) -> ag_primitives::Digest {
        ag_primitives::Digest::hash_domain(
            "qualification-fixture-not-human-authority/adapter/v1",
            label.as_bytes(),
        )
    }

    fn scope(path: &str) -> CanonicalEffectScopeV1 {
        CanonicalEffectScopeV1::new(
            "repair".to_owned(),
            vec![CanonicalEffectResourceV1 {
                resource: "repository".to_owned(),
                path: path.to_owned(),
                operations: vec![CanonicalEffectOperationV1::Modify],
            }],
        )
        .unwrap()
    }

    fn unsafe_timestamp_fixture(
        timestamp: u64,
    ) -> (DocketScopeExpansionWireV1, DocketGovernedRepairOutcomeRefV1) {
        let original = scope("bounded/original");
        let delta = scope("bounded/delta");
        let campaign = CampaignId::from_digest(digest("campaign"));
        let issuance = AgIssuanceRefV1::from_digest(digest("issuance"));
        let custody = DocketCustodyRefV1::from_digest(digest("custody"));
        let attempt = DocketAttemptRefV1::from_digest(digest("attempt"));
        let binding = DocketGovernedRepairBindingWireV1 {
            campaign,
            occurrence: Uuid::from_u128(1).to_string(),
            proposal: ProposalRefV1::from_digest(digest("proposal")),
            observation: ObservationRefV1::from_digest(digest("observation")),
            standing_resolution: StandingResolutionRefV1::from_digest(digest("standing")),
            admission_decision: AdmissionDecisionRefV1::from_digest(digest("decision")),
            spend: AgSpendRefV1::from_digest(digest("spend")),
            issuance: issuance.clone(),
            custody: custody.clone(),
            attempt: attempt.clone(),
            executor_result: digest("executor-result"),
            executor_binding: digest("executor-binding"),
            original_scope_digest: original.digest(),
            original_scope: original,
            effect_journal_digest: digest("journal"),
            reported_authorized_effects_occurred: false,
            created_at_unix_ms: 1,
            expires_at_unix_ms: timestamp,
            idempotency: digest("idempotency"),
        };
        let mut wire = DocketScopeExpansionWireV1 {
            schema: DOCKET_SCOPE_REQUIREMENT_SCHEMA_V1.to_owned(),
            requirement_identity: digest("placeholder"),
            binding,
            requested_delta_digest: delta.digest(),
            requested_delta: delta,
            blocked_effect: DocketBlockedEffectWireV1 {
                effect_class: "repair".to_owned(),
                resource: "repository".to_owned(),
                path: "bounded/delta".to_owned(),
                operation: CanonicalEffectOperationV1::Modify,
            },
            reason: digest("reason"),
            dependency_evidence: vec![digest("dependency")],
            no_unauthorized_effect_reported: true,
            limitations: vec![digest("limitation")],
        };
        wire.requirement_identity = docket_scope_requirement_identity(&wire);
        let outcome = DocketGovernedRepairOutcomeRefV1 {
            checkpoint: DocketCheckpointRefV1::from_digest(digest("checkpoint")),
            sealed_result: DocketSealedResultRefV1::from_digest(digest("sealed")),
            outcome: wire.requirement_identity.clone(),
            issuance,
            custody,
            attempt,
            effect_journal: digest("journal"),
            executor_binding: digest("executor-binding"),
            executor_result: digest("executor-result"),
            executor_receipt: ReceiptRefV1::from_digest(digest("receipt")),
            immutable_work_checkpoint: None,
            reported_authorized_effects_occurred: false,
            created_at_unix_ms: 1,
            expires_at_unix_ms: timestamp,
            idempotency: digest("idempotency"),
        };
        (wire, outcome)
    }

    #[test]
    fn docket_adapter_refuses_timestamp_outside_canonical_json_integer_range() {
        let (wire, outcome) = unsafe_timestamp_fixture(MAX_CANONICAL_JSON_INTEGER_V1 + 1);
        assert!(adapt_scope_requirement(wire, outcome).is_err());
    }

    #[test]
    fn docket_adapter_accepts_safe_maximum_timestamp_when_other_bindings_are_exact() {
        let (wire, outcome) = unsafe_timestamp_fixture(MAX_CANONICAL_JSON_INTEGER_V1);
        assert!(adapt_scope_requirement(wire, outcome).is_ok());
    }

    #[test]
    fn docket_requirement_identity_binds_reported_effect_containment_observation() {
        let (mut wire, _) = unsafe_timestamp_fixture(MAX_CANONICAL_JSON_INTEGER_V1);
        let clean_identity = wire.requirement_identity.clone();
        wire.no_unauthorized_effect_reported = false;
        assert_ne!(docket_scope_requirement_identity(&wire), clean_identity);
    }
}
