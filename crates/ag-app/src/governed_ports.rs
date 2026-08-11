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

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ag_campaign::governed::*;
use ag_primitives::JcsDocument;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Schema for the authenticated canonical AG issuance handed to Docket.
pub const SIGNED_AG_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.signed-issuance/v1";
/// Schema for process observation-resolution requests.
pub const OBSERVATION_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.observation-request/v1";
/// Schema for process standing-resolution requests.
pub const STANDING_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.standing-request/v1";
/// Schema for process human-verification requests.
pub const HUMAN_VERIFICATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.human-verification-request/v1";
/// Schema for process human-verification responses.
pub const HUMAN_VERIFICATION_RESPONSE_SCHEMA_V1: &str =
    "ag.governed-loop.human-verification-response/v1";

const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";

/// Authentication metadata for one exact canonical issuance body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceAuthenticationV1 {
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
pub struct SignedAgIssuanceEnvelopeV1 {
    /// Exact envelope schema.
    pub schema: String,
    /// Canonical `AgIssuanceV1` bytes, base64url-no-pad.
    pub body_b64: String,
    /// Exact authentication over `body_b64`'s decoded bytes.
    pub authentication: AgIssuanceAuthenticationV1,
}

/// AG's configured issuance signer.  It does not create or spend authority;
/// it authenticates an issuance that already exists in the spend journal.
pub struct AgIssuanceSignerV1 {
    issuer_principal: String,
    key_id: String,
    key_pair: Ed25519KeyPair,
}

impl AgIssuanceSignerV1 {
    /// Loads one explicit PKCS#8 v2 Ed25519 credential.
    pub fn from_pkcs8_file(
        issuer_principal: impl Into<String>,
        key_id: impl Into<String>,
        path: &Path,
    ) -> Result<Self, GovernedPortErrorV1> {
        let bytes = fs::read(path).map_err(GovernedPortErrorV1::Io)?;
        Self::from_pkcs8(issuer_principal, key_id, &bytes)
    }

    /// Parses one explicit PKCS#8 v2 Ed25519 credential.
    pub fn from_pkcs8(
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

    /// Authenticates an exact durable issuance without changing it.
    pub fn sign(
        &self,
        issuance: &AgIssuanceV1,
    ) -> Result<SignedAgIssuanceEnvelopeV1, GovernedPortErrorV1> {
        let body = JcsDocument::canonicalize(issuance)
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.as_bytes().len());
        signed.extend_from_slice(SIGNATURE_PREFIX_V1);
        signed.extend_from_slice(body.as_bytes());
        let signature = self.key_pair.sign(&signed);
        Ok(SignedAgIssuanceEnvelopeV1 {
            schema: SIGNED_AG_ISSUANCE_SCHEMA_V1.to_owned(),
            body_b64: URL_SAFE_NO_PAD.encode(body.as_bytes()),
            authentication: AgIssuanceAuthenticationV1 {
                issuer_principal: self.issuer_principal.clone(),
                signer_key_id: self.key_id.clone(),
                signer_public_key: URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref()),
                signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
            },
        })
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

/// Exact request sent to the external human-authority verifier.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct HumanVerificationCommandRequestV1<'a> {
    schema: &'static str,
    artifact: &'a HumanDispositionV1,
    expected_principal: &'a HumanPrincipalRefV1,
    expected_mandate: &'a MandateRefV1,
    now_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanVerificationCommandResponseV1 {
    schema: String,
    verification: HumanVerificationRefV1,
}

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

/// Fresh process adapter for external human-authority verification.
pub struct CommandHumanDispositionVerifierV1 {
    program: PathBuf,
}

impl CommandHumanDispositionVerifierV1 {
    /// Configures the exact executable invoked once per verification.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl HumanDispositionVerifierV1 for CommandHumanDispositionVerifierV1 {
    fn verify_human_disposition(
        &mut self,
        request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
        let response: HumanVerificationCommandResponseV1 = run_json_program(
            &self.program,
            &[],
            &HumanVerificationCommandRequestV1 {
                schema: HUMAN_VERIFICATION_REQUEST_SCHEMA_V1,
                artifact: request.artifact,
                expected_principal: &request.expected_scope.principal,
                expected_mandate: &request.expected_scope.mandate,
                now_unix_ms: request.now_unix_ms,
            },
        )
        .map_err(external_error)?;
        if response.schema != HUMAN_VERIFICATION_RESPONSE_SCHEMA_V1 {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "foreign-human-verification-schema".to_owned(),
                evidence: None,
            });
        }
        Ok(response.verification)
    }
}

/// Concrete authenticated subprocess seam to Docket's custody service.
pub struct CommandDocketCustodyPortV1 {
    docket_program: PathBuf,
    state_directory: PathBuf,
    trust_config: PathBuf,
    standing_resolver: PathBuf,
    executor_adapter: PathBuf,
    executor_config: PathBuf,
    signer: AgIssuanceSignerV1,
}

impl CommandDocketCustodyPortV1 {
    /// Binds the exact Docket deployment and its external execution boundaries.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        docket_program: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        trust_config: impl Into<PathBuf>,
        standing_resolver: impl Into<PathBuf>,
        executor_adapter: impl Into<PathBuf>,
        executor_config: impl Into<PathBuf>,
        signer: AgIssuanceSignerV1,
    ) -> Self {
        Self {
            docket_program: docket_program.into(),
            state_directory: state_directory.into(),
            trust_config: trust_config.into(),
            standing_resolver: standing_resolver.into(),
            executor_adapter: executor_adapter.into(),
            executor_config: executor_config.into(),
            signer,
        }
    }

    fn arguments(&self, operation: &str) -> Vec<String> {
        vec![
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
        ]
    }
}

impl DocketCustodyPortV1 for CommandDocketCustodyPortV1 {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        let envelope = self.signer.sign(issuance).map_err(external_error)?;
        let arguments = self.arguments("accept");
        run_json_program(&self.docket_program, &arguments, &envelope).map_err(external_error)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
        }
        let arguments = self.arguments("reconcile-issuance");
        run_json_program(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &issuance.issuance,
            },
        )
        .map_err(external_error)
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
            attempt: &'a DocketAttemptRefV1,
        }
        let arguments = self.arguments("reconcile-attempt");
        run_json_program(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &custody.issuance,
                attempt: &custody.attempt,
            },
        )
        .map_err(external_error)
    }
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
    serde_json::from_slice(&output.stdout)
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
