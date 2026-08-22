//! Authenticated, exact-byte custody for governed-intervention submissions.
//!
//! This module authenticates delivery to one genesis-bound AG runtime and
//! retains immutable ingress receipts.  It does not decide intervention
//! applicability, mint authority, or execute work; those remain in the
//! governed campaign kernel and its existing owner ports.

use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use ag_campaign::governed::{GovernedInterventionRequestIdV1, GovernedInterventionRequestV1};
use ag_primitives::{Digest, JcsDocument};
use ag_protocol::strict_json_from_slice;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nix::fcntl::{Flock, FlockArg};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::governed_ports::GovernedInterventionIngressV1;

/// Canonical signed submission-envelope schema.
pub const INTERVENTION_SUBMISSION_SCHEMA_V1: &str = "ag.governed-loop.intervention-submission/v1";
/// Canonical signed submission-body schema.
pub const INTERVENTION_SUBMISSION_BODY_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-submission-body/v1";
/// Canonical immutable ingress-receipt schema.
pub const INTERVENTION_SUBMISSION_RECEIPT_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-submission-receipt/v1";
/// Canonical read-only ingress-history schema.
pub const INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-submission-history/v1";
/// Canonical exact-request inspection schema.
pub const INTERVENTION_REQUEST_INSPECTION_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-request-inspection/v1";

const SUBMISSION_DOMAIN_V1: &str = "ag.governed-loop.intervention-submission-id/v1";
const SUBMISSION_SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-intervention-submission\0v1\0";
const RECEIPT_DOMAIN_V1: &str = "ag.governed-loop.intervention-submission-receipt-id/v1";
const PRESENTATION_DOMAIN_V1: &str = "ag.governed-loop.intervention-submission-bytes/v1";
const REQUEST_BYTES_DOMAIN_V1: &str = "ag.governed-loop.intervention-request-bytes/v1";
const CUSTODY_VERIFICATION_DOMAIN_V1: &str =
    "ag.governed-loop.intervention-submission-custody-verification/v1";
const LEDGER_SCHEMA_NAME: &str = "ag-governed-intervention-ingress-ledger/v1";
const LEDGER_SCHEMA_VERSION: u32 = 1;
const LEDGER_APPLICATION_ID: u32 = 0x4147_4931; // AGI1
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_SUBMISSION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 4096;

const LEDGER_SCHEMA_SQL: &str = r"
CREATE TABLE ledger_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id INTEGER NOT NULL,
    schema_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    schema_digest TEXT NOT NULL,
    target_runtime_profile TEXT NOT NULL
) STRICT;

CREATE TABLE receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    submission_id TEXT,
    presentation_digest TEXT NOT NULL,
    request_id TEXT,
    stage TEXT NOT NULL,
    receipt_jcs BLOB NOT NULL,
    previous_receipt_id TEXT,
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms >= 0)
) STRICT;

CREATE INDEX receipts_by_submission_sequence
    ON receipts(submission_id, sequence);
CREATE INDEX receipts_by_presentation_sequence
    ON receipts(presentation_digest, sequence);
";

/// Fail-closed ingress/receipt failure.
#[derive(Debug, Error)]
pub enum InterventionIngressErrorV1 {
    /// Filesystem or lock operation failed.
    #[error("intervention ingress I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// Receipt-ledger operation failed.
    #[error("intervention ingress SQLite failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Canonical encoding or exact-byte validation failed.
    #[error("intervention ingress canonical record refused: {0}")]
    Canonical(String),
    /// Submission authentication or target binding failed.
    #[error("intervention submission custody refused: {0:?}")]
    Custody(InterventionCustodyRefusalCodeV1),
    /// Receipt ledger identity or chain is inconsistent.
    #[error("intervention ingress ledger is corrupt: {0}")]
    Corrupt(String),
}

/// Closed pre-governance custody refusal vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionCustodyRefusalCodeV1 {
    /// Input was not a bounded regular file or could not be read exactly.
    UnsafeInput,
    /// Input exceeded its explicit byte bound.
    Oversized,
    /// JSON or exact canonical bytes were malformed.
    Malformed,
    /// Envelope/body schema is unsupported.
    UnsupportedSchema,
    /// Submission self-identity or request-byte binding differs.
    BindingMismatch,
    /// Submission names a different genesis-bound runtime.
    WrongTargetRuntime,
    /// Submission names a different deployment submitter.
    WrongSubmittingPrincipal,
    /// Submission names a different deployment key.
    WrongSubmittingKey,
    /// Ed25519 authentication failed.
    AuthenticationFailed,
    /// Exclusive submission evaluation window has expired.
    Expired,
    /// The same submission identity was presented with different bytes.
    ConflictingSubmission,
}

/// Exact draft used only to construct a canonical governed-intervention request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionRequestDraftV1 {
    /// Authenticated requesting principal.
    pub principal: ag_campaign::governed::HumanPrincipalRefV1,
    /// Exact mandate checked by the existing governed verifier.
    pub mandate: ag_campaign::governed::MandateRefV1,
    /// Exact request replay nonce.
    pub nonce: ag_campaign::governed::GovernedInterventionNonceRefV1,
    /// Exact target campaign.
    pub campaign: ag_campaign::CampaignId,
    /// Exact target occurrence.
    pub occurrence: ag_campaign::governed::OccurrenceId,
    /// Exact target state digest.
    pub target_state_digest: Digest,
    /// Closed intervention class.
    pub intervention: ag_campaign::governed::GovernedInterventionClassV1,
    /// Creation time retained as evidence.
    pub created_at_unix_ms: u64,
    /// Exclusive governed-evaluation expiry.
    pub expires_at_unix_ms: u64,
}

impl GovernedInterventionRequestDraftV1 {
    /// Constructs the content-derived canonical governed request.
    ///
    /// # Errors
    ///
    /// Returns the campaign kernel's canonical validation error when any
    /// identity, time window, evidence set, or class-specific binding is
    /// invalid.
    pub fn construct(
        self,
    ) -> Result<GovernedInterventionRequestV1, ag_campaign::governed::KernelErrorV1> {
        GovernedInterventionRequestV1::new(
            self.principal,
            self.mandate,
            self.nonce,
            self.campaign,
            self.occurrence,
            self.target_state_digest,
            self.intervention,
            self.created_at_unix_ms,
            self.expires_at_unix_ms,
        )
    }
}

/// Read-only proof of the exact request bytes an operator inspected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionRequestInspectionV1 {
    /// Exact inspection schema.
    pub schema: String,
    /// Canonical request identity.
    pub request: GovernedInterventionRequestIdV1,
    /// Digest over the exact file bytes, including an optional final LF.
    pub exact_bytes_digest: Digest,
    /// Exact byte length.
    pub exact_bytes_len: u64,
    /// Full typed request; presentation never replaces the canonical bytes.
    pub value: GovernedInterventionRequestV1,
}

/// Exact signed body carried by a submission envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionSubmissionBodyV1 {
    /// Exact body schema.
    pub schema: String,
    /// Content-derived exact submission identity.
    pub submission: Digest,
    /// Identity asserted by and rederived from the enclosed request bytes.
    pub request: GovernedInterventionRequestIdV1,
    /// Digest over the exact enclosed request bytes.
    pub request_bytes_digest: Digest,
    /// Exact request bytes, base64url-no-pad, never regenerated at submission.
    pub request_bytes_b64: String,
    /// Authenticated transport/service principal.
    pub submitting_principal: String,
    /// Exact signing-key identity pinned by deployment.
    pub submitting_key_id: String,
    /// Genesis runtime-profile identity targeted by this submission.
    pub target_runtime_profile: Digest,
    /// Submission creation time retained as evidence.
    pub created_at_unix_ms: u64,
    /// Exclusive custody-authentication expiry.
    pub expires_at_unix_ms: u64,
}

#[derive(Serialize)]
struct SubmissionDigestInputV1<'a> {
    schema: &'a str,
    request: &'a GovernedInterventionRequestIdV1,
    request_bytes_digest: &'a Digest,
    request_bytes_b64: &'a str,
    submitting_principal: &'a str,
    submitting_key_id: &'a str,
    target_runtime_profile: &'a Digest,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl GovernedInterventionSubmissionBodyV1 {
    fn derived_submission(&self) -> Digest {
        digest_value(
            SUBMISSION_DOMAIN_V1,
            &SubmissionDigestInputV1 {
                schema: &self.schema,
                request: &self.request,
                request_bytes_digest: &self.request_bytes_digest,
                request_bytes_b64: &self.request_bytes_b64,
                submitting_principal: &self.submitting_principal,
                submitting_key_id: &self.submitting_key_id,
                target_runtime_profile: &self.target_runtime_profile,
                created_at_unix_ms: self.created_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
            },
        )
    }
}

/// Ed25519-authenticated transport envelope over exact request bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionSubmissionV1 {
    /// Exact envelope schema.
    pub schema: String,
    /// Exact signed custody body.
    pub body: GovernedInterventionSubmissionBodyV1,
    /// Ed25519 signature, base64url-no-pad.
    pub signature: String,
}

/// Result of successful custody authentication, before governed evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInterventionSubmissionV1 {
    /// Exact signed envelope.
    pub envelope: GovernedInterventionSubmissionV1,
    /// Exact original envelope-file digest.
    pub presentation_digest: Digest,
    /// Exact original request bytes.
    pub request_bytes: Vec<u8>,
    /// Parsed, integrity-checked canonical request.
    pub request: GovernedInterventionRequestV1,
    /// Content-derived authentication/custody evidence reference.
    pub custody_verification: Digest,
}

/// Operator-side signer for one configured submitting service.
pub struct GovernedInterventionSubmissionSignerV1 {
    principal: String,
    key_id: String,
    key_pair: Ed25519KeyPair,
}

impl GovernedInterventionSubmissionSignerV1 {
    /// Loads a protected PKCS#8 Ed25519 key from a nonsymlink regular file.
    ///
    /// # Errors
    ///
    /// Returns an error when the principal/key identity is malformed, file
    /// custody is unsafe, or the bytes are not a valid Ed25519 PKCS#8 key.
    pub fn from_protected_file(
        principal: impl Into<String>,
        key_id: impl Into<String>,
        path: &Path,
    ) -> Result<Self, InterventionIngressErrorV1> {
        let principal = principal.into();
        let key_id = key_id.into();
        require_token(&principal).map_err(InterventionIngressErrorV1::Canonical)?;
        require_token(&key_id).map_err(InterventionIngressErrorV1::Canonical)?;
        let bytes = read_bounded_regular(path, MAX_SIGNING_KEY_BYTES, true)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| {
            InterventionIngressErrorV1::Canonical("invalid submitter Ed25519 key".to_owned())
        })?;
        Ok(Self {
            principal,
            key_id,
            key_pair,
        })
    }

    /// Canonical base64url-no-pad public key corresponding to this signer.
    #[must_use]
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref())
    }

    /// Packages the exact inspected request bytes without normalizing them.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is oversized or noncanonical, or
    /// when the submission time window is invalid.
    pub fn package(
        &self,
        request_bytes: &[u8],
        target_runtime_profile: Digest,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<GovernedInterventionSubmissionV1, InterventionIngressErrorV1> {
        if u64::try_from(request_bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
            return Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::Oversized,
            ));
        }
        let request = parse_exact_request_bytes(request_bytes)?;
        if created_at_unix_ms >= expires_at_unix_ms {
            return Err(InterventionIngressErrorV1::Canonical(
                "invalid submission window".to_owned(),
            ));
        }
        let mut body = GovernedInterventionSubmissionBodyV1 {
            schema: INTERVENTION_SUBMISSION_BODY_SCHEMA_V1.to_owned(),
            submission: Digest::hash_bytes(b"pending"),
            request: request.request,
            request_bytes_digest: Digest::hash_domain(REQUEST_BYTES_DOMAIN_V1, request_bytes),
            request_bytes_b64: URL_SAFE_NO_PAD.encode(request_bytes),
            submitting_principal: self.principal.clone(),
            submitting_key_id: self.key_id.clone(),
            target_runtime_profile,
            created_at_unix_ms,
            expires_at_unix_ms,
        };
        body.submission = body.derived_submission();
        let body_jcs = JcsDocument::canonicalize(&body)
            .map_err(|error| InterventionIngressErrorV1::Canonical(error.to_string()))?;
        let mut signed =
            Vec::with_capacity(SUBMISSION_SIGNATURE_PREFIX_V1.len() + body_jcs.as_bytes().len());
        signed.extend_from_slice(SUBMISSION_SIGNATURE_PREFIX_V1);
        signed.extend_from_slice(body_jcs.as_bytes());
        Ok(GovernedInterventionSubmissionV1 {
            schema: INTERVENTION_SUBMISSION_SCHEMA_V1.to_owned(),
            body,
            signature: URL_SAFE_NO_PAD.encode(self.key_pair.sign(&signed).as_ref()),
        })
    }
}

/// Validates exact request bytes and returns a display-safe inspection record.
///
/// # Errors
///
/// Returns an error when the bytes are oversized, malformed, noncanonical, or
/// fail the governed intervention request's own content binding.
pub fn inspect_request_bytes(
    bytes: &[u8],
) -> Result<GovernedInterventionRequestInspectionV1, InterventionIngressErrorV1> {
    let value = parse_exact_request_bytes(bytes)?;
    Ok(GovernedInterventionRequestInspectionV1 {
        schema: INTERVENTION_REQUEST_INSPECTION_SCHEMA_V1.to_owned(),
        request: value.request.clone(),
        exact_bytes_digest: Digest::hash_domain(REQUEST_BYTES_DOMAIN_V1, bytes),
        exact_bytes_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        value,
    })
}

/// Parses and authenticates one exact submission presentation.
///
/// # Errors
///
/// Returns a typed custody refusal when the presentation, target, submitter,
/// signature, time window, or enclosed exact request bytes fail validation.
pub fn verify_submission_bytes(
    presentation: &[u8],
    configured: &GovernedInterventionIngressV1,
    target_runtime_profile: &Digest,
    now_unix_ms: u64,
) -> Result<VerifiedInterventionSubmissionV1, InterventionIngressErrorV1> {
    if u64::try_from(presentation.len()).unwrap_or(u64::MAX) > MAX_SUBMISSION_BYTES {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Oversized,
        ));
    }
    let envelope: GovernedInterventionSubmissionV1 =
        strict_json_from_slice(presentation).map_err(|_| {
            InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::Malformed)
        })?;
    require_exact_json(presentation, &envelope)?;
    if envelope.schema != INTERVENTION_SUBMISSION_SCHEMA_V1
        || envelope.body.schema != INTERVENTION_SUBMISSION_BODY_SCHEMA_V1
    {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::UnsupportedSchema,
        ));
    }
    if envelope.body.submission != envelope.body.derived_submission() {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::BindingMismatch,
        ));
    }
    if &envelope.body.target_runtime_profile != target_runtime_profile {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::WrongTargetRuntime,
        ));
    }
    if envelope.body.submitting_principal != configured.submitter_principal {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::WrongSubmittingPrincipal,
        ));
    }
    if envelope.body.submitting_key_id != configured.submitter_key_id {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::WrongSubmittingKey,
        ));
    }
    if now_unix_ms >= envelope.body.expires_at_unix_ms {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Expired,
        ));
    }
    let body_jcs = JcsDocument::canonicalize(&envelope.body)
        .map_err(|error| InterventionIngressErrorV1::Canonical(error.to_string()))?;
    let signature = URL_SAFE_NO_PAD.decode(&envelope.signature).map_err(|_| {
        InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::AuthenticationFailed)
    })?;
    let public_key = URL_SAFE_NO_PAD
        .decode(&configured.submitter_public_key)
        .map_err(|_| {
            InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::AuthenticationFailed,
            )
        })?;
    let mut signed =
        Vec::with_capacity(SUBMISSION_SIGNATURE_PREFIX_V1.len() + body_jcs.as_bytes().len());
    signed.extend_from_slice(SUBMISSION_SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(body_jcs.as_bytes());
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&signed, &signature)
        .map_err(|_| {
            InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::AuthenticationFailed,
            )
        })?;
    let request_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.body.request_bytes_b64)
        .map_err(|_| {
            InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::BindingMismatch)
        })?;
    if Digest::hash_domain(REQUEST_BYTES_DOMAIN_V1, &request_bytes)
        != envelope.body.request_bytes_digest
    {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::BindingMismatch,
        ));
    }
    let request = parse_exact_request_bytes(&request_bytes)?;
    if request.request != envelope.body.request {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::BindingMismatch,
        ));
    }
    let custody_verification = digest_value(
        CUSTODY_VERIFICATION_DOMAIN_V1,
        &(
            &envelope.body.submission,
            &envelope.body.target_runtime_profile,
            &envelope.signature,
        ),
    );
    Ok(VerifiedInterventionSubmissionV1 {
        envelope,
        presentation_digest: Digest::hash_domain(PRESENTATION_DOMAIN_V1, presentation),
        request_bytes,
        request,
        custody_verification,
    })
}

/// Durable receipt stage.  Custody, governance, and outcome ambiguity remain distinct.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum InterventionSubmissionStatusV1 {
    /// Exact submission authenticated and durably received for evaluation.
    Received {
        /// Content-derived custody-verification evidence.
        custody_verification: Digest,
    },
    /// Existing governed kernel committed the exact transition.
    GovernedAccepted {
        /// Exact hash-chained campaign event.
        event: Digest,
        /// Exact authoritative successor state.
        successor_state: Digest,
        /// Canonical transition kind.
        transition: String,
    },
    /// Existing governed evaluation durably refused the request.
    GovernedRefused {
        /// Canonical campaign refusal when trusted request verification reached it.
        refusal: Option<Digest>,
        /// Stable refusal classification.
        code: String,
    },
    /// Custody was valid but the durable governed outcome cannot yet be established.
    OutcomeUnknown {
        /// Stable ambiguity classification.
        code: String,
    },
    /// Authentication/transport failed before governed evaluation.
    CustodyRefused {
        /// Closed custody failure classification.
        code: InterventionCustodyRefusalCodeV1,
    },
}

impl InterventionSubmissionStatusV1 {
    fn stage(&self) -> &'static str {
        match self {
            Self::Received { .. } => "received",
            Self::GovernedAccepted { .. } => "governed_accepted",
            Self::GovernedRefused { .. } => "governed_refused",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::CustodyRefused { .. } => "custody_refused",
        }
    }
}

/// One immutable, chained ingress receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionSubmissionReceiptV1 {
    /// Exact receipt schema.
    pub schema: String,
    /// Content-derived receipt identity.
    pub receipt: Digest,
    /// Claimed submission identity when structurally available. It is
    /// authenticated only for `received` and post-governance stages.
    pub submission: Option<Digest>,
    /// Digest over the exact presented envelope bytes.
    pub presentation_digest: Digest,
    /// Claimed governed request identity when structurally available. It is
    /// authenticated only for `received` and post-governance stages.
    pub request: Option<GovernedInterventionRequestIdV1>,
    /// Exact target runtime when structurally available.
    pub target_runtime_profile: Option<Digest>,
    /// Authenticated submitter when structurally available.
    pub submitting_principal: Option<String>,
    /// Exact immutable receipt stage.
    pub result: InterventionSubmissionStatusV1,
    /// Previous receipt for this exact submission/presentation.
    pub previous_receipt: Option<Digest>,
    /// Durable receipt time; not governance freshness authority.
    pub recorded_at_unix_ms: u64,
}

#[derive(Serialize)]
struct ReceiptDigestInputV1<'a> {
    schema: &'a str,
    submission: &'a Option<Digest>,
    presentation_digest: &'a Digest,
    request: &'a Option<GovernedInterventionRequestIdV1>,
    target_runtime_profile: &'a Option<Digest>,
    submitting_principal: &'a Option<String>,
    result: &'a InterventionSubmissionStatusV1,
    previous_receipt: &'a Option<Digest>,
    recorded_at_unix_ms: u64,
}

impl InterventionSubmissionReceiptV1 {
    fn derived_receipt(&self) -> Digest {
        digest_value(
            RECEIPT_DOMAIN_V1,
            &ReceiptDigestInputV1 {
                schema: &self.schema,
                submission: &self.submission,
                presentation_digest: &self.presentation_digest,
                request: &self.request,
                target_runtime_profile: &self.target_runtime_profile,
                submitting_principal: &self.submitting_principal,
                result: &self.result,
                previous_receipt: &self.previous_receipt,
                recorded_at_unix_ms: self.recorded_at_unix_ms,
            },
        )
    }
}

/// Verified read-only projection of ingress receipt history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionSubmissionHistoryV1 {
    /// Exact projection schema.
    pub schema: String,
    /// Genesis-bound target runtime.
    pub target_runtime_profile: Digest,
    /// Optional exact lookup selector.
    pub submission: Option<Digest>,
    /// Immutable receipts in durable sequence order.
    pub receipts: Vec<InterventionSubmissionReceiptV1>,
}

/// Append-only ingress receipt ledger. Its lock fences concurrent submitters;
/// the campaign store remains the only governed-transition owner.
pub struct InterventionSubmissionLedgerV1 {
    path: PathBuf,
    connection: Connection,
    target_runtime_profile: Digest,
    writer_lock: Option<Flock<File>>,
}

impl InterventionSubmissionLedgerV1 {
    /// Canonical sidecar path derived from the campaign database locator.
    #[must_use]
    pub fn path_for_campaign(database: &Path) -> PathBuf {
        let mut value = database.as_os_str().to_os_string();
        // Deliberately not `.sqlite`: Phosphor-ng discovers only immediate
        // campaign `*.sqlite` stores and must never mistake this custody
        // sidecar for an authority-bearing campaign database.
        value.push(".intervention-receipts");
        PathBuf::from(value)
    }

    /// Opens/creates the ledger and takes a blocking single-writer fence.
    ///
    /// # Errors
    ///
    /// Returns an error when file custody, the database schema/runtime
    /// binding, locking, or durable store initialization fails.
    pub fn open_writer(
        path: &Path,
        target_runtime_profile: Digest,
    ) -> Result<Self, InterventionIngressErrorV1> {
        let parent = path.parent().ok_or_else(|| {
            InterventionIngressErrorV1::Corrupt("ledger path has no parent".to_owned())
        })?;
        if !parent.is_dir() {
            return Err(InterventionIngressErrorV1::Corrupt(
                "ledger parent is absent".to_owned(),
            ));
        }
        let lock_path = path.with_extension("intervention-submissions.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)?;
        let lock_metadata = lock_file.metadata()?;
        if !lock_metadata.is_file()
            || lock_metadata.nlink() != 1
            || lock_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(InterventionIngressErrorV1::Corrupt(
                "ledger writer lock has unsafe custody".to_owned(),
            ));
        }
        let writer_lock = Flock::lock(lock_file, FlockArg::LockExclusive)
            .map_err(|(_, error)| std::io::Error::from_raw_os_error(error as i32))?;
        let mut ledger = Self::open_internal(path, target_runtime_profile, true)?;
        ledger.writer_lock = Some(writer_lock);
        Ok(ledger)
    }

    /// Opens an existing ledger for verified read-only projection.
    ///
    /// # Errors
    ///
    /// Returns an error when file custody, the database schema/runtime
    /// binding, or any immutable receipt chain fails validation.
    pub fn open_reader(
        path: &Path,
        target_runtime_profile: Digest,
    ) -> Result<Self, InterventionIngressErrorV1> {
        Self::open_internal(path, target_runtime_profile, false)
    }

    fn open_internal(
        path: &Path,
        target_runtime_profile: Digest,
        create: bool,
    ) -> Result<Self, InterventionIngressErrorV1> {
        let created_new = create && !path.exists();
        if created_new {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(InterventionIngressErrorV1::Corrupt(
                "ledger does not have safe single-owner file custody".to_owned(),
            ));
        }
        let connection = Connection::open_with_flags(
            path,
            if create {
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW
            },
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        if created_new {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            connection.execute_batch(LEDGER_SCHEMA_SQL)?;
            let schema_digest = Digest::hash_domain(
                "ag.governed-loop.intervention-ledger-schema/v1",
                LEDGER_SCHEMA_SQL.as_bytes(),
            );
            connection.execute(
                "INSERT OR IGNORE INTO ledger_identity
                 (singleton, application_id, schema_name, schema_version, schema_digest,
                  target_runtime_profile) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    i64::from(LEDGER_APPLICATION_ID),
                    LEDGER_SCHEMA_NAME,
                    i64::from(LEDGER_SCHEMA_VERSION),
                    schema_digest.as_str(),
                    target_runtime_profile.as_str(),
                ],
            )?;
            connection.pragma_update(None, "application_id", LEDGER_APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", LEDGER_SCHEMA_VERSION)?;
        }
        let ledger = Self {
            path: path.to_owned(),
            connection,
            target_runtime_profile,
            writer_lock: None,
        };
        ledger.verify()?;
        Ok(ledger)
    }

    /// Ledger path retained for operational inspection.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends or returns the idempotent custody-received receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong target runtime, conflicting presentation,
    /// corrupt receipt chain, or failed durable write.
    pub fn record_received(
        &mut self,
        verified: &VerifiedInterventionSubmissionV1,
        recorded_at_unix_ms: u64,
    ) -> Result<InterventionSubmissionReceiptV1, InterventionIngressErrorV1> {
        if verified.envelope.body.target_runtime_profile != self.target_runtime_profile {
            return Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::WrongTargetRuntime,
            ));
        }
        self.append_for_verified(
            verified,
            InterventionSubmissionStatusV1::Received {
                custody_verification: verified.custody_verification.clone(),
            },
            recorded_at_unix_ms,
        )
    }

    /// Appends or returns one idempotent post-evaluation receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong receipt stage, conflicting presentation,
    /// corrupt receipt chain, or failed durable write.
    pub fn record_result(
        &mut self,
        verified: &VerifiedInterventionSubmissionV1,
        result: InterventionSubmissionStatusV1,
        recorded_at_unix_ms: u64,
    ) -> Result<InterventionSubmissionReceiptV1, InterventionIngressErrorV1> {
        if matches!(
            result,
            InterventionSubmissionStatusV1::Received { .. }
                | InterventionSubmissionStatusV1::CustodyRefused { .. }
        ) {
            return Err(InterventionIngressErrorV1::Corrupt(
                "wrong receipt stage for governed result".to_owned(),
            ));
        }
        self.append_for_verified(verified, result, recorded_at_unix_ms)
    }

    fn append_for_verified(
        &mut self,
        verified: &VerifiedInterventionSubmissionV1,
        result: InterventionSubmissionStatusV1,
        recorded_at_unix_ms: u64,
    ) -> Result<InterventionSubmissionReceiptV1, InterventionIngressErrorV1> {
        let submission = verified.envelope.body.submission.clone();
        let existing = self.history(Some(&submission))?;
        if let Some(received) = existing.receipts.first()
            && received.presentation_digest != verified.presentation_digest
        {
            return Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::ConflictingSubmission,
            ));
        }
        if let Some(equal) = existing
            .receipts
            .iter()
            .find(|receipt| receipt.result == result)
        {
            return Ok(equal.clone());
        }
        if existing.receipts.iter().any(|receipt| {
            matches!(
                receipt.result,
                InterventionSubmissionStatusV1::GovernedAccepted { .. }
                    | InterventionSubmissionStatusV1::GovernedRefused { .. }
            )
        }) {
            return Err(InterventionIngressErrorV1::Corrupt(
                "terminal submission result cannot change".to_owned(),
            ));
        }
        let previous_receipt = existing
            .receipts
            .last()
            .map(|receipt| receipt.receipt.clone());
        let mut receipt = InterventionSubmissionReceiptV1 {
            schema: INTERVENTION_SUBMISSION_RECEIPT_SCHEMA_V1.to_owned(),
            receipt: Digest::hash_bytes(b"pending"),
            submission: Some(submission),
            presentation_digest: verified.presentation_digest.clone(),
            request: Some(verified.request.request.clone()),
            target_runtime_profile: Some(self.target_runtime_profile.clone()),
            submitting_principal: Some(verified.envelope.body.submitting_principal.clone()),
            result,
            previous_receipt,
            recorded_at_unix_ms,
        };
        receipt.receipt = receipt.derived_receipt();
        self.insert_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Records a bounded pre-governance custody refusal over presented bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the immutable refusal is internally invalid or
    /// cannot be persisted.
    pub fn record_custody_refusal(
        &mut self,
        presentation: &[u8],
        claimed_submission: Option<Digest>,
        claimed_request: Option<GovernedInterventionRequestIdV1>,
        code: InterventionCustodyRefusalCodeV1,
        recorded_at_unix_ms: u64,
    ) -> Result<InterventionSubmissionReceiptV1, InterventionIngressErrorV1> {
        let presentation_digest = Digest::hash_domain(PRESENTATION_DOMAIN_V1, presentation);
        let existing = self.receipts_for_presentation(&presentation_digest)?;
        let result = InterventionSubmissionStatusV1::CustodyRefused { code };
        if let Some(equal) = existing.iter().find(|receipt| receipt.result == result) {
            return Ok(equal.clone());
        }
        let previous_receipt = existing.last().map(|receipt| receipt.receipt.clone());
        let mut receipt = InterventionSubmissionReceiptV1 {
            schema: INTERVENTION_SUBMISSION_RECEIPT_SCHEMA_V1.to_owned(),
            receipt: Digest::hash_bytes(b"pending"),
            submission: claimed_submission,
            presentation_digest,
            request: claimed_request,
            target_runtime_profile: Some(self.target_runtime_profile.clone()),
            submitting_principal: None,
            result,
            previous_receipt,
            recorded_at_unix_ms,
        };
        receipt.receipt = receipt.derived_receipt();
        self.insert_receipt(&receipt)?;
        Ok(receipt)
    }

    fn insert_receipt(
        &mut self,
        receipt: &InterventionSubmissionReceiptV1,
    ) -> Result<(), InterventionIngressErrorV1> {
        validate_receipt(receipt)?;
        let bytes = canonical_bytes(receipt)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO receipts
             (receipt_id, submission_id, presentation_digest, request_id, stage,
              receipt_jcs, previous_receipt_id, recorded_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                receipt.receipt.as_str(),
                receipt.submission.as_ref().map(Digest::as_str),
                receipt.presentation_digest.as_str(),
                receipt
                    .request
                    .as_ref()
                    .map(|request| request.as_digest().as_str()),
                receipt.result.stage(),
                bytes,
                receipt.previous_receipt.as_ref().map(Digest::as_str),
                i64::try_from(receipt.recorded_at_unix_ms).map_err(|_| {
                    InterventionIngressErrorV1::Canonical("receipt time overflow".to_owned())
                })?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Returns verified receipts for one submission or the complete ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when reading, decoding, or validating the immutable
    /// receipt history fails.
    pub fn history(
        &self,
        submission: Option<&Digest>,
    ) -> Result<InterventionSubmissionHistoryV1, InterventionIngressErrorV1> {
        let sql = if submission.is_some() {
            "SELECT receipt_jcs FROM receipts WHERE submission_id=?1 ORDER BY sequence"
        } else {
            "SELECT receipt_jcs FROM receipts ORDER BY sequence"
        };
        let mut statement = self.connection.prepare(sql)?;
        let mut receipts = Vec::new();
        if let Some(submission) = submission {
            let rows = statement
                .query_map(params![submission.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let bytes = row?;
                decode_receipt_row(&bytes, &mut receipts)?;
            }
        } else {
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let bytes = row?;
                decode_receipt_row(&bytes, &mut receipts)?;
            }
        }
        validate_receipt_chains(&receipts)?;
        Ok(InterventionSubmissionHistoryV1 {
            schema: INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
            target_runtime_profile: self.target_runtime_profile.clone(),
            submission: submission.cloned(),
            receipts,
        })
    }

    fn receipts_for_presentation(
        &self,
        presentation: &Digest,
    ) -> Result<Vec<InterventionSubmissionReceiptV1>, InterventionIngressErrorV1> {
        let mut statement = self.connection.prepare(
            "SELECT receipt_jcs FROM receipts WHERE presentation_digest=?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map(params![presentation.as_str()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut receipts = Vec::new();
        for row in rows {
            let receipt: InterventionSubmissionReceiptV1 = strict_json_from_slice(&row?)
                .map_err(|error| InterventionIngressErrorV1::Corrupt(error.to_string()))?;
            validate_receipt(&receipt)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn verify(&self) -> Result<(), InterventionIngressErrorV1> {
        let application_id: u32 =
            self.connection
                .query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let user_version: u32 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let identity: (u32, String, u32, String, String) = self.connection.query_row(
            "SELECT application_id, schema_name, schema_version, schema_digest,
                    target_runtime_profile FROM ledger_identity WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        let schema_digest = Digest::hash_domain(
            "ag.governed-loop.intervention-ledger-schema/v1",
            LEDGER_SCHEMA_SQL.as_bytes(),
        );
        if application_id != LEDGER_APPLICATION_ID
            || user_version != LEDGER_SCHEMA_VERSION
            || identity.0 != LEDGER_APPLICATION_ID
            || identity.1 != LEDGER_SCHEMA_NAME
            || identity.2 != LEDGER_SCHEMA_VERSION
            || identity.3 != schema_digest.as_str()
            || identity.4 != self.target_runtime_profile.as_str()
        {
            return Err(InterventionIngressErrorV1::Corrupt(
                "ledger identity mismatch".to_owned(),
            ));
        }
        let _ = self.history(None)?;
        Ok(())
    }
}

fn decode_receipt_row(
    bytes: &[u8],
    receipts: &mut Vec<InterventionSubmissionReceiptV1>,
) -> Result<(), InterventionIngressErrorV1> {
    let receipt: InterventionSubmissionReceiptV1 = strict_json_from_slice(bytes)
        .map_err(|error| InterventionIngressErrorV1::Corrupt(error.to_string()))?;
    validate_receipt(&receipt)?;
    receipts.push(receipt);
    Ok(())
}

/// Reads exact bytes from a bounded nonsymlink regular input file.
///
/// # Errors
///
/// Returns an error when the path is not a safe regular file, exceeds the
/// bound, changes while being read, or cannot be read exactly.
pub fn read_exact_input(path: &Path, maximum: u64) -> Result<Vec<u8>, InterventionIngressErrorV1> {
    read_bounded_regular(path, maximum, false)
}

/// Request input byte bound used by CLI/tests.
#[must_use]
pub const fn max_request_bytes() -> u64 {
    MAX_REQUEST_BYTES
}

/// Submission input byte bound used by CLI/tests.
#[must_use]
pub const fn max_submission_bytes() -> u64 {
    MAX_SUBMISSION_BYTES
}

fn read_bounded_regular(
    path: &Path,
    maximum: u64,
    protected: bool,
) -> Result<Vec<u8>, InterventionIngressErrorV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::UnsafeInput)
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::UnsafeInput,
        ));
    }
    if metadata.len() > maximum {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Oversized,
        ));
    }
    if protected && metadata.permissions().mode() & 0o077 != 0 {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::UnsafeInput,
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Oversized,
        ));
    }
    let after = file.metadata()?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || after.nlink() != 1
    {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::UnsafeInput,
        ));
    }
    Ok(bytes)
}

fn parse_exact_request_bytes(
    bytes: &[u8],
) -> Result<GovernedInterventionRequestV1, InterventionIngressErrorV1> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Oversized,
        ));
    }
    let request: GovernedInterventionRequestV1 = strict_json_from_slice(bytes).map_err(|_| {
        InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::Malformed)
    })?;
    require_exact_json(bytes, &request)?;
    request.validate_integrity().map_err(|_| {
        InterventionIngressErrorV1::Custody(InterventionCustodyRefusalCodeV1::BindingMismatch)
    })?;
    Ok(request)
}

fn require_exact_json<T: Serialize + ?Sized>(
    bytes: &[u8],
    value: &T,
) -> Result<(), InterventionIngressErrorV1> {
    let canonical = JcsDocument::canonicalize(value)
        .map_err(|error| InterventionIngressErrorV1::Canonical(error.to_string()))?;
    if bytes != canonical.as_bytes()
        && !(bytes.ends_with(b"\n") && &bytes[..bytes.len() - 1] == canonical.as_bytes())
    {
        return Err(InterventionIngressErrorV1::Custody(
            InterventionCustodyRefusalCodeV1::Malformed,
        ));
    }
    Ok(())
}

fn validate_receipt(
    receipt: &InterventionSubmissionReceiptV1,
) -> Result<(), InterventionIngressErrorV1> {
    if receipt.schema != INTERVENTION_SUBMISSION_RECEIPT_SCHEMA_V1
        || receipt.receipt != receipt.derived_receipt()
    {
        return Err(InterventionIngressErrorV1::Corrupt(
            "receipt identity mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_receipt_chains(
    receipts: &[InterventionSubmissionReceiptV1],
) -> Result<(), InterventionIngressErrorV1> {
    let mut latest = std::collections::BTreeMap::<String, Digest>::new();
    for receipt in receipts {
        // Pre-authentication claims are useful lookup selectors, but they are
        // not allowed to join or disrupt an authenticated submission chain.
        let key = if matches!(
            receipt.result,
            InterventionSubmissionStatusV1::CustodyRefused { .. }
        ) {
            format!("presentation:{}", receipt.presentation_digest.as_str())
        } else {
            format!(
                "submission:{}",
                receipt
                    .submission
                    .as_ref()
                    .map_or_else(|| receipt.presentation_digest.as_str(), Digest::as_str)
            )
        };
        if receipt.previous_receipt != latest.get(&key).cloned() {
            return Err(InterventionIngressErrorV1::Corrupt(
                "receipt chain mismatch".to_owned(),
            ));
        }
        latest.insert(key, receipt.receipt.clone());
    }
    Ok(())
}

/// Extracts untrusted lookup selectors from a structurally decodable envelope.
///
/// A returned identity remains merely claimed until full custody verification
/// succeeds. Malformed or oversized bytes return no selectors.
#[must_use]
pub fn claimed_submission_references(
    presentation: &[u8],
) -> (Option<Digest>, Option<GovernedInterventionRequestIdV1>) {
    if u64::try_from(presentation.len()).unwrap_or(u64::MAX) > MAX_SUBMISSION_BYTES {
        return (None, None);
    }
    strict_json_from_slice::<GovernedInterventionSubmissionV1>(presentation)
        .map_or((None, None), |envelope| {
            (Some(envelope.body.submission), Some(envelope.body.request))
        })
}

fn canonical_bytes<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, InterventionIngressErrorV1> {
    Ok(JcsDocument::canonicalize(value)
        .map_err(|error| InterventionIngressErrorV1::Canonical(error.to_string()))?
        .as_bytes()
        .to_vec())
}

fn digest_value<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let bytes = JcsDocument::canonicalize(value).expect("strict internal ingress digest input");
    Digest::hash_domain(domain, bytes.as_bytes())
}

fn require_token(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_whitespace) {
        return Err("identity must be one bounded nonempty token".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use ag_campaign::CampaignId;
    use ag_campaign::governed::{
        AgIssuanceRefV1, DocketAttemptRefV1, GovernedInterventionClassV1,
        GovernedInterventionNonceRefV1, HaltReasonRefV1, HumanPrincipalRefV1, MandateRefV1,
        OccurrenceId,
    };
    use uuid::Uuid;

    use super::*;

    const TEST_PKCS8_HEX: &str = "3051020101300506032b657004220420c226c22f628685cd349518c28eff015fd216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f26313275119934a021918f5d37d100ad2f27acbaf776";

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    fn key_bytes() -> Vec<u8> {
        (0..TEST_PKCS8_HEX.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&TEST_PKCS8_HEX[offset..offset + 2], 16).unwrap())
            .collect()
    }

    fn signer(root: &Path) -> GovernedInterventionSubmissionSignerV1 {
        let path = root.join("submitter.pk8");
        fs::write(&path, key_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        GovernedInterventionSubmissionSignerV1::from_protected_file(
            "maude-intervention-submitter",
            "maude-submit-key-1",
            &path,
        )
        .unwrap()
    }

    fn request() -> GovernedInterventionRequestV1 {
        request_for_class(
            GovernedInterventionClassV1::RequestProbe {
                exact_probe_work: digest("probe"),
                evidence: vec![digest("evidence")],
            },
            "nonce",
        )
    }

    fn request_for_class(
        intervention: GovernedInterventionClassV1,
        nonce: &str,
    ) -> GovernedInterventionRequestV1 {
        GovernedInterventionRequestV1::new(
            HumanPrincipalRefV1::from_digest(digest("operator")),
            MandateRefV1::from_digest(digest("mandate")),
            GovernedInterventionNonceRefV1::from_digest(digest(nonce)),
            CampaignId::from_digest(digest("campaign")),
            OccurrenceId::from_uuid(Uuid::from_u128(1)),
            digest("state"),
            intervention,
            100,
            1_000,
        )
        .unwrap()
    }

    fn configured(
        signer: &GovernedInterventionSubmissionSignerV1,
    ) -> GovernedInterventionIngressV1 {
        GovernedInterventionIngressV1 {
            schema: crate::governed_ports::GOVERNED_INTERVENTION_INGRESS_SCHEMA_V1.to_owned(),
            submitter_principal: "maude-intervention-submitter".to_owned(),
            submitter_key_id: "maude-submit-key-1".to_owned(),
            submitter_public_key: signer.public_key_b64(),
        }
    }

    fn resign(
        signer: &GovernedInterventionSubmissionSignerV1,
        envelope: &mut GovernedInterventionSubmissionV1,
    ) {
        envelope.body.submission = envelope.body.derived_submission();
        let body = JcsDocument::canonicalize(&envelope.body).unwrap();
        let mut authenticated_bytes = Vec::new();
        authenticated_bytes.extend_from_slice(SUBMISSION_SIGNATURE_PREFIX_V1);
        authenticated_bytes.extend_from_slice(body.as_bytes());
        envelope.signature =
            URL_SAFE_NO_PAD.encode(signer.key_pair.sign(&authenticated_bytes).as_ref());
    }

    #[test]
    fn exact_request_bytes_are_inspected_signed_and_recovered_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let signer = signer(directory.path());
        let request = request();
        let mut bytes = JcsDocument::canonicalize(&request)
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes.push(b'\n');
        let inspection = inspect_request_bytes(&bytes).unwrap();
        assert_eq!(inspection.request, request.request);
        assert_eq!(inspection.exact_bytes_len, bytes.len() as u64);

        let target = digest("runtime-profile");
        let envelope = signer.package(&bytes, target.clone(), 200, 800).unwrap();
        let presentation = JcsDocument::canonicalize(&envelope).unwrap();
        let verified =
            verify_submission_bytes(presentation.as_bytes(), &configured(&signer), &target, 300)
                .unwrap();
        assert_eq!(verified.request_bytes, bytes);
        assert_eq!(verified.request, request);
        assert_eq!(
            verified.envelope.body.request_bytes_digest,
            inspection.exact_bytes_digest
        );
    }

    #[test]
    fn custody_preserves_every_closed_intervention_class_without_inference() {
        let directory = tempfile::tempdir().unwrap();
        let signer = signer(directory.path());
        let target = digest("runtime-profile");
        let issuance = AgIssuanceRefV1::from_digest(digest("issuance"));
        let classes = [
            GovernedInterventionClassV1::ReconcileAttempt {
                attempt: DocketAttemptRefV1::for_issuance(&issuance),
                issuance,
                evidence: vec![digest("reconciliation-evidence")],
            },
            GovernedInterventionClassV1::RequestProbe {
                exact_probe_work: digest("probe-work"),
                evidence: vec![digest("probe-evidence")],
            },
            GovernedInterventionClassV1::OpenSuccessor {
                successor_occurrence: OccurrenceId::from_uuid(Uuid::from_u128(2)),
                exact_work: digest("successor-work"),
            },
            GovernedInterventionClassV1::HaltContinuation {
                reason: HaltReasonRefV1::from_digest(digest("halt-reason")),
            },
        ];
        for (index, class) in classes.into_iter().enumerate() {
            let request = request_for_class(class.clone(), &format!("nonce-{index}"));
            let bytes = canonical_bytes(&request).unwrap();
            let envelope = signer.package(&bytes, target.clone(), 200, 800).unwrap();
            let presentation = canonical_bytes(&envelope).unwrap();
            let verified =
                verify_submission_bytes(&presentation, &configured(&signer), &target, 300).unwrap();
            assert_eq!(verified.request_bytes, bytes);
            assert_eq!(verified.request.intervention, class);
        }
    }

    #[test]
    fn submitter_target_expiry_and_signature_are_independent_custody_checks() {
        let directory = tempfile::tempdir().unwrap();
        let signer = signer(directory.path());
        let target = digest("runtime-profile");
        let request = JcsDocument::canonicalize(&request()).unwrap();
        let envelope = signer
            .package(request.as_bytes(), target.clone(), 200, 800)
            .unwrap();
        let mut presentation = JcsDocument::canonicalize(&envelope)
            .unwrap()
            .as_bytes()
            .to_vec();
        let expected = configured(&signer);

        let mut wrong_principal = expected.clone();
        wrong_principal.submitter_principal = "substituted".to_owned();
        assert!(matches!(
            verify_submission_bytes(&presentation, &wrong_principal, &target, 300),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::WrongSubmittingPrincipal
            ))
        ));
        let mut wrong_key = expected.clone();
        wrong_key.submitter_key_id = "wrong-key".to_owned();
        assert!(matches!(
            verify_submission_bytes(&presentation, &wrong_key, &target, 300),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::WrongSubmittingKey
            ))
        ));
        assert!(matches!(
            verify_submission_bytes(&presentation, &expected, &digest("other-runtime"), 300),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::WrongTargetRuntime
            ))
        ));
        assert!(matches!(
            verify_submission_bytes(&presentation, &expected, &target, 800),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::Expired
            ))
        ));

        let last = presentation.len() - 2;
        presentation[last] = if presentation[last] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(verify_submission_bytes(&presentation, &expected, &target, 300).is_err());

        // Even with every unauthenticated content digest recomputed, changing
        // the target remains visible to the signature verification.
        let mut rebound = envelope;
        rebound.body.target_runtime_profile = digest("substituted-runtime");
        rebound.body.submission = rebound.body.derived_submission();
        let rebound = JcsDocument::canonicalize(&rebound).unwrap();
        assert!(matches!(
            verify_submission_bytes(
                rebound.as_bytes(),
                &expected,
                &digest("substituted-runtime"),
                300,
            ),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::AuthenticationFailed
            ))
        ));
    }

    #[test]
    fn receipt_ledger_is_restart_stable_idempotent_and_runtime_bound() {
        let directory = tempfile::tempdir().unwrap();
        let signer = signer(directory.path());
        let target = digest("runtime-profile");
        let request = JcsDocument::canonicalize(&request()).unwrap();
        let envelope = signer
            .package(request.as_bytes(), target.clone(), 200, 800)
            .unwrap();
        let presentation = JcsDocument::canonicalize(&envelope).unwrap();
        let verified =
            verify_submission_bytes(presentation.as_bytes(), &configured(&signer), &target, 300)
                .unwrap();
        let path = directory.path().join("ingress.sqlite");
        let first = {
            let mut ledger =
                InterventionSubmissionLedgerV1::open_writer(&path, target.clone()).unwrap();
            let first = ledger.record_received(&verified, 301).unwrap();
            let duplicate = ledger.record_received(&verified, 999).unwrap();
            assert_eq!(first, duplicate);
            first
        };
        let result = InterventionSubmissionStatusV1::GovernedAccepted {
            event: digest("event"),
            successor_state: digest("successor"),
            transition: "probe_noted".to_owned(),
        };
        {
            let mut reopened =
                InterventionSubmissionLedgerV1::open_writer(&path, target.clone()).unwrap();
            let accepted = reopened
                .record_result(&verified, result.clone(), 302)
                .unwrap();
            assert_eq!(accepted.previous_receipt, Some(first.receipt));
            assert_eq!(
                reopened.record_result(&verified, result, 1_000).unwrap(),
                accepted
            );
            assert!(
                reopened
                    .record_result(
                        &verified,
                        InterventionSubmissionStatusV1::GovernedRefused {
                            refusal: Some(digest("refusal")),
                            code: "substituted-result".to_owned(),
                        },
                        1_001,
                    )
                    .is_err()
            );
        }
        let reader = InterventionSubmissionLedgerV1::open_reader(&path, target.clone()).unwrap();
        let history = reader
            .history(Some(&verified.envelope.body.submission))
            .unwrap();
        assert_eq!(history.receipts.len(), 2);
        assert!(InterventionSubmissionLedgerV1::open_reader(&path, digest("other")).is_err());
    }

    #[test]
    fn malformed_and_unsafe_file_inputs_fail_before_governance() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("request.json");
        fs::write(&target, b"{}").unwrap();
        let alias = directory.path().join("request-link.json");
        symlink(&target, &alias).unwrap();
        assert!(matches!(
            read_exact_input(&alias, max_request_bytes()),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::UnsafeInput
            ))
        ));
        assert!(matches!(
            inspect_request_bytes(b"{}"),
            Err(InterventionIngressErrorV1::Custody(_))
        ));
        assert!(matches!(
            inspect_request_bytes(&vec![
                b'x';
                usize::try_from(max_request_bytes() + 1).unwrap()
            ]),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::Oversized
            ))
        ));
        let signer = signer(directory.path());
        let configured = configured(&signer);
        assert!(matches!(
            verify_submission_bytes(b"{}", &configured, &digest("runtime"), 300),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::Malformed
            ))
        ));
        assert!(matches!(
            verify_submission_bytes(
                &vec![b'x'; usize::try_from(max_submission_bytes() + 1).unwrap()],
                &configured,
                &digest("runtime"),
                300,
            ),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::Oversized
            ))
        ));
    }

    #[test]
    fn valid_transport_does_not_validate_requester_and_cannot_hide_request_id_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let signer = signer(directory.path());
        let target = digest("runtime-profile");
        let request = request();
        let request_bytes = JcsDocument::canonicalize(&request).unwrap();
        let mut envelope = signer
            .package(request_bytes.as_bytes(), target.clone(), 200, 800)
            .unwrap();

        let mut substituted = request;
        substituted.principal = HumanPrincipalRefV1::from_digest(digest("other-operator"));
        substituted.request = substituted.derived_request_id();
        let substituted_bytes = JcsDocument::canonicalize(&substituted).unwrap();
        envelope.body.request = substituted.request.clone();
        envelope.body.request_bytes_digest =
            Digest::hash_domain(REQUEST_BYTES_DOMAIN_V1, substituted_bytes.as_bytes());
        envelope.body.request_bytes_b64 = URL_SAFE_NO_PAD.encode(substituted_bytes.as_bytes());
        resign(&signer, &mut envelope);
        let presentation = JcsDocument::canonicalize(&envelope).unwrap();
        let verified =
            verify_submission_bytes(presentation.as_bytes(), &configured(&signer), &target, 300)
                .unwrap();
        assert_eq!(verified.request.principal, substituted.principal);
        // Custody authenticates the service's bytes; the existing governed
        // verifier, not this layer, owns whether that requester has a mandate.

        let mut mismatch = envelope;
        mismatch.body.request = GovernedInterventionRequestIdV1::from_digest(digest("fake-id"));
        resign(&signer, &mut mismatch);
        let mismatch = JcsDocument::canonicalize(&mismatch).unwrap();
        assert!(matches!(
            verify_submission_bytes(mismatch.as_bytes(), &configured(&signer), &target, 300,),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::BindingMismatch
            ))
        ));

        let mut foreign = signer
            .package(request_bytes.as_bytes(), target.clone(), 200, 800)
            .unwrap();
        foreign.schema = "ag.governed-loop.intervention-submission/v2".to_owned();
        let foreign = JcsDocument::canonicalize(&foreign).unwrap();
        assert!(matches!(
            verify_submission_bytes(foreign.as_bytes(), &configured(&signer), &target, 300,),
            Err(InterventionIngressErrorV1::Custody(
                InterventionCustodyRefusalCodeV1::UnsupportedSchema
            ))
        ));
    }
}
