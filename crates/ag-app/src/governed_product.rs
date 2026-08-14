//! Stable versioned product DTO and service surface for governed campaigns.
//!
//! This module is the reusable application contract.  CLI records are views of
//! these DTOs; they are not a second orchestration API.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::governed_store::{
    CampaignEventV1, CampaignStoreErrorV1, CampaignStoreV1, StoreLifecycleArtifactKindV1,
};
use ag_campaign::CampaignId;
use ag_primitives::{Digest, JcsDocument};
use serde::{Deserialize, Serialize};

use ag_campaign::governed::{
    AG_ISSUANCE_SCHEMA_V2, AdmissionDecisionV1, AuthorityHistoryV1, AuthorizedSuccessorBasisV1,
    C1RejectedReviewBasisV1, CanonicalEffectScopeV1, CurrentStandingResolutionV1,
    DOCKET_CUSTODY_SCHEMA_V1, DOCKET_SETTLEMENT_SCHEMA_V1, DocketAttemptRefV1,
    DocketCheckpointRefV1, DocketIssuanceRefusalV1, DocketSealedResultRefV1,
    EXACT_WORK_PROPOSAL_SCHEMA_V1, ExactWorkProposalV1, GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1,
    GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1, GovernedRepairCheckpointV1, GovernedRepairClosedV1,
    GovernedRepairDispositionV1, GovernedRepairVerifierProfileV1, HUMAN_DECISION_REQUEST_SCHEMA_V1,
    HUMAN_DISPOSITION_SCHEMA_V1, HaltReasonRefV1, HumanDecisionIdV1, HumanDecisionRequestRefV1,
    HumanDecisionRequestV1, HumanDecisionRequirementV1, HumanDispositionRefV1, HumanPrincipalRefV1,
    HumanVerificationRefV1, IndeterminateOutcomeV1, LoopBudgetV1, MandateRefV1, ObservationRefV1,
    ObservationResolutionV1, OccurrenceId, OccurrenceKeyV1, OccurrenceSnapshotV1,
    PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1, PreSpendScopeDiscoveryParametersV1,
    PreSpendScopeDiscoveryRefV1, PreSpendScopeInsufficiencyV1, ProgramBasisRefV1, ProgramCounterV1,
    ProposalClassV1, ProposalRefV1, RefusalCodeV1, ResidualSetV1, TerminalWitnessRefV1,
};

use crate::governed_loop::{CampaignEngineErrorV1, CampaignEngineV1};
pub use crate::governed_loop::{
    CampaignEngineErrorV1 as GovernedProductErrorV1, EXACT_WORK_CATALOG_SCHEMA_V1,
    ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
};
use crate::governed_ports::{
    AgIssuanceSignerV2, CommandDocketCustodyPortV1, CommandObservationResolverV1,
    CommandStandingResolverV1,
};

impl CampaignEngineErrorV1 {
    /// Returns the stable product/CLI failure taxonomy for this closed error.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::Store(error) => match error {
                CampaignStoreErrorV1::AlreadyExists(_) => "store_already_exists",
                CampaignStoreErrorV1::Missing(_) => "store_not_found",
                CampaignStoreErrorV1::Sqlite(_) => "store_sqlite_failure",
                CampaignStoreErrorV1::Io(_) => "store_io_failure",
                CampaignStoreErrorV1::Canonical(_) => "invalid_store_record",
                CampaignStoreErrorV1::Kernel(_) => "transition_refused",
                CampaignStoreErrorV1::StalePredecessor { .. } => "stale_state",
                CampaignStoreErrorV1::BindingMismatch => "binding_mismatch",
                CampaignStoreErrorV1::StoreIdentity => "invalid_store_identity",
                CampaignStoreErrorV1::Corrupt(_) => "corrupt_store",
                CampaignStoreErrorV1::HumanDispositionReplay => {
                    "human_disposition_replay_or_substitution"
                }
                CampaignStoreErrorV1::GovernedRepairReplay => {
                    "governed_repair_replay_or_substitution"
                }
                CampaignStoreErrorV1::PreSpendScopeInsufficiencyCollision => {
                    "pre_spend_scope_insufficiency_replay_or_substitution"
                }
                CampaignStoreErrorV1::PreSpendScopeDiscoveryCollision => {
                    "pre_spend_scope_discovery_replay_or_substitution"
                }
                CampaignStoreErrorV1::IssuanceSigningAlreadyReserved => {
                    "issuance_reconciliation_required"
                }
                CampaignStoreErrorV1::GovernedRepairVerifier(_) => "verifier_refused",
            },
            Self::Kernel(_) => "transition_refused",
            Self::External(ag_campaign::governed::ExternalBoundaryErrorV1::Refused { .. }) => {
                "external_boundary_refused"
            }
            Self::External(ag_campaign::governed::ExternalBoundaryErrorV1::Unavailable {
                ..
            }) => "external_boundary_unavailable",
            Self::InvalidCatalog => "invalid_catalog",
            Self::Canonical(_) => "invalid_canonical_record",
            Self::OperationNotAllowed(_) => "operation_not_allowed",
            Self::DocketResponse => "invalid_docket_response",
        }
    }

    /// Returns the caller-presented state for a stale compare-and-swap failure.
    #[must_use]
    pub const fn cas_expected_state(&self) -> Option<&Digest> {
        match self {
            Self::Store(CampaignStoreErrorV1::StalePredecessor { expected, .. }) => Some(expected),
            _ => None,
        }
    }

    /// Returns the authoritative state for a stale compare-and-swap failure.
    #[must_use]
    pub const fn cas_authoritative_state(&self) -> Option<&Digest> {
        match self {
            Self::Store(CampaignStoreErrorV1::StalePredecessor { authoritative, .. }) => {
                Some(authoritative)
            }
            _ => None,
        }
    }
}

/// Stable product API schema.
pub const GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1: &str = "ag.governed-loop.product-service/v1";

/// Root/deployment-owned verifier profile catalog schema.
pub const GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verifier-catalog/v1";
/// Immutable deployment-root schema for the governed-repair verifier.
pub const GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1: &str =
    "ag.governed-loop.governed-repair-verifier-root/v1";
/// Immutable deployment-owned Docket adapter configuration schema.
pub const GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1: &str = "ag.governed-loop.docket-adapter-root/v1";
/// Immutable deployment-owned AG governance boundary schema.
pub const GOVERNED_AG_POLICY_ROOT_SCHEMA_V1: &str = "ag.governed-loop.ag-policy-root/v1";
/// Stable AG-owned occurrence projection schema.
pub const GOVERNED_OCCURRENCE_VIEW_SCHEMA_V1: &str = "ag.governed-loop.occurrence-view/v1";
/// Stable closed artifact response schema.
pub const GOVERNED_ARTIFACT_RECORD_SCHEMA_V1: &str = "ag.governed-loop.artifact-record/v1";
/// Stable allowed-transition response schema.
pub const GOVERNED_ALLOWED_TRANSITIONS_SCHEMA_V1: &str = "ag.governed-loop.allowed-transitions/v1";
/// AG-held Docket checkpoint correspondence schema.
pub const DOCKET_CHECKPOINT_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.docket-checkpoint-reference/v1";
/// AG-held Docket effect-journal correspondence schema.
pub const EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.effect-journal-reference/v1";
/// Authority-empty successor binding artifact schema.
pub const SUCCESSOR_BINDING_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.successor-binding-artifact/v1";
/// Exact residual-state artifact schema.
pub const RESIDUAL_STATE_ARTIFACT_SCHEMA_V1: &str = "ag.governed-loop.residual-state-artifact/v1";
/// Exact admission-decision artifact envelope schema. The admission decision's
/// existing semantic identity remains the address; the envelope supplies a
/// closed version discriminator without changing that identity law.
pub const ADMISSION_DECISION_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.admission-decision-artifact/v1";
/// Exact observation-resolution artifact envelope schema.
pub const OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.observation-resolution-artifact/v1";
/// Exact standing-resolution artifact envelope schema.
pub const STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.standing-resolution-artifact/v1";
/// Exact indeterminate Docket outcome artifact schema.
pub const DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.docket-indeterminate-outcome-artifact/v1";
/// Exact completion-observation artifact schema.
pub const COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.completion-observation-artifact/v1";
/// Exact completion-witness correspondence artifact schema.
pub const TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1: &str =
    "ag.governed-loop.terminal-witness-reference-artifact/v1";

/// One deployment-owned verifier root pinned into the campaign store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairVerifierRootV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact semantic label; fixtures must identify themselves as such.
    pub verifier_label: String,
    /// Operational absolute executable locator.
    pub executable: PathBuf,
    /// SHA-256 over the exact executable bytes, remeasured per use.
    pub executable_identity: Digest,
    /// Closed root-owned profile catalog.
    pub catalog: GovernedRepairVerifierCatalogV1,
}

impl GovernedRepairVerifierRootV1 {
    fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        self.validate()?;
        let document = ag_primitives::JcsDocument::canonicalize(self)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        Ok(Digest::hash_domain(
            "ag.governed-loop.governed-repair-verifier-root/v1",
            document.as_bytes(),
        ))
    }

    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1
            || self.verifier_label.is_empty()
            || !self.executable.is_absolute()
            || self.catalog.schema != GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1
            || self.catalog.profiles.is_empty()
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "invalid governed-repair verifier root".to_owned(),
            ));
        }
        self.catalog.validate()?;
        Ok(())
    }

    /// Remeasures the exact verifier executable required by a disposition.
    /// This is an availability observation only: it invokes no verifier and
    /// constructs no verification or disposition authority.
    fn verify_runtime_correspondence(&self) -> Result<(), CampaignEngineErrorV1> {
        self.validate()?;
        let executable = PinnedDeploymentFileV1 {
            path: self.executable.clone(),
            identity: self.executable_identity.clone(),
        };
        let _ = executable.verify_bytes(true)?;
        Ok(())
    }
}

/// Root-owned verifier catalog.  Caller artifacts cannot nominate acceptance
/// premises; service operations select one entry by its exact profile digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairVerifierCatalogV1 {
    /// Exact schema.
    pub schema: String,
    /// Nonempty closed profiles.
    pub profiles: Vec<GovernedRepairVerifierProfileRecordV1>,
}

/// Serializable root-owned verifier profile record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRepairVerifierProfileRecordV1 {
    /// Exact profile identity.
    pub profile: Digest,
    /// Exact expected principal.
    pub principal: HumanPrincipalRefV1,
    /// Exact expected mandate.
    pub mandate: MandateRefV1,
}

impl GovernedRepairVerifierCatalogV1 {
    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != GOVERNED_REPAIR_VERIFIER_CATALOG_SCHEMA_V1
            || self.profiles.is_empty()
            || self
                .profiles
                .windows(2)
                .any(|pair| pair[0].profile >= pair[1].profile)
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "invalid root verifier profile catalog".to_owned(),
            ));
        }
        Ok(())
    }

    /// Resolves one exact root-owned profile or fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the catalog is malformed or the exact profile is absent.
    pub fn resolve(
        &self,
        identity: &Digest,
        root: Digest,
        executable: Digest,
    ) -> Result<GovernedRepairVerifierProfileV1, CampaignEngineErrorV1> {
        self.validate()?;
        let row = self
            .profiles
            .iter()
            .find(|row| &row.profile == identity)
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "required verifier profile is not root-configured".to_owned(),
                )
            })?;
        Ok(GovernedRepairVerifierProfileV1 {
            profile: row.profile.clone(),
            root,
            executable,
            principal: row.principal.clone(),
            mandate: row.mandate.clone(),
        })
    }
}

/// One immutable deployment file coordinate. Its path is operational
/// configuration; its digest binds the exact bytes accepted at consequence
/// time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedDeploymentFileV1 {
    /// Absolute deployment path.
    pub path: PathBuf,
    /// SHA-256 over exact file bytes.
    pub identity: Digest,
}

impl PinnedDeploymentFileV1 {
    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if !self.path.is_absolute() {
            return Err(CampaignEngineErrorV1::Canonical(
                "pinned deployment file path must be absolute".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_bytes(&self, executable: bool) -> Result<Vec<u8>, CampaignEngineErrorV1> {
        self.validate()?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|error| {
                CampaignEngineErrorV1::Canonical(format!(
                    "open pinned deployment file {}: {error}",
                    self.path.display()
                ))
            })?;
        let metadata = file.metadata().map_err(|error| {
            CampaignEngineErrorV1::Canonical(format!(
                "inspect pinned deployment file {}: {error}",
                self.path.display()
            ))
        })?;
        if !metadata.is_file() || (executable && metadata.permissions().mode() & 0o111 == 0) {
            return Err(CampaignEngineErrorV1::Canonical(format!(
                "pinned deployment file has wrong type/mode: {}",
                self.path.display()
            )));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| {
            CampaignEngineErrorV1::Canonical(format!(
                "measure pinned deployment file {}: {error}",
                self.path.display()
            ))
        })?;
        if Digest::hash_bytes(&bytes) != self.identity {
            return Err(CampaignEngineErrorV1::Canonical(format!(
                "pinned deployment file identity mismatch: {}",
                self.path.display()
            )));
        }
        Ok(bytes)
    }
}

/// Deployment-owned governance inputs used by the stable AG producer. Product
/// callers select operations and exact work, never resolvers, clocks, policy,
/// or controlling diagnostic testimony.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedAgPolicyRootV1 {
    /// Exact schema.
    pub schema: String,
    /// Deployment-owned semantic label; fixtures must identify themselves.
    pub policy_label: String,
    /// Exact consequence-time source executable. It emits one canonical u64
    /// Unix-millisecond value followed by an optional LF.
    pub consequence_clock: PinnedDeploymentFileV1,
    /// Exact observation-owner resolver executable.
    pub observation_resolver: PinnedDeploymentFileV1,
    /// Exact Standing resolver executable.
    pub standing_resolver: PinnedDeploymentFileV1,
    /// Exact canonical `ExactWorkCatalogV1` bytes.
    pub exact_work_catalog: PinnedDeploymentFileV1,
    /// Optional exact externally supplied C1 rejection testimony. AG binds and
    /// compares it; AG does not decide its NQ meaning.
    pub controlling_review: Option<PinnedDeploymentFileV1>,
}

impl GovernedAgPolicyRootV1 {
    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != GOVERNED_AG_POLICY_ROOT_SCHEMA_V1 || self.policy_label.is_empty() {
            return Err(CampaignEngineErrorV1::Canonical(
                "invalid governed AG policy root".to_owned(),
            ));
        }
        for file in [
            &self.consequence_clock,
            &self.observation_resolver,
            &self.standing_resolver,
            &self.exact_work_catalog,
        ] {
            file.validate()?;
        }
        if let Some(file) = &self.controlling_review {
            file.validate()?;
        }
        Ok(())
    }

    fn now_unix_ms(&self) -> Result<u64, CampaignEngineErrorV1> {
        let _ = self.consequence_clock.verify_bytes(true)?;
        let output = Command::new(&self.consequence_clock.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| {
                CampaignEngineErrorV1::Canonical(format!(
                    "invoke pinned consequence clock {}: {error}",
                    self.consequence_clock.path.display()
                ))
            })?;
        if !output.status.success() {
            return Err(CampaignEngineErrorV1::Canonical(format!(
                "pinned consequence clock refused: {}",
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(256)
                    .collect::<String>()
            )));
        }
        let body = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
        if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
            return Err(CampaignEngineErrorV1::Canonical(
                "pinned consequence clock output is not exact".to_owned(),
            ));
        }
        let value = std::str::from_utf8(body)
            .map_err(|_| CampaignEngineErrorV1::Canonical("clock output is not UTF-8".to_owned()))?
            .parse::<u64>()
            .map_err(|_| CampaignEngineErrorV1::Canonical("clock output is not u64".to_owned()))?;
        if value > ag_campaign::governed::MAX_CANONICAL_JSON_INTEGER_V1 {
            return Err(CampaignEngineErrorV1::Canonical(
                "clock output exceeds canonical JSON integer range".to_owned(),
            ));
        }
        Ok(value)
    }

    fn verify_deployment(&self) -> Result<(), CampaignEngineErrorV1> {
        self.validate()?;
        let _ = self.consequence_clock.verify_bytes(true)?;
        let _ = self.observation_resolver.verify_bytes(true)?;
        let _ = self.standing_resolver.verify_bytes(true)?;
        let _ = self.exact_work_catalog.verify_bytes(false)?;
        if let Some(review) = &self.controlling_review {
            let _ = review.verify_bytes(false)?;
        }
        Ok(())
    }

    fn observation(&self) -> Result<CommandObservationResolverV1, CampaignEngineErrorV1> {
        let _ = self.observation_resolver.verify_bytes(true)?;
        Ok(CommandObservationResolverV1::new(
            self.observation_resolver.path.clone(),
        ))
    }

    fn standing(&self) -> Result<CommandStandingResolverV1, CampaignEngineErrorV1> {
        let _ = self.standing_resolver.verify_bytes(true)?;
        Ok(CommandStandingResolverV1::new(
            self.standing_resolver.path.clone(),
        ))
    }

    fn catalog(&self) -> Result<ExactWorkCatalogV1, CampaignEngineErrorV1> {
        let bytes = self.exact_work_catalog.verify_bytes(false)?;
        let document = ag_primitives::JcsDocument::from_canonical_bytes(
            bytes.strip_suffix(b"\n").unwrap_or(&bytes),
        )
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        let catalog: ExactWorkCatalogV1 = serde_json::from_slice(document.as_bytes())
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        catalog.validate()?;
        Ok(catalog)
    }

    fn review(&self) -> Result<Option<C1RejectedReviewBasisV1>, CampaignEngineErrorV1> {
        self.controlling_review
            .as_ref()
            .map(|file| {
                let bytes = file.verify_bytes(false)?;
                let document = ag_primitives::JcsDocument::from_canonical_bytes(
                    bytes.strip_suffix(b"\n").unwrap_or(&bytes),
                )
                .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                serde_json::from_slice(document.as_bytes())
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))
            })
            .transpose()
    }
}

/// Deployment-owned exact Docket adapter root. Normal lifecycle operations do
/// not accept any of these authority or execution premises from callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedDocketAdapterRootV1 {
    /// Exact schema.
    pub schema: String,
    /// Deployment-owned semantic label.
    pub adapter_label: String,
    /// Exact Docket executable.
    pub docket_program: PinnedDeploymentFileV1,
    /// Exact mutable Docket state-directory location.
    pub state_directory: PathBuf,
    /// Exact Docket trust configuration.
    pub trust_config: PinnedDeploymentFileV1,
    /// Exact Standing resolver executable.
    pub standing_resolver: PinnedDeploymentFileV1,
    /// Exact executor adapter executable.
    pub executor_adapter: PinnedDeploymentFileV1,
    /// Exact executor configuration.
    pub executor_config: PinnedDeploymentFileV1,
    /// Optional exact checkpoint verifier executable.
    pub checkpoint_verifier: Option<PinnedDeploymentFileV1>,
    /// Exact AG issuance principal presented to Docket.
    pub issuer_principal: String,
    /// Exact issuance signing-key identifier.
    pub issuer_key_id: String,
    /// Exact Ed25519 PKCS#8 issuance signing key bytes.
    pub issuer_key: PinnedDeploymentFileV1,
}

impl GovernedDocketAdapterRootV1 {
    fn validate(&self) -> Result<(), CampaignEngineErrorV1> {
        if self.schema != GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1
            || self.adapter_label.is_empty()
            || self.issuer_principal.is_empty()
            || self.issuer_key_id.is_empty()
            || !self.state_directory.is_absolute()
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "invalid governed Docket adapter root".to_owned(),
            ));
        }
        for file in [
            &self.docket_program,
            &self.trust_config,
            &self.standing_resolver,
            &self.executor_adapter,
            &self.executor_config,
            &self.issuer_key,
        ] {
            file.validate()?;
        }
        if let Some(file) = &self.checkpoint_verifier {
            file.validate()?;
        }
        Ok(())
    }

    /// Remeasures every deployment coordinate needed to open the Docket
    /// custody port. This check is non-authorizing: it creates neither a Store
    /// signing permit nor an execution-custody value.
    fn verify_runtime_correspondence(&self) -> Result<(), CampaignEngineErrorV1> {
        self.validate()?;
        let state = std::fs::symlink_metadata(&self.state_directory).map_err(|error| {
            CampaignEngineErrorV1::Canonical(format!(
                "inspect pinned Docket state directory {}: {error}",
                self.state_directory.display()
            ))
        })?;
        if state.file_type().is_symlink() || !state.is_dir() {
            return Err(CampaignEngineErrorV1::Canonical(
                "pinned Docket state path is not an exact directory".to_owned(),
            ));
        }
        let _ = self.docket_program.verify_bytes(true)?;
        let _ = self.trust_config.verify_bytes(false)?;
        let _ = self.standing_resolver.verify_bytes(true)?;
        let _ = self.executor_adapter.verify_bytes(true)?;
        let _ = self.executor_config.verify_bytes(false)?;
        if let Some(file) = &self.checkpoint_verifier {
            let _ = file.verify_bytes(true)?;
        }
        let key = self.issuer_key.verify_bytes(false)?;
        let _ = AgIssuanceSignerV2::from_pkcs8(
            self.issuer_principal.clone(),
            self.issuer_key_id.clone(),
            &key,
        )
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        Ok(())
    }

    fn open_port(
        &self,
        signing_permit: Option<crate::governed_store::StoreIssuanceSigningPermitV1>,
    ) -> Result<CommandDocketCustodyPortV1, CampaignEngineErrorV1> {
        self.verify_runtime_correspondence()?;
        // Reread and reparse at the actual port-construction boundary. The
        // preceding projection check is never inherited as live authority.
        let key = self.issuer_key.verify_bytes(false)?;
        let signer = AgIssuanceSignerV2::from_pkcs8(
            self.issuer_principal.clone(),
            self.issuer_key_id.clone(),
            &key,
        )
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        Ok(CommandDocketCustodyPortV1::new(
            self.docket_program.path.clone(),
            self.state_directory.clone(),
            self.trust_config.path.clone(),
            self.standing_resolver.path.clone(),
            self.executor_adapter.path.clone(),
            self.executor_config.path.clone(),
            self.checkpoint_verifier
                .as_ref()
                .map(|file| file.path.clone()),
            signer,
            signing_permit,
        ))
    }
}

/// Stable page request used for occurrences and ordered events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequestV1 {
    /// Exclusive stable cursor; absent means start.
    pub after: Option<String>,
    /// Bounded page size in `1..=1000`.
    pub limit: u32,
}

/// Stable occurrence-specific page request. Filters are applied by AG to its
/// authoritative occurrence projection; clients never reconstruct state from
/// event streams.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrencePageRequestV1 {
    /// Exclusive stable occurrence UUID cursor; absent means start.
    pub after: Option<String>,
    /// Bounded page size in `1..=1000` after filtering.
    pub limit: u32,
    /// Optional exact closed program-counter filter.
    pub program_counter: Option<ProgramCounterV1>,
    /// Optional governed-repair-pending filter.
    pub governed_repair_pending: Option<bool>,
}

/// Stable occurrence page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrencePageV1 {
    /// Exact items in stable UUID order.
    pub items: Vec<OccurrenceViewV1>,
    /// Cursor for the next page, absent at exhaustion.
    pub next: Option<String>,
}

/// Closed product operation vocabulary. Every value is directly executable by
/// `ag-loopctl` using [`Self::cli_subcommand`]; aliases accepted by the CLI are
/// compatibility spellings and never appear in this contract.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedOperationV1 {
    /// Resolve a fresh observation and record an exact proposal.
    RecordProposal,
    /// Enter the explicit current-standing-required state.
    RequireStanding,
    /// Resolve current premises and record the admission decision.
    Decide,
    /// Re-resolve current premises and spend one AG authorization.
    Authorize,
    /// Submit the already-spent exact issuance to Docket custody.
    Dispatch,
    /// Reconcile the exact Docket attempt.
    ReconcileDocket,
    /// Apply the state-specific restart law.
    Recover,
    /// Open an authority-empty post-settlement continuation.
    OpenContinuation,
    /// Persist one read-only probe-count fact.
    NoteProbe,
    /// Halt from an authority-safe boundary.
    Halt,
    /// Record a typed nonauthorizing pre-spend scope-insufficiency halt.
    HaltPreSpendScopeInsufficiency,
    /// Record one exact discovery and open its authority-empty revised occurrence.
    RecordPreSpendScopeDiscovery,
    /// Consume one escalation budget fact and halt.
    Escalate,
    /// Complete an authority-empty occurrence.
    Complete,
    /// Create one durable non-authorizing governed-repair request.
    CreateDecisionRequest,
    /// Submit one externally verified governed-repair disposition.
    SubmitDisposition,
    /// Persist one typed no-state-change refusal.
    RecordRefusal,
}

impl GovernedOperationV1 {
    /// Returns the stable snake-case product identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordProposal => "record_proposal",
            Self::RequireStanding => "require_standing",
            Self::Decide => "decide",
            Self::Authorize => "authorize",
            Self::Dispatch => "dispatch",
            Self::ReconcileDocket => "reconcile_docket",
            Self::Recover => "recover",
            Self::OpenContinuation => "open_continuation",
            Self::NoteProbe => "note_probe",
            Self::Halt => "halt",
            Self::HaltPreSpendScopeInsufficiency => "halt_pre_spend_scope_insufficiency",
            Self::RecordPreSpendScopeDiscovery => "record_pre_spend_scope_discovery",
            Self::Escalate => "escalate",
            Self::Complete => "complete",
            Self::CreateDecisionRequest => "create_decision_request",
            Self::SubmitDisposition => "submit_disposition",
            Self::RecordRefusal => "record_refusal",
        }
    }

    /// Returns the canonical executable `ag-loopctl` subcommand.
    #[must_use]
    pub const fn cli_subcommand(self) -> &'static str {
        match self {
            Self::RecordProposal => "record-proposal",
            Self::RequireStanding => "require-standing",
            Self::Decide => "decide",
            Self::Authorize => "authorize",
            Self::Dispatch => "dispatch",
            Self::ReconcileDocket => "reconcile-docket",
            Self::Recover => "recover",
            Self::OpenContinuation => "open-continuation",
            Self::NoteProbe => "note-probe",
            Self::Halt => "halt",
            Self::HaltPreSpendScopeInsufficiency => "halt-pre-spend-scope-insufficiency",
            Self::RecordPreSpendScopeDiscovery => "record-pre-spend-scope-discovery",
            Self::Escalate => "escalate",
            Self::Complete => "complete",
            Self::CreateDecisionRequest => "create-decision-request",
            Self::SubmitDisposition => "submit-disposition",
            Self::RecordRefusal => "record-refusal",
        }
    }
}

/// Closed semantic class for every canonical artifact retrievable through the
/// governed product service. Adding a durable lifecycle artifact requires an
/// explicit extension here; clients never infer authority from JSON shape.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedArtifactKindV1 {
    /// Exact product campaign-creation basis.
    ProductCreation,
    /// Genesis-pinned governed-repair verifier root.
    GovernedRepairVerifierRoot,
    /// Exact immutable work proposal.
    ExactWorkProposal,
    /// Exact external observation/currentness record consumed by AG.
    ObservationResolution,
    /// Exact external standing/currentness record consumed by AG.
    StandingResolution,
    /// Exact AG admissibility decision.
    AdmissionDecision,
    /// Durable one-use AG authorization spend evidence.
    AgAuthorizationSpend,
    /// Exact AG issuance.
    AgIssuance,
    /// Exact Docket custody evidence.
    DocketCustody,
    /// Exact Docket settlement evidence.
    DocketSettlement,
    /// Exact indeterminate Docket reconciliation evidence.
    DocketIndeterminateOutcome,
    /// Exact Docket issuance refusal.
    DocketIssuanceRefusal,
    /// Complete Docket-sealed governed-repair result.
    DocketGovernedRepairResult,
    /// AG-held correspondence projection for Docket's sealed checkpoint ref.
    DocketCheckpointReference,
    /// AG-held correspondence projection for Docket's effect-journal ref.
    EffectJournalReference,
    /// Exact non-authorizing human-decision request.
    HumanDecisionRequest,
    /// Exact governed-repair disposition evidence.
    GovernedRepairDisposition,
    /// Exact external-verifier receipt consumed by AG.
    GovernedRepairVerification,
    /// Exact authority-empty predecessor/successor constraint.
    SuccessorBinding,
    /// Exact nonauthorizing pre-spend scope discovery and revision binding.
    PreSpendScopeDiscovery,
    /// Exact residual state at one occurrence cut.
    ResidualState,
    /// Exact fresh observation that completed an occurrence.
    CompletionObservation,
    /// AG-held correspondence for the externally owned terminal witness.
    TerminalWitness,
    /// Historical disposition evidence from the retired decoder-only path.
    HistoricalHumanDisposition,
    /// Exact durable non-authorizing refusal.
    Refusal,
}

/// AG-held correspondence for a Docket checkpoint reference. The Docket
/// identity remains externally owned; these canonical bytes prove exactly
/// which sealed result and immutable source checkpoint AG associated with it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketCheckpointArtifactV1 {
    /// Stable product schema.
    pub schema: String,
    /// Exact Docket checkpoint identity.
    pub checkpoint: DocketCheckpointRefV1,
    /// Exact Docket sealed result containing the reference.
    pub sealed_result: DocketSealedResultRefV1,
    /// Exact immutable work checkpoint, when Docket sealed one.
    pub immutable_work_checkpoint: Option<GovernedRepairCheckpointV1>,
}

/// Versioned product envelope for AG's exact admission decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecisionArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact immutable AG state cut retaining the record.
    pub state_digest: Digest,
    /// Exact decision record whose existing identity addresses this artifact.
    pub record: AdmissionDecisionV1,
}

/// Versioned product envelope for one exact external observation resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationResolutionArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact immutable AG state cut retaining the record.
    pub state_digest: Digest,
    /// Exact resolver record. Its semantic observation reference is not
    /// overloaded as a content identity because fresh resolutions may differ.
    pub record: ObservationResolutionV1,
}

/// Versioned product envelope for one exact external standing resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingResolutionArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact immutable AG state cut retaining the record.
    pub state_digest: Digest,
    /// Exact resolver record. Its external resolution reference is evidence,
    /// not assumed to be a canonical-byte hash.
    pub record: CurrentStandingResolutionV1,
}

/// Versioned product envelope for exact indeterminate Docket evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocketIndeterminateArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact immutable AG state cut retaining the record.
    pub state_digest: Digest,
    /// Exact Docket indeterminate outcome.
    pub record: IndeterminateOutcomeV1,
}

/// Versioned product envelope for the exact fresh observation that completed
/// one occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionObservationArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact immutable completed-state cut retaining the record.
    pub state_digest: Digest,
    /// Exact terminal observation resolution.
    pub record: ObservationResolutionV1,
}

/// Versioned AG-held correspondence for an externally owned terminal witness.
/// The wrapper is content-addressed so reuse of one external witness reference
/// across occurrences cannot alias changed AG correspondence bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalWitnessArtifactV1 {
    /// Stable product artifact schema.
    pub schema: String,
    /// Exact completed occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact immutable completed-state cut.
    pub state_digest: Digest,
    /// Exact external terminal-witness identity.
    pub witness: TerminalWitnessRefV1,
}

fn product_artifact_identity<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Digest, CampaignEngineErrorV1> {
    Ok(Digest::hash_domain(
        domain,
        JcsDocument::canonicalize(value)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?
            .as_bytes(),
    ))
}

impl ObservationResolutionArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1, self)
    }
}

impl StandingResolutionArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1, self)
    }
}

impl AdmissionDecisionArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(ADMISSION_DECISION_ARTIFACT_SCHEMA_V1, self)
    }
}

impl DocketIndeterminateArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1, self)
    }
}

impl CompletionObservationArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1, self)
    }
}

impl TerminalWitnessArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        product_artifact_identity(TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1, self)
    }
}

/// AG-held correspondence for Docket's cumulative effect-journal reference.
/// AG does not claim custody of the journal entries themselves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectJournalReferenceArtifactV1 {
    /// Stable product schema.
    pub schema: String,
    /// Exact Docket-owned cumulative journal identity.
    pub effect_journal: Digest,
}

/// Exact non-authorizing successor lineage retained by AG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorBindingArtifactV1 {
    /// Stable product schema.
    pub schema: String,
    /// Exact predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Exact successor occurrence.
    pub successor: OccurrenceKeyV1,
    /// Closed externally verified successor constraint.
    pub binding: AuthorizedSuccessorBasisV1,
}

/// Exact residual obligations at one immutable occurrence-state cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualStateArtifactV1 {
    /// Stable product schema.
    pub schema: String,
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact state cut.
    pub state_digest: Digest,
    /// Complete open residual set at that cut.
    pub residuals: ResidualSetV1,
}

impl ResidualStateArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        Ok(Digest::hash_domain(
            "ag.governed-loop.residual-state-artifact/v1",
            JcsDocument::canonicalize(self)
                .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?
                .as_bytes(),
        ))
    }
}

impl SuccessorBindingArtifactV1 {
    pub(crate) fn identity(&self) -> Result<Digest, CampaignEngineErrorV1> {
        Ok(Digest::hash_domain(
            "ag.governed-loop.successor-binding-artifact/v1",
            JcsDocument::canonicalize(self)
                .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?
                .as_bytes(),
        ))
    }
}

/// One exact artifact address exposed by an AG-owned occurrence or campaign
/// projection. The link is evidence/navigation only and grants no authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedArtifactLinkV1 {
    /// Closed semantic artifact class.
    pub kind: GovernedArtifactKindV1,
    /// Exact domain-specific artifact identity.
    pub identity: Digest,
}

/// Stable AG-owned occurrence projection. It exposes exact loop facts and
/// evidence references without coupling clients to the kernel/persistence
/// state's nested Docket-shaped variants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceViewV1 {
    /// Exact projection schema.
    pub schema: String,
    /// Exact occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact program basis.
    pub program: ProgramBasisRefV1,
    /// Closed AG program counter.
    pub program_counter: ProgramCounterV1,
    /// Exact predecessor-state identity.
    pub prior_state_digest: Digest,
    /// Exact authoritative state identity used for CAS.
    pub state_digest: Digest,
    /// Exact open residuals.
    pub residuals: ResidualSetV1,
    /// Durable loop budget facts.
    pub budget: LoopBudgetV1,
    /// Exact consumed human decisions.
    pub used_human_decisions: Vec<HumanDecisionIdV1>,
    /// Evidence-only authority lineage references.
    pub authority_history: AuthorityHistoryV1,
    /// Closed exact artifact addresses reachable from this occurrence without
    /// querying Docket or reconstructing private Store state.
    pub artifacts: Vec<GovernedArtifactLinkV1>,
    /// Exact immutable proposal contract once proposal recording occurred.
    /// Authority-empty observation shells expose `None`.
    pub proposal_contract: Option<ProposalContractViewV1>,
    /// Exact nonauthorizing pre-spend revision constraint on an
    /// observation-required successor.  This records its pending proposal but
    /// carries no observation, standing, admission, spend, or issuance.
    pub pre_spend_revision: Option<PreSpendRevisionConstraintViewV1>,
    /// Halt-specific facts, absent at every other program counter.
    pub halted: Option<HaltedOccurrenceViewV1>,
    /// Completion-specific evidence, absent at every other program counter.
    pub completed: Option<CompletedOccurrenceViewV1>,
}

/// Stable projection of the identity-bearing proposal governance terms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalContractViewV1 {
    /// Exact proposal identity committing to the complete canonical record.
    pub proposal: ProposalRefV1,
    /// Complete immutable proposal contract. The record revalidates to
    /// `proposal` and contains the exact subject, scope, work, checkpoint,
    /// repair citation, nonclaims, and expiry.
    pub exact_record: ExactWorkProposalV1,
    /// Explicit sorted, duplicate-free nonclaim identities.
    pub nonclaims: Vec<Digest>,
    /// Exclusive absolute deadline for fresh consequence-bearing progress.
    pub expires_at_unix_ms: u64,
}

/// Stable product projection of an exact pending pre-spend revision.  The
/// constraint is lineage/evidence only and cannot substitute for recording a
/// fresh observation against the exact revised proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSpendRevisionConstraintViewV1 {
    /// Exact immutable predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Exact discovery artifact that opened the revised occurrence.
    pub discovery: PreSpendScopeDiscoveryRefV1,
    /// Exact pending revised proposal identity.
    pub revised_proposal: ProposalRefV1,
    /// Complete pending revised proposal contract.
    pub exact_revised_proposal: ExactWorkProposalV1,
}

impl OccurrenceViewV1 {
    /// Returns the exact occurrence key.
    #[must_use]
    pub const fn key(&self) -> &OccurrenceKeyV1 {
        &self.key
    }

    /// Returns the exact authoritative state identity.
    #[must_use]
    pub const fn state_digest(&self) -> &Digest {
        &self.state_digest
    }

    /// Returns the closed AG program counter.
    #[must_use]
    pub const fn program_counter(&self) -> ProgramCounterV1 {
        self.program_counter
    }

    /// Returns halt-specific facts when the occurrence is halted.
    #[must_use]
    pub const fn halted(&self) -> Option<&HaltedOccurrenceViewV1> {
        self.halted.as_ref()
    }

    /// Returns exact completion evidence when this occurrence is completed.
    #[must_use]
    pub const fn completed(&self) -> Option<&CompletedOccurrenceViewV1> {
        self.completed.as_ref()
    }
}

/// Stable completion projection containing the exact fresh observation and
/// external terminal-witness reference consumed by the kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedOccurrenceViewV1 {
    /// Exact fresh terminal observation resolution.
    pub terminal_observation: ObservationResolutionV1,
    /// Exact externally owned terminal witness identity.
    pub terminal_witness: TerminalWitnessRefV1,
}

/// Stable halt projection containing only AG-owned lifecycle facts and exact
/// evidence references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltedOccurrenceViewV1 {
    /// State from which the occurrence halted.
    pub source: ProgramCounterV1,
    /// Exact halt reason.
    pub reason: HaltReasonRefV1,
    /// Exact unresolved Docket attempt, when any.
    pub unresolved_attempt: Option<DocketAttemptRefV1>,
    /// Exact governed-repair requirement, when Docket sealed one.
    pub governed_repair_requirement: Option<HumanDecisionRequirementV1>,
    /// Terminal governed-repair rejection, when any.
    pub governed_repair_closed: Option<GovernedRepairClosedV1>,
    /// Exact Docket pre-custody refusal, when that terminalized the consumed issuance.
    pub docket_issuance_refusal: Option<DocketIssuanceRefusalV1>,
    /// Exact typed pre-spend insufficiency basis, when this is the sole
    /// nonauthorizing discovery/revision eligibility class.
    pub pre_spend_scope_insufficiency: Option<PreSpendScopeInsufficiencyV1>,
    /// Exact current unconsumed and unexpired human-decision request. This is
    /// populated by the product service, not reconstructed from the snapshot.
    pub open_human_decision_request: Option<HumanDecisionRequestRefV1>,
}

impl HaltedOccurrenceViewV1 {
    /// Returns the exact governed-repair requirement, when any.
    #[must_use]
    pub const fn governed_repair_requirement(&self) -> Option<&HumanDecisionRequirementV1> {
        self.governed_repair_requirement.as_ref()
    }

    /// Returns the terminal governed-repair rejection, when any.
    #[must_use]
    pub const fn governed_repair_closed(&self) -> Option<&GovernedRepairClosedV1> {
        self.governed_repair_closed.as_ref()
    }
}

impl TryFrom<&OccurrenceSnapshotV1> for OccurrenceViewV1 {
    type Error = CampaignEngineErrorV1;

    fn try_from(snapshot: &OccurrenceSnapshotV1) -> Result<Self, Self::Error> {
        snapshot.validate_integrity()?;
        let meta = snapshot.state().meta();
        let halted = snapshot.halted().map(|halted| HaltedOccurrenceViewV1 {
            source: halted.source(),
            reason: halted.reason().clone(),
            unresolved_attempt: halted.unresolved_attempt().cloned(),
            governed_repair_requirement: halted.governed_repair_requirement().cloned(),
            governed_repair_closed: halted.governed_repair_closed().cloned(),
            docket_issuance_refusal: halted.docket_issuance_refusal().cloned(),
            pre_spend_scope_insufficiency: halted.pre_spend_scope_insufficiency().cloned(),
            open_human_decision_request: None,
        });
        let completed =
            snapshot
                .terminal_observation()
                .map(|terminal_observation| CompletedOccurrenceViewV1 {
                    terminal_observation: terminal_observation.clone(),
                    terminal_witness: snapshot
                        .terminal_witness()
                        .expect("completed state retains its terminal witness")
                        .clone(),
                });
        let proposal_contract =
            snapshot
                .proposal_contract()
                .map(|proposal| ProposalContractViewV1 {
                    proposal: proposal.reference(),
                    exact_record: proposal.clone(),
                    nonclaims: proposal.nonclaims().to_vec(),
                    expires_at_unix_ms: proposal.expires_at_unix_ms(),
                });
        Ok(Self {
            schema: GOVERNED_OCCURRENCE_VIEW_SCHEMA_V1.to_owned(),
            key: snapshot.key().clone(),
            program: meta.program().clone(),
            program_counter: snapshot.program_counter(),
            prior_state_digest: snapshot.prior_state_digest().clone(),
            state_digest: snapshot.state_digest().clone(),
            residuals: meta.residuals().clone(),
            budget: meta.budget(),
            used_human_decisions: meta.used_human_decisions().to_vec(),
            authority_history: snapshot.state().authority_history(),
            artifacts: occurrence_artifact_links(snapshot)?,
            proposal_contract,
            pre_spend_revision: snapshot.pre_spend_revision_constraint().map(|constraint| {
                PreSpendRevisionConstraintViewV1 {
                    predecessor: constraint.predecessor().clone(),
                    discovery: constraint.discovery().clone(),
                    revised_proposal: constraint.revised_proposal().clone(),
                    exact_revised_proposal: constraint.exact_revised_proposal().clone(),
                }
            }),
            halted,
            completed,
        })
    }
}

/// Stable ordered event page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventPageV1 {
    /// Exact events in monotone store sequence order.
    pub items: Vec<GovernedEventV1>,
    /// Exclusive sequence cursor for the next page.
    pub next: Option<u64>,
}

/// Stable product event DTO. Store implementation types never escape through
/// the future Maude/Phosphor-facing contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedEventV1 {
    /// Stable event schema.
    pub schema: String,
    /// Monotone campaign-local cursor.
    pub sequence: u64,
    /// Closed transition name.
    pub transition: String,
    /// Source occurrence, absent only at genesis.
    pub source_occurrence: Option<String>,
    /// Exact successor occurrence.
    pub successor_occurrence: String,
    /// Exact state correspondence.
    pub predecessor_state_digest: Digest,
    /// Exact state correspondence.
    pub successor_state_digest: Digest,
    /// Exact event-chain identity.
    pub event_digest: Digest,
    /// Durable event time.
    pub recorded_at_unix_ms: u64,
}

impl From<CampaignEventV1> for GovernedEventV1 {
    fn from(value: CampaignEventV1) -> Self {
        Self {
            schema: "ag.governed-loop.product-event/v1".to_owned(),
            sequence: value.sequence,
            transition: value.kind.as_str().to_owned(),
            source_occurrence: value.source_occurrence,
            successor_occurrence: value.successor_occurrence,
            predecessor_state_digest: value.predecessor_state_digest,
            successor_state_digest: value.successor_state_digest,
            event_digest: value.event_digest,
            recorded_at_unix_ms: value.recorded_at_unix_ms,
        }
    }
}

/// Stable product replay/consistency report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedReplayReportV1 {
    /// Stable report schema.
    pub schema: String,
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Durable record censuses.
    pub transitions: u64,
    /// Durable one-use AG spends.
    pub ag_spends: u64,
    /// Docket custody attempts.
    pub docket_attempts: u64,
    /// Known terminal settlements.
    pub settlements: u64,
    /// Historical retired-path dispositions retained only as evidence.
    pub human_dispositions: u64,
    /// Durable non-authorizing decision requests.
    pub human_decision_requests: u64,
    /// Consumed verified governed-repair dispositions.
    pub governed_repair_dispositions: u64,
    /// Exact authoritative current state.
    pub current_state_digest: Digest,
}

/// Stable exact artifact response; identity and byte hash are returned with
/// the canonical bytes to prevent caller-side substitution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecordV1 {
    /// Stable response schema.
    pub schema: String,
    /// Closed semantic artifact class, verified from exact Store-owned bytes.
    pub kind: GovernedArtifactKindV1,
    /// Exact artifact schema/version, independently surfaced for stable
    /// clients rather than inferred by them from private record shape.
    pub artifact_schema: String,
    /// Requested domain-specific identity.
    pub identity: Digest,
    /// SHA-256 of the exact canonical bytes.
    pub bytes_identity: Digest,
    /// Exact canonical bytes.
    pub bytes: Vec<u8>,
    /// Occurrences whose AG projections address this exact artifact. Empty
    /// denotes a campaign/genesis artifact rather than missing provenance.
    pub occurrences: Vec<OccurrenceKeyV1>,
}

/// Stable current-state view including legal next operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignStateViewV1 {
    /// Stable service schema.
    pub schema: String,
    /// Exact current occurrence.
    pub current: OccurrenceViewV1,
    /// Genesis/campaign artifact addresses needed by observer clients without
    /// direct Store access.
    pub campaign_artifacts: Vec<GovernedArtifactLinkV1>,
    /// Exact current unconsumed, unexpired decision request, when one exists.
    pub open_human_decision_request: Option<HumanDecisionRequestRefV1>,
    /// Closed operations legal from the current program counter.
    pub allowed_transitions: Vec<GovernedOperationV1>,
    /// Last durable event sequence.
    pub event_sequence: u64,
    /// Deployment-owned consequence-clock observation used for this view.
    pub observed_at_unix_ms: u64,
}

/// Stable machine-readable projection of legal operations at one exact state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedTransitionsViewV1 {
    /// Stable response schema.
    pub schema: String,
    /// Exact current occurrence.
    pub key: OccurrenceKeyV1,
    /// Exact state for which these operations were derived.
    pub state_digest: Digest,
    /// Last durable event sequence observed at the same Store cut.
    pub event_sequence: u64,
    /// Deployment-owned consequence-clock observation used to evaluate
    /// expiry-sensitive legality at this otherwise immutable state cut.
    pub observed_at_unix_ms: u64,
    /// Exact currently open request, when request expiry participates in the
    /// legal transition projection.
    pub open_human_decision_request: Option<HumanDecisionRequestRefV1>,
    /// Closed product operations legal from this exact state.
    pub allowed_transitions: Vec<GovernedOperationV1>,
}

/// Stable create operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCampaignV1 {
    /// Exact campaign.
    pub campaign: CampaignId,
    /// Fresh occurrence.
    pub occurrence: OccurrenceId,
    /// Exact program.
    pub program: ProgramBasisRefV1,
    /// Exact residual set.
    pub residuals: ResidualSetV1,
    /// Exact bounded budget.
    pub budget: LoopBudgetV1,
    /// Stable outer creation idempotency identity.
    pub idempotency_key: Digest,
    /// Mandatory deployment-owned AG observation/standing/policy/clock root.
    pub governed_ag_policy_root: GovernedAgPolicyRootV1,
    /// Optional deployment-owned verifier root, pinned once at creation.
    pub governed_repair_verifier_root: Option<GovernedRepairVerifierRootV1>,
    /// Optional deployment-owned Docket adapter root, pinned once at creation.
    pub governed_docket_adapter_root: Option<GovernedDocketAdapterRootV1>,
}

/// Stable request for a typed, nonauthorizing pre-spend scope-insufficiency
/// halt.  The Store derives and binds the current occurrence, proposal, and
/// scope; the caller supplies only the exact diagnostic basis and CAS cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltPreSpendScopeInsufficiencyV1 {
    /// Exact expected current state.
    pub expected_state_digest: Digest,
    /// Exact diagnostic/evidence basis that identified insufficient scope.
    pub diagnostic_basis: Digest,
    /// Stable exact-request idempotency identity.
    pub idempotency_key: Digest,
}

/// Stable idempotent result of one typed pre-spend insufficiency halt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltPreSpendScopeInsufficiencyResultV1 {
    /// Exact typed halted occurrence.
    pub halted: OccurrenceViewV1,
    /// Whether this call observed an already committed exact replay.
    pub replayed: bool,
}

/// Stable request to preserve one exact pre-spend discovery and open its
/// distinct authority-empty revised occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPreSpendScopeDiscoveryV1 {
    /// Exact typed-halt state observed by the caller.
    pub expected_state_digest: Digest,
    /// Exact immutable predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Exact immutable predecessor proposal.
    pub original_proposal: ProposalRefV1,
    /// Exact immutable predecessor scope identity.
    pub original_scope_identity: Digest,
    /// Exact diagnostic basis already pinned by the typed halt.
    pub diagnostic_basis: Digest,
    /// Exact additive scope delta; this is evidence, not authority.
    pub requested_delta: CanonicalEffectScopeV1,
    /// Claimed mechanically derived revised scope, checked by AG.
    pub revised_scope: CanonicalEffectScopeV1,
    /// Exact mechanically derived revised proposal identity.
    pub revised_proposal: ProposalRefV1,
    /// Complete mechanically derived revised proposal contract.
    pub exact_revised_proposal: ExactWorkProposalV1,
    /// Fresh distinct occurrence that will hold the pending exact proposal.
    pub revised_occurrence: OccurrenceId,
    /// Stable exact-request idempotency identity.
    pub idempotency_key: Digest,
}

/// Stable result of one atomic pre-spend discovery/revision operation.
/// Identities describe the original committed cut even after the revised
/// occurrence later advances through fresh governance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSpendScopeDiscoveryResultV1 {
    /// Exact durable discovery artifact.
    pub discovery: PreSpendScopeDiscoveryRefV1,
    /// Immutable halted predecessor occurrence.
    pub predecessor: OccurrenceKeyV1,
    /// Exact predecessor halt state bound by the discovery.
    pub predecessor_state_digest: Digest,
    /// Fresh distinct revised occurrence.
    pub revised_occurrence: OccurrenceKeyV1,
    /// Exact initial authority-empty state of the revised occurrence.
    pub revised_initial_state_digest: Digest,
    /// Exact pending revised proposal bound into that occurrence.
    pub revised_proposal: ProposalRefV1,
    /// Whether this call observed an already committed exact replay.
    pub replayed: bool,
}

/// Stable request-creation operation with explicit CAS and idempotency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDecisionRequestV1 {
    /// Exact expected current state.
    pub expected_state_digest: Digest,
    /// Exact typed requirement.
    pub requirement: HumanDecisionRequirementV1,
    /// Root-owned verifier profile identity.
    pub required_verifier_profile: Digest,
    /// Exact consequence identities.
    pub decision_consequences: Vec<Digest>,
    /// Exact nonclaim identities.
    pub nonclaims: Vec<Digest>,
    /// Stable one-operation idempotency identity.
    pub idempotency_key: Digest,
    /// Exclusive request expiry.
    pub expires_at_unix_ms: u64,
}

/// Stable verified-disposition submission.  Verifier configuration is
/// root-owned and therefore deliberately absent from caller DTOs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitGovernedDispositionV1 {
    /// Exact expected current state.
    pub expected_state_digest: Digest,
    /// Exact durable decision request.
    pub request: HumanDecisionRequestRefV1,
    /// Exact external disposition artifact.
    pub artifact: GovernedRepairDispositionV1,
}

/// Stable idempotent disposition result.  Exact replay returns the same
/// disposition identity and authoritative current state without reverifying.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitGovernedDispositionResultV1 {
    /// Exact external artifact identity.
    pub disposition: HumanDispositionRefV1,
    /// Exact consumed request.
    pub request: HumanDecisionRequestRefV1,
    /// Exact externally verified disposition receipt persisted by AG.
    pub verification: HumanVerificationRefV1,
    /// Authoritative state after the atomic operation.
    pub current: OccurrenceViewV1,
    /// Whether this call observed an already committed exact replay.
    pub replayed: bool,
}

#[cfg(test)]
type AfterProjectionBeforeMutationHookV1 =
    Box<dyn FnOnce(&Path, &Digest, GovernedOperationV1) + Send>;

/// Reusable service around the one canonical engine/store state machine.
pub struct GovernedCampaignServiceV1 {
    engine: CampaignEngineV1,
    policy_root: GovernedAgPolicyRootV1,
    verifier_root: Option<GovernedRepairVerifierRootV1>,
    docket_root: Option<GovernedDocketAdapterRootV1>,
    #[cfg(test)]
    after_projection_before_mutation: std::sync::Mutex<Option<AfterProjectionBeforeMutationHookV1>>,
}

impl GovernedCampaignServiceV1 {
    /// Creates one campaign through the canonical engine.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid root, identity collision, Store failure, or invalid genesis.
    pub fn create(
        database: &Path,
        request: CreateCampaignV1,
    ) -> Result<Self, CampaignEngineErrorV1> {
        request.governed_ag_policy_root.verify_deployment()?;
        if let Some(root) = &request.governed_docket_adapter_root {
            root.validate()?;
        }
        let canonical = ag_primitives::JcsDocument::canonicalize(&request)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        let request_identity =
            Digest::hash_domain("ag.governed-loop.product-create/v1", canonical.as_bytes());
        if database.exists() {
            let service = Self::open(database)?;
            let pinned = CampaignStoreV1::open(database)?.product_creation_request()?;
            if pinned
                != Some((
                    request.idempotency_key.clone(),
                    request_identity,
                    canonical.as_bytes().to_vec(),
                ))
            {
                return Err(CampaignEngineErrorV1::Canonical(
                    "product create idempotency collision".to_owned(),
                ));
            }
            return Ok(service);
        }
        let policy_root = request.governed_ag_policy_root.clone();
        let now_unix_ms = policy_root.now_unix_ms()?;
        let root = request.governed_repair_verifier_root.clone();
        let docket_root = request.governed_docket_adapter_root.clone();
        let root_record = root
            .as_ref()
            .map(|config| {
                config.validate()?;
                let document = ag_primitives::JcsDocument::canonicalize(config)
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                Ok::<_, CampaignEngineErrorV1>((config.identity()?, document))
            })
            .transpose()?;
        let engine = CampaignEngineV1::create_with_product_records(
            database,
            request.campaign,
            request.occurrence,
            request.program,
            request.residuals,
            request.budget,
            now_unix_ms,
            (
                &request.idempotency_key,
                &request_identity,
                canonical.as_bytes(),
            ),
            root_record
                .as_ref()
                .map(|(identity, document)| (identity, document.as_bytes())),
        )?;
        Ok(Self {
            engine,
            policy_root,
            verifier_root: root,
            docket_root,
            #[cfg(test)]
            after_projection_before_mutation: std::sync::Mutex::new(None),
        })
    }

    /// Opens one existing campaign.
    ///
    /// # Errors
    ///
    /// Returns an error when the Store or a pinned deployment record fails exact validation.
    pub fn open(database: &Path) -> Result<Self, CampaignEngineErrorV1> {
        let engine = CampaignEngineV1::open(database)?;
        let store = CampaignStoreV1::open(database)?;
        let verifier_root = store
            .governed_repair_verifier_root()?
            .map(|(identity, bytes)| {
                let value: GovernedRepairVerifierRootV1 = serde_json::from_slice(&bytes)
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                let document = ag_primitives::JcsDocument::canonicalize(&value)
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                if document.as_bytes() != bytes || value.identity()? != identity {
                    return Err(CampaignEngineErrorV1::Canonical(
                        "pinned verifier root identity mismatch".to_owned(),
                    ));
                }
                value.validate()?;
                Ok(value)
            })
            .transpose()?;
        let (policy_root, docket_root) = store
            .product_creation_request()?
            .map(|(_, identity, bytes)| {
                if Digest::hash_domain("ag.governed-loop.product-create/v1", &bytes) != identity {
                    return Err(CampaignEngineErrorV1::Canonical(
                        "pinned product creation identity mismatch".to_owned(),
                    ));
                }
                let value: CreateCampaignV1 = serde_json::from_slice(&bytes)
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                let document = ag_primitives::JcsDocument::canonicalize(&value)
                    .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
                if document.as_bytes() != bytes {
                    return Err(CampaignEngineErrorV1::Canonical(
                        "pinned product creation record is not canonical".to_owned(),
                    ));
                }
                if let Some(root) = &value.governed_docket_adapter_root {
                    root.validate()?;
                }
                value.governed_ag_policy_root.verify_deployment()?;
                Ok((
                    value.governed_ag_policy_root,
                    value.governed_docket_adapter_root,
                ))
            })
            .transpose()?
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "pinned product creation record is missing".to_owned(),
                )
            })?;
        Ok(Self {
            engine,
            policy_root,
            verifier_root,
            docket_root,
            #[cfg(test)]
            after_projection_before_mutation: std::sync::Mutex::new(None),
        })
    }

    /// Installs root-owned deployment verifier configuration.  The catalog is
    /// configuration, not standing; the external verifier still must
    /// authenticate every exact disposition now.
    /// Returns the exact current state and legal next operation vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error when current state, Store head, or projection integrity is invalid.
    pub fn state(&self) -> Result<CampaignStateViewV1, CampaignEngineErrorV1> {
        let now_unix_ms = self.policy_root.now_unix_ms()?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        let read = store.campaign_state_read(now_unix_ms)?;
        if now_unix_ms < read.last_recorded_at_unix_ms {
            return Err(CampaignEngineErrorV1::Canonical(
                "deployment consequence clock regressed behind durable state".to_owned(),
            ));
        }
        let current = read.current;
        let open_request = read.open_human_decision_request;
        let governed_state = governed_decision_state(&current, open_request.is_some())?;
        let mut current_view = project_occurrence(&store, &current, now_unix_ms)?;
        if let Some(halted) = current_view.halted.as_mut() {
            halted.open_human_decision_request.clone_from(&open_request);
        }
        let campaign_artifacts = campaign_artifact_links(&store)?;
        let docket = if self
            .docket_root
            .as_ref()
            .is_some_and(|root| root.verify_runtime_correspondence().is_ok())
        {
            DocketDeploymentStateV1::RuntimeCurrent
        } else {
            DocketDeploymentStateV1::Unavailable
        };
        let verifier = match &self.verifier_root {
            None => VerifierDeploymentStateV1::Absent,
            Some(root) if root.verify_runtime_correspondence().is_ok() => {
                VerifierDeploymentStateV1::RuntimeCurrent
            }
            Some(_) => VerifierDeploymentStateV1::Configured,
        };
        Ok(CampaignStateViewV1 {
            schema: GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1.to_owned(),
            allowed_transitions: allowed_transitions(
                current.program_counter(),
                AllowedTransitionStateV1 {
                    governed: governed_state,
                    proposal: if current
                        .proposal_contract()
                        .or_else(|| {
                            current
                                .pre_spend_revision_constraint()
                                .map(
                                    ag_campaign::governed::PreSpendRevisionConstraintV1::exact_revised_proposal,
                                )
                        })
                        .is_some_and(|proposal| now_unix_ms >= proposal.expires_at_unix_ms())
                    {
                        ProposalTimeStateV1::Expired
                    } else {
                        ProposalTimeStateV1::Current
                    },
                    budget: current_view.budget,
                    residuals_empty: current_view.residuals.is_empty(),
                    pre_spend_revision_eligible: current
                        .proposal_contract()
                        .is_some_and(|proposal| proposal.governed_repair_checkpoint().is_none()),
                    docket,
                    verifier,
                },
            ),
            current: current_view,
            campaign_artifacts,
            open_human_decision_request: open_request,
            event_sequence: read.head.event_count,
            observed_at_unix_ms: now_unix_ms,
        })
    }

    /// Returns the stable machine-readable legal operation projection for the
    /// exact current Store cut.
    ///
    /// # Errors
    ///
    /// Returns an error when current product state cannot be verified.
    pub fn allowed_transitions(&self) -> Result<AllowedTransitionsViewV1, CampaignEngineErrorV1> {
        let state = self.state()?;
        Ok(AllowedTransitionsViewV1 {
            schema: GOVERNED_ALLOWED_TRANSITIONS_SCHEMA_V1.to_owned(),
            key: state.current.key.clone(),
            state_digest: state.current.state_digest.clone(),
            event_sequence: state.event_sequence,
            observed_at_unix_ms: state.observed_at_unix_ms,
            open_human_decision_request: state.open_human_decision_request,
            allowed_transitions: state.allowed_transitions,
        })
    }

    /// Replays and verifies the authoritative store.
    ///
    /// # Errors
    ///
    /// Returns an error when any journal, materialization, or identity check fails.
    pub fn replay(&self) -> Result<GovernedReplayReportV1, CampaignEngineErrorV1> {
        let value = self.engine.replay()?;
        Ok(GovernedReplayReportV1 {
            schema: "ag.governed-loop.product-replay-report/v1".to_owned(),
            campaign: value.campaign,
            transitions: value.transitions,
            ag_spends: value.ag_spends,
            docket_attempts: value.docket_attempts,
            settlements: value.settlements,
            human_dispositions: value.human_dispositions,
            human_decision_requests: value.human_decision_requests,
            governed_repair_dispositions: value.governed_repair_dispositions,
            current_state_digest: value.current_state_digest,
        })
    }

    /// Retrieves one exact occurrence.
    ///
    /// # Errors
    ///
    /// Returns an error for Store failure or an invalid occurrence projection.
    pub fn occurrence(
        &self,
        key: &OccurrenceKeyV1,
    ) -> Result<Option<OccurrenceViewV1>, CampaignEngineErrorV1> {
        let now = self.consequence_now()?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        store
            .occurrence(key)?
            .as_ref()
            .map(|snapshot| project_occurrence(&store, snapshot, now))
            .transpose()
    }

    /// Lists exact occurrences using a stable exclusive cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page, Store failure, or invalid projection.
    pub fn list_occurrences(
        &self,
        page: &OccurrencePageRequestV1,
    ) -> Result<OccurrencePageV1, CampaignEngineErrorV1> {
        if page.limit == 0 || page.limit > 1000 {
            return Err(CampaignEngineErrorV1::Canonical(
                "occurrence page limit outside 1..=1000".to_owned(),
            ));
        }
        let canonical_after = page
            .after
            .as_deref()
            .map(|after| {
                uuid::Uuid::parse_str(after)
                    .map(|value| value.hyphenated().to_string())
                    .map_err(|_| {
                        CampaignEngineErrorV1::Canonical("invalid occurrence cursor".to_owned())
                    })
            })
            .transpose()?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        let mut cursor = canonical_after;
        let mut snapshots = Vec::new();
        let target = page.limit as usize + 1;
        loop {
            let batch = store.list_occurrences(cursor.as_deref(), 1000)?;
            let exhausted = batch.len() < 1000;
            if let Some(last) = batch.last() {
                cursor = Some(last.key().occurrence.to_string());
            }
            snapshots.extend(batch.into_iter().filter(|snapshot| {
                page.program_counter
                    .is_none_or(|counter| snapshot.program_counter() == counter)
                    && page.governed_repair_pending.is_none_or(|expected| {
                        snapshot.halted().is_some_and(|halted| {
                            halted.governed_repair_requirement().is_some()
                                && halted.governed_repair_closed().is_none()
                        }) == expected
                    })
            }));
            if snapshots.len() >= target || exhausted {
                break;
            }
        }
        let has_more = snapshots.len() > page.limit as usize;
        snapshots.truncate(page.limit as usize);
        let next = has_more
            .then(|| {
                snapshots
                    .last()
                    .map(|item| item.key().occurrence.to_string())
            })
            .flatten();
        let now = self.consequence_now()?;
        let items = snapshots
            .iter()
            .map(|snapshot| project_occurrence(&store, snapshot, now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OccurrencePageV1 { items, next })
    }

    /// Lists exact ordered events using a monotone exclusive cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cursor/page or Store failure.
    pub fn list_events(&self, page: &PageRequestV1) -> Result<EventPageV1, CampaignEngineErrorV1> {
        if page.limit == 0 || page.limit > 1000 {
            return Err(CampaignEngineErrorV1::Canonical(
                "event page limit outside 1..=1000".to_owned(),
            ));
        }
        let after = page
            .after
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| CampaignEngineErrorV1::Canonical("invalid event cursor".to_owned()))?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        let mut items = if page.limit < 1000 {
            store.list_events(after, page.limit + 1)?
        } else {
            store.list_events(after, page.limit)?
        };
        let has_more = match items.len().cmp(&(page.limit as usize)) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => {
                let last = items.last().map_or(after, |event| event.sequence);
                !store.list_events(last, 1)?.is_empty()
            }
            std::cmp::Ordering::Less => false,
        };
        items.truncate(page.limit as usize);
        let next = has_more
            .then(|| items.last().map(|event| event.sequence))
            .flatten();
        Ok(EventPageV1 {
            items: items.into_iter().map(GovernedEventV1::from).collect(),
            next,
        })
    }

    /// Retrieves one exact durable artifact as canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the Store cannot read or validate the artifact.
    pub fn artifact(
        &self,
        identity: &Digest,
    ) -> Result<Option<ArtifactRecordV1>, CampaignEngineErrorV1> {
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        store
            .artifact_bytes(identity)?
            .map(|bytes| {
                let kind = classify_artifact(&bytes)?;
                Ok(ArtifactRecordV1 {
                    schema: GOVERNED_ARTIFACT_RECORD_SCHEMA_V1.to_owned(),
                    kind,
                    artifact_schema: artifact_schema(kind).to_owned(),
                    identity: identity.clone(),
                    bytes_identity: Digest::hash_bytes(&bytes),
                    bytes,
                    occurrences: artifact_occurrences(&store, identity)?,
                })
            })
            .transpose()
    }

    /// Retrieves one exact governed-repair decision request.
    ///
    /// # Errors
    ///
    /// Returns an error when durable request retrieval or validation fails.
    pub fn decision_request(
        &self,
        identity: &HumanDecisionRequestRefV1,
    ) -> Result<Option<HumanDecisionRequestV1>, CampaignEngineErrorV1> {
        self.engine.governed_repair_request(identity)
    }

    /// Creates one durable non-authorizing decision request.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, absent/mismatched root, invalid request, or Store failure.
    pub fn create_decision_request(
        &mut self,
        request: CreateDecisionRequestV1,
    ) -> Result<HumanDecisionRequestV1, CampaignEngineErrorV1> {
        let root = self.verifier_root.as_ref().ok_or_else(|| {
            CampaignEngineErrorV1::Canonical(
                "governed-repair verifier catalog is not configured".to_owned(),
            )
        })?;
        root.validate()?;
        let root_identity = root.identity()?;
        let profile = root.catalog.resolve(
            &request.required_verifier_profile,
            root_identity,
            root.executable_identity.clone(),
        )?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        if let Some(existing) =
            store.human_decision_request_by_idempotency(&request.idempotency_key)?
        {
            if existing.halted_state_digest == request.expected_state_digest
                && existing.requirement == request.requirement
                && existing.required_verifier_profile == profile.profile
                && existing.required_verifier_root == profile.root
                && existing.required_verifier_executable == profile.executable
                && existing.decision_consequences == request.decision_consequences
                && existing.nonclaims == request.nonclaims
                && existing.expires_at_unix_ms == request.expires_at_unix_ms
            {
                return Ok(existing);
            }
            return Err(CampaignEngineErrorV1::Store(
                CampaignStoreErrorV1::GovernedRepairReplay,
            ));
        }
        self.require_allowed(
            &request.expected_state_digest,
            GovernedOperationV1::CreateDecisionRequest,
        )?;
        let current = store.current()?;
        let pinned_requirement = current
            .halted()
            .and_then(|halted| halted.governed_repair_requirement())
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "decision request requires an exact Docket-sealed governed-repair halt"
                        .to_owned(),
                )
            })?;
        if current.state_digest() != &request.expected_state_digest
            || pinned_requirement != &request.requirement
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "decision request differs from exact governed-repair halt".to_owned(),
            ));
        }
        let now_unix_ms = self.consequence_now()?;
        self.engine.create_governed_repair_request(
            &request.expected_state_digest,
            request.requirement,
            profile.profile,
            profile.root,
            profile.executable,
            request.decision_consequences,
            request.nonclaims,
            request.idempotency_key,
            now_unix_ms,
            request.expires_at_unix_ms,
        )
    }

    /// Submits one exact disposition through the configured verifier boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for any binding, verification, expiry, replay-collision, or Store failure.
    pub fn submit_governed_disposition(
        &mut self,
        request: SubmitGovernedDispositionV1,
    ) -> Result<SubmitGovernedDispositionResultV1, CampaignEngineErrorV1> {
        let now_unix_ms = self.consequence_now()?;
        let root = self.verifier_root.as_ref().ok_or_else(|| {
            CampaignEngineErrorV1::Canonical(
                "governed-repair verifier catalog is not configured".to_owned(),
            )
        })?;
        // Consequence-bearing caller-authored records must pass the one
        // recursive strict-JCS gate before any identity helper can observe
        // their numeric fields. In particular this refuses integers outside
        // RFC 8785's interoperable exact range instead of allowing a
        // transcript/reference to precede typed validation.
        JcsDocument::canonicalize(&request.artifact)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        let disposition = request.artifact.reference();
        let exact_artifact = request.artifact.clone();
        let request_ref = request.request.clone();
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        if request.artifact.request() != &request.request
            || request.artifact.halted_state_digest != request.expected_state_digest
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "submit request/artifact/state binding mismatch".to_owned(),
            ));
        }
        let stored_request = store
            .human_decision_request(&request.request)?
            .ok_or_else(|| {
                CampaignEngineErrorV1::Store(CampaignStoreErrorV1::GovernedRepairReplay)
            })?;
        if stored_request.reference() != request.request
            || stored_request.halted_state_digest != request.expected_state_digest
        {
            return Err(CampaignEngineErrorV1::Canonical(
                "stored request differs from submitted exact basis".to_owned(),
            ));
        }
        if store.governed_repair_disposition(&disposition)? == Some(request.artifact.clone()) {
            return self.committed_disposition_result(disposition, request_ref, true);
        }
        self.require_allowed(
            &request.expected_state_digest,
            GovernedOperationV1::SubmitDisposition,
        )?;
        // The Store repeats root parsing, same-file executable measurement,
        // exact response validation, and seals the only persistence permit.
        // This application-side check keeps malformed/substituted profiles out
        // before process invocation but is not itself authority.
        let _profile = root.catalog.resolve(
            &request.artifact.verifier_profile,
            root.identity()?,
            root.executable_identity.clone(),
        )?;
        let result = self.engine.apply_governed_repair_disposition(
            &request.expected_state_digest,
            &request.request,
            request.artifact,
            now_unix_ms,
        );
        match result {
            Ok(_) => self.committed_disposition_result(disposition, request_ref, false),
            Err(error)
                if matches!(
                    &error,
                    CampaignEngineErrorV1::Store(
                        CampaignStoreErrorV1::GovernedRepairReplay
                            | CampaignStoreErrorV1::StalePredecessor { .. }
                    )
                ) =>
            {
                let store = CampaignStoreV1::open(self.engine.store_path())?;
                if store.governed_repair_disposition(&disposition)? == Some(exact_artifact) {
                    self.committed_disposition_result(disposition, request_ref, true)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn committed_disposition_result(
        &self,
        disposition: HumanDispositionRefV1,
        request: HumanDecisionRequestRefV1,
        replayed: bool,
    ) -> Result<SubmitGovernedDispositionResultV1, CampaignEngineErrorV1> {
        let verification = CampaignStoreV1::open(self.engine.store_path())?
            .governed_repair_verification_for_disposition(&disposition)?
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "committed disposition lacks exact verification receipt".to_owned(),
                )
            })?
            .verification;
        Ok(SubmitGovernedDispositionResultV1 {
            disposition,
            request,
            verification,
            current: OccurrenceViewV1::try_from(&self.engine.current()?)?,
            replayed,
        })
    }

    /// Records an exact proposal through the canonical engine under caller
    /// CAS; the resolver remains the only observation-currentness source.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, resolver refusal, invalid proposal, or Store failure.
    pub fn record_proposal(
        &mut self,
        expected_state_digest: &Digest,
        observation: ObservationRefV1,
        proposal: ExactWorkProposalV1,
        class: ProposalClassV1,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected_state_digest, GovernedOperationV1::RecordProposal)?;
        let now_unix_ms = self.consequence_now()?;
        let mut resolver = self.policy_root.observation()?;
        let current = self.engine.record_proposal(
            expected_state_digest,
            observation,
            proposal,
            class,
            &mut resolver,
            now_unix_ms,
        )?;
        OccurrenceViewV1::try_from(&current)
    }

    /// Reconciles Docket through the canonical engine under exact state CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, absent/mismatched adapter root, Docket refusal, or Store failure.
    pub fn reconcile_docket(
        &mut self,
        expected_state_digest: &Digest,
    ) -> Result<CampaignStateViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected_state_digest, GovernedOperationV1::ReconcileDocket)?;
        let now_unix_ms = self.consequence_now()?;
        let mut docket = self.docket_port(None)?;
        let _ = self
            .engine
            .poll_docket(expected_state_digest, &mut docket, now_unix_ms)?;
        self.state()
    }

    /// Opens one ordinary post-settlement continuation through the canonical
    /// engine under exact state CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/illegal state, identity collision, or Store failure.
    pub fn open_continuation(
        &mut self,
        expected_state_digest: &Digest,
        occurrence: OccurrenceId,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected_state_digest, GovernedOperationV1::OpenContinuation)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.open_continuation(
            expected_state_digest,
            occurrence,
            now_unix_ms,
        )?)
    }

    /// Halts from one exact authority-safe state under caller CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/unsafe state or Store failure.
    pub fn halt(
        &mut self,
        expected_state_digest: &Digest,
        reason: HaltReasonRefV1,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected_state_digest, GovernedOperationV1::Halt)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(
            &self
                .engine
                .halt(expected_state_digest, reason, now_unix_ms)?,
        )
    }

    /// Records one exact typed pre-spend scope-insufficiency halt.  The marker
    /// is nonauthorizing and can only make the exact discovery/revision
    /// transition eligible; it cannot enter the post-spend human-disposition
    /// path.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, an ineligible source, identity
    /// collision, or Store failure.
    pub fn halt_pre_spend_scope_insufficiency(
        &mut self,
        request: HaltPreSpendScopeInsufficiencyV1,
    ) -> Result<HaltPreSpendScopeInsufficiencyResultV1, CampaignEngineErrorV1> {
        if self.engine.current()?.state_digest() == &request.expected_state_digest {
            self.require_allowed(
                &request.expected_state_digest,
                GovernedOperationV1::HaltPreSpendScopeInsufficiency,
            )?;
        }
        let now_unix_ms = self.consequence_now()?;
        let commit = self.engine.halt_pre_spend_scope_insufficiency(
            &request.expected_state_digest,
            request.diagnostic_basis,
            request.idempotency_key,
            now_unix_ms,
        )?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        Ok(HaltPreSpendScopeInsufficiencyResultV1 {
            halted: project_occurrence(&store, &commit.halted, now_unix_ms)?,
            replayed: commit.replayed,
        })
    }

    /// Atomically records one exact pre-spend scope discovery and creates one
    /// distinct authority-empty revised occurrence.  Every caller-supplied
    /// predecessor coordinate is rechecked by the Store in the committing
    /// transaction; the revised proposal is pending exact fresh observation,
    /// not admitted or authorized work.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, generic-halt laundering, an altered
    /// predecessor/delta/proposal, replay collision, or Store failure.
    pub fn record_pre_spend_scope_discovery(
        &mut self,
        request: RecordPreSpendScopeDiscoveryV1,
    ) -> Result<PreSpendScopeDiscoveryResultV1, CampaignEngineErrorV1> {
        // Apply the strict recursive JCS/safe-integer gate before any caller
        // value participates in identity derivation or durable lookup.
        JcsDocument::canonicalize(&request)
            .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
        if self.engine.current()?.state_digest() == &request.expected_state_digest {
            self.require_allowed(
                &request.expected_state_digest,
                GovernedOperationV1::RecordPreSpendScopeDiscovery,
            )?;
        }
        let now_unix_ms = self.consequence_now()?;
        let commit = self.engine.record_pre_spend_scope_discovery(
            &request.expected_state_digest,
            PreSpendScopeDiscoveryParametersV1 {
                predecessor: request.predecessor,
                original_proposal: request.original_proposal,
                original_scope_identity: request.original_scope_identity,
                diagnostic_basis: request.diagnostic_basis,
                requested_delta: request.requested_delta,
                claimed_revised_scope: request.revised_scope,
                claimed_revised_proposal: request.revised_proposal,
                exact_revised_proposal: request.exact_revised_proposal,
                revised_occurrence: request.revised_occurrence,
                idempotency_key: request.idempotency_key,
                recorded_at_unix_ms: now_unix_ms,
            },
        )?;
        Ok(PreSpendScopeDiscoveryResultV1 {
            discovery: commit.discovery.reference().clone(),
            predecessor: commit.predecessor.key().clone(),
            predecessor_state_digest: commit.predecessor.state_digest().clone(),
            revised_occurrence: commit.successor.key().clone(),
            revised_initial_state_digest: commit.successor.state_digest().clone(),
            revised_proposal: commit.discovery.revised_proposal().clone(),
            replayed: commit.replayed,
        })
    }

    /// Enters standing-required through the canonical engine under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/illegal state or Store failure.
    pub fn require_standing(
        &mut self,
        expected: &Digest,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::RequireStanding)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.require_standing(expected, now_unix_ms)?)
    }

    /// Records one exact admissibility decision through the canonical engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, failed currentness/standing, inadmissibility, or Store failure.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(&mut self, expected: &Digest) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Decide)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        let mut standing = self.policy_root.standing()?;
        let catalog = self.policy_root.catalog()?;
        let controlling_review = self.policy_root.review()?;
        OccurrenceViewV1::try_from(&self.engine.decide(
            expected,
            &mut observation,
            &mut standing,
            &catalog,
            controlling_review.as_ref(),
            now_unix_ms,
        )?)
    }

    /// Spends one exact AG authorization through the canonical engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, failed revalidation, consumed authority, or Store failure.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        expected: &Digest,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Authorize)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        let mut standing = self.policy_root.standing()?;
        let catalog = self.policy_root.catalog()?;
        let controlling_review = self.policy_root.review()?;
        OccurrenceViewV1::try_from(&self.engine.authorize(
            expected,
            &mut observation,
            &mut standing,
            &catalog,
            controlling_review.as_ref(),
            now_unix_ms,
        )?)
    }

    /// Delegates one exact issuance to Docket under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, absent/mismatched adapter root, Docket refusal, or Store failure.
    pub fn dispatch(
        &mut self,
        expected: &Digest,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Dispatch)?;
        let now_unix_ms = self.consequence_now()?;
        let mut store = CampaignStoreV1::open(self.engine.store_path())?;
        match store.issuance_signing_permit(expected) {
            Ok(permit) => {
                let mut docket = self.docket_port(Some(permit))?;
                OccurrenceViewV1::try_from(&self.engine.dispatch(
                    expected,
                    &mut docket,
                    now_unix_ms,
                )?)
            }
            Err(CampaignStoreErrorV1::IssuanceSigningAlreadyReserved) => {
                // A prior process already crossed the one-use authentication
                // boundary. Never mint or sign again: reconcile the exact
                // issuance through Docket's replay-safe read boundary.
                let mut docket = self.docket_port(None)?;
                let _ = self.engine.recover(expected, &mut docket, now_unix_ms)?;
                OccurrenceViewV1::try_from(&self.engine.current()?)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Applies restart recovery through the canonical engine under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, absent/mismatched adapter root, Docket refusal, or Store failure.
    pub fn recover(
        &mut self,
        expected: &Digest,
    ) -> Result<CampaignStateViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Recover)?;
        let now_unix_ms = self.consequence_now()?;
        let mut docket = self.docket_port(None)?;
        let _ = self.engine.recover(expected, &mut docket, now_unix_ms)?;
        self.state()
    }

    fn docket_port(
        &self,
        signing_permit: Option<crate::governed_store::StoreIssuanceSigningPermitV1>,
    ) -> Result<CommandDocketCustodyPortV1, CampaignEngineErrorV1> {
        self.docket_root
            .as_ref()
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "deployment-owned Docket adapter root is not configured".to_owned(),
                )
            })?
            .open_port(signing_permit)
    }

    /// Samples the deployment-owned consequence clock and refuses regression
    /// behind any already committed campaign event. Time is a Store/AG input,
    /// never a product-caller selected authorization premise.
    fn consequence_now(&self) -> Result<u64, CampaignEngineErrorV1> {
        let now = self.policy_root.now_unix_ms()?;
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        if now < store.last_recorded_at_unix_ms()? {
            return Err(CampaignEngineErrorV1::Canonical(
                "deployment consequence clock regressed behind durable state".to_owned(),
            ));
        }
        Ok(now)
    }

    /// Applies the exact same product legality projection used for
    /// `allowed_transitions` before invoking a consequence-bearing mutation.
    /// Kernel/Store validation remains the final authority and can only be
    /// stricter for live resolver results unavailable to a read projection.
    fn require_allowed(
        &self,
        expected: &Digest,
        operation: GovernedOperationV1,
    ) -> Result<(), CampaignEngineErrorV1> {
        require_expected(&self.engine, expected)?;
        let view = self.allowed_transitions()?;
        if view.state_digest != *expected || !view.allowed_transitions.contains(&operation) {
            return Err(CampaignEngineErrorV1::OperationNotAllowed(format!(
                "{} at the exact reported state",
                operation.as_str()
            )));
        }
        #[cfg(test)]
        if let Some(hook) = self
            .after_projection_before_mutation
            .lock()
            .expect("test interleaving hook mutex must remain usable")
            .take()
        {
            hook(self.engine.store_path(), expected, operation);
        }
        Ok(())
    }

    /// Installs one test-only deterministic interleaving at the precise seam
    /// after advisory product projection but before the lower-layer mutation.
    /// The hook is consumed once and is absent from production builds.
    #[cfg(test)]
    pub(crate) fn set_after_projection_before_mutation_hook(
        &self,
        hook: impl FnOnce(&Path, &Digest, GovernedOperationV1) + Send + 'static,
    ) {
        *self
            .after_projection_before_mutation
            .lock()
            .expect("test interleaving hook mutex must remain usable") = Some(Box::new(hook));
    }

    /// Records one read-only probe fact under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/illegal state, exhausted budget, or Store failure.
    pub fn note_probe(
        &mut self,
        expected: &Digest,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::NoteProbe)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.note_probe(expected, now_unix_ms)?)
    }

    /// Records one escalation halt under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/illegal state, exhausted budget, or Store failure.
    pub fn escalate(
        &mut self,
        expected: &Digest,
        reason: HaltReasonRefV1,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Escalate)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.escalate(expected, reason, now_unix_ms)?)
    }

    /// Completes one exact authority-empty occurrence under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, open residuals, observation refusal, or Store failure.
    pub fn complete(
        &mut self,
        expected: &Digest,
        observation_ref: ObservationRefV1,
        subject: &Digest,
        terminal_witness: TerminalWitnessRefV1,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::Complete)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        OccurrenceViewV1::try_from(&self.engine.complete(
            expected,
            observation_ref,
            subject,
            terminal_witness,
            &mut observation,
            now_unix_ms,
        )?)
    }

    /// Persists one typed no-state-change refusal under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, invalid refusal, or Store failure.
    pub fn record_refusal(
        &mut self,
        expected: &Digest,
        code: RefusalCodeV1,
        evidence: Option<Digest>,
    ) -> Result<Digest, CampaignEngineErrorV1> {
        self.require_allowed(expected, GovernedOperationV1::RecordRefusal)?;
        let now_unix_ms = self.consequence_now()?;
        self.engine
            .record_refusal(expected, code, evidence, now_unix_ms)
    }
}

fn require_expected(
    engine: &CampaignEngineV1,
    expected: &Digest,
) -> Result<(), CampaignEngineErrorV1> {
    let current = engine.current()?;
    if current.state_digest() != expected {
        return Err(CampaignStoreErrorV1::StalePredecessor {
            expected: expected.clone(),
            authoritative: current.state_digest().clone(),
        }
        .into());
    }
    Ok(())
}

fn project_occurrence(
    store: &CampaignStoreV1,
    snapshot: &OccurrenceSnapshotV1,
    now_unix_ms: u64,
) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
    let mut view = OccurrenceViewV1::try_from(snapshot)?;
    if let Some(halted) = view.halted.as_mut() {
        halted.open_human_decision_request =
            store.open_human_decision_request_for_state(snapshot.state_digest(), now_unix_ms)?;
        if let Some(request) = &halted.open_human_decision_request {
            push_artifact_link(
                &mut view.artifacts,
                GovernedArtifactKindV1::HumanDecisionRequest,
                request.as_digest(),
            );
        }
        if let Some(closed) = &halted.governed_repair_closed
            && let Some(verification) =
                store.governed_repair_verification_for_disposition(&closed.disposition)?
        {
            push_artifact_link(
                &mut view.artifacts,
                GovernedArtifactKindV1::GovernedRepairVerification,
                verification.verification.as_digest(),
            );
        }
    }
    for link in store.lifecycle_artifact_links(snapshot.key())? {
        let kind = match link.kind {
            StoreLifecycleArtifactKindV1::ObservationResolution => {
                GovernedArtifactKindV1::ObservationResolution
            }
            StoreLifecycleArtifactKindV1::StandingResolution => {
                GovernedArtifactKindV1::StandingResolution
            }
            StoreLifecycleArtifactKindV1::AdmissionDecision => {
                GovernedArtifactKindV1::AdmissionDecision
            }
            StoreLifecycleArtifactKindV1::AgAuthorizationSpend => {
                GovernedArtifactKindV1::AgAuthorizationSpend
            }
            StoreLifecycleArtifactKindV1::AgIssuance => GovernedArtifactKindV1::AgIssuance,
            StoreLifecycleArtifactKindV1::DocketCustody => GovernedArtifactKindV1::DocketCustody,
            StoreLifecycleArtifactKindV1::DocketSettlement => {
                GovernedArtifactKindV1::DocketSettlement
            }
            StoreLifecycleArtifactKindV1::DocketGovernedRepairResult => {
                GovernedArtifactKindV1::DocketGovernedRepairResult
            }
            StoreLifecycleArtifactKindV1::GovernedRepairDisposition => {
                GovernedArtifactKindV1::GovernedRepairDisposition
            }
            StoreLifecycleArtifactKindV1::GovernedRepairVerification => {
                GovernedArtifactKindV1::GovernedRepairVerification
            }
            StoreLifecycleArtifactKindV1::HumanDecisionRequest => {
                GovernedArtifactKindV1::HumanDecisionRequest
            }
            StoreLifecycleArtifactKindV1::DocketCheckpointReference => {
                GovernedArtifactKindV1::DocketCheckpointReference
            }
            StoreLifecycleArtifactKindV1::EffectJournalReference => {
                GovernedArtifactKindV1::EffectJournalReference
            }
            StoreLifecycleArtifactKindV1::DocketIndeterminateOutcome => {
                GovernedArtifactKindV1::DocketIndeterminateOutcome
            }
            StoreLifecycleArtifactKindV1::SuccessorBinding => {
                GovernedArtifactKindV1::SuccessorBinding
            }
            StoreLifecycleArtifactKindV1::PreSpendScopeDiscovery => {
                GovernedArtifactKindV1::PreSpendScopeDiscovery
            }
            StoreLifecycleArtifactKindV1::ResidualState => GovernedArtifactKindV1::ResidualState,
            StoreLifecycleArtifactKindV1::CompletionObservation => {
                GovernedArtifactKindV1::CompletionObservation
            }
            StoreLifecycleArtifactKindV1::TerminalWitness => {
                GovernedArtifactKindV1::TerminalWitness
            }
            StoreLifecycleArtifactKindV1::HistoricalHumanDisposition => {
                GovernedArtifactKindV1::HistoricalHumanDisposition
            }
            StoreLifecycleArtifactKindV1::DocketIssuanceRefusal => {
                GovernedArtifactKindV1::DocketIssuanceRefusal
            }
            StoreLifecycleArtifactKindV1::Refusal => GovernedArtifactKindV1::Refusal,
        };
        push_artifact_link(&mut view.artifacts, kind, &link.identity);
    }
    view.artifacts.sort();
    view.artifacts.dedup();
    Ok(view)
}

fn campaign_artifact_links(
    store: &CampaignStoreV1,
) -> Result<Vec<GovernedArtifactLinkV1>, CampaignEngineErrorV1> {
    let mut links = Vec::new();
    if let Some((_, identity, _)) = store.product_creation_request()? {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::ProductCreation,
            &identity,
        );
    }
    if let Some((identity, _)) = store.governed_repair_verifier_root()? {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::GovernedRepairVerifierRoot,
            &identity,
        );
    }
    links.sort();
    links.dedup();
    Ok(links)
}

fn occurrence_artifact_links(
    snapshot: &OccurrenceSnapshotV1,
) -> Result<Vec<GovernedArtifactLinkV1>, CampaignEngineErrorV1> {
    let mut links = Vec::new();
    if let Some(proposal) = snapshot.proposal_contract() {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::ExactWorkProposal,
            proposal.reference().as_digest(),
        );
    }
    if let Some(spend) = snapshot.ag_spend() {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::AgAuthorizationSpend,
            spend.spend.as_digest(),
        );
    }
    if let Some(issuance) = snapshot.issuance() {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::AgIssuance,
            issuance.issuance.as_digest(),
        );
    }
    if let Some(custody) = snapshot.docket_custody() {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::DocketCustody,
            custody.reference().as_digest(),
        );
    }
    if let Some(settlement) = snapshot.settlement() {
        push_artifact_link(
            &mut links,
            GovernedArtifactKindV1::DocketSettlement,
            settlement.settlement.as_digest(),
        );
        if let Some(journal) = &settlement.cumulative_effect_journal_identity {
            push_artifact_link(
                &mut links,
                GovernedArtifactKindV1::EffectJournalReference,
                journal,
            );
        }
    }
    append_halted_artifact_links(snapshot, &mut links);
    append_completion_artifact_links(snapshot, &mut links)?;
    links.sort();
    links.dedup();
    Ok(links)
}

fn append_halted_artifact_links(
    snapshot: &OccurrenceSnapshotV1,
    links: &mut Vec<GovernedArtifactLinkV1>,
) {
    let Some(halted) = snapshot.halted() else {
        return;
    };
    if let Some(refusal) = halted.docket_issuance_refusal() {
        push_artifact_link(
            links,
            GovernedArtifactKindV1::DocketIssuanceRefusal,
            &refusal.refusal,
        );
    }
    if let Some(requirement) = halted.governed_repair_requirement() {
        let outcome = match requirement {
            HumanDecisionRequirementV1::ScopeExpansion(value) => value.docket_outcome.as_ref(),
            HumanDecisionRequirementV1::Readjudication(value) => value.docket_outcome.as_ref(),
        };
        if let Some(outcome) = outcome {
            for (kind, identity) in [
                (
                    GovernedArtifactKindV1::DocketGovernedRepairResult,
                    outcome.sealed_result.as_digest(),
                ),
                (
                    GovernedArtifactKindV1::DocketCustody,
                    outcome.custody.as_digest(),
                ),
                (
                    GovernedArtifactKindV1::AgIssuance,
                    outcome.issuance.as_digest(),
                ),
            ] {
                push_artifact_link(links, kind, identity);
            }
        }
    }
    if let Some(closed) = halted.governed_repair_closed() {
        push_artifact_link(
            links,
            GovernedArtifactKindV1::HumanDecisionRequest,
            closed.request.as_digest(),
        );
        push_artifact_link(
            links,
            GovernedArtifactKindV1::GovernedRepairDisposition,
            closed.disposition.as_digest(),
        );
    }
}

fn append_completion_artifact_links(
    snapshot: &OccurrenceSnapshotV1,
    links: &mut Vec<GovernedArtifactLinkV1>,
) -> Result<(), CampaignEngineErrorV1> {
    if let Some(terminal_observation) = snapshot.terminal_observation() {
        let artifact = CompletionObservationArtifactV1 {
            schema: COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1.to_owned(),
            state_digest: snapshot.state_digest().clone(),
            record: terminal_observation.clone(),
        };
        push_artifact_link(
            links,
            GovernedArtifactKindV1::CompletionObservation,
            &artifact.identity()?,
        );
    }
    if let Some(terminal_witness) = snapshot.terminal_witness() {
        let artifact = TerminalWitnessArtifactV1 {
            schema: TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1.to_owned(),
            key: snapshot.key().clone(),
            state_digest: snapshot.state_digest().clone(),
            witness: terminal_witness.clone(),
        };
        push_artifact_link(
            links,
            GovernedArtifactKindV1::TerminalWitness,
            &artifact.identity()?,
        );
    }
    Ok(())
}

fn push_artifact_link(
    links: &mut Vec<GovernedArtifactLinkV1>,
    kind: GovernedArtifactKindV1,
    identity: &Digest,
) {
    links.push(GovernedArtifactLinkV1 {
        kind,
        identity: identity.clone(),
    });
}

fn artifact_schema(kind: GovernedArtifactKindV1) -> &'static str {
    match kind {
        GovernedArtifactKindV1::ProductCreation => "ag.governed-loop.product-create/v1",
        GovernedArtifactKindV1::GovernedRepairVerifierRoot => {
            GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1
        }
        GovernedArtifactKindV1::ExactWorkProposal => EXACT_WORK_PROPOSAL_SCHEMA_V1,
        GovernedArtifactKindV1::ObservationResolution => OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::StandingResolution => STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::AdmissionDecision => ADMISSION_DECISION_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::AgAuthorizationSpend => "ag.governed-loop.authorization-spend/v1",
        GovernedArtifactKindV1::AgIssuance => AG_ISSUANCE_SCHEMA_V2,
        GovernedArtifactKindV1::DocketCustody => DOCKET_CUSTODY_SCHEMA_V1,
        GovernedArtifactKindV1::DocketSettlement => DOCKET_SETTLEMENT_SCHEMA_V1,
        GovernedArtifactKindV1::DocketIndeterminateOutcome => {
            DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1
        }
        GovernedArtifactKindV1::DocketIssuanceRefusal => "docket.governed-loop.issuance-refusal/v1",
        GovernedArtifactKindV1::DocketGovernedRepairResult => {
            "docket.governed-loop.sealed-governed-repair-result/v1"
        }
        GovernedArtifactKindV1::DocketCheckpointReference => DOCKET_CHECKPOINT_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::EffectJournalReference => {
            EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1
        }
        GovernedArtifactKindV1::HumanDecisionRequest => HUMAN_DECISION_REQUEST_SCHEMA_V1,
        GovernedArtifactKindV1::GovernedRepairDisposition => GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1,
        GovernedArtifactKindV1::GovernedRepairVerification => {
            GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1
        }
        GovernedArtifactKindV1::SuccessorBinding => SUCCESSOR_BINDING_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::PreSpendScopeDiscovery => PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1,
        GovernedArtifactKindV1::ResidualState => RESIDUAL_STATE_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::CompletionObservation => COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::TerminalWitness => TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1,
        GovernedArtifactKindV1::HistoricalHumanDisposition => HUMAN_DISPOSITION_SCHEMA_V1,
        GovernedArtifactKindV1::Refusal => "ag.governed-loop.store-refusal/v1",
    }
}

fn artifact_occurrences(
    store: &CampaignStoreV1,
    identity: &Digest,
) -> Result<Vec<OccurrenceKeyV1>, CampaignEngineErrorV1> {
    let mut occurrences = Vec::new();
    let mut cursor = None;
    loop {
        let page = store.list_occurrences(cursor.as_deref(), 1000)?;
        if page.is_empty() {
            break;
        }
        for snapshot in &page {
            let mut links = occurrence_artifact_links(snapshot)?;
            links.extend(
                store
                    .lifecycle_artifact_links(snapshot.key())?
                    .into_iter()
                    .map(|link| GovernedArtifactLinkV1 {
                        kind: match link.kind {
                            StoreLifecycleArtifactKindV1::ObservationResolution => {
                                GovernedArtifactKindV1::ObservationResolution
                            }
                            StoreLifecycleArtifactKindV1::StandingResolution => {
                                GovernedArtifactKindV1::StandingResolution
                            }
                            StoreLifecycleArtifactKindV1::AdmissionDecision => {
                                GovernedArtifactKindV1::AdmissionDecision
                            }
                            StoreLifecycleArtifactKindV1::AgAuthorizationSpend => {
                                GovernedArtifactKindV1::AgAuthorizationSpend
                            }
                            StoreLifecycleArtifactKindV1::AgIssuance => {
                                GovernedArtifactKindV1::AgIssuance
                            }
                            StoreLifecycleArtifactKindV1::DocketCustody => {
                                GovernedArtifactKindV1::DocketCustody
                            }
                            StoreLifecycleArtifactKindV1::DocketSettlement => {
                                GovernedArtifactKindV1::DocketSettlement
                            }
                            StoreLifecycleArtifactKindV1::DocketGovernedRepairResult => {
                                GovernedArtifactKindV1::DocketGovernedRepairResult
                            }
                            StoreLifecycleArtifactKindV1::GovernedRepairDisposition => {
                                GovernedArtifactKindV1::GovernedRepairDisposition
                            }
                            StoreLifecycleArtifactKindV1::GovernedRepairVerification => {
                                GovernedArtifactKindV1::GovernedRepairVerification
                            }
                            StoreLifecycleArtifactKindV1::HumanDecisionRequest => {
                                GovernedArtifactKindV1::HumanDecisionRequest
                            }
                            StoreLifecycleArtifactKindV1::DocketCheckpointReference => {
                                GovernedArtifactKindV1::DocketCheckpointReference
                            }
                            StoreLifecycleArtifactKindV1::EffectJournalReference => {
                                GovernedArtifactKindV1::EffectJournalReference
                            }
                            StoreLifecycleArtifactKindV1::DocketIndeterminateOutcome => {
                                GovernedArtifactKindV1::DocketIndeterminateOutcome
                            }
                            StoreLifecycleArtifactKindV1::SuccessorBinding => {
                                GovernedArtifactKindV1::SuccessorBinding
                            }
                            StoreLifecycleArtifactKindV1::PreSpendScopeDiscovery => {
                                GovernedArtifactKindV1::PreSpendScopeDiscovery
                            }
                            StoreLifecycleArtifactKindV1::ResidualState => {
                                GovernedArtifactKindV1::ResidualState
                            }
                            StoreLifecycleArtifactKindV1::CompletionObservation => {
                                GovernedArtifactKindV1::CompletionObservation
                            }
                            StoreLifecycleArtifactKindV1::TerminalWitness => {
                                GovernedArtifactKindV1::TerminalWitness
                            }
                            StoreLifecycleArtifactKindV1::HistoricalHumanDisposition => {
                                GovernedArtifactKindV1::HistoricalHumanDisposition
                            }
                            StoreLifecycleArtifactKindV1::DocketIssuanceRefusal => {
                                GovernedArtifactKindV1::DocketIssuanceRefusal
                            }
                            StoreLifecycleArtifactKindV1::Refusal => {
                                GovernedArtifactKindV1::Refusal
                            }
                        },
                        identity: link.identity,
                    }),
            );
            if links.iter().any(|link| &link.identity == identity) {
                occurrences.push(snapshot.key().clone());
            }
        }
        cursor = page
            .last()
            .map(|snapshot| snapshot.key().occurrence.to_string());
        if page.len() < 1000 {
            break;
        }
    }
    occurrences.sort();
    occurrences.dedup();
    Ok(occurrences)
}

fn classify_artifact(bytes: &[u8]) -> Result<GovernedArtifactKindV1, CampaignEngineErrorV1> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| CampaignEngineErrorV1::Canonical(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        CampaignEngineErrorV1::Canonical("durable artifact is not a JSON object".to_owned())
    })?;
    let schema = object.get("schema").and_then(serde_json::Value::as_str);
    let kind = match schema {
        Some(GOVERNED_REPAIR_VERIFIER_ROOT_SCHEMA_V1) => {
            GovernedArtifactKindV1::GovernedRepairVerifierRoot
        }
        Some(EXACT_WORK_PROPOSAL_SCHEMA_V1) => GovernedArtifactKindV1::ExactWorkProposal,
        Some(AG_ISSUANCE_SCHEMA_V2) => GovernedArtifactKindV1::AgIssuance,
        Some(DOCKET_CUSTODY_SCHEMA_V1) => GovernedArtifactKindV1::DocketCustody,
        Some(DOCKET_SETTLEMENT_SCHEMA_V1) => GovernedArtifactKindV1::DocketSettlement,
        Some(DOCKET_INDETERMINATE_ARTIFACT_SCHEMA_V1) => {
            GovernedArtifactKindV1::DocketIndeterminateOutcome
        }
        Some("docket.governed-loop.issuance-refusal/v1") => {
            GovernedArtifactKindV1::DocketIssuanceRefusal
        }
        Some(HUMAN_DECISION_REQUEST_SCHEMA_V1) => GovernedArtifactKindV1::HumanDecisionRequest,
        Some(GOVERNED_REPAIR_DISPOSITION_SCHEMA_V1) => {
            GovernedArtifactKindV1::GovernedRepairDisposition
        }
        Some(GOVERNED_REPAIR_VERIFICATION_SCHEMA_V1) => {
            GovernedArtifactKindV1::GovernedRepairVerification
        }
        Some(OBSERVATION_RESOLUTION_ARTIFACT_SCHEMA_V1) => {
            GovernedArtifactKindV1::ObservationResolution
        }
        Some(STANDING_RESOLUTION_ARTIFACT_SCHEMA_V1) => GovernedArtifactKindV1::StandingResolution,
        Some(ADMISSION_DECISION_ARTIFACT_SCHEMA_V1) => GovernedArtifactKindV1::AdmissionDecision,
        Some(DOCKET_CHECKPOINT_ARTIFACT_SCHEMA_V1) => {
            GovernedArtifactKindV1::DocketCheckpointReference
        }
        Some(EFFECT_JOURNAL_REFERENCE_ARTIFACT_SCHEMA_V1) => {
            GovernedArtifactKindV1::EffectJournalReference
        }
        Some(SUCCESSOR_BINDING_ARTIFACT_SCHEMA_V1) => GovernedArtifactKindV1::SuccessorBinding,
        Some(PRE_SPEND_SCOPE_DISCOVERY_SCHEMA_V1) => GovernedArtifactKindV1::PreSpendScopeDiscovery,
        Some(RESIDUAL_STATE_ARTIFACT_SCHEMA_V1) => GovernedArtifactKindV1::ResidualState,
        Some(COMPLETION_OBSERVATION_ARTIFACT_SCHEMA_V1) => {
            GovernedArtifactKindV1::CompletionObservation
        }
        Some(TERMINAL_WITNESS_ARTIFACT_SCHEMA_V1) => GovernedArtifactKindV1::TerminalWitness,
        Some(HUMAN_DISPOSITION_SCHEMA_V1) => GovernedArtifactKindV1::HistoricalHumanDisposition,
        _ if object.contains_key("kind") && object.contains_key("record") => {
            GovernedArtifactKindV1::DocketGovernedRepairResult
        }
        _ if object.contains_key("authorization")
            && object.contains_key("spend")
            && object.contains_key("consumed_at_unix_ms") =>
        {
            GovernedArtifactKindV1::AgAuthorizationSpend
        }
        _ if object.contains_key("key")
            && object.contains_key("at_state_digest")
            && object.contains_key("code") =>
        {
            GovernedArtifactKindV1::Refusal
        }
        _ if object.contains_key("governed_ag_policy_root")
            && object.contains_key("idempotency_key")
            && object.contains_key("campaign") =>
        {
            GovernedArtifactKindV1::ProductCreation
        }
        _ => {
            return Err(CampaignEngineErrorV1::Canonical(
                "durable artifact is outside the closed product taxonomy".to_owned(),
            ));
        }
    };
    Ok(kind)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GovernedDecisionStateV1 {
    NotGoverned,
    PreSpendScopeInsufficiency,
    AwaitingRequest,
    RequestOpen,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProposalTimeStateV1 {
    Current,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DocketDeploymentStateV1 {
    Unavailable,
    RuntimeCurrent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifierDeploymentStateV1 {
    Absent,
    Configured,
    RuntimeCurrent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AllowedTransitionStateV1 {
    governed: GovernedDecisionStateV1,
    proposal: ProposalTimeStateV1,
    budget: LoopBudgetV1,
    residuals_empty: bool,
    pre_spend_revision_eligible: bool,
    docket: DocketDeploymentStateV1,
    verifier: VerifierDeploymentStateV1,
}

fn governed_decision_state(
    current: &OccurrenceSnapshotV1,
    has_open_request: bool,
) -> Result<GovernedDecisionStateV1, CampaignEngineErrorV1> {
    if current.program_counter() != ProgramCounterV1::Halted {
        return Ok(GovernedDecisionStateV1::NotGoverned);
    }
    let halted = current.halted().ok_or_else(|| {
        CampaignEngineErrorV1::Canonical("halted program counter lacks halted state".to_owned())
    })?;
    Ok(if halted.pre_spend_scope_insufficiency().is_some() {
        GovernedDecisionStateV1::PreSpendScopeInsufficiency
    } else if halted.governed_repair_closed().is_some() {
        GovernedDecisionStateV1::Closed
    } else if has_open_request {
        GovernedDecisionStateV1::RequestOpen
    } else if halted.governed_repair_requirement().is_some() {
        GovernedDecisionStateV1::AwaitingRequest
    } else {
        GovernedDecisionStateV1::NotGoverned
    })
}

fn allow_halted_transition(names: &mut Vec<GovernedOperationV1>, state: AllowedTransitionStateV1) {
    match state.governed {
        GovernedDecisionStateV1::PreSpendScopeInsufficiency => {
            if state.proposal == ProposalTimeStateV1::Current {
                names.push(GovernedOperationV1::RecordPreSpendScopeDiscovery);
            }
        }
        GovernedDecisionStateV1::AwaitingRequest
            if state.verifier != VerifierDeploymentStateV1::Absent =>
        {
            names.push(GovernedOperationV1::CreateDecisionRequest);
        }
        GovernedDecisionStateV1::RequestOpen
            if state.verifier == VerifierDeploymentStateV1::RuntimeCurrent =>
        {
            names.push(GovernedOperationV1::SubmitDisposition);
        }
        GovernedDecisionStateV1::NotGoverned
        | GovernedDecisionStateV1::AwaitingRequest
        | GovernedDecisionStateV1::RequestOpen
        | GovernedDecisionStateV1::Closed => {}
    }
}

fn allowed_transitions(
    pc: ProgramCounterV1,
    state: AllowedTransitionStateV1,
) -> Vec<GovernedOperationV1> {
    let mut names = Vec::new();
    let mut allow = |legal: bool, operation: GovernedOperationV1| {
        if legal {
            names.push(operation);
        }
    };
    let docket_current = state.docket == DocketDeploymentStateV1::RuntimeCurrent;
    match pc {
        ProgramCounterV1::ObservationRequired => {
            allow(
                state.proposal == ProposalTimeStateV1::Current,
                GovernedOperationV1::RecordProposal,
            );
            allow(state.residuals_empty, GovernedOperationV1::Complete);
            allow(
                state.budget.probe_available(),
                GovernedOperationV1::NoteProbe,
            );
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::ProposalRecorded => {
            allow(true, GovernedOperationV1::RequireStanding);
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.pre_spend_revision_eligible && state.proposal == ProposalTimeStateV1::Current,
                GovernedOperationV1::HaltPreSpendScopeInsufficiency,
            );
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::StandingRequired => {
            allow(
                state.proposal == ProposalTimeStateV1::Current,
                GovernedOperationV1::Decide,
            );
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::AdmissiblePendingAuthorization => {
            allow(
                state.proposal == ProposalTimeStateV1::Current && docket_current,
                GovernedOperationV1::Authorize,
            );
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::AuthorizationConsumed => {
            allow(
                state.proposal == ProposalTimeStateV1::Current && docket_current,
                GovernedOperationV1::Dispatch,
            );
            allow(docket_current, GovernedOperationV1::Recover);
        }
        ProgramCounterV1::Dispatched => {
            allow(docket_current, GovernedOperationV1::ReconcileDocket);
            allow(docket_current, GovernedOperationV1::Recover);
        }
        ProgramCounterV1::ReconciliationRequired => {
            allow(docket_current, GovernedOperationV1::ReconcileDocket);
            allow(docket_current, GovernedOperationV1::Recover);
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::SettledObservationRequired => {
            // Exact settlement replay is a read-only reconciliation. Docket
            // re-emits the already sealed result and the kernel requires byte
            // equality, so this never repeats executor mechanics or creates a
            // fresh transition.
            allow(docket_current, GovernedOperationV1::ReconcileDocket);
            allow(true, GovernedOperationV1::OpenContinuation);
            allow(
                state.budget.probe_available(),
                GovernedOperationV1::NoteProbe,
            );
            allow(true, GovernedOperationV1::Halt);
            allow(
                state.budget.escalation_available(),
                GovernedOperationV1::Escalate,
            );
        }
        ProgramCounterV1::Halted => allow_halted_transition(&mut names, state),
        ProgramCounterV1::Completed => {}
    }
    // Recording a refusal is the sole legal no-state-change consequence at
    // every valid program counter.
    names.push(GovernedOperationV1::RecordRefusal);
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive table makes the closed transition vocabulary auditable"
    )]
    fn allowed_transition_vocabulary_is_closed_for_every_program_counter() {
        let ordinary = AllowedTransitionStateV1 {
            governed: GovernedDecisionStateV1::NotGoverned,
            proposal: ProposalTimeStateV1::Current,
            budget: LoopBudgetV1 {
                retry_limit: 1,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            residuals_empty: true,
            pre_spend_revision_eligible: true,
            docket: DocketDeploymentStateV1::RuntimeCurrent,
            verifier: VerifierDeploymentStateV1::RuntimeCurrent,
        };
        let cases = [
            (
                ProgramCounterV1::ObservationRequired,
                ordinary,
                &[
                    GovernedOperationV1::RecordProposal,
                    GovernedOperationV1::Complete,
                    GovernedOperationV1::NoteProbe,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ][..],
            ),
            (
                ProgramCounterV1::ProposalRecorded,
                ordinary,
                &[
                    GovernedOperationV1::RequireStanding,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::HaltPreSpendScopeInsufficiency,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::StandingRequired,
                ordinary,
                &[
                    GovernedOperationV1::Decide,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::AdmissiblePendingAuthorization,
                ordinary,
                &[
                    GovernedOperationV1::Authorize,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::AuthorizationConsumed,
                ordinary,
                &[
                    GovernedOperationV1::Dispatch,
                    GovernedOperationV1::Recover,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::Dispatched,
                ordinary,
                &[
                    GovernedOperationV1::ReconcileDocket,
                    GovernedOperationV1::Recover,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::ReconciliationRequired,
                ordinary,
                &[
                    GovernedOperationV1::ReconcileDocket,
                    GovernedOperationV1::Recover,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::SettledObservationRequired,
                ordinary,
                &[
                    GovernedOperationV1::ReconcileDocket,
                    GovernedOperationV1::OpenContinuation,
                    GovernedOperationV1::NoteProbe,
                    GovernedOperationV1::Halt,
                    GovernedOperationV1::Escalate,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::Halted,
                ordinary,
                &[GovernedOperationV1::RecordRefusal],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::PreSpendScopeInsufficiency,
                    ..ordinary
                },
                &[
                    GovernedOperationV1::RecordPreSpendScopeDiscovery,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::AwaitingRequest,
                    ..ordinary
                },
                &[
                    GovernedOperationV1::CreateDecisionRequest,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::RequestOpen,
                    ..ordinary
                },
                &[
                    GovernedOperationV1::SubmitDisposition,
                    GovernedOperationV1::RecordRefusal,
                ],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::Closed,
                    ..ordinary
                },
                &[GovernedOperationV1::RecordRefusal],
            ),
            (
                ProgramCounterV1::Completed,
                ordinary,
                &[GovernedOperationV1::RecordRefusal],
            ),
        ];
        for (pc, state, expected) in cases {
            assert_eq!(allowed_transitions(pc, state), expected);
        }
        assert_eq!(
            allowed_transitions(
                ProgramCounterV1::AuthorizationConsumed,
                AllowedTransitionStateV1 {
                    proposal: ProposalTimeStateV1::Expired,
                    ..ordinary
                },
            ),
            [
                GovernedOperationV1::Recover,
                GovernedOperationV1::RecordRefusal,
            ],
        );
    }
}
