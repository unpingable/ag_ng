//! Stable versioned product DTO and service surface for governed campaigns.
//!
//! This module is the reusable application contract.  CLI records are views of
//! these DTOs; they are not a second orchestration API.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ag_campaign::CampaignId;
use ag_primitives::Digest;
use ag_store::campaign::{CampaignEventV1, CampaignStoreErrorV1, CampaignStoreV1};
use serde::{Deserialize, Serialize};

use ag_campaign::governed::{
    AuthorityHistoryV1, C1RejectedReviewBasisV1, DocketAttemptRefV1, DocketIssuanceRefusalV1,
    ExactWorkProposalV1, GovernedRepairClosedV1, GovernedRepairDispositionV1,
    GovernedRepairVerifierProfileV1, HaltReasonRefV1, HumanDecisionIdV1, HumanDecisionRequestRefV1,
    HumanDecisionRequestV1, HumanDecisionRequirementV1, HumanDispositionRefV1, HumanPrincipalRefV1,
    HumanVerificationRefV1, LoopBudgetV1, MandateRefV1, ObservationRefV1, OccurrenceId,
    OccurrenceKeyV1, OccurrenceSnapshotV1, ProgramBasisRefV1, ProgramCounterV1, ProposalClassV1,
    ProposalRefV1, RefusalCodeV1, ResidualSetV1, TerminalWitnessRefV1,
};

use crate::governed_loop::{CampaignEngineErrorV1, CampaignEngineV1, ExactWorkCatalogV1};
use crate::governed_ports::{
    AgIssuanceSignerV2, CommandDocketCustodyPortV1, CommandObservationResolverV1,
    CommandStandingResolverV1,
};

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

    fn open_port(&self) -> Result<CommandDocketCustodyPortV1, CampaignEngineErrorV1> {
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
    /// Exact immutable proposal contract once proposal recording occurred.
    /// Authority-empty observation shells expose `None`.
    pub proposal_contract: Option<ProposalContractViewV1>,
    /// Halt-specific facts, absent at every other program counter.
    pub halted: Option<HaltedOccurrenceViewV1>,
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
            open_human_decision_request: None,
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
            proposal_contract,
            halted,
        })
    }
}

/// Stable ordered event page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventPageV1 {
    /// Exact events in monotone store sequence order.
    pub items: Vec<CampaignEventV1>,
    /// Exclusive sequence cursor for the next page.
    pub next: Option<u64>,
}

/// Stable exact artifact response; identity and byte hash are returned with
/// the canonical bytes to prevent caller-side substitution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecordV1 {
    /// Requested domain-specific identity.
    pub identity: Digest,
    /// SHA-256 of the exact canonical bytes.
    pub bytes_identity: Digest,
    /// Exact canonical bytes.
    pub bytes: Vec<u8>,
}

/// Stable current-state view including legal next operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignStateViewV1 {
    /// Stable service schema.
    pub schema: String,
    /// Exact current occurrence.
    pub current: OccurrenceViewV1,
    /// Exact current unconsumed, unexpired decision request, when one exists.
    pub open_human_decision_request: Option<HumanDecisionRequestRefV1>,
    /// Closed operation names legal from the current program counter.
    pub allowed_transitions: Vec<String>,
    /// Last durable event sequence.
    pub event_sequence: u64,
    /// Deployment-owned consequence-clock observation used for this view.
    pub observed_at_unix_ms: u64,
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

/// Reusable service around the one canonical engine/store state machine.
pub struct GovernedCampaignServiceV1 {
    engine: CampaignEngineV1,
    policy_root: GovernedAgPolicyRootV1,
    verifier_root: Option<GovernedRepairVerifierRootV1>,
    docket_root: Option<GovernedDocketAdapterRootV1>,
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
        let mut current_view = OccurrenceViewV1::try_from(&current)?;
        if let Some(halted) = current_view.halted.as_mut() {
            halted.open_human_decision_request.clone_from(&open_request);
        }
        Ok(CampaignStateViewV1 {
            schema: GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1.to_owned(),
            allowed_transitions: allowed_transitions(
                current.program_counter(),
                AllowedTransitionStateV1 {
                    governed: governed_state,
                    proposal: if current
                        .proposal_contract()
                        .is_some_and(|proposal| now_unix_ms >= proposal.expires_at_unix_ms())
                    {
                        ProposalTimeStateV1::Expired
                    } else {
                        ProposalTimeStateV1::Current
                    },
                },
            ),
            current: current_view,
            open_human_decision_request: open_request,
            event_sequence: read.head.event_count,
            observed_at_unix_ms: now_unix_ms,
        })
    }

    /// Replays and verifies the authoritative store.
    ///
    /// # Errors
    ///
    /// Returns an error when any journal, materialization, or identity check fails.
    pub fn replay(
        &self,
    ) -> Result<ag_store::campaign::CampaignReplayReportV1, CampaignEngineErrorV1> {
        self.engine.replay()
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
        let store = CampaignStoreV1::open(self.engine.store_path())?;
        let mut cursor = page.after.clone();
        let mut snapshots = Vec::new();
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
            if snapshots.len() >= page.limit as usize || exhausted {
                break;
            }
        }
        snapshots.truncate(page.limit as usize);
        let next = snapshots
            .last()
            .map(|item| item.key().occurrence.to_string());
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
        let after = page
            .after
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| CampaignEngineErrorV1::Canonical("invalid event cursor".to_owned()))?;
        let items =
            CampaignStoreV1::open(self.engine.store_path())?.list_events(after, page.limit)?;
        let next = items.last().map(|event| event.sequence);
        Ok(EventPageV1 { items, next })
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
        Ok(CampaignStoreV1::open(self.engine.store_path())?
            .artifact_bytes(identity)?
            .map(|bytes| ArtifactRecordV1 {
                identity: identity.clone(),
                bytes_identity: Digest::hash_bytes(&bytes),
                bytes,
            }))
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
            Err(CampaignEngineErrorV1::Store(CampaignStoreErrorV1::GovernedRepairReplay)) => {
                let store = CampaignStoreV1::open(self.engine.store_path())?;
                if store.governed_repair_disposition(&disposition)? == Some(exact_artifact) {
                    self.committed_disposition_result(disposition, request_ref, true)
                } else {
                    Err(CampaignEngineErrorV1::Store(
                        CampaignStoreErrorV1::GovernedRepairReplay,
                    ))
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
        require_expected(&self.engine, expected_state_digest)?;
        let now_unix_ms = self.consequence_now()?;
        let mut resolver = self.policy_root.observation()?;
        let current = self.engine.record_proposal(
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
        require_expected(&self.engine, expected_state_digest)?;
        let now_unix_ms = self.consequence_now()?;
        let mut docket = self.docket_port()?;
        let _ = self.engine.poll_docket(&mut docket, now_unix_ms)?;
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
        require_expected(&self.engine, expected_state_digest)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.open_continuation(occurrence, now_unix_ms)?)
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
        require_expected(&self.engine, expected_state_digest)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.halt(reason, now_unix_ms)?)
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.require_standing(now_unix_ms)?)
    }

    /// Records one exact admissibility decision through the canonical engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, failed currentness/standing, inadmissibility, or Store failure.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(&mut self, expected: &Digest) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        let mut standing = self.policy_root.standing()?;
        let catalog = self.policy_root.catalog()?;
        let controlling_review = self.policy_root.review()?;
        OccurrenceViewV1::try_from(&self.engine.decide(
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        let mut standing = self.policy_root.standing()?;
        let catalog = self.policy_root.catalog()?;
        let controlling_review = self.policy_root.review()?;
        OccurrenceViewV1::try_from(&self.engine.authorize(
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        let mut docket = self.docket_port()?;
        OccurrenceViewV1::try_from(&self.engine.dispatch(&mut docket, now_unix_ms)?)
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        let mut docket = self.docket_port()?;
        let _ = self.engine.recover(&mut docket, now_unix_ms)?;
        self.state()
    }

    fn docket_port(&self) -> Result<CommandDocketCustodyPortV1, CampaignEngineErrorV1> {
        self.docket_root
            .as_ref()
            .ok_or_else(|| {
                CampaignEngineErrorV1::Canonical(
                    "deployment-owned Docket adapter root is not configured".to_owned(),
                )
            })?
            .open_port()
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

    /// Records one read-only probe fact under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/illegal state, exhausted budget, or Store failure.
    pub fn note_probe(
        &mut self,
        expected: &Digest,
    ) -> Result<OccurrenceViewV1, CampaignEngineErrorV1> {
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.note_probe(now_unix_ms)?)
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        OccurrenceViewV1::try_from(&self.engine.escalate(reason, now_unix_ms)?)
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        let mut observation = self.policy_root.observation()?;
        OccurrenceViewV1::try_from(&self.engine.complete(
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
        require_expected(&self.engine, expected)?;
        let now_unix_ms = self.consequence_now()?;
        self.engine.record_refusal(code, evidence, now_unix_ms)
    }
}

fn require_expected(
    engine: &CampaignEngineV1,
    expected: &Digest,
) -> Result<(), CampaignEngineErrorV1> {
    let current = engine.current()?;
    if current.state_digest() != expected {
        return Err(CampaignEngineErrorV1::Canonical(
            "product operation expected-state CAS mismatch".to_owned(),
        ));
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
    }
    Ok(view)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GovernedDecisionStateV1 {
    NotGoverned,
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
struct AllowedTransitionStateV1 {
    governed: GovernedDecisionStateV1,
    proposal: ProposalTimeStateV1,
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
    Ok(if halted.governed_repair_closed().is_some() {
        GovernedDecisionStateV1::Closed
    } else if has_open_request {
        GovernedDecisionStateV1::RequestOpen
    } else if halted.governed_repair_requirement().is_some() {
        GovernedDecisionStateV1::AwaitingRequest
    } else {
        GovernedDecisionStateV1::NotGoverned
    })
}

fn allowed_transitions(pc: ProgramCounterV1, state: AllowedTransitionStateV1) -> Vec<String> {
    let names: &[&str] = match pc {
        ProgramCounterV1::ObservationRequired => &[
            "record_proposal",
            "complete",
            "note_probe",
            "halt",
            "escalate",
            "record_refusal",
        ],
        ProgramCounterV1::ProposalRecorded => {
            &["require_standing", "halt", "escalate", "record_refusal"]
        }
        ProgramCounterV1::StandingRequired => &["decide", "halt", "escalate", "record_refusal"],
        ProgramCounterV1::AdmissiblePendingAuthorization => {
            &["authorize", "halt", "escalate", "record_refusal"]
        }
        ProgramCounterV1::AuthorizationConsumed
            if state.proposal == ProposalTimeStateV1::Expired =>
        {
            &["recover", "record_refusal"]
        }
        ProgramCounterV1::AuthorizationConsumed => &["dispatch", "recover", "record_refusal"],
        ProgramCounterV1::Dispatched => &["reconcile_docket", "recover", "record_refusal"],
        ProgramCounterV1::ReconciliationRequired => &[
            "reconcile_docket",
            "recover",
            "halt",
            "escalate",
            "record_refusal",
        ],
        ProgramCounterV1::SettledObservationRequired => &[
            "open_continuation",
            "note_probe",
            "halt",
            "escalate",
            "record_refusal",
        ],
        ProgramCounterV1::Halted if state.governed == GovernedDecisionStateV1::Closed => {
            &["record_refusal"]
        }
        ProgramCounterV1::Halted if state.governed == GovernedDecisionStateV1::RequestOpen => &[
            "create_decision_request",
            "submit_disposition",
            "record_refusal",
        ],
        ProgramCounterV1::Halted if state.governed == GovernedDecisionStateV1::AwaitingRequest => {
            &["create_decision_request", "record_refusal"]
        }
        ProgramCounterV1::Halted | ProgramCounterV1::Completed => &["record_refusal"],
    };
    names.iter().map(|name| (*name).to_owned()).collect()
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
        };
        let cases = [
            (
                ProgramCounterV1::ObservationRequired,
                ordinary,
                &[
                    "record_proposal",
                    "complete",
                    "note_probe",
                    "halt",
                    "escalate",
                    "record_refusal",
                ][..],
            ),
            (
                ProgramCounterV1::ProposalRecorded,
                ordinary,
                &["require_standing", "halt", "escalate", "record_refusal"],
            ),
            (
                ProgramCounterV1::StandingRequired,
                ordinary,
                &["decide", "halt", "escalate", "record_refusal"],
            ),
            (
                ProgramCounterV1::AdmissiblePendingAuthorization,
                ordinary,
                &["authorize", "halt", "escalate", "record_refusal"],
            ),
            (
                ProgramCounterV1::AuthorizationConsumed,
                ordinary,
                &["dispatch", "recover", "record_refusal"],
            ),
            (
                ProgramCounterV1::Dispatched,
                ordinary,
                &["reconcile_docket", "recover", "record_refusal"],
            ),
            (
                ProgramCounterV1::ReconciliationRequired,
                ordinary,
                &[
                    "reconcile_docket",
                    "recover",
                    "halt",
                    "escalate",
                    "record_refusal",
                ],
            ),
            (
                ProgramCounterV1::SettledObservationRequired,
                ordinary,
                &[
                    "open_continuation",
                    "note_probe",
                    "halt",
                    "escalate",
                    "record_refusal",
                ],
            ),
            (ProgramCounterV1::Halted, ordinary, &["record_refusal"]),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::AwaitingRequest,
                    proposal: ProposalTimeStateV1::Current,
                },
                &["create_decision_request", "record_refusal"],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::RequestOpen,
                    proposal: ProposalTimeStateV1::Current,
                },
                &[
                    "create_decision_request",
                    "submit_disposition",
                    "record_refusal",
                ],
            ),
            (
                ProgramCounterV1::Halted,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::Closed,
                    proposal: ProposalTimeStateV1::Current,
                },
                &["record_refusal"],
            ),
            (ProgramCounterV1::Completed, ordinary, &["record_refusal"]),
        ];
        for (pc, state, expected) in cases {
            assert_eq!(allowed_transitions(pc, state), expected);
        }
        assert_eq!(
            allowed_transitions(
                ProgramCounterV1::AuthorizationConsumed,
                AllowedTransitionStateV1 {
                    governed: GovernedDecisionStateV1::NotGoverned,
                    proposal: ProposalTimeStateV1::Expired,
                },
            ),
            ["recover", "record_refusal"],
        );
    }
}
