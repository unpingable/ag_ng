#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    clippy::unnecessary_wraps,
    reason = "the frozen V0 wire and transition API keeps every refusal predicate explicit"
)]
//! Bounded, non-planning Governed Campaign Loop V0 coordination contract.
//!
//! This module owns no standing, authorization, qualification judgment,
//! successor selection, or effect authority. It validates one immutable packet
//! containing exactly three predeclared stages and advances only when existing
//! offices return their exact retained facts. In particular, the controller
//! never accepts an NQ status or a caller-authored qualification verdict. Its
//! only qualification transition input is an AG disposition bound to a fresh
//! Nightshift repository-qualification observation.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Frozen V0 packet schema.
pub const CAMPAIGN_PACKET_SCHEMA_V0: &str = "ag.governed-campaign.packet/v0";
/// Frozen V0 coordination snapshot schema.
pub const CAMPAIGN_SNAPSHOT_SCHEMA_V0: &str = "ag.governed-campaign.snapshot/v0";
/// Frozen NQ qualification profile required for every stage.
pub const NQ_QUALIFICATION_PROFILE_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification-profile/v1";
/// The sole qualification basis type accepted from Nightshift.
pub const REPOSITORY_QUALIFICATION_BASIS_TYPE_V1: &str =
    "nightshift.repository-qualification-applicability/v1";
/// The sole qualification resolver accepted by V0.
pub const REPOSITORY_QUALIFICATION_RESOLVER_V1: &str =
    "nightshift.repository-qualification-resolver/v1";

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn jcs_sha256(value: &impl Serialize) -> Result<String, PacketRefusalV0> {
    serde_jcs::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| PacketRefusalV0::NonCanonical)
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_git_object(value: &GitObjectV0) -> bool {
    let len = match value.object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => return false,
    };
    value.digest.len() == len
        && value
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_string<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.as_object()?.get(field)?.as_str()
}

/// One exact Git object identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitObjectV0 {
    /// Git object format (`sha1` or `sha256`).
    pub object_format: String,
    /// Lower-case object digest.
    pub digest: String,
}

/// One fixed worker/model binding shared by every stage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedWorkerV0 {
    /// Deployment identity of the worker class.
    pub worker_id: String,
    /// Exact executable content hash.
    pub executable_sha256: String,
    /// Fixed model name; `NOT_APPLICABLE` is lawful for a local fixture.
    pub model: String,
    /// Fixed effort setting; `NOT_OBSERVABLE` is lawful where unavailable.
    pub effort: String,
    /// Hash of the complete launch configuration.
    pub launch_configuration_sha256: String,
}

/// Fixed Crow admission margins and campaign containment ceilings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyV0 {
    /// Minimum available memory required before every stage.
    pub minimum_available_memory_bytes: u64,
    /// Minimum available disk required before every stage.
    pub minimum_available_disk_bytes: u64,
    /// Maximum admitted concurrent V0 campaigns. V0 requires one.
    pub maximum_concurrent_campaigns: u32,
    /// Campaign cgroup/process memory ceiling.
    pub campaign_memory_ceiling_bytes: u64,
    /// Campaign process ceiling.
    pub campaign_process_ceiling: u32,
    /// Campaign CPU quota percentage.
    pub campaign_cpu_quota_percent: u32,
}

/// One exact, packet-declared gate invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredGateV0 {
    /// Contiguous ordinal beginning at zero.
    pub ordinal: u32,
    /// Stable gate identity.
    pub gate_id: String,
    /// Exact executable path.
    pub executable: String,
    /// Exact argv, including argv zero.
    pub argv: Vec<String>,
    /// Exact repository-relative working directory.
    pub repository_relative_cwd: String,
    /// Sorted allowed environment names and values.
    pub allowed_environment: Vec<(String, String)>,
    /// Required exit code.
    pub required_exit_code: i32,
}

/// One immutable stage declaration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageV0 {
    /// Unique stage identity.
    pub stage_id: String,
    /// Unique predeclared attempt identity.
    pub attempt_id: String,
    /// Exact predecessor HEAD.
    pub predecessor_head: GitObjectV0,
    /// Exact predecessor tree.
    pub predecessor_tree: GitObjectV0,
    /// Exact predecessor qualification artifacts and hashes.
    pub predecessor_qualification_artifacts: Vec<(String, String)>,
    /// Exact expected result HEAD.
    pub result_head: GitObjectV0,
    /// Exact expected result tree.
    pub result_tree: GitObjectV0,
    /// Exact typed work schema.
    pub work_schema: String,
    /// Exact work identity.
    pub work: String,
    /// Hash of the bounded immutable task instruction.
    pub instruction_sha256: String,
    /// Closed repository-relative mutation scope.
    pub allowed_mutation_paths: Vec<String>,
    /// Exact declared qualification commands.
    pub qualification_gates: Vec<DeclaredGateV0>,
    /// Exact frozen NQ profile document.
    pub nq_qualification_profile: serde_json::Value,
    /// Hash of the exact NQ profile document.
    pub nq_qualification_profile_sha256: String,
    /// Expected successor stage, or `None` for stage three.
    pub expected_successor_stage_id: Option<String>,
}

/// One immutable, exactly three-stage V0 packet.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPacketV0 {
    /// Exact packet schema.
    pub schema: String,
    /// Domain-separated packet identity.
    pub packet_id: String,
    /// AG campaign identity.
    pub campaign_id: String,
    /// Exact repository identity.
    pub repository_id: String,
    /// One absolute persistently writable workspace.
    pub workspace: String,
    /// Exact branch/ref name.
    pub repository_ref: String,
    /// One fixed worker/model binding.
    pub worker: FixedWorkerV0,
    /// Fixed resource admission/containment policy.
    pub resources: ResourcePolicyV0,
    /// Exactly three predeclared sequential stages.
    pub stages: Vec<CampaignStageV0>,
}

impl CampaignPacketV0 {
    /// Compute the packet identity over a cycle-free transcript. The packet
    /// identity and each nested NQ `campaign_packet_sha256` field are blanked;
    /// every other byte, including all three complete profiles, is committed.
    pub fn computed_packet_id(&self) -> Result<String, PacketRefusalV0> {
        let mut preimage = self.clone();
        preimage.packet_id.clear();
        for stage in &mut preimage.stages {
            stage.nq_qualification_profile_sha256.clear();
            let profile = stage
                .nq_qualification_profile
                .as_object_mut()
                .ok_or(PacketRefusalV0::NqProfileMismatch)?;
            let field = profile
                .get_mut("campaign_packet_sha256")
                .ok_or(PacketRefusalV0::NqProfileMismatch)?;
            *field = serde_json::Value::String(String::new());
        }
        let bytes = serde_jcs::to_vec(&preimage).map_err(|_| PacketRefusalV0::NonCanonical)?;
        let mut transcript = b"ag.governed-campaign.packet/v0\0".to_vec();
        transcript.extend_from_slice(&bytes);
        Ok(sha256(&transcript))
    }

    /// Validate the complete closed V0 packet and every frozen NQ profile.
    pub fn validate(&self) -> Result<(), PacketRefusalV0> {
        if self.schema != CAMPAIGN_PACKET_SCHEMA_V0
            || self.stages.len() != 3
            || !is_sha256(&self.packet_id)
            || self.packet_id != self.computed_packet_id()?
            || !is_sha256(&self.campaign_id)
            || !is_sha256(&self.repository_id)
            || !Path::new(&self.workspace).is_absolute()
            || self.repository_ref.trim().is_empty()
        {
            return Err(PacketRefusalV0::Envelope);
        }
        if self.worker.worker_id.trim().is_empty()
            || !is_sha256(&self.worker.executable_sha256)
            || self.worker.model.trim().is_empty()
            || self.worker.effort.trim().is_empty()
            || !is_sha256(&self.worker.launch_configuration_sha256)
        {
            return Err(PacketRefusalV0::Worker);
        }
        if self.resources.maximum_concurrent_campaigns != 1
            || self.resources.minimum_available_memory_bytes == 0
            || self.resources.minimum_available_disk_bytes == 0
            || self.resources.campaign_memory_ceiling_bytes == 0
            || self.resources.campaign_process_ceiling == 0
            || !(1..=100).contains(&self.resources.campaign_cpu_quota_percent)
        {
            return Err(PacketRefusalV0::Resources);
        }
        let mut stage_ids = BTreeSet::new();
        let mut attempt_ids = BTreeSet::new();
        for (index, stage) in self.stages.iter().enumerate() {
            if stage.stage_id.trim().is_empty()
                || stage.attempt_id.trim().is_empty()
                || !stage_ids.insert(&stage.stage_id)
                || !attempt_ids.insert(&stage.attempt_id)
                || !is_git_object(&stage.predecessor_head)
                || !is_git_object(&stage.predecessor_tree)
                || !is_git_object(&stage.result_head)
                || !is_git_object(&stage.result_tree)
                || !is_sha256(&stage.work)
                || !is_sha256(&stage.instruction_sha256)
                || stage.work_schema.trim().is_empty()
                || stage.allowed_mutation_paths.is_empty()
                || stage.qualification_gates.is_empty()
            {
                return Err(PacketRefusalV0::Stage(index));
            }
            if index > 0
                && (stage.predecessor_head != self.stages[index - 1].result_head
                    || stage.predecessor_tree != self.stages[index - 1].result_tree)
            {
                return Err(PacketRefusalV0::PredecessorChain(index));
            }
            let expected_successor = self.stages.get(index + 1).map(|next| next.stage_id.clone());
            if stage.expected_successor_stage_id != expected_successor {
                return Err(PacketRefusalV0::SuccessorChain(index));
            }
            self.validate_nq_profile(index, stage)?;
        }
        Ok(())
    }

    fn validate_nq_profile(
        &self,
        index: usize,
        stage: &CampaignStageV0,
    ) -> Result<(), PacketRefusalV0> {
        let profile = stage
            .nq_qualification_profile
            .as_object()
            .ok_or(PacketRefusalV0::NqProfileMismatch)?;
        if exact_string(&stage.nq_qualification_profile, "schema")
            != Some(NQ_QUALIFICATION_PROFILE_SCHEMA_V1)
            || exact_string(&stage.nq_qualification_profile, "campaign_packet_sha256")
                != Some(self.packet_id.as_str())
            || exact_string(&stage.nq_qualification_profile, "stage_id")
                != Some(stage.stage_id.as_str())
            || exact_string(&stage.nq_qualification_profile, "repository_id")
                != Some(self.repository_id.as_str())
            || exact_string(&stage.nq_qualification_profile, "repository_ref")
                != Some(self.repository_ref.as_str())
            || jcs_sha256(&stage.nq_qualification_profile)? != stage.nq_qualification_profile_sha256
        {
            return Err(PacketRefusalV0::NqProfileMismatch);
        }
        let head_matches = |field: &str, expected: &GitObjectV0| {
            profile.get(field).is_some_and(|value| {
                exact_string(value, "object_format") == Some(expected.object_format.as_str())
                    && exact_string(value, "digest") == Some(expected.digest.as_str())
            })
        };
        if !head_matches("predecessor_head", &stage.predecessor_head)
            || !head_matches("predecessor_tree", &stage.predecessor_tree)
            || !head_matches("result_head", &stage.result_head)
            || !head_matches("result_tree", &stage.result_tree)
        {
            return Err(PacketRefusalV0::NqProfileMismatch);
        }
        let gates = profile
            .get("ordered_gates")
            .and_then(serde_json::Value::as_array)
            .ok_or(PacketRefusalV0::NqProfileMismatch)?;
        if gates.len() != stage.qualification_gates.len() {
            return Err(PacketRefusalV0::NqProfileMismatch);
        }
        for (ordinal, (required, declared)) in
            gates.iter().zip(&stage.qualification_gates).enumerate()
        {
            if declared.ordinal
                != u32::try_from(ordinal).map_err(|_| PacketRefusalV0::Stage(index))?
                || required.get("ordinal").and_then(serde_json::Value::as_u64)
                    != Some(u64::from(declared.ordinal))
                || exact_string(required, "gate_id") != Some(declared.gate_id.as_str())
                || required
                    .get("required_exit_code")
                    .and_then(serde_json::Value::as_i64)
                    != Some(i64::from(declared.required_exit_code))
            {
                return Err(PacketRefusalV0::NqProfileMismatch);
            }
        }
        Ok(())
    }
}

/// Closed packet refusal vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PacketRefusalV0 {
    /// Packet envelope or identity is malformed.
    #[error("invalid campaign packet envelope")]
    Envelope,
    /// Canonical encoding failed.
    #[error("campaign packet is not canonicalizable")]
    NonCanonical,
    /// Fixed worker binding is malformed.
    #[error("invalid fixed worker binding")]
    Worker,
    /// Resource policy violates V0 bounds.
    #[error("invalid V0 resource policy")]
    Resources,
    /// Stage declaration is malformed.
    #[error("invalid stage declaration at index {0}")]
    Stage(usize),
    /// Predecessor chain is not exact.
    #[error("stage {0} does not name the prior frozen result")]
    PredecessorChain(usize),
    /// Successor chain is not the exact enumerated next stage.
    #[error("stage {0} has an invalid successor")]
    SuccessorChain(usize),
    /// Frozen NQ profile does not exactly bind the stage.
    #[error("NQ qualification profile does not exactly bind its stage")]
    NqProfileMismatch,
}

/// Machine-checkable admission result produced by the existing factual
/// workspace/resource/worker admission owners.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageAdmissionV0 {
    /// Exact packet identity.
    pub packet_id: String,
    /// Exact stage identity.
    pub stage_id: String,
    /// Exact predecessor HEAD observed.
    pub predecessor_head: GitObjectV0,
    /// Exact predecessor tree observed.
    pub predecessor_tree: GitObjectV0,
    /// Workspace existence and repository identity passed.
    pub workspace_custody_passed: bool,
    /// Non-destructive write/read/reopen persistence probe passed.
    pub persistence_probe_passed: bool,
    /// Worktree cleanliness matched the packet.
    pub worktree_state_passed: bool,
    /// All predecessor artifacts matched.
    pub predecessor_artifacts_passed: bool,
    /// Fixed worker executable and launch configuration matched.
    pub worker_available: bool,
    /// Memory/disk/load/concurrent campaign admission passed.
    pub resources_admitted: bool,
}

impl StageAdmissionV0 {
    fn admits(&self, packet: &CampaignPacketV0, stage: &CampaignStageV0) -> bool {
        self.packet_id == packet.packet_id
            && self.stage_id == stage.stage_id
            && self.predecessor_head == stage.predecessor_head
            && self.predecessor_tree == stage.predecessor_tree
            && self.workspace_custody_passed
            && self.persistence_probe_passed
            && self.worktree_state_passed
            && self.predecessor_artifacts_passed
            && self.worker_available
            && self.resources_admitted
    }
}

/// Exact settled Docket attempt fact. The controller cannot synthesize it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageSettlementV0 {
    /// Exact stage identity.
    pub stage_id: String,
    /// Exact packet-declared attempt.
    pub attempt_id: String,
    /// Docket settlement identity.
    pub settlement_id: String,
    /// Mechanics receipt identity.
    pub mechanics_receipt: String,
    /// Exact resulting HEAD.
    pub result_head: GitObjectV0,
    /// Exact resulting tree.
    pub result_tree: GitObjectV0,
}

/// AG's only positive V0 continuation fact, after NQ evaluation and fresh
/// Nightshift applicability. No NQ status field crosses this boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgQualifiedContinuationV0 {
    /// Exact completed stage.
    pub source_stage_id: String,
    /// Exact predeclared successor.
    pub successor_stage_id: String,
    /// Exact frozen NQ profile identity.
    pub nq_profile_sha256: String,
    /// Nightshift typed basis class.
    pub basis_type: String,
    /// Complete opaque Nightshift applicability identity.
    pub basis_identity: String,
    /// Exact Nightshift resolver identity.
    pub resolver_id: String,
    /// Must be `current`; stale/superseded are never positive inputs.
    pub observation_status: String,
    /// AG authorization/spend identity for the exact successor.
    pub ag_authorization: String,
    /// Exact successor work identity authorized by AG.
    pub authorized_work: String,
}

impl AgQualifiedContinuationV0 {
    fn authorizes(&self, source: &CampaignStageV0, successor: &CampaignStageV0) -> bool {
        self.source_stage_id == source.stage_id
            && self.successor_stage_id == successor.stage_id
            && self.nq_profile_sha256 == source.nq_qualification_profile_sha256
            && self.basis_type == REPOSITORY_QUALIFICATION_BASIS_TYPE_V1
            && is_sha256(&self.basis_identity)
            && self.resolver_id == REPOSITORY_QUALIFICATION_RESOLVER_V1
            && self.observation_status == "current"
            && is_sha256(&self.ag_authorization)
            && self.authorized_work == successor.work
    }
}

/// AG's mandatory terminal result after exact Stage 3 qualification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgTerminalHumanStopV0 {
    /// Exact Stage 3 identity.
    pub stage_id: String,
    /// Exact Stage 3 NQ profile identity.
    pub nq_profile_sha256: String,
    /// Exact fresh qualification applicability identity.
    pub basis_identity: String,
    /// AG program counter result.
    pub program_counter: String,
}

/// One exact freeze fact for a qualified stage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageFreezeV0 {
    /// Exact stage identity.
    pub stage_id: String,
    /// Exact frozen HEAD.
    pub head: GitObjectV0,
    /// Exact frozen tree.
    pub tree: GitObjectV0,
    /// Exact retained qualification evidence-set hash.
    pub evidence_set_sha256: String,
    /// Worktree was clean after freeze.
    pub clean_worktree: bool,
}

/// Durable V0 controller phases. They are coordination only, never authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignPhaseV0 {
    /// Packet validated; no stage admission yet.
    Prepared,
    /// Exact current stage admitted.
    Admitted,
    /// Exact Docket attempt is in custody or settlement reconciliation.
    Executing,
    /// Result settled; factual gates/NQ/Nightshift/AG are pending.
    Qualifying,
    /// Qualified stage and evidence are frozen.
    Frozen,
    /// Fresh AG continuation was observed; next predeclared stage may begin.
    Observed,
    /// Mandatory terminal human boundary after Stage 3.
    HumanRequired,
    /// Typed refusal; no automatic repair exists in V0.
    Stopped,
}

/// Durable, authority-free V0 coordination snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSnapshotV0 {
    /// Exact snapshot schema.
    pub schema: String,
    /// Exact immutable packet identity.
    pub packet_id: String,
    /// Current stage index, zero through two.
    pub stage_index: usize,
    /// Current coordination phase.
    pub phase: CampaignPhaseV0,
    /// Last exact Docket settlement, if any.
    pub settlement: Option<StageSettlementV0>,
    /// Last exact stage freeze, if any.
    pub freeze: Option<StageFreezeV0>,
    /// Non-authorizing typed stop reason.
    pub stop_reason: Option<String>,
}

impl CampaignSnapshotV0 {
    /// Create the authority-empty initial snapshot after complete packet validation.
    pub fn prepare(packet: &CampaignPacketV0) -> Result<Self, PacketRefusalV0> {
        packet.validate()?;
        Ok(Self {
            schema: CAMPAIGN_SNAPSHOT_SCHEMA_V0.into(),
            packet_id: packet.packet_id.clone(),
            stage_index: 0,
            phase: CampaignPhaseV0::Prepared,
            settlement: None,
            freeze: None,
            stop_reason: None,
        })
    }

    fn stage<'a>(&self, packet: &'a CampaignPacketV0) -> Result<&'a CampaignStageV0, String> {
        if self.schema != CAMPAIGN_SNAPSHOT_SCHEMA_V0
            || self.packet_id != packet.packet_id
            || packet.validate().is_err()
        {
            return Err("snapshot/packet identity mismatch".into());
        }
        packet
            .stages
            .get(self.stage_index)
            .ok_or_else(|| "snapshot names an unknown stage".into())
    }

    /// Admit the exact current stage from independently produced facts.
    pub fn admit(
        mut self,
        packet: &CampaignPacketV0,
        admission: &StageAdmissionV0,
    ) -> Result<Self, String> {
        let stage = self.stage(packet)?;
        if self.phase != CampaignPhaseV0::Prepared || !admission.admits(packet, stage) {
            return self.stop("stage admission refused");
        }
        self.phase = CampaignPhaseV0::Admitted;
        Ok(self)
    }

    /// Record that Docket owns the exact attempt. Restart from this phase may
    /// reconcile only; it may never dispatch another attempt.
    pub fn dispatched(mut self, packet: &CampaignPacketV0, attempt: &str) -> Result<Self, String> {
        let stage = self.stage(packet)?;
        if self.phase != CampaignPhaseV0::Admitted || attempt != stage.attempt_id {
            return self.stop("Docket attempt substitution");
        }
        self.phase = CampaignPhaseV0::Executing;
        Ok(self)
    }

    /// Consume one exact Docket settlement and enter factual qualification.
    pub fn settled(
        mut self,
        packet: &CampaignPacketV0,
        settlement: StageSettlementV0,
    ) -> Result<Self, String> {
        let stage = self.stage(packet)?;
        if self.phase != CampaignPhaseV0::Executing
            || settlement.stage_id != stage.stage_id
            || settlement.attempt_id != stage.attempt_id
            || !is_sha256(&settlement.settlement_id)
            || !is_sha256(&settlement.mechanics_receipt)
            || settlement.result_head != stage.result_head
            || settlement.result_tree != stage.result_tree
        {
            return self.stop("settlement/result binding refused");
        }
        self.settlement = Some(settlement);
        self.phase = CampaignPhaseV0::Qualifying;
        Ok(self)
    }

    /// Freeze a stage only after AG has consumed the sole Q1-Q4 bridge.
    pub fn qualified_and_frozen(
        mut self,
        packet: &CampaignPacketV0,
        disposition: QualificationDispositionV0,
        freeze: StageFreezeV0,
    ) -> Result<Self, String> {
        let stage = self.stage(packet)?;
        if self.phase != CampaignPhaseV0::Qualifying
            || freeze.stage_id != stage.stage_id
            || freeze.head != stage.result_head
            || freeze.tree != stage.result_tree
            || !freeze.clean_worktree
            || !is_sha256(&freeze.evidence_set_sha256)
        {
            return self.stop("freeze identity refused");
        }
        match disposition {
            QualificationDispositionV0::SuccessorAuthorized(authorization) => {
                let Some(successor) = packet.stages.get(self.stage_index + 1) else {
                    return self.stop("Stage 3 cannot authorize a successor");
                };
                if !authorization.authorizes(stage, successor) {
                    return self.stop("AG qualification continuation refused");
                }
                self.freeze = Some(freeze);
                self.phase = CampaignPhaseV0::Frozen;
            }
            QualificationDispositionV0::TerminalHumanRequired(stop) => {
                if self.stage_index != 2
                    || stop.stage_id != stage.stage_id
                    || stop.nq_profile_sha256 != stage.nq_qualification_profile_sha256
                    || !is_sha256(&stop.basis_identity)
                    || stop.program_counter != "HUMAN_REQUIRED"
                {
                    return self.stop("terminal AG disposition refused");
                }
                self.freeze = Some(freeze);
                self.phase = CampaignPhaseV0::HumanRequired;
            }
        }
        Ok(self)
    }

    /// Advance from the exact frozen stage only to its enumerated successor.
    pub fn observe_successor(mut self, packet: &CampaignPacketV0) -> Result<Self, String> {
        let stage = self.stage(packet)?;
        if self.phase != CampaignPhaseV0::Frozen || stage.expected_successor_stage_id.is_none() {
            return self.stop("no automatic successor is available");
        }
        self.phase = CampaignPhaseV0::Observed;
        self.stage_index += 1;
        self.phase = CampaignPhaseV0::Prepared;
        self.settlement = None;
        self.freeze = None;
        Ok(self)
    }

    /// Restart law: an executing stage can only reconcile the same attempt;
    /// no controller-memory loss can create another dispatch.
    pub fn restart_action(&self, packet: &CampaignPacketV0) -> Result<RestartActionV0, String> {
        let stage = self.stage(packet)?;
        Ok(match self.phase {
            CampaignPhaseV0::Prepared | CampaignPhaseV0::Observed => RestartActionV0::Readmit,
            CampaignPhaseV0::Admitted => RestartActionV0::DispatchExact {
                attempt_id: stage.attempt_id.clone(),
            },
            CampaignPhaseV0::Executing => RestartActionV0::ReconcileExact {
                attempt_id: stage.attempt_id.clone(),
            },
            CampaignPhaseV0::Qualifying => RestartActionV0::ReplayQualificationEvidence,
            CampaignPhaseV0::Frozen => RestartActionV0::ObservePredeclaredSuccessor,
            CampaignPhaseV0::HumanRequired | CampaignPhaseV0::Stopped => RestartActionV0::Stop,
        })
    }

    fn stop(mut self, reason: &str) -> Result<Self, String> {
        self.phase = CampaignPhaseV0::Stopped;
        self.stop_reason = Some(reason.into());
        Ok(self)
    }
}

/// Only AG-originated positive dispositions cross the qualification boundary.
/// There is deliberately no `Qualified` constructor and no NQ status field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", content = "record", rename_all = "snake_case")]
pub enum QualificationDispositionV0 {
    /// AG authorized the exact enumerated successor after a current Q1-Q4 observation.
    SuccessorAuthorized(AgQualifiedContinuationV0),
    /// AG reached the mandatory human boundary after exact Stage 3 qualification.
    TerminalHumanRequired(AgTerminalHumanStopV0),
}

/// Closed restart action vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RestartActionV0 {
    /// Re-run admission against current facts.
    Readmit,
    /// Dispatch the one exact not-yet-dispatched attempt.
    DispatchExact {
        /// Exact packet attempt identity.
        attempt_id: String,
    },
    /// Reconcile only; never dispatch a replacement attempt.
    ReconcileExact {
        /// Exact already-custodied attempt identity.
        attempt_id: String,
    },
    /// Replay retained raw evidence/NQ receipt and re-establish applicability.
    ReplayQualificationEvidence,
    /// Observe only the enumerated successor.
    ObservePredeclaredSuccessor,
    /// Terminal stop.
    Stop,
}

/// Existing-office operations required by the unattended V0 driver.
///
/// Implementations transport exact retained facts. They do not delegate
/// qualification judgment to the controller: the only qualification method
/// returns an AG disposition after NQ evaluation and Nightshift applicability.
pub trait CampaignOfficePortV0 {
    /// Re-establish all workspace, predecessor, worker, and resource predicates.
    fn admit_stage(
        &mut self,
        packet: &CampaignPacketV0,
        stage: &CampaignStageV0,
    ) -> Result<StageAdmissionV0, String>;

    /// Submit exactly the packet attempt to Docket custody. Implementations
    /// must reconcile a lost response and may not create another attempt.
    fn dispatch_exact_attempt(
        &mut self,
        packet: &CampaignPacketV0,
        stage: &CampaignStageV0,
    ) -> Result<(), String>;

    /// Read/reconcile the exact Docket attempt to one settled result.
    fn reconcile_exact_attempt(
        &mut self,
        packet: &CampaignPacketV0,
        stage: &CampaignStageV0,
    ) -> Result<StageSettlementV0, String>;

    /// Request factual gates, NQ evaluation, Nightshift applicability, and
    /// AG's exact successor or terminal decision. No caller verdict exists.
    fn qualify_and_ask_ag(
        &mut self,
        packet: &CampaignPacketV0,
        stage: &CampaignStageV0,
        settlement: &StageSettlementV0,
    ) -> Result<(QualificationDispositionV0, StageFreezeV0), String>;

    /// Persist authority-free controller coordination after every transition.
    /// AG and Docket remain the truth stores for authority and attempts.
    fn persist_snapshot(&mut self, snapshot: &CampaignSnapshotV0) -> Result<(), String>;
}

/// Drive the exact three-stage V0 packet without interstage human input.
///
/// The function stops only at `HUMAN_REQUIRED`, a typed controller refusal,
/// or an external-office error. It never selects a stage or retries an effect.
///
/// # Errors
///
/// Returns an error when an existing office cannot establish an exact fact or
/// when the authority-free coordination snapshot cannot be durably retained.
pub fn run_unattended_v0<P: CampaignOfficePortV0>(
    packet: &CampaignPacketV0,
    mut snapshot: CampaignSnapshotV0,
    offices: &mut P,
) -> Result<CampaignSnapshotV0, String> {
    packet.validate().map_err(|error| error.to_string())?;
    loop {
        let stage = packet
            .stages
            .get(snapshot.stage_index)
            .ok_or_else(|| "controller snapshot names an unknown V0 stage".to_owned())?;
        snapshot = match snapshot.phase {
            CampaignPhaseV0::Prepared => {
                let admission = offices.admit_stage(packet, stage)?;
                snapshot.admit(packet, &admission)?
            }
            CampaignPhaseV0::Admitted => {
                offices.dispatch_exact_attempt(packet, stage)?;
                snapshot.dispatched(packet, &stage.attempt_id)?
            }
            CampaignPhaseV0::Executing => {
                let settlement = offices.reconcile_exact_attempt(packet, stage)?;
                snapshot.settled(packet, settlement)?
            }
            CampaignPhaseV0::Qualifying => {
                let settlement = snapshot
                    .settlement
                    .as_ref()
                    .ok_or_else(|| "qualifying snapshot has no Docket settlement".to_owned())?
                    .clone();
                let (disposition, freeze) =
                    offices.qualify_and_ask_ag(packet, stage, &settlement)?;
                snapshot.qualified_and_frozen(packet, disposition, freeze)?
            }
            CampaignPhaseV0::Frozen => snapshot.observe_successor(packet)?,
            CampaignPhaseV0::Observed => {
                return Err("OBSERVED is not a durable dispatch boundary".into());
            }
            CampaignPhaseV0::HumanRequired | CampaignPhaseV0::Stopped => return Ok(snapshot),
        };
        offices.persist_snapshot(&snapshot)?;
    }
}
