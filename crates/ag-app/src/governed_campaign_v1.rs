//! Versioned external-evidence reservation contract for Governed Campaign Loop V1.
//!
//! This module is construction and validation only. A reservation names one
//! future evidence slot; it is not execution, evidence, qualification,
//! applicability, standing, settlement, authorization, or continuation.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

pub const EXTERNAL_EVIDENCE_RESERVATION_SCHEMA_V1: &str = "ag.external-evidence-reservation/v1";
pub const CAMPAIGN_PACKET_SCHEMA_V1: &str = "ag.governed-campaign.packet/v1";
pub const RESERVED_APPLICABILITY_BASIS_TYPE_V1: &str =
    "nightshift.repository-qualification-reservation-applicability/v1";

pub const RESERVATION_NONCLAIMS_V1: [&str; 8] = [
    "execution",
    "success",
    "qualification",
    "applicability",
    "standing",
    "settlement",
    "authorization",
    "continuation",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitObjectV1 {
    pub object_format: String,
    pub digest: String,
}

impl GitObjectV1 {
    fn validate(&self) -> bool {
        matches!(
            (self.object_format.as_str(), self.digest.len()),
            ("sha1", 40) | ("sha256", 64)
        ) && self.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

/// An exact predecessor known before execution. Later stages name the one
/// result admitted under an earlier reservation rather than predicting its
/// future Git object identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PredecessorBindingV1 {
    InitialGit {
        head: GitObjectV1,
        tree: GitObjectV1,
    },
    PriorStageRealization {
        stage_id: String,
        reservation: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedResultConstraintsV1 {
    pub must_descend_from_predecessor: bool,
    pub required_commit_count: u32,
    pub expected_clean_worktree: bool,
    pub allowed_mutation_paths: Vec<String>,
    pub factual_gate_profile_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SuccessorLawV1 {
    Stage {
        stage_id: String,
        work_schema: String,
        work: String,
    },
    HumanRequired,
}

/// Cycle-free, pre-execution description of one future evidence slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceReservationV1 {
    pub schema: String,
    pub reservation_id: String,
    pub campaign_id: String,
    pub stage_id: String,
    pub ordinal: u32,
    pub logical_attempt_id: String,
    pub predecessor: PredecessorBindingV1,
    pub result_constraints: ExpectedResultConstraintsV1,
    pub successor: SuccessorLawV1,
    pub worker_session_manifest_sha256: String,
    pub executor_plan_template_sha256: String,
    pub instruction_sha256: String,
    pub mutation_profile_sha256: String,
    pub resource_profile_sha256: String,
    pub nq_profile_template_sha256: String,
    pub does_not_establish: Vec<String>,
}

impl ExternalEvidenceReservationV1 {
    pub fn computed_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.reservation_id.clear();
        domain_hash("ag.external-evidence-reservation/v1", &preimage)
    }

    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = EXTERNAL_EVIDENCE_RESERVATION_SCHEMA_V1.into();
        self.reservation_id.clear();
        self.reservation_id = self.computed_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXTERNAL_EVIDENCE_RESERVATION_SCHEMA_V1
            || self.reservation_id != self.computed_id()?
            || !is_digest(&self.campaign_id)
            || self.stage_id.trim().is_empty()
            || self.logical_attempt_id.trim().is_empty()
            || self.ordinal == 0
            || !self.result_constraints.must_descend_from_predecessor
            || self.result_constraints.required_commit_count == 0
            || self.result_constraints.allowed_mutation_paths.is_empty()
            || !paths_are_closed(&self.result_constraints.allowed_mutation_paths)
            || self.does_not_establish != RESERVATION_NONCLAIMS_V1.map(str::to_owned).to_vec()
        {
            return Err("external evidence reservation envelope mismatch".into());
        }
        for value in [
            &self.result_constraints.factual_gate_profile_sha256,
            &self.worker_session_manifest_sha256,
            &self.executor_plan_template_sha256,
            &self.instruction_sha256,
            &self.mutation_profile_sha256,
            &self.resource_profile_sha256,
            &self.nq_profile_template_sha256,
        ] {
            if !is_digest(value) {
                return Err("external evidence reservation digest mismatch".into());
            }
        }
        match &self.predecessor {
            PredecessorBindingV1::InitialGit { head, tree } => {
                if !head.validate() || !tree.validate() {
                    return Err("initial predecessor identity mismatch".into());
                }
            }
            PredecessorBindingV1::PriorStageRealization {
                stage_id,
                reservation,
            } => {
                if stage_id.trim().is_empty() || !is_digest(reservation) {
                    return Err("prior-stage predecessor identity mismatch".into());
                }
            }
        }
        match &self.successor {
            SuccessorLawV1::Stage {
                stage_id,
                work_schema,
                work,
            } => {
                if stage_id.trim().is_empty() || work_schema.trim().is_empty() || !is_digest(work) {
                    return Err("successor law mismatch".into());
                }
            }
            SuccessorLawV1::HumanRequired => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageV1 {
    pub stage_id: String,
    pub ordinal: u32,
    pub logical_attempt_id: String,
    pub work_schema: String,
    pub work: String,
    pub instruction_sha256: String,
    pub mutation_profile_sha256: String,
    pub resource_profile_sha256: String,
    pub worker_session_manifest_sha256: String,
    /// Closed JSON template whose `evidence_reservation` member is empty.
    pub executor_plan_template: serde_json::Value,
    pub executor_plan_template_sha256: String,
    /// Closed JSON template whose `evidence_reservation` member is empty.
    pub nq_profile_template: serde_json::Value,
    pub nq_profile_template_sha256: String,
    pub reservation: ExternalEvidenceReservationV1,
}

impl CampaignStageV1 {
    pub fn validate(&self, campaign_id: &str) -> Result<(), String> {
        self.reservation.validate()?;
        if self.stage_id != self.reservation.stage_id
            || self.ordinal != self.reservation.ordinal
            || self.logical_attempt_id != self.reservation.logical_attempt_id
            || campaign_id != self.reservation.campaign_id
            || self.instruction_sha256 != self.reservation.instruction_sha256
            || self.mutation_profile_sha256 != self.reservation.mutation_profile_sha256
            || self.resource_profile_sha256 != self.reservation.resource_profile_sha256
            || self.worker_session_manifest_sha256
                != self.reservation.worker_session_manifest_sha256
            || self.executor_plan_template_sha256 != self.reservation.executor_plan_template_sha256
            || self.nq_profile_template_sha256 != self.reservation.nq_profile_template_sha256
            || self.work_schema.trim().is_empty()
            || !is_digest(&self.work)
        {
            return Err("campaign stage/reservation binding mismatch".into());
        }
        validate_template_slots(
            &self.executor_plan_template,
            &self.executor_plan_template_sha256,
            &["evidence_reservation"],
        )?;
        validate_template_slots(
            &self.nq_profile_template,
            &self.nq_profile_template_sha256,
            &["campaign_packet_sha256", "evidence_reservation"],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPacketV1 {
    pub schema: String,
    pub packet_id: String,
    pub campaign_id: String,
    pub repository_id: String,
    pub workspace: String,
    pub repository_ref: String,
    pub stages: Vec<CampaignStageV1>,
}

impl CampaignPacketV1 {
    pub fn computed_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.packet_id.clear();
        domain_hash("ag.governed-campaign.packet/v1", &preimage)
    }

    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = CAMPAIGN_PACKET_SCHEMA_V1.into();
        self.packet_id.clear();
        self.packet_id = self.computed_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CAMPAIGN_PACKET_SCHEMA_V1
            || self.packet_id != self.computed_id()?
            || !is_digest(&self.campaign_id)
            || !is_digest(&self.repository_id)
            || !Path::new(&self.workspace).is_absolute()
            || self.repository_ref.trim().is_empty()
            || self.stages.len() != 3
        {
            return Err("campaign packet v1 envelope mismatch".into());
        }
        let mut reservations = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        for (index, stage) in self.stages.iter().enumerate() {
            stage.validate(&self.campaign_id)?;
            if stage.ordinal != u32::try_from(index + 1).map_err(|_| "stage ordinal")?
                || !reservations.insert(&stage.reservation.reservation_id)
                || !attempts.insert(&stage.logical_attempt_id)
            {
                return Err("campaign packet v1 cardinality mismatch".into());
            }
            if index == 0 {
                if !matches!(
                    stage.reservation.predecessor,
                    PredecessorBindingV1::InitialGit { .. }
                ) {
                    return Err("stage one requires literal predecessor".into());
                }
            } else {
                match &stage.reservation.predecessor {
                    PredecessorBindingV1::PriorStageRealization {
                        stage_id,
                        reservation,
                    } if stage_id == &self.stages[index - 1].stage_id
                        && reservation == &self.stages[index - 1].reservation.reservation_id => {}
                    _ => return Err("stage predecessor chain mismatch".into()),
                }
            }
            if index + 1 < self.stages.len() {
                match &stage.reservation.successor {
                    SuccessorLawV1::Stage {
                        stage_id,
                        work_schema,
                        work,
                    } if stage_id == &self.stages[index + 1].stage_id
                        && work_schema == &self.stages[index + 1].work_schema
                        && work == &self.stages[index + 1].work => {}
                    _ => return Err("stage successor chain mismatch".into()),
                }
            } else if !matches!(stage.reservation.successor, SuccessorLawV1::HumanRequired) {
                return Err("stage three must terminate HUMAN_REQUIRED".into());
            }
        }
        Ok(())
    }
}

pub fn materialize_template(
    template: &serde_json::Value,
    reservation: &str,
) -> Result<serde_json::Value, String> {
    if !is_digest(reservation) {
        return Err("malformed reservation identity".into());
    }
    let mut value = template.clone();
    let object = value
        .as_object_mut()
        .ok_or_else(|| "reservation template must be an object".to_owned())?;
    let slot = object
        .get_mut("evidence_reservation")
        .ok_or_else(|| "reservation template has no evidence_reservation".to_owned())?;
    if slot.as_str() != Some("") {
        return Err("reservation template is not cycle-free".into());
    }
    *slot = serde_json::Value::String(reservation.to_owned());
    Ok(value)
}

pub fn canonical_sha256(value: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
/// packet has been sealed: its predeclared reservation and its own identity.
/// Materialize the two closed, non-random NQ profile coordinates after the
pub fn materialize_nq_profile_template(
    template: &serde_json::Value,
    reservation: &str,
    campaign_packet_sha256: &str,
) -> Result<serde_json::Value, String> {
    if !is_digest(reservation) || !is_digest(campaign_packet_sha256) {
        return Err("malformed NQ template coordinate".into());
    }
    let mut value = template.clone();
    let object = value
        .as_object_mut()
        .ok_or_else(|| "NQ profile template must be an object".to_owned())?;
    for (name, exact) in [
        ("evidence_reservation", reservation),
        ("campaign_packet_sha256", campaign_packet_sha256),
    ] {
        let slot = object
            .get_mut(name)
            .ok_or_else(|| format!("NQ profile template has no {name}"))?;
        if slot.as_str() != Some("") {
            return Err("NQ profile template is not cycle-free".into());
        }
        *slot = serde_json::Value::String(exact.to_owned());
    }
    Ok(value)
}

fn validate_template_slots(
    template: &serde_json::Value,
    expected_template_hash: &str,
    empty_slots: &[&str],
) -> Result<(), String> {
    if canonical_sha256(template)? != expected_template_hash {
        return Err("reservation template hash mismatch".into());
    }
    let object = template
        .as_object()
        .ok_or_else(|| "reservation template must be an object".to_owned())?;
    for name in empty_slots {
        if object.get(*name).and_then(serde_json::Value::as_str) != Some("") {
            return Err(format!(
                "reservation template slot {name} is not cycle-free"
            ));
        }
    }
    Ok(())
}

fn paths_are_closed(paths: &[String]) -> bool {
    let mut prior = None;
    for path in paths {
        let candidate = Path::new(path);
        if path.is_empty()
            || candidate.is_absolute()
            || candidate
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || prior.is_some_and(|value: &String| value >= path)
        {
            return false;
        }
        prior = Some(path);
    }
    true
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn domain_hash<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
