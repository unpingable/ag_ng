//! Versioned production antecedent-issuance lifecycle for Governed Campaign Loop V1.
//!
//! This application contract surrounds, but does not reinterpret, the
//! canonical AG loop. Executable authority remains exactly the existing
//! authorization spend and issuance. The journal retains facts and the final
//! non-authorizing human stop.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use ag_campaign::governed::{
    AgIssuanceV1, DocketCustodyV1, DocketSettlementV1, OccurrenceSnapshotV1, ProgramCounterV1,
    TypedObservationStatusV1, VersionedObservationResolutionV1,
};
use ag_primitives::{Digest, JcsDocument};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::governed_campaign_v1::{
    CampaignPacketV1, RESERVED_APPLICABILITY_BASIS_TYPE_V1, SuccessorLawV1, executor_plan_identity,
};

pub const PRODUCTION_LIFECYCLE_SCHEMA_V1: &str = "ag.governed-campaign.production-lifecycle/v1";
pub const VERIFIED_CAMPAIGN_START_BASIS_SCHEMA_V1: &str =
    "ag.governed-campaign.verified-start-basis/v1";
pub const VERIFIED_CAMPAIGN_START_BASIS_TYPE_V1: &str = "ag.governed-campaign.verified-start/v1";
pub const HUMAN_REQUIRED_RECEIPT_SCHEMA_V1: &str = "ag.governed-campaign.human-required-receipt/v1";
pub const LIFECYCLE_EVENT_SCHEMA_V1: &str = "ag.governed-campaign.lifecycle-event/v1";

const ROOT_NONCLAIMS: [&str; 7] = [
    "execution",
    "qualification",
    "standing",
    "authorization",
    "issuance",
    "docket_custody",
    "continuation",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCampaignStartBasisV1 {
    pub schema: String,
    pub basis_id: String,
    pub campaign_id: String,
    pub campaign_packet_id: String,
    pub stage_1_work: String,
    pub subject: String,
    pub scope: String,
    pub initial_occurrence: String,
    pub mandate: String,
    pub observation: String,
    pub observation_resolver_id: String,
    pub standing_resolver_id: String,
    pub human_decision: String,
    pub human_principal: String,
    pub human_verification: String,
    pub verification_profile: String,
    pub decided_at_unix_ms: u64,
    pub does_not_establish: Vec<String>,
}

impl VerifiedCampaignStartBasisV1 {
    pub fn seal(mut self) -> Result<Self, LifecycleErrorV1> {
        self.schema = VERIFIED_CAMPAIGN_START_BASIS_SCHEMA_V1.into();
        self.basis_id.clear();
        self.basis_id = domain_hash(VERIFIED_CAMPAIGN_START_BASIS_SCHEMA_V1, &self)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), LifecycleErrorV1> {
        let mut preimage = self.clone();
        preimage.basis_id.clear();
        if self.schema != VERIFIED_CAMPAIGN_START_BASIS_SCHEMA_V1
            || self.basis_id != domain_hash(VERIFIED_CAMPAIGN_START_BASIS_SCHEMA_V1, &preimage)?
            || self.does_not_establish != ROOT_NONCLAIMS.map(str::to_owned)
            || self.decided_at_unix_ms == 0
            || self.initial_occurrence.parse::<uuid::Uuid>().is_err()
            || self.observation_resolver_id.trim().is_empty()
            || self.standing_resolver_id.trim().is_empty()
            || self.verification_profile.trim().is_empty()
        {
            return Err(LifecycleErrorV1::Contract(
                "verified campaign-start envelope",
            ));
        }
        for value in [
            &self.campaign_id,
            &self.campaign_packet_id,
            &self.stage_1_work,
            &self.subject,
            &self.scope,
            &self.mandate,
            &self.observation,
            &self.human_decision,
            &self.human_principal,
            &self.human_verification,
        ] {
            require_digest(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AntecedentObservationV1 {
    VerifiedCampaignStart { basis_id: String },
    CurrentReservationRealization { reservation: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionStageLawV1 {
    pub stage_id: String,
    pub ordinal: u32,
    pub occurrence: String,
    pub reservation: String,
    pub logical_work_schema: String,
    pub logical_work: String,
    pub executor_work_schema: String,
    pub executor_plan_template_sha256: String,
    pub subject: String,
    pub scope: String,
    pub mandate: String,
    pub observation: String,
    pub observation_resolver_id: String,
    pub standing_resolver_id: String,
    pub antecedent: AntecedentObservationV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequiredLawV1 {
    pub terminal_packet_id: String,
    pub stage_3_occurrence: String,
    pub reservation: String,
    pub observation: String,
    pub observation_resolver_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCampaignLifecycleV1 {
    pub schema: String,
    pub lifecycle_id: String,
    pub campaign_id: String,
    pub campaign_packet_id: String,
    pub program: String,
    pub verified_start: VerifiedCampaignStartBasisV1,
    pub stages: Vec<ProductionStageLawV1>,
    pub terminal: HumanRequiredLawV1,
}

impl ProductionCampaignLifecycleV1 {
    pub fn seal(mut self, packet: &CampaignPacketV1) -> Result<Self, LifecycleErrorV1> {
        self.schema = PRODUCTION_LIFECYCLE_SCHEMA_V1.into();
        self.lifecycle_id.clear();
        self.lifecycle_id = domain_hash(PRODUCTION_LIFECYCLE_SCHEMA_V1, &self)?;
        self.validate(packet)?;
        Ok(self)
    }

    pub fn validate(&self, packet: &CampaignPacketV1) -> Result<(), LifecycleErrorV1> {
        packet.validate().map_err(LifecycleErrorV1::Packet)?;
        self.verified_start.validate()?;
        let mut preimage = self.clone();
        preimage.lifecycle_id.clear();
        if self.schema != PRODUCTION_LIFECYCLE_SCHEMA_V1
            || self.lifecycle_id != domain_hash(PRODUCTION_LIFECYCLE_SCHEMA_V1, &preimage)?
            || self.campaign_id != packet.campaign_id
            || self.campaign_packet_id != packet.packet_id
            || self.verified_start.campaign_id != self.campaign_id
            || self.verified_start.campaign_packet_id != self.campaign_packet_id
            || self.stages.len() != 3
        {
            return Err(LifecycleErrorV1::Contract("production lifecycle envelope"));
        }
        require_digest(&self.program)?;
        for (index, (stage, frozen)) in self.stages.iter().zip(&packet.stages).enumerate() {
            let ordinal = u32::try_from(index + 1)
                .map_err(|_| LifecycleErrorV1::Contract("stage ordinal"))?;
            if stage.ordinal != ordinal
                || stage.stage_id != frozen.stage_id
                || stage.reservation != frozen.reservation.reservation_id
                || stage.logical_work_schema != frozen.work_schema
                || stage.logical_work != frozen.work
                || stage.executor_plan_template_sha256 != frozen.executor_plan_template_sha256
                || stage.executor_work_schema.trim().is_empty()
                || stage.occurrence.parse::<uuid::Uuid>().is_err()
                || stage.observation_resolver_id.trim().is_empty()
                || stage.standing_resolver_id.trim().is_empty()
            {
                return Err(LifecycleErrorV1::Contract("stage/packet binding"));
            }
            for value in [
                &stage.reservation,
                &stage.logical_work,
                &stage.executor_plan_template_sha256,
                &stage.subject,
                &stage.scope,
                &stage.mandate,
                &stage.observation,
            ] {
                require_digest(value)?;
            }
            match (&stage.antecedent, index) {
                (AntecedentObservationV1::VerifiedCampaignStart { basis_id }, 0)
                    if basis_id == &self.verified_start.basis_id
                        && stage.logical_work == self.verified_start.stage_1_work
                        && stage.subject == self.verified_start.subject
                        && stage.scope == self.verified_start.scope
                        && stage.occurrence == self.verified_start.initial_occurrence
                        && stage.mandate == self.verified_start.mandate
                        && stage.observation == self.verified_start.observation
                        && stage.observation_resolver_id
                            == self.verified_start.observation_resolver_id
                        && stage.standing_resolver_id
                            == self.verified_start.standing_resolver_id => {}
                (AntecedentObservationV1::CurrentReservationRealization { reservation }, 1 | 2)
                    if reservation == &packet.stages[index - 1].reservation.reservation_id => {}
                _ => return Err(LifecycleErrorV1::Contract("antecedent chain")),
            }
        }
        let third = &self.stages[2];
        if !matches!(
            packet.stages[2].reservation.successor,
            SuccessorLawV1::HumanRequired
        ) || self.terminal.stage_3_occurrence != third.occurrence
            || self.terminal.reservation != third.reservation
            || self.terminal.observation_resolver_id != third.observation_resolver_id
            || self.terminal.terminal_packet_id.trim().is_empty()
        {
            return Err(LifecycleErrorV1::Contract("terminal HUMAN_REQUIRED law"));
        }
        require_digest(&self.terminal.reservation)?;
        require_digest(&self.terminal.observation)?;
        require_digest(&self.terminal.terminal_packet_id)?;
        Ok(())
    }

    pub fn validate_issuance<'a>(
        &self,
        ordinal: u32,
        snapshot: &'a OccurrenceSnapshotV1,
        executor_plan: &serde_json::Value,
    ) -> Result<&'a AgIssuanceV1, LifecycleErrorV1> {
        let stage = self.stage(ordinal)?;
        let plan = executor_plan
            .as_object()
            .ok_or(LifecycleErrorV1::Evidence("executor plan is not an object"))?;
        let plan_id = executor_plan_identity(executor_plan).map_err(LifecycleErrorV1::Packet)?;
        if plan
            .get("evidence_reservation")
            .and_then(serde_json::Value::as_str)
            != Some(&stage.reservation)
            || plan.get("work_schema").and_then(serde_json::Value::as_str)
                != Some(&stage.executor_work_schema)
            || plan.get("subject").and_then(serde_json::Value::as_str) != Some(&stage.subject)
            || plan.get("scope").and_then(serde_json::Value::as_str) != Some(&stage.scope)
        {
            return Err(LifecycleErrorV1::Evidence("W5 executor plan binding"));
        }
        snapshot
            .validate_integrity()
            .map_err(|_| LifecycleErrorV1::Evidence("AG snapshot integrity"))?;
        let proposal = snapshot
            .proposal()
            .ok_or(LifecycleErrorV1::Evidence("proposal absent"))?;
        let issuance = snapshot
            .issuance()
            .ok_or(LifecycleErrorV1::Evidence("issuance absent"))?;
        let standing = snapshot
            .standing_resolution()
            .ok_or(LifecycleErrorV1::Evidence("standing absent"))?;
        let observation = snapshot
            .observation()
            .ok_or(LifecycleErrorV1::Evidence("observation absent"))?;
        let occurrence = stage
            .occurrence
            .parse::<uuid::Uuid>()
            .map_err(|_| LifecycleErrorV1::Contract("occurrence"))?;
        let expected_basis = match &stage.antecedent {
            AntecedentObservationV1::VerifiedCampaignStart { basis_id } => {
                (VERIFIED_CAMPAIGN_START_BASIS_TYPE_V1, basis_id.as_str())
            }
            AntecedentObservationV1::CurrentReservationRealization { reservation } => {
                (RESERVED_APPLICABILITY_BASIS_TYPE_V1, reservation.as_str())
            }
        };
        let typed = observation
            .typed_basis()
            .ok_or(LifecycleErrorV1::Evidence("typed basis absent"))?;
        if snapshot.key().campaign.as_str() != self.campaign_id
            || snapshot.key().occurrence.as_uuid() != occurrence
            || snapshot.state().meta().expected_work().as_str() != plan_id
            || proposal.work_schema() != stage.executor_work_schema
            || proposal.work().as_str() != plan_id
            || proposal.subject().as_str() != stage.subject
            || proposal.scope().as_str() != stage.scope
            || observation.observation().as_str() != stage.observation
            || observation.resolver_id() != stage.observation_resolver_id
            || observation.status_label() != "Current"
            || typed.basis_type != expected_basis.0
            || typed.basis_identity.as_str() != expected_basis.1
            || standing.mandate.as_str() != stage.mandate
            || standing.resolver_id != stage.standing_resolver_id
            || issuance.key != *snapshot.key()
            || issuance.program.as_str() != self.program
            || issuance.work_schema != stage.executor_work_schema
            || issuance.work.as_str() != plan_id
            || issuance.subject.as_str() != stage.subject
            || issuance.scope.as_str() != stage.scope
            || issuance.observation.as_str() != stage.observation
            || issuance.mandate.as_str() != stage.mandate
        {
            return Err(LifecycleErrorV1::Evidence("antecedent issuance binding"));
        }
        Ok(issuance)
    }

    pub fn validate_terminal(
        &self,
        snapshot: &OccurrenceSnapshotV1,
        resolution: &VersionedObservationResolutionV1,
        now_unix_ms: u64,
    ) -> Result<HumanRequiredReceiptV1, LifecycleErrorV1> {
        let stage = self.stage(3)?;
        if snapshot.program_counter() != ProgramCounterV1::SettledObservationRequired
            || snapshot.key().occurrence.to_string() != stage.occurrence
            || snapshot.settlement().is_none()
            || snapshot.issuance().is_none()
        {
            return Err(LifecycleErrorV1::Evidence("Stage 3 is not exactly settled"));
        }
        let VersionedObservationResolutionV1::TypedV3(typed) = resolution else {
            return Err(LifecycleErrorV1::Evidence(
                "terminal typed realization absent",
            ));
        };
        if typed.key != *snapshot.key()
            || typed.observation.as_str() != self.terminal.observation
            || typed.subject.as_str() != stage.subject
            || typed.resolver_id != self.terminal.observation_resolver_id
            || typed.status != TypedObservationStatusV1::Current
            || typed.resolved_at_unix_ms > now_unix_ms
            || typed.fresh_until_unix_ms <= now_unix_ms
            || typed.basis.basis_type != RESERVED_APPLICABILITY_BASIS_TYPE_V1
            || typed.basis.basis_identity.as_str() != self.terminal.reservation
            || typed.normalized_preconditions.as_digest()
                != &typed
                    .basis
                    .binding_digest()
                    .map_err(LifecycleErrorV1::Packet)?
        {
            return Err(LifecycleErrorV1::Evidence("terminal R3 realization"));
        }
        let settlement = snapshot.settlement().expect("checked");
        let issuance = snapshot.issuance().expect("checked");
        let mut receipt = HumanRequiredReceiptV1 {
            schema: HUMAN_REQUIRED_RECEIPT_SCHEMA_V1.into(),
            receipt_id: String::new(),
            lifecycle_id: self.lifecycle_id.clone(),
            campaign_id: self.campaign_id.clone(),
            terminal_packet_id: self.terminal.terminal_packet_id.clone(),
            stage_3_occurrence: stage.occurrence.clone(),
            reservation: self.terminal.reservation.clone(),
            observation_currentness: typed.currentness.as_str().to_owned(),
            settlement: settlement.settlement.as_str().to_owned(),
            issuance: issuance.issuance.as_str().to_owned(),
            ag_spend: issuance.spend.as_str().to_owned(),
            state_digest_before: snapshot.state_digest().as_str().to_owned(),
            recorded_at_unix_ms: now_unix_ms,
            disposition: "HUMAN_REQUIRED".into(),
            authorization_spends_created: 0,
            issuances_created: 0,
            successor_occurrences_created: 0,
        };
        receipt.receipt_id = domain_hash(HUMAN_REQUIRED_RECEIPT_SCHEMA_V1, &receipt)?;
        Ok(receipt)
    }

    fn stage(&self, ordinal: u32) -> Result<&ProductionStageLawV1, LifecycleErrorV1> {
        self.stages
            .get(usize::try_from(ordinal.saturating_sub(1)).unwrap_or(usize::MAX))
            .filter(|stage| stage.ordinal == ordinal)
            .ok_or(LifecycleErrorV1::Contract("stage ordinal"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequiredReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub lifecycle_id: String,
    pub campaign_id: String,
    pub terminal_packet_id: String,
    pub stage_3_occurrence: String,
    pub reservation: String,
    pub observation_currentness: String,
    pub settlement: String,
    pub issuance: String,
    pub ag_spend: String,
    pub state_digest_before: String,
    pub recorded_at_unix_ms: u64,
    pub disposition: String,
    pub authorization_spends_created: u32,
    pub issuances_created: u32,
    pub successor_occurrences_created: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductionLifecycleFactV1 {
    VerifiedStart {
        basis_id: String,
    },
    Issuance {
        ordinal: u32,
        spend: String,
        issuance: String,
    },
    DocketCustody {
        ordinal: u32,
        attempt: String,
    },
    Settlement {
        ordinal: u32,
        settlement: String,
    },
    ReservationCurrent {
        ordinal: u32,
        reservation: String,
        currentness: String,
    },
    ContinuationOpened {
        ordinal: u32,
        occurrence: String,
    },
    HumanRequired {
        receipt: HumanRequiredReceiptV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionLifecycleEventV1 {
    pub schema: String,
    pub event_id: String,
    pub lifecycle_id: String,
    pub fact: ProductionLifecycleFactV1,
}

impl ProductionLifecycleEventV1 {
    pub fn seal(
        lifecycle_id: String,
        fact: ProductionLifecycleFactV1,
    ) -> Result<Self, LifecycleErrorV1> {
        let mut value = Self {
            schema: LIFECYCLE_EVENT_SCHEMA_V1.into(),
            event_id: String::new(),
            lifecycle_id,
            fact,
        };
        value.event_id = domain_hash(LIFECYCLE_EVENT_SCHEMA_V1, &value)?;
        Ok(value)
    }
}

pub struct ProductionLifecycleJournalV1 {
    path: PathBuf,
    contract: ProductionCampaignLifecycleV1,
}

impl ProductionLifecycleJournalV1 {
    pub fn create(
        path: &Path,
        contract: &ProductionCampaignLifecycleV1,
    ) -> Result<Self, LifecycleErrorV1> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS lifecycle_contract (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               lifecycle_id TEXT NOT NULL UNIQUE,
               contract_jcs BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS lifecycle_events (
               sequence INTEGER PRIMARY KEY,
               event_id TEXT NOT NULL UNIQUE,
               event_jcs BLOB NOT NULL
             );",
        )?;
        let bytes = JcsDocument::canonicalize(contract)
            .map_err(|error| LifecycleErrorV1::Canonical(error.to_string()))?;
        connection.execute(
            "INSERT INTO lifecycle_contract(singleton,lifecycle_id,contract_jcs) VALUES(1,?1,?2)
             ON CONFLICT(singleton) DO NOTHING",
            params![contract.lifecycle_id, bytes.as_bytes()],
        )?;
        let retained: (String, Vec<u8>) = connection.query_row(
            "SELECT lifecycle_id,contract_jcs FROM lifecycle_contract WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if retained.0 != contract.lifecycle_id || retained.1 != bytes.as_bytes() {
            return Err(LifecycleErrorV1::Conflict(
                "lifecycle contract substitution",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            contract: contract.clone(),
        })
    }

    pub fn open(path: &Path) -> Result<Self, LifecycleErrorV1> {
        let connection = Connection::open(path)?;
        let bytes: Vec<u8> = connection.query_row(
            "SELECT contract_jcs FROM lifecycle_contract WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let contract = serde_json::from_slice(&bytes)
            .map_err(|error| LifecycleErrorV1::Canonical(error.to_string()))?;
        Ok(Self {
            path: path.to_owned(),
            contract,
        })
    }

    pub fn record_verified_start(
        &self,
        basis: &VerifiedCampaignStartBasisV1,
    ) -> Result<bool, LifecycleErrorV1> {
        basis.validate()?;
        if basis != &self.contract.verified_start {
            return Err(LifecycleErrorV1::Conflict("verified start substitution"));
        }
        self.append(ProductionLifecycleFactV1::VerifiedStart {
            basis_id: basis.basis_id.clone(),
        })
    }

    pub fn record_issuance(
        &self,
        ordinal: u32,
        snapshot: &OccurrenceSnapshotV1,
        executor_plan: &serde_json::Value,
    ) -> Result<bool, LifecycleErrorV1> {
        let issuance = self
            .contract
            .validate_issuance(ordinal, snapshot, executor_plan)?;
        self.append(ProductionLifecycleFactV1::Issuance {
            ordinal,
            spend: issuance.spend.as_str().to_owned(),
            issuance: issuance.issuance.as_str().to_owned(),
        })
    }

    pub fn record_docket_custody(
        &self,
        ordinal: u32,
        snapshot: &OccurrenceSnapshotV1,
        executor_plan: &serde_json::Value,
    ) -> Result<bool, LifecycleErrorV1> {
        self.contract
            .validate_issuance(ordinal, snapshot, executor_plan)?;
        let custody = snapshot
            .docket_custody()
            .ok_or(LifecycleErrorV1::Evidence("Docket custody absent"))?;
        self.append(custody_fact(ordinal, custody))
    }

    pub fn record_settlement(
        &self,
        ordinal: u32,
        snapshot: &OccurrenceSnapshotV1,
        executor_plan: &serde_json::Value,
    ) -> Result<bool, LifecycleErrorV1> {
        self.contract
            .validate_issuance(ordinal, snapshot, executor_plan)?;
        let settlement = snapshot
            .settlement()
            .ok_or(LifecycleErrorV1::Evidence("Docket settlement absent"))?;
        self.append(settlement_fact(ordinal, settlement))
    }

    pub fn record_reservation_current(
        &self,
        ordinal: u32,
        snapshot: &OccurrenceSnapshotV1,
        resolution: &VersionedObservationResolutionV1,
        now_unix_ms: u64,
    ) -> Result<bool, LifecycleErrorV1> {
        let stage = self.contract.stage(ordinal)?;
        if snapshot.program_counter() != ProgramCounterV1::SettledObservationRequired
            || snapshot.key().occurrence.to_string() != stage.occurrence
            || snapshot.settlement().is_none()
        {
            return Err(LifecycleErrorV1::Evidence(
                "reservation source is not settled",
            ));
        }
        let expected_observation = if ordinal < 3 {
            &self.contract.stage(ordinal + 1)?.observation
        } else {
            &self.contract.terminal.observation
        };
        let VersionedObservationResolutionV1::TypedV3(typed) = resolution else {
            return Err(LifecycleErrorV1::Evidence("reservation realization absent"));
        };
        if typed.key != *snapshot.key()
            || typed.observation.as_str() != expected_observation
            || typed.subject.as_str() != stage.subject
            || typed.resolver_id != self.contract.terminal.observation_resolver_id
            || typed.status != TypedObservationStatusV1::Current
            || typed.resolved_at_unix_ms > now_unix_ms
            || typed.fresh_until_unix_ms <= now_unix_ms
            || typed.basis.basis_type != RESERVED_APPLICABILITY_BASIS_TYPE_V1
            || typed.basis.basis_identity.as_str() != stage.reservation
            || typed.normalized_preconditions.as_digest()
                != &typed
                    .basis
                    .binding_digest()
                    .map_err(LifecycleErrorV1::Packet)?
        {
            return Err(LifecycleErrorV1::Evidence(
                "reservation realization mismatch",
            ));
        }
        self.append(ProductionLifecycleFactV1::ReservationCurrent {
            ordinal,
            reservation: stage.reservation.clone(),
            currentness: typed.currentness.as_str().to_owned(),
        })
    }

    pub fn record_continuation_opened(
        &self,
        ordinal: u32,
        snapshot: &OccurrenceSnapshotV1,
        executor_plan: &serde_json::Value,
    ) -> Result<bool, LifecycleErrorV1> {
        let stage = self.contract.stage(ordinal)?;
        let plan_id = executor_plan_identity(executor_plan).map_err(LifecycleErrorV1::Packet)?;
        if snapshot.program_counter() != ProgramCounterV1::ObservationRequired
            || snapshot.key().occurrence.to_string() != stage.occurrence
            || snapshot.state().meta().expected_work().as_str() != plan_id
            || snapshot.issuance().is_some()
            || snapshot.docket_custody().is_some()
        {
            return Err(LifecycleErrorV1::Evidence(
                "continuation is not authority-empty",
            ));
        }
        self.append(ProductionLifecycleFactV1::ContinuationOpened {
            ordinal,
            occurrence: stage.occurrence.clone(),
        })
    }

    pub fn record_human_required(
        &self,
        snapshot: &OccurrenceSnapshotV1,
        resolution: &VersionedObservationResolutionV1,
        now_unix_ms: u64,
    ) -> Result<(bool, HumanRequiredReceiptV1), LifecycleErrorV1> {
        let receipt = self
            .contract
            .validate_terminal(snapshot, resolution, now_unix_ms)?;
        let inserted = self.append(ProductionLifecycleFactV1::HumanRequired {
            receipt: receipt.clone(),
        })?;
        Ok((inserted, receipt))
    }

    fn append(&self, fact: ProductionLifecycleFactV1) -> Result<bool, LifecycleErrorV1> {
        let event = ProductionLifecycleEventV1::seal(self.contract.lifecycle_id.clone(), fact)?;
        let connection = Connection::open(&self.path)?;
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT event_jcs FROM lifecycle_events WHERE event_id=?1",
                params![event.event_id],
                |row| row.get(0),
            )
            .optional()?;
        let bytes = JcsDocument::canonicalize(&event)
            .map_err(|error| LifecycleErrorV1::Canonical(error.to_string()))?;
        if let Some(existing) = existing {
            return if existing == bytes.as_bytes() {
                Ok(false)
            } else {
                Err(LifecycleErrorV1::Conflict("event identity collision"))
            };
        }
        let prior = self.events()?;
        validate_next_fact(&self.contract, &prior, &event.fact)?;
        connection.execute(
            "INSERT INTO lifecycle_events(sequence,event_id,event_jcs) VALUES(?1,?2,?3)",
            params![
                i64::try_from(prior.len() + 1)
                    .map_err(|_| LifecycleErrorV1::Contract("event count"))?,
                event.event_id,
                bytes.as_bytes()
            ],
        )?;
        Ok(true)
    }

    pub fn events(&self) -> Result<Vec<ProductionLifecycleEventV1>, LifecycleErrorV1> {
        let connection = Connection::open(&self.path)?;
        let mut statement =
            connection.prepare("SELECT event_jcs FROM lifecycle_events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            serde_json::from_slice(&row?)
                .map_err(|error| LifecycleErrorV1::Canonical(error.to_string()))
        })
        .collect()
    }

    pub const fn contract(&self) -> &ProductionCampaignLifecycleV1 {
        &self.contract
    }
}

fn validate_next_fact(
    contract: &ProductionCampaignLifecycleV1,
    prior: &[ProductionLifecycleEventV1],
    next: &ProductionLifecycleFactV1,
) -> Result<(), LifecycleErrorV1> {
    use ProductionLifecycleFactV1 as F;
    match (prior.last().map(|event| &event.fact), next) {
        (None, F::VerifiedStart { basis_id }) if basis_id == &contract.verified_start.basis_id => {
            Ok(())
        }
        (Some(F::VerifiedStart { .. }), F::Issuance { ordinal: 1, .. }) => Ok(()),
        (Some(F::ContinuationOpened { ordinal: prior, .. }), F::Issuance { ordinal, .. })
            if ordinal == prior =>
        {
            Ok(())
        }
        (Some(F::Issuance { ordinal: prior, .. }), F::DocketCustody { ordinal, .. })
            if ordinal == prior =>
        {
            Ok(())
        }
        (Some(F::DocketCustody { ordinal: prior, .. }), F::Settlement { ordinal, .. })
            if ordinal == prior =>
        {
            Ok(())
        }
        (
            Some(F::Settlement { ordinal: prior, .. }),
            F::ReservationCurrent {
                ordinal,
                reservation,
                ..
            },
        ) if ordinal == prior && reservation == &contract.stage(*ordinal)?.reservation => Ok(()),
        (
            Some(F::ReservationCurrent {
                ordinal: prior @ (1 | 2),
                ..
            }),
            F::ContinuationOpened {
                ordinal,
                occurrence,
            },
        ) if *ordinal == *prior + 1 && occurrence == &contract.stage(*ordinal)?.occurrence => {
            Ok(())
        }
        (Some(F::ReservationCurrent { ordinal: 3, .. }), F::HumanRequired { receipt })
            if receipt.lifecycle_id == contract.lifecycle_id
                && receipt.reservation == contract.terminal.reservation
                && receipt.authorization_spends_created == 0
                && receipt.issuances_created == 0
                && receipt.successor_occurrences_created == 0 =>
        {
            Ok(())
        }
        _ => Err(LifecycleErrorV1::Conflict(
            "illegal or premature lifecycle fact",
        )),
    }
}

#[derive(Debug, Error)]
pub enum LifecycleErrorV1 {
    #[error("invalid packet: {0}")]
    Packet(String),
    #[error("invalid lifecycle contract: {0}")]
    Contract(&'static str),
    #[error("invalid or missing production evidence: {0}")]
    Evidence(&'static str),
    #[error("lifecycle conflict: {0}")]
    Conflict(&'static str),
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    #[error("durable lifecycle store failed: {0}")]
    Store(#[from] rusqlite::Error),
}

fn require_digest(value: &str) -> Result<(), LifecycleErrorV1> {
    Digest::parse(value)
        .map(|_| ())
        .map_err(|_| LifecycleErrorV1::Contract("digest coordinate"))
}

fn domain_hash<T: Serialize>(domain: &str, value: &T) -> Result<String, LifecycleErrorV1> {
    let bytes =
        serde_jcs::to_vec(value).map_err(|error| LifecycleErrorV1::Canonical(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn custody_fact(ordinal: u32, custody: &DocketCustodyV1) -> ProductionLifecycleFactV1 {
    ProductionLifecycleFactV1::DocketCustody {
        ordinal,
        attempt: custody.attempt.as_str().to_owned(),
    }
}

pub fn settlement_fact(ordinal: u32, settlement: &DocketSettlementV1) -> ProductionLifecycleFactV1 {
    ProductionLifecycleFactV1::Settlement {
        ordinal,
        settlement: settlement.settlement.as_str().to_owned(),
    }
}
