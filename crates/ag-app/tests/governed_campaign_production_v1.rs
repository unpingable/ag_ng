#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ag_app::governed_campaign_production_v1::*;
use ag_app::governed_campaign_v1::{
    CampaignPacketV1, GitObjectV1, PredecessorBindingV1, RESERVED_APPLICABILITY_BASIS_TYPE_V1,
    executor_plan_identity, materialize_executor_plan_template,
};
use ag_app::governed_loop::{
    CampaignEngineV1, DocketProgressV1, EXACT_WORK_CATALOG_SCHEMA_V2,
    ExactObservationBasisRequirementV1, ExactWorkCatalogEntryV2, ExactWorkCatalogV2,
};
use ag_campaign::{CampaignId, governed::*};
use ag_primitives::Digest;
use uuid::Uuid;

const OBSERVATION_RESOLVER: &str = "nightshift.repository-qualification-resolver/v1";
const STANDING_RESOLVER: &str = "docket.current-standing-resolver/v1";
const NOW: u64 = 1_800_000_000_000;

fn digest(label: &str) -> Digest {
    Digest::hash_domain(
        "brass-rabbit.production-lifecycle-test/v1",
        label.as_bytes(),
    )
}

fn git(character: char) -> GitObjectV1 {
    GitObjectV1 {
        object_format: "sha1".into(),
        digest: character.to_string().repeat(40),
    }
}

fn frozen_packet() -> CampaignPacketV1 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../qualification/governed-campaign-loop-v1/velvet-pigeon/evidence/glass-heron-packet.v1.json",
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn production_contract(packet: &CampaignPacketV1) -> ProductionCampaignLifecycleV1 {
    let subject = packet.stages[0].executor_plan_template["subject"]
        .as_str()
        .unwrap()
        .to_owned();
    let occurrences = [
        Uuid::from_u128(0xb001),
        Uuid::from_u128(0xb002),
        Uuid::from_u128(0xb003),
    ];
    let mandate = digest("human-campaign-mandate").to_string();
    let observations = [
        digest("verified-root-observation").to_string(),
        digest("r1-current-observation").to_string(),
        digest("r2-current-observation").to_string(),
    ];
    let verified_start = VerifiedCampaignStartBasisV1 {
        schema: String::new(),
        basis_id: String::new(),
        campaign_id: packet.campaign_id.clone(),
        campaign_packet_id: packet.packet_id.clone(),
        stage_1_work: packet.stages[0].work.clone(),
        subject: subject.clone(),
        scope: packet.stages[0].executor_plan_template["scope"]
            .as_str()
            .unwrap()
            .to_owned(),
        initial_occurrence: occurrences[0].to_string(),
        mandate: mandate.clone(),
        observation: observations[0].clone(),
        observation_resolver_id: OBSERVATION_RESOLVER.into(),
        standing_resolver_id: STANDING_RESOLVER.into(),
        human_decision: digest("explicit-human-campaign-start").to_string(),
        human_principal: digest("verified-human-principal").to_string(),
        human_verification: digest("verified-human-start-record").to_string(),
        verification_profile: "ag.human-campaign-start-verification/v1".into(),
        decided_at_unix_ms: NOW,
        does_not_establish: [
            "execution",
            "qualification",
            "standing",
            "authorization",
            "issuance",
            "docket_custody",
            "continuation",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
    .seal()
    .unwrap();
    let stages = packet
        .stages
        .iter()
        .enumerate()
        .map(|(index, frozen)| ProductionStageLawV1 {
            stage_id: frozen.stage_id.clone(),
            ordinal: frozen.ordinal,
            occurrence: occurrences[index].to_string(),
            reservation: frozen.reservation.reservation_id.clone(),
            logical_work_schema: frozen.work_schema.clone(),
            logical_work: frozen.work.clone(),
            executor_work_schema: frozen.executor_plan_template["work_schema"]
                .as_str()
                .unwrap()
                .to_owned(),
            executor_plan_template_sha256: frozen.executor_plan_template_sha256.clone(),
            subject: subject.clone(),
            scope: frozen.executor_plan_template["scope"]
                .as_str()
                .unwrap()
                .to_owned(),
            mandate: mandate.clone(),
            observation: observations[index].clone(),
            observation_resolver_id: OBSERVATION_RESOLVER.into(),
            standing_resolver_id: STANDING_RESOLVER.into(),
            antecedent: if index == 0 {
                AntecedentObservationV1::VerifiedCampaignStart {
                    basis_id: verified_start.basis_id.clone(),
                }
            } else {
                AntecedentObservationV1::CurrentReservationRealization {
                    reservation: packet.stages[index - 1].reservation.reservation_id.clone(),
                }
            },
        })
        .collect();
    ProductionCampaignLifecycleV1 {
        schema: String::new(),
        lifecycle_id: String::new(),
        campaign_id: packet.campaign_id.clone(),
        campaign_packet_id: packet.packet_id.clone(),
        program: digest("production-program").to_string(),
        verified_start,
        stages,
        terminal: HumanRequiredLawV1 {
            terminal_packet_id: digest("terminal-packet-law").to_string(),
            stage_3_occurrence: occurrences[2].to_string(),
            reservation: packet.stages[2].reservation.reservation_id.clone(),
            observation: digest("r3-terminal-observation").to_string(),
            observation_resolver_id: OBSERVATION_RESOLVER.into(),
        },
    }
    .seal(packet)
    .unwrap()
}

#[derive(Clone)]
struct TypedObservation {
    basis: TypedOpaqueObservationBasisV1,
}

impl ObservationResolverV1 for TypedObservation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        Ok(typed_resolution(
            request.key.clone(),
            request.observation.clone(),
            request.subject.clone(),
            self.basis.clone(),
            request.now_unix_ms,
        ))
    }
}

fn typed_resolution(
    key: OccurrenceKeyV1,
    observation: ObservationRefV1,
    subject: Digest,
    basis: TypedOpaqueObservationBasisV1,
    now: u64,
) -> VersionedObservationResolutionV1 {
    ObservationResolutionV3 {
        schema: OBSERVATION_RESOLUTION_SCHEMA_V3.into(),
        key,
        observation,
        currentness: ObservationCurrentnessRefV1::from_digest(Digest::hash_domain(
            "brass-rabbit.currentness/v1",
            format!("{}:{now}", basis.basis_identity).as_bytes(),
        )),
        normalized_preconditions: PreconditionBasisRefV1::from_digest(
            basis.binding_digest().unwrap(),
        ),
        basis,
        resolver_id: OBSERVATION_RESOLVER.into(),
        subject,
        status: TypedObservationStatusV1::Current,
        resolved_at_unix_ms: now,
        fresh_until_unix_ms: now + 60_000,
    }
    .into()
}

struct Standing {
    mandate: MandateRefV1,
}

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.into(),
            resolution: StandingResolutionRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.standing-resolution/v1",
                request.proposal.as_str().as_bytes(),
            )),
            currentness: StandingCurrentnessRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.standing-currentness/v1",
                request.proposal.as_str().as_bytes(),
            )),
            mandate: self.mandate.clone(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: STANDING_RESOLVER.into(),
            status: StandingStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 60_000,
        })
    }
}

#[derive(Default)]
struct ProductionDocket {
    records: BTreeMap<AgIssuanceRefV1, (DocketCustodyV1, DocketSettlementV1)>,
    accept_calls: u32,
}

impl ProductionDocket {
    fn response(&self, issuance: &AgIssuanceRefV1) -> DocketIssuanceReconciliationV1 {
        let (custody, settlement) = self.records.get(issuance).expect("custody");
        DocketIssuanceReconciliationV1::Settled {
            custody: custody.clone(),
            settlement: settlement.clone(),
        }
    }
}

impl DocketCustodyPortV1 for ProductionDocket {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        if let Some((custody, _)) = self.records.get(&issuance.issuance) {
            return Ok(custody.clone());
        }
        self.accept_calls += 1;
        let custody = DocketCustodyV1 {
            schema: DOCKET_CUSTODY_SCHEMA_V1.into(),
            issuance: issuance.issuance.clone(),
            ag_spend: issuance.spend.clone(),
            execution_standing: DocketExecutionStandingRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.docket-standing/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            standing_currentness: StandingCurrentnessRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.docket-currentness/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            attempt: DocketAttemptRefV1::for_issuance(&issuance.issuance),
            executor_marker: ExecutorAttemptMarkerRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.executor-marker/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            accepted_at_unix_ms: NOW + u64::from(self.accept_calls) * 100,
        };
        let settlement = DocketSettlementV1 {
            schema: DOCKET_SETTLEMENT_SCHEMA_V1.into(),
            settlement: SettlementRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.settlement/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            issuance: custody.issuance.clone(),
            attempt: custody.attempt.clone(),
            executor_marker: custody.executor_marker.clone(),
            receipt: ReceiptRefV1::from_digest(Digest::hash_domain(
                "brass-rabbit.receipt/v1",
                issuance.issuance.as_str().as_bytes(),
            )),
            outcome: KnownOutcomeV1::Success,
            settled_at_unix_ms: custody.accepted_at_unix_ms + 1,
        };
        self.records
            .insert(issuance.issuance.clone(), (custody.clone(), settlement));
        Ok(custody)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        Ok(self.response(&issuance.issuance))
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        let response = self.response(&custody.issuance);
        match &response {
            DocketIssuanceReconciliationV1::Settled {
                custody: retained, ..
            } if retained == custody => Ok(response),
            _ => Err(ExternalBoundaryErrorV1::Refused {
                code: "custody-substitution".into(),
                evidence: None,
            }),
        }
    }
}

fn catalog(
    stage: &ProductionStageLawV1,
    basis: TypedOpaqueObservationBasisV1,
) -> ExactWorkCatalogV2 {
    ExactWorkCatalogV2 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V2.into(),
        entries: BTreeMap::from([(
            stage.executor_work_schema.clone(),
            ExactWorkCatalogEntryV2 {
                work_schema: stage.executor_work_schema.clone(),
                subject: Digest::parse(&stage.subject).unwrap(),
                scope: Digest::parse(&stage.scope).unwrap(),
                observation_basis: ExactObservationBasisRequirementV1::TypedBasis(basis),
            },
        )]),
    }
}

#[test]
fn production_chain_has_three_antecedent_issuances_and_non_authorizing_terminal() {
    let packet = frozen_packet();
    let contract = production_contract(&packet);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ag.sqlite3");
    let journal_path = directory.path().join("lifecycle.sqlite3");
    let mut journal = ProductionLifecycleJournalV1::create(&journal_path, &contract).unwrap();
    assert!(
        journal
            .record_verified_start(&contract.verified_start)
            .unwrap()
    );
    journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();

    let (mut predecessor_head, mut predecessor_tree) =
        match &packet.stages[0].reservation.predecessor {
            PredecessorBindingV1::InitialGit { head, tree } => (head.clone(), tree.clone()),
            _ => panic!("Stage 1 predecessor must be literal"),
        };
    let mut current_plan = materialize_executor_plan_template(
        &packet.stages[0].executor_plan_template,
        &packet.stages[0].reservation,
        predecessor_head.clone(),
        predecessor_tree.clone(),
    )
    .unwrap();
    let first_plan_id = executor_plan_identity(&current_plan).unwrap();

    let campaign = CampaignId::from_digest(Digest::parse(&contract.campaign_id).unwrap());
    let first = &contract.stages[0];
    let mut engine = CampaignEngineV1::create(
        &database,
        campaign,
        OccurrenceId::from_uuid(first.occurrence.parse().unwrap()),
        ProgramBasisRefV1::from_digest(Digest::parse(&contract.program).unwrap()),
        Digest::parse(&first_plan_id).unwrap(),
        ResidualSetV1::default(),
        LoopBudgetV1 {
            retry_limit: 0,
            retries_used: 0,
            probe_limit: 0,
            probes_used: 0,
            escalation_limit: 0,
            escalations_used: 0,
        },
        NOW,
    )
    .unwrap();
    let mut docket = ProductionDocket::default();
    let mandate = MandateRefV1::from_digest(Digest::parse(&first.mandate).unwrap());
    let mut settled_stage_3 = None;
    let mut terminal_resolution = None;
    let mut executor_plan_ids = Vec::new();
    let mut issuance_ids = Vec::new();
    let mut spend_ids = Vec::new();
    let mut attempt_ids = Vec::new();
    let mut settlement_ids = Vec::new();
    let mut currentness_ids = Vec::new();

    for index in 0..3 {
        let stage = &contract.stages[index];
        let basis = if index == 0 {
            TypedOpaqueObservationBasisV1::new(
                VERIFIED_CAMPAIGN_START_BASIS_TYPE_V1.into(),
                Digest::parse(&contract.verified_start.basis_id).unwrap(),
            )
            .unwrap()
        } else {
            TypedOpaqueObservationBasisV1::new(
                RESERVED_APPLICABILITY_BASIS_TYPE_V1.into(),
                Digest::parse(&contract.stages[index - 1].reservation).unwrap(),
            )
            .unwrap()
        };
        let mut observation = TypedObservation {
            basis: basis.clone(),
        };
        let mut standing = Standing {
            mandate: mandate.clone(),
        };
        let current_plan_id = executor_plan_identity(&current_plan).unwrap();
        executor_plan_ids.push(current_plan_id.clone());
        let proposal = ExactWorkProposalV1::new(
            CampaignId::from_digest(Digest::parse(&contract.campaign_id).unwrap()),
            Digest::parse(&stage.subject).unwrap(),
            Digest::parse(&stage.scope).unwrap(),
            stage.executor_work_schema.clone(),
            Digest::parse(&current_plan_id).unwrap(),
            None,
        )
        .unwrap();
        engine
            .record_proposal(
                ObservationRefV1::from_digest(Digest::parse(&stage.observation).unwrap()),
                proposal,
                if index == 0 {
                    ProposalClassV1::Initial
                } else {
                    ProposalClassV1::Successor
                },
                &mut observation,
                OBSERVATION_RESOLVER,
                NOW + 10 + (index as u64) * 100,
            )
            .unwrap();
        engine = CampaignEngineV1::open(&database).unwrap();
        engine
            .require_standing(NOW + 11 + (index as u64) * 100)
            .unwrap();
        engine = CampaignEngineV1::open(&database).unwrap();
        let exact_catalog = catalog(stage, basis);
        engine
            .decide_with_catalog_v2(
                &mut observation,
                &mut standing,
                &exact_catalog,
                None,
                OBSERVATION_RESOLVER,
                STANDING_RESOLVER,
                60_000,
                NOW + 12 + (index as u64) * 100,
            )
            .unwrap();
        assert!(engine.current().unwrap().issuance().is_none());
        engine = CampaignEngineV1::open(&database).unwrap();
        let authorized = engine
            .authorize_with_catalog_v2(
                &mut observation,
                &mut standing,
                &exact_catalog,
                None,
                OBSERVATION_RESOLVER,
                STANDING_RESOLVER,
                60_000,
                NOW + 13 + (index as u64) * 100,
            )
            .unwrap();
        if index == 0 {
            let mut substituted_plan = current_plan.clone();
            substituted_plan["evidence_reservation"] =
                serde_json::Value::String(contract.stages[1].reservation.clone());
            assert!(
                contract
                    .validate_issuance(stage.ordinal, &authorized, &substituted_plan)
                    .is_err()
            );
        }
        let validated = contract
            .validate_issuance(stage.ordinal, &authorized, &current_plan)
            .unwrap();
        issuance_ids.push(validated.issuance.as_str().to_owned());
        spend_ids.push(validated.spend.as_str().to_owned());
        journal
            .record_issuance(stage.ordinal, &authorized, &current_plan)
            .unwrap();
        journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();

        engine = CampaignEngineV1::open(&database).unwrap();
        let dispatched = engine
            .dispatch(&mut docket, NOW + 14 + (index as u64) * 100)
            .unwrap();
        attempt_ids.push(
            dispatched
                .docket_custody()
                .unwrap()
                .attempt
                .as_str()
                .to_owned(),
        );
        journal
            .record_docket_custody(stage.ordinal, &dispatched, &current_plan)
            .unwrap();
        journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();
        engine = CampaignEngineV1::open(&database).unwrap();
        let DocketProgressV1::Settled(settled) = engine
            .poll_docket(&mut docket, NOW + 15 + (index as u64) * 100)
            .unwrap()
        else {
            panic!("fixture Docket must settle");
        };
        settlement_ids.push(settled.settlement().unwrap().settlement.as_str().to_owned());
        journal
            .record_settlement(stage.ordinal, &settled, &current_plan)
            .unwrap();
        journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();

        let realization_observation = if index < 2 {
            &contract.stages[index + 1].observation
        } else {
            &contract.terminal.observation
        };
        let realization = typed_resolution(
            settled.key().clone(),
            ObservationRefV1::from_digest(Digest::parse(realization_observation).unwrap()),
            Digest::parse(&stage.subject).unwrap(),
            TypedOpaqueObservationBasisV1::new(
                RESERVED_APPLICABILITY_BASIS_TYPE_V1.into(),
                Digest::parse(&stage.reservation).unwrap(),
            )
            .unwrap(),
            NOW + 16 + (index as u64) * 100,
        );
        currentness_ids.push(realization.currentness().as_str().to_owned());
        journal
            .record_reservation_current(
                stage.ordinal,
                &settled,
                &realization,
                NOW + 17 + (index as u64) * 100,
            )
            .unwrap();
        journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();

        if index < 2 {
            let next = &contract.stages[index + 1];
            (predecessor_head, predecessor_tree) = if index == 0 {
                (git('2'), git('B'))
            } else {
                (git('3'), git('C'))
            };
            current_plan = materialize_executor_plan_template(
                &packet.stages[index + 1].executor_plan_template,
                &packet.stages[index + 1].reservation,
                predecessor_head.clone(),
                predecessor_tree.clone(),
            )
            .unwrap();
            let next_plan_id = executor_plan_identity(&current_plan).unwrap();
            engine = CampaignEngineV1::open(&database).unwrap();
            let opened = engine
                .open_continuation(
                    OccurrenceId::from_uuid(next.occurrence.parse().unwrap()),
                    Digest::parse(&next_plan_id).unwrap(),
                    NOW + 17 + (index as u64) * 100,
                )
                .unwrap();
            assert_eq!(
                opened.program_counter(),
                ProgramCounterV1::ObservationRequired
            );
            assert!(opened.issuance().is_none());
            journal
                .record_continuation_opened(next.ordinal, &opened, &current_plan)
                .unwrap();
            journal = ProductionLifecycleJournalV1::open(&journal_path).unwrap();
        } else {
            settled_stage_3 = Some(settled);
            terminal_resolution = Some(realization);
        }
    }

    let settled = settled_stage_3.unwrap();
    let terminal_resolution = terminal_resolution.unwrap();
    let (inserted, receipt) = journal
        .record_human_required(&settled, &terminal_resolution, NOW + 500)
        .unwrap();
    assert!(inserted);
    assert_eq!(receipt.disposition, "HUMAN_REQUIRED");
    assert_eq!(receipt.authorization_spends_created, 0);
    assert_eq!(receipt.issuances_created, 0);
    assert_eq!(receipt.successor_occurrences_created, 0);

    let replay = CampaignEngineV1::open(&database).unwrap().replay().unwrap();
    assert_eq!(replay.ag_spends, 3);
    assert_eq!(replay.docket_attempts, 3);
    assert_eq!(replay.settlements, 3);
    assert_eq!(docket.accept_calls, 3);
    assert_eq!(docket.records.len(), 3);
    assert_eq!(journal.events().unwrap().len(), 16);
    assert!(contract.stages.get(3).is_none());

    if let Ok(output) = std::env::var("BRASS_RABBIT_EVIDENCE_DIR") {
        let output = PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        let events = journal.events().unwrap();
        let summary = serde_json::json!({
            "schema": "ag.governed-campaign.brass-rabbit-specimen/v1",
            "lifecycle_id": contract.lifecycle_id,
            "verified_start_basis": contract.verified_start.basis_id,
            "campaign_packet_id": contract.campaign_packet_id,
            "logical_stage_works": contract.stages.iter().map(|stage| stage.logical_work.clone()).collect::<Vec<_>>(),
            "executor_plan_templates": contract.stages.iter().map(|stage| stage.executor_plan_template_sha256.clone()).collect::<Vec<_>>(),
            "materialized_executor_plans": executor_plan_ids,
            "ag_spends": spend_ids,
            "ag_issuances": issuance_ids,
            "docket_attempts": attempt_ids,
            "settlements": settlement_ids,
            "reservation_currentness": currentness_ids,
            "human_required_receipt": receipt.receipt_id,
            "cardinality": {
                "verified_starts": 1,
                "ag_spends": 3,
                "ag_issuances": 3,
                "docket_attempts": 3,
                "reservation_realizations": 3,
                "human_required": 1,
                "stage_4": 0
            }
        });
        for (name, value) in [
            (
                "production-lifecycle.v1.json",
                serde_json::to_value(&contract).unwrap(),
            ),
            (
                "lifecycle-events.v1.json",
                serde_json::to_value(&events).unwrap(),
            ),
            (
                "human-required-receipt.v1.json",
                serde_json::to_value(&receipt).unwrap(),
            ),
            ("specimen-summary.v1.json", summary),
        ] {
            std::fs::write(output.join(name), serde_jcs::to_vec(&value).unwrap()).unwrap();
        }
    }

    let reopened = ProductionLifecycleJournalV1::open(&journal_path).unwrap();
    assert_eq!(reopened.contract(), &contract);
    assert_eq!(reopened.events().unwrap(), journal.events().unwrap());
    assert!(
        !reopened
            .record_human_required(&settled, &terminal_resolution, NOW + 500)
            .unwrap()
            .0
    );
}

#[test]
fn lifecycle_contract_has_no_preissued_successors_and_v0_source_is_unchanged() {
    let packet = frozen_packet();
    let contract = production_contract(&packet);
    let encoded = serde_json::to_string(&contract).unwrap();
    assert!(!encoded.contains("porter_run"));
    assert!(!encoded.contains("ag_issuance"));
    assert!(!encoded.contains("stage-4"));
    assert_eq!(contract.stages.len(), 3);
    assert!(matches!(
        contract.stages[1].antecedent,
        AntecedentObservationV1::CurrentReservationRealization { .. }
    ));
    assert!(matches!(
        contract.stages[2].antecedent,
        AntecedentObservationV1::CurrentReservationRealization { .. }
    ));
    let frozen_v0 = include_bytes!("../src/governed_campaign_v0.rs");
    assert_eq!(
        Digest::hash_bytes(frozen_v0).to_string(),
        "sha256:f33864aa36f52069ce25fd5edeeeb0428e82fcdd27e10d7ea421d3edfc45f1de"
    );
}
#[test]
fn authority_hostile_ordering_and_root_substitution_refuse() {
    let packet = frozen_packet();
    let contract = production_contract(&packet);
    let directory = tempfile::tempdir().unwrap();
    let journal =
        ProductionLifecycleJournalV1::create(&directory.path().join("hostile.sqlite3"), &contract)
            .unwrap();

    let mut wrong = contract.verified_start.clone();
    wrong.human_verification = digest("substituted-verification").to_string();
    assert!(journal.record_verified_start(&wrong).is_err());
    assert!(
        journal
            .record_verified_start(&contract.verified_start)
            .unwrap()
    );
    assert!(
        !journal
            .record_verified_start(&contract.verified_start)
            .unwrap()
    );

    let first = &contract.stages[0];
    let (head, tree) = match &packet.stages[0].reservation.predecessor {
        PredecessorBindingV1::InitialGit { head, tree } => (head.clone(), tree.clone()),
        _ => panic!("Stage 1 predecessor must be literal"),
    };
    let plan = materialize_executor_plan_template(
        &packet.stages[0].executor_plan_template,
        &packet.stages[0].reservation,
        head,
        tree,
    )
    .unwrap();
    let mut engine = CampaignEngineV1::create(
        &directory.path().join("hostile-ag.sqlite3"),
        CampaignId::from_digest(Digest::parse(&contract.campaign_id).unwrap()),
        OccurrenceId::from_uuid(first.occurrence.parse().unwrap()),
        ProgramBasisRefV1::from_digest(Digest::parse(&contract.program).unwrap()),
        Digest::parse(&executor_plan_identity(&plan).unwrap()).unwrap(),
        ResidualSetV1::default(),
        LoopBudgetV1 {
            retry_limit: 0,
            retries_used: 0,
            probe_limit: 0,
            probes_used: 0,
            escalation_limit: 0,
            escalations_used: 0,
        },
        NOW,
    )
    .unwrap();
    let initial = engine.current().unwrap();
    let mut docket = ProductionDocket::default();
    assert!(engine.dispatch(&mut docket, NOW + 1).is_err());
    assert!(journal.record_issuance(1, &initial, &plan).is_err());
    assert!(journal.record_issuance(2, &initial, &plan).is_err());

    let fabricated_r3 = typed_resolution(
        initial.key().clone(),
        ObservationRefV1::from_digest(Digest::parse(&contract.terminal.observation).unwrap()),
        Digest::parse(&first.subject).unwrap(),
        TypedOpaqueObservationBasisV1::new(
            RESERVED_APPLICABILITY_BASIS_TYPE_V1.into(),
            Digest::parse(&contract.terminal.reservation).unwrap(),
        )
        .unwrap(),
        NOW + 2,
    );
    assert!(
        journal
            .record_human_required(&initial, &fabricated_r3, NOW + 3)
            .is_err()
    );

    let mut wrong_contract = contract.clone();
    wrong_contract.verified_start.human_verification =
        digest("contract-substituted-verification").to_string();
    assert!(wrong_contract.validate(&packet).is_err());
}
