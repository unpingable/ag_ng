//! Campaign-specific GLASS-HERON W7 qualification controller.
//!
//! This is deliberately not a scheduler or VM manager. It runs one frozen
//! three-stage packet through existing AG, Docket, W5, NQ, and Nightshift.

#![allow(clippy::too_many_lines, missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::governed_campaign_production_v1::*;
use ag_app::governed_campaign_v1::{
    CampaignPacketV1, GitObjectV1, PredecessorBindingV1, RESERVED_APPLICABILITY_BASIS_TYPE_V1,
    executor_plan_identity, materialize_executor_plan_template, materialize_nq_profile_template,
};
use ag_app::governed_loop::{
    CampaignEngineV1, DocketProgressV1, EXACT_WORK_CATALOG_SCHEMA_V2,
    ExactObservationBasisRequirementV1, ExactWorkCatalogEntryV2, ExactWorkCatalogV2,
};
use ag_app::governed_ports::{AgIssuanceSignerV1, CommandDocketCustodyPortV1};
use ag_campaign::{CampaignId, governed::*};
use ag_primitives::{Digest, JcsDocument};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const OBSERVATION_RESOLVER: &str = "nightshift.repository-qualification-resolver/v1";
const STANDING_RESOLVER: &str = "docket.current-standing-resolver/v1";
const TTL: u64 = 300_000;

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn label(value: &str) -> Digest {
    Digest::hash_domain("ag.glass-heron/v1", value.as_bytes())
}

fn write_jcs(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = JcsDocument::canonicalize(value).map_err(|error| anyhow!(error.to_string()))?;
    fs::write(path, bytes.as_bytes())?;
    Ok(())
}

fn checked(command: &mut Command, name: &str) -> Result<Output> {
    let output = command.output().with_context(|| format!("run {name}"))?;
    ensure!(
        output.status.success(),
        "{name} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn git(repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = checked(
        Command::new("/usr/bin/git")
            .args(arguments)
            .current_dir(repository)
            .env_clear()
            .envs([
                ("HOME", "/nonexistent"),
                ("PATH", "/usr/bin:/bin"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("LC_ALL", "C"),
            ]),
        "git",
    )?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[derive(Clone)]
struct Observation {
    exact: VersionedObservationResolutionV1,
}

impl ObservationResolverV1 for Observation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> std::result::Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        if self.exact.observation() != request.observation
            || self.exact.resolver_id() != OBSERVATION_RESOLVER
        {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "glass-heron-observation-substitution".into(),
                evidence: None,
            });
        }
        Ok(self.exact.clone())
    }
}

struct Standing {
    mandate: MandateRefV1,
}

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> std::result::Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.into(),
            resolution: StandingResolutionRefV1::from_digest(Digest::hash_domain(
                "ag.glass-heron.standing-resolution/v1",
                request.proposal.as_str().as_bytes(),
            )),
            currentness: StandingCurrentnessRefV1::from_digest(Digest::hash_domain(
                "ag.glass-heron.standing-currentness/v1",
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
            expires_at_unix_ms: request.now_unix_ms + TTL,
        })
    }
}

fn typed_resolution(
    key: OccurrenceKeyV1,
    observation: &str,
    subject: &str,
    basis_type: &str,
    basis_identity: &str,
) -> Result<VersionedObservationResolutionV1> {
    let now = now_ms()?;
    let basis =
        TypedOpaqueObservationBasisV1::new(basis_type.into(), Digest::parse(basis_identity)?)
            .map_err(anyhow::Error::msg)?;
    Ok(ObservationResolutionV3 {
        schema: OBSERVATION_RESOLUTION_SCHEMA_V3.into(),
        key,
        observation: ObservationRefV1::from_digest(Digest::parse(observation)?),
        currentness: ObservationCurrentnessRefV1::from_digest(Digest::hash_domain(
            "ag.glass-heron.currentness/v1",
            format!("{basis_type}:{basis_identity}:{now}").as_bytes(),
        )),
        normalized_preconditions: PreconditionBasisRefV1::from_digest(
            basis.binding_digest().map_err(anyhow::Error::msg)?,
        ),
        basis,
        resolver_id: OBSERVATION_RESOLVER.into(),
        subject: Digest::parse(subject)?,
        status: TypedObservationStatusV1::Current,
        resolved_at_unix_ms: now,
        fresh_until_unix_ms: now + TTL,
    }
    .into())
}

fn build_contract(
    packet: &CampaignPacketV1,
    start_path: &Path,
) -> Result<ProductionCampaignLifecycleV1> {
    let subject = packet.stages[0].executor_plan_template["subject"]
        .as_str()
        .context("subject")?
        .to_owned();
    let occurrences = [
        Uuid::parse_str("00000000-0000-4000-8000-00000000c001")?,
        Uuid::parse_str("00000000-0000-4000-8000-00000000c002")?,
        Uuid::parse_str("00000000-0000-4000-8000-00000000c003")?,
    ];
    let mandate = label("human-campaign-mandate").to_string();
    let root_observation = label("verified-root-observation").to_string();
    let start_bytes = fs::read(start_path)?;
    let verified_start = VerifiedCampaignStartBasisV1 {
        schema: String::new(),
        basis_id: String::new(),
        campaign_id: packet.campaign_id.clone(),
        campaign_packet_id: packet.packet_id.clone(),
        stage_1_work: packet.stages[0].work.clone(),
        subject: subject.clone(),
        scope: packet.stages[0].executor_plan_template["scope"]
            .as_str()
            .context("scope")?
            .into(),
        initial_occurrence: occurrences[0].to_string(),
        mandate: mandate.clone(),
        observation: root_observation.clone(),
        observation_resolver_id: OBSERVATION_RESOLVER.into(),
        standing_resolver_id: STANDING_RESOLVER.into(),
        human_decision: Digest::hash_bytes(&start_bytes).to_string(),
        human_principal: label("controlling-workspace-human").to_string(),
        human_verification: Digest::hash_domain(
            "ag.glass-heron.human-start-verification/v1",
            &start_bytes,
        )
        .to_string(),
        verification_profile: "ag.human-campaign-start-verification/v1".into(),
        decided_at_unix_ms: now_ms()?,
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
    .seal()?;
    let observations = [
        root_observation,
        packet.stages[0].reservation.reservation_id.clone(),
        packet.stages[1].reservation.reservation_id.clone(),
    ];
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
                .expect("work schema")
                .into(),
            executor_plan_template_sha256: frozen.executor_plan_template_sha256.clone(),
            subject: subject.clone(),
            scope: frozen.executor_plan_template["scope"]
                .as_str()
                .expect("scope")
                .into(),
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
    Ok(ProductionCampaignLifecycleV1 {
        schema: String::new(),
        lifecycle_id: String::new(),
        campaign_id: packet.campaign_id.clone(),
        campaign_packet_id: packet.packet_id.clone(),
        program: label("production-program").to_string(),
        verified_start,
        stages,
        terminal: HumanRequiredLawV1 {
            terminal_packet_id: label("terminal-human-required-law").to_string(),
            stage_3_occurrence: occurrences[2].to_string(),
            reservation: packet.stages[2].reservation.reservation_id.clone(),
            observation: packet.stages[2].reservation.reservation_id.clone(),
            observation_resolver_id: OBSERVATION_RESOLVER.into(),
        },
    }
    .seal(packet)?)
}

fn catalog(
    stage: &ProductionStageLawV1,
    basis_type: &str,
    basis_identity: &str,
) -> Result<ExactWorkCatalogV2> {
    Ok(ExactWorkCatalogV2 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V2.into(),
        entries: BTreeMap::from([(
            stage.executor_work_schema.clone(),
            ExactWorkCatalogEntryV2 {
                work_schema: stage.executor_work_schema.clone(),
                subject: Digest::parse(&stage.subject)?,
                scope: Digest::parse(&stage.scope)?,
                observation_basis: ExactObservationBasisRequirementV1::TypedBasis(
                    TypedOpaqueObservationBasisV1::new(
                        basis_type.into(),
                        Digest::parse(basis_identity)?,
                    )
                    .map_err(anyhow::Error::msg)?,
                ),
            },
        )]),
    })
}

fn write_docket_resolver(path: &Path) -> Result<()> {
    fs::write(
        path,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256((label+":"+i["issuance"]).encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("resolution"),"currentness":d("currentness"),"execution_standing":d("execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+300000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn nightshift_resolution(
    resolver: &Path,
    store: &Path,
    binding: &Path,
    key: &OccurrenceKeyV1,
    observation: &str,
    subject: &str,
) -> Result<VersionedObservationResolutionV1> {
    let request = json!({
        "schema":"ag.governed-loop.observation-request/v1",
        "key":{"campaign":key.campaign.as_str(),"occurrence":key.occurrence.to_string()},
        "observation":observation,"subject":subject,"now_unix_ms":now_ms()?
    });
    let mut child = Command::new(resolver)
        .args([
            "--store",
            store.to_str().context("store")?,
            "--resolver-id",
            OBSERVATION_RESOLVER,
            "--default-ttl-ms",
            "86400000",
            "--reservation-qualification-binding",
            binding.to_str().context("binding")?,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("resolver stdin")?
        .write_all(&serde_jcs::to_vec(&request)?)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "Nightshift resolver refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn main() -> Result<()> {
    let root = PathBuf::from(std::env::var("GH_ROOT").context("GH_ROOT")?);
    let packet_path = PathBuf::from(std::env::var("GH_PACKET").context("GH_PACKET")?);
    let start_path = PathBuf::from(std::env::var("GH_START").context("GH_START")?);
    ensure!(
        !root.join("campaign.sqlite3").exists(),
        "campaign already started"
    );
    fs::create_dir_all(&root)?;
    let packet: CampaignPacketV1 = serde_json::from_slice(&fs::read(&packet_path)?)?;
    packet.validate().map_err(anyhow::Error::msg)?;
    let contract = build_contract(&packet, &start_path)?;
    write_jcs(&root.join("production-lifecycle.v1.json"), &contract)?;
    let journal_path = root.join("lifecycle.sqlite3");
    let mut journal = ProductionLifecycleJournalV1::create(&journal_path, &contract)?;
    ensure!(
        journal.record_verified_start(&contract.verified_start)?,
        "verified start replay"
    );

    let fixture = PathBuf::from(&packet.workspace);
    let docket = PathBuf::from(std::env::var("GH_DOCKET_BIN")?);
    let executor = PathBuf::from(std::env::var("GH_EXECUTOR_BIN")?);
    let nq = PathBuf::from(std::env::var("GH_NQ_BIN")?);
    let nightshift = PathBuf::from(std::env::var("GH_NIGHTSHIFT_BIN")?);
    let ns_resolver = PathBuf::from(std::env::var("GH_NIGHTSHIFT_RESOLVER_BIN")?);
    let docket_state = root.join("docket-state");
    let resolver_path = root.join("docket-standing-resolver");
    write_docket_resolver(&resolver_path)?;

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow!("key generation"))?;
    let pair =
        Ed25519KeyPair::from_pkcs8(key_document.as_ref()).map_err(|_| anyhow!("key parse"))?;
    let key_path = root.join("ag-issuer.pk8");
    fs::write(&key_path, key_document.as_ref())?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    let trust_path = root.join("docket-trust.json");
    write_jcs(
        &trust_path,
        &json!({"issuers":[{
            "issuer_principal":"ag-glass-heron",
            "key_id":"glass-heron-key-1",
            "public_key":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        }]}),
    )?;

    let (mut predecessor_head, mut predecessor_tree) =
        match &packet.stages[0].reservation.predecessor {
            PredecessorBindingV1::InitialGit { head, tree } => (head.clone(), tree.clone()),
            _ => bail!("Stage 1 predecessor is not literal"),
        };
    ensure!(
        git(&fixture, &["rev-parse", "HEAD"])? == predecessor_head.digest,
        "fixture HEAD substitution"
    );
    ensure!(
        git(&fixture, &["rev-parse", "HEAD^{tree}"])? == predecessor_tree.digest,
        "fixture tree substitution"
    );

    let mut current_plan = materialize_executor_plan_template(
        &packet.stages[0].executor_plan_template,
        &packet.stages[0].reservation,
        predecessor_head.clone(),
        predecessor_tree.clone(),
    )
    .map_err(anyhow::Error::msg)?;
    let database = root.join("campaign.sqlite3");
    let first = &contract.stages[0];
    let mut engine = CampaignEngineV1::create(
        &database,
        CampaignId::from_digest(Digest::parse(&contract.campaign_id)?),
        OccurrenceId::from_uuid(Uuid::parse_str(&first.occurrence)?),
        ProgramBasisRefV1::from_digest(Digest::parse(&contract.program)?),
        Digest::parse(&executor_plan_identity(&current_plan).map_err(anyhow::Error::msg)?)?,
        ResidualSetV1::default(),
        LoopBudgetV1 {
            retry_limit: 0,
            retries_used: 0,
            probe_limit: 0,
            probes_used: 0,
            escalation_limit: 0,
            escalations_used: 0,
        },
        now_ms()?,
    )?;
    let mandate = MandateRefV1::from_digest(Digest::parse(&first.mandate)?);
    let mut prior_qualification: Option<Value> = None;
    let mut next_observation: Option<VersionedObservationResolutionV1> = None;
    let ns_store = root.join("nightshift-realizations.sqlite3");
    let mut summaries = Vec::new();
    let mut terminal = None;

    for index in 0..3 {
        let frozen = &packet.stages[index];
        let stage = &contract.stages[index];
        let stage_dir = root.join(format!("stage-{}", index + 1));
        let plan_path = stage_dir.join("executor-plan.v2.json");
        write_jcs(&plan_path, &current_plan)?;
        let plan_id = executor_plan_identity(&current_plan).map_err(anyhow::Error::msg)?;
        let (basis_type, basis_identity, exact) = if index == 0 {
            let basis_identity = contract.verified_start.basis_id.as_str();
            (
                VERIFIED_CAMPAIGN_START_BASIS_TYPE_V1,
                basis_identity,
                typed_resolution(
                    engine.current()?.key().clone(),
                    &stage.observation,
                    &stage.subject,
                    VERIFIED_CAMPAIGN_START_BASIS_TYPE_V1,
                    basis_identity,
                )?,
            )
        } else {
            (
                RESERVED_APPLICABILITY_BASIS_TYPE_V1,
                packet.stages[index - 1].reservation.reservation_id.as_str(),
                next_observation
                    .take()
                    .context("prior Nightshift resolution absent")?,
            )
        };
        let mut observation = Observation { exact };
        let proposal = ExactWorkProposalV1::new(
            CampaignId::from_digest(Digest::parse(&contract.campaign_id)?),
            Digest::parse(&stage.subject)?,
            Digest::parse(&stage.scope)?,
            stage.executor_work_schema.clone(),
            Digest::parse(&plan_id)?,
            None,
        )?;
        engine.record_proposal(
            ObservationRefV1::from_digest(Digest::parse(&stage.observation)?),
            proposal,
            if index == 0 {
                ProposalClassV1::Initial
            } else {
                ProposalClassV1::Successor
            },
            &mut observation,
            OBSERVATION_RESOLVER,
            now_ms()?,
        )?;
        engine = CampaignEngineV1::open(&database)?;
        engine.require_standing(now_ms()?)?;
        engine = CampaignEngineV1::open(&database)?;
        let exact_catalog = catalog(stage, basis_type, basis_identity)?;
        let mut standing = Standing {
            mandate: mandate.clone(),
        };
        engine.decide_with_catalog_v2(
            &mut observation,
            &mut standing,
            &exact_catalog,
            None,
            OBSERVATION_RESOLVER,
            STANDING_RESOLVER,
            TTL,
            now_ms()?,
        )?;
        engine = CampaignEngineV1::open(&database)?;
        let authorized = engine.authorize_with_catalog_v2(
            &mut observation,
            &mut standing,
            &exact_catalog,
            None,
            OBSERVATION_RESOLVER,
            STANDING_RESOLVER,
            TTL,
            now_ms()?,
        )?;
        journal.record_issuance(stage.ordinal, &authorized, &current_plan)?;
        journal = ProductionLifecycleJournalV1::open(&journal_path)?;

        let signer = AgIssuanceSignerV1::from_pkcs8(
            "ag-glass-heron",
            "glass-heron-key-1",
            &fs::read(&key_path)?,
        )?;
        let mut docket_port = CommandDocketCustodyPortV1::new(
            &docket,
            &docket_state,
            &trust_path,
            &resolver_path,
            &executor,
            &plan_path,
            signer,
        );
        engine = CampaignEngineV1::open(&database)?;
        let dispatched = engine.dispatch(&mut docket_port, now_ms()?)?;
        journal.record_docket_custody(stage.ordinal, &dispatched, &current_plan)?;
        journal = ProductionLifecycleJournalV1::open(&journal_path)?;
        engine = CampaignEngineV1::open(&database)?;
        let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut docket_port, now_ms()?)?
        else {
            bail!("Stage {} did not settle definitely", index + 1);
        };
        ensure!(
            settled.settlement().context("settlement")?.outcome == KnownOutcomeV1::Success,
            "Stage {} executor did not succeed",
            index + 1
        );
        journal.record_settlement(stage.ordinal, &settled, &current_plan)?;
        journal = ProductionLifecycleJournalV1::open(&journal_path)?;

        let result_head = git(&fixture, &["rev-parse", "HEAD"])?;
        let result_tree = git(&fixture, &["rev-parse", "HEAD^{tree}"])?;
        ensure!(
            git(&fixture, &["status", "--porcelain"])?.is_empty(),
            "fixture dirty after application"
        );
        let gate_started = now_ms()?;
        let gate = Command::new("/usr/bin/python3")
            .args(["-m", "unittest", "discover", "-s", "tests", "-v"])
            .current_dir(&fixture)
            .env_clear()
            .envs([
                ("HOME", "/nonexistent"),
                ("PATH", "/usr/bin:/bin"),
                ("LC_ALL", "C"),
            ])
            .output()?;
        let gate_finished = now_ms()?;
        ensure!(
            gate.status.success(),
            "Stage {} factual gate failed: {}",
            index + 1,
            String::from_utf8_lossy(&gate.stderr)
        );

        let custody = settled.docket_custody().context("custody")?;
        let attempt = custody.attempt.as_str().to_owned();
        let executor_store = PathBuf::from(
            current_plan["attempt_store"]
                .as_str()
                .context("attempt store")?,
        );
        let connection = Connection::open(&executor_store)?;
        let (porter_run, record_sha): (String, String) = connection.query_row(
            "SELECT porter_run,porter_record_sha256 FROM attempt WHERE attempt=?1",
            [&attempt],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let profile = materialize_nq_profile_template(
            &frozen.nq_profile_template,
            &frozen.reservation,
            &packet.packet_id,
            predecessor_head.clone(),
            predecessor_tree.clone(),
        )
        .map_err(anyhow::Error::msg)?;
        let profile_path = stage_dir.join("nq-profile.v2.json");
        let evidence_path = stage_dir.join("nq-evidence.v2.json");
        let receipt_path = stage_dir.join("nq-receipt.v2.json");
        write_jcs(&profile_path, &profile)?;
        let profile_sha = sha(&serde_jcs::to_vec(&profile)?);
        let evidence = json!({
            "schema":"nq-ng.campaign-stage-realization-evidence/v2",
            "evidence_id":format!("glass-heron.real-stage-{}",index+1),
            "profile_id":profile["profile_id"],"profile_sha256":profile_sha,
            "evidence_reservation":frozen.reservation.reservation_id,
            "campaign_packet_sha256":packet.packet_id,"stage_id":frozen.stage_id,
            "repository_id":packet.repository_id,"repository_ref":packet.repository_ref,
            "predecessor_qualification":prior_qualification.clone(),
            "realizations":[{
                "evidence_reservation":frozen.reservation.reservation_id,
                "docket_attempt":attempt,
                "executor_plan_template":frozen.executor_plan_template_sha256,
                "executor_plan":plan_id,
                "docket_settlement":settled.settlement().unwrap().settlement.as_str(),
                "porter_run_id":porter_run,
                "porter_record_sha256":format!("sha256:{record_sha}"),
                "executor_receipt":settled.settlement().unwrap().receipt.as_str(),
                "predecessor_head":predecessor_head,"predecessor_tree":predecessor_tree,
                "result_head":{"object_format":"sha1","digest":result_head},
                "result_tree":{"object_format":"sha1","digest":result_tree}
            }],
            "producer":profile["expected_evidence_producer"],
            "qualification_started_at_unix_ms":gate_started,
            "qualification_finished_at_unix_ms":gate_finished,
            "gates":[{
                "ordinal":0,"gate_id":"python-unittest",
                "context":profile["ordered_gates"][0]["context"],
                "started_at_unix_ms":gate_started,"finished_at_unix_ms":gate_finished,
                "outcome":{"outcome":"COMPLETED","exit_code":0,
                    "stdout_sha256":sha(&gate.stdout),"stderr_sha256":sha(&gate.stderr)}
            }],
            "artifacts":[],
            "workspace_custody":[{
                "predicate":"REPOSITORY_IDENTITY_MATCHES",
                "observation_sha256":sha(format!("{}:{result_head}:{result_tree}",packet.repository_id).as_bytes()),
                "outcome":{"outcome":"PASSED"}
            }],
            "observed_clean_worktree":true
        });
        write_jcs(&evidence_path, &evidence)?;
        let evaluated = now_ms()?;
        checked(
            Command::new(&nq).args([
                "campaign-stage-realization",
                "evaluate",
                "--profile",
                profile_path.to_str().unwrap(),
                "--evidence",
                evidence_path.to_str().unwrap(),
                "--evaluated-at-unix-ms",
                &evaluated.to_string(),
                "--output",
                receipt_path.to_str().unwrap(),
            ]),
            "NQ realization evaluation",
        )?;
        let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        ensure!(
            receipt["status"] == "QUALIFIED",
            "Stage {} NQ status was {}",
            index + 1,
            receipt["status"]
        );
        prior_qualification =
            Some(json!({"profile":profile,"evidence":evidence,"receipt":receipt}));

        let mut applicability = json!({
            "schema":"nightshift.repository-qualification-reservation-applicability-profile/v1",
            "profile_id":"","evidence_reservation":frozen.reservation.reservation_id,
            "expected_nq_profile_id":receipt["profile_id"],
            "expected_nq_profile_sha256":receipt["profile_sha256"],
            "expected_nq_evaluator_id":receipt["evaluator_id"],
            "expected_nq_evaluator_version":receipt["evaluator_version"],
            "expected_nq_evaluator_executable_sha256":receipt["evaluator_executable_sha256"],
            "source_campaign_id":contract.campaign_id,"source_occurrence_id":stage.occurrence,
            "source_attempt_id":attempt,
            "source_settlement_id":settled.settlement().unwrap().settlement.as_str(),
            "subject_digest":stage.subject,"resolver_id":OBSERVATION_RESOLVER,
            "max_age_ms":86400000
        });
        let mut preimage = applicability.clone();
        preimage.as_object_mut().unwrap().remove("profile_id");
        applicability["profile_id"] = Value::String(sha(&serde_jcs::to_vec(&preimage)?));
        let applicability_path = stage_dir.join("nightshift-applicability.v1.json");
        write_jcs(&applicability_path, &applicability)?;
        let ingest = checked(
            Command::new(&nightshift).args([
                "--store",
                ns_store.to_str().unwrap(),
                "reservation-qualification",
                "ingest",
                "--applicability",
                applicability_path.to_str().unwrap(),
                "--nq-profile",
                profile_path.to_str().unwrap(),
                "--nq-evidence",
                evidence_path.to_str().unwrap(),
                "--nq-receipt",
                receipt_path.to_str().unwrap(),
                "--nq-executable",
                nq.to_str().unwrap(),
            ]),
            "Nightshift reservation ingest",
        )?;
        fs::write(stage_dir.join("nightshift-ingest.json"), &ingest.stdout)?;
        let snapshot_value = serde_json::to_value(&settled)?;
        let source = json!({
            "schema":"nightshift.ag_occurrence_reference.v1",
            "campaign_id":contract.campaign_id,"occurrence_id":stage.occurrence,
            "state_digest":settled.state_digest().as_str(),
            "snapshot_digest":sha(&serde_jcs::to_vec(&snapshot_value)?),
            "program_counter":"settled_observation_required",
            "docket_attempt_id":attempt,
            "settlement_id":settled.settlement().unwrap().settlement.as_str(),
            "exact_snapshot":snapshot_value
        });
        let binding = json!({
            "schema":"nightshift.repository-qualification-reservation-resolver-binding/v1",
            "applicability":applicability,"source":source
        });
        let binding_path = stage_dir.join("nightshift-resolver-binding.v1.json");
        write_jcs(&binding_path, &binding)?;
        let realization_observation = if index < 2 {
            &contract.stages[index + 1].observation
        } else {
            &contract.terminal.observation
        };
        let source_resolution = nightshift_resolution(
            &ns_resolver,
            &ns_store,
            &binding_path,
            settled.key(),
            realization_observation,
            &stage.subject,
        )?;
        write_jcs(
            &stage_dir.join("nightshift-source-resolution.v3.json"),
            &source_resolution,
        )?;
        journal.record_reservation_current(
            stage.ordinal,
            &settled,
            &source_resolution,
            now_ms()?,
        )?;
        journal = ProductionLifecycleJournalV1::open(&journal_path)?;
        summaries.push(json!({
            "ordinal":index+1,"reservation":frozen.reservation.reservation_id,
            "porter_run":porter_run,"docket_attempt":attempt,"executor_plan":plan_id,
            "settlement":settled.settlement().unwrap().settlement.as_str(),
            "executor_receipt":settled.settlement().unwrap().receipt.as_str(),
            "nq_receipt":receipt["receipt_sha256"],
            "result_head":result_head,"result_tree":result_tree,
            "gate_stdout_sha256":sha(&gate.stdout),"gate_stderr_sha256":sha(&gate.stderr)
        }));

        if index < 2 {
            predecessor_head = GitObjectV1 {
                object_format: "sha1".into(),
                digest: result_head,
            };
            predecessor_tree = GitObjectV1 {
                object_format: "sha1".into(),
                digest: result_tree,
            };
            current_plan = materialize_executor_plan_template(
                &packet.stages[index + 1].executor_plan_template,
                &packet.stages[index + 1].reservation,
                predecessor_head.clone(),
                predecessor_tree.clone(),
            )
            .map_err(anyhow::Error::msg)?;
            engine = CampaignEngineV1::open(&database)?;
            let opened = engine.open_continuation(
                OccurrenceId::from_uuid(Uuid::parse_str(&contract.stages[index + 1].occurrence)?),
                Digest::parse(&executor_plan_identity(&current_plan).map_err(anyhow::Error::msg)?)?,
                now_ms()?,
            )?;
            journal.record_continuation_opened(
                contract.stages[index + 1].ordinal,
                &opened,
                &current_plan,
            )?;
            journal = ProductionLifecycleJournalV1::open(&journal_path)?;
            next_observation = Some(nightshift_resolution(
                &ns_resolver,
                &ns_store,
                &binding_path,
                opened.key(),
                &contract.stages[index + 1].observation,
                &contract.stages[index + 1].subject,
            )?);
        } else {
            terminal = Some((settled, source_resolution));
        }
    }

    let (settled, terminal_resolution) = terminal.context("terminal evidence")?;
    let (_, human_required) =
        journal.record_human_required(&settled, &terminal_resolution, now_ms()?)?;
    write_jcs(
        &root.join("human-required-receipt.v1.json"),
        &human_required,
    )?;
    write_jcs(&root.join("lifecycle-events.v1.json"), &journal.events()?)?;
    let replay = CampaignEngineV1::open(&database)?.replay()?;
    ensure!(
        replay.ag_spends == 3 && replay.docket_attempts == 3 && replay.settlements == 3,
        "AG cardinality mismatch"
    );
    let summary = json!({
        "schema":"ag.glass-heron.real-w7-specimen/v1","campaign":"GLASS-HERON",
        "packet_id":packet.packet_id,"lifecycle_id":contract.lifecycle_id,
        "session_manifest_sha256":packet.stages[0].worker_session_manifest_sha256,
        "stages":summaries,
        "cardinality":{"worker_sessions":1,"reservations":3,"porter_runs":3,
            "ag_spends":replay.ag_spends,"issuances":3,"docket_attempts":replay.docket_attempts,
            "codex_invocations":3,"candidate_applications":3,"nq_qualified":3,
            "nightshift_current_realizations":3,"human_required":1,"stage_4":0},
        "human_required_receipt":human_required.receipt_id,
        "final_head":git(&fixture,&["rev-parse","HEAD"])?,
        "final_tree":git(&fixture,&["rev-parse","HEAD^{tree}"])?
    });
    write_jcs(&root.join("w7-summary.v1.json"), &summary)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
