//! Runnable AG-ng + Docket adoption example using a disposable managed file.
//!
//! The harness supplies deterministic observation/standing policy and drives
//! the real AG durable engine, signed Docket process boundary, and ag-effectd
//! executor.  No model or network service is involved.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use ag_app::effect_executor_adapter::{
    EFFECT_EXECUTOR_PLAN_SCHEMA_V1, EFFECT_EXECUTOR_WORK_SCHEMA_V1, EffectArtifactFileV1,
    EffectExecutorPlanV1, EffectFilePolicyV1,
};
use ag_app::governed_loop::{
    CampaignEngineV1, DocketProgressV1, EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1,
    ExactWorkCatalogV1, WorkPreconditionV1,
};
use ag_app::governed_ports::{AgIssuanceSignerV1, CommandDocketCustodyPortV1};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_effect::{CanonicalEffectV1, TargetId};
use ag_primitives::{Digest, JcsDocument};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};
use uuid::Uuid;

const OBSERVATION_RESOLVER_ID: &str = "example.observation-resolver/v1";
const STANDING_RESOLVER_ID: &str = "example.ag-standing-resolver/v1";
const WORK_SCHEMA: &str = EFFECT_EXECUTOR_WORK_SCHEMA_V1;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-docket-adoption-example/v1", label.as_bytes())
}

fn clean_basis() -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.to_owned(),
        rule: DecisionBasisRuleV1 {
            id: DECISION_BASIS_RULE_ID_V1.to_owned(),
            version: DECISION_BASIS_RULE_VERSION_V1.to_owned(),
            digest: decision_basis_rule_digest_v1().as_str().to_owned(),
        },
        atoms: BTreeSet::from([
            "condition.clean".to_owned(),
            "delivery.not_required".to_owned(),
        ]),
    }
}

struct Observation;

impl ObservationResolverV1 for Observation {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        let basis = clean_basis();
        Ok(ObservationResolutionV2 {
            schema: OBSERVATION_RESOLUTION_SCHEMA_V2.to_owned(),
            key: request.key.clone(),
            observation: request.observation.clone(),
            currentness: ObservationCurrentnessRefV1::from_digest(digest("observation-current")),
            normalized_preconditions: PreconditionBasisRefV1::from_digest(
                basis
                    .decision_basis_digest()
                    .map_err(|_| ExternalBoundaryErrorV1::Refused {
                        code: "example-basis".to_owned(),
                        evidence: None,
                    })?,
            ),
            basis,
            resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
            subject: request.subject.clone(),
            status: ObservationStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            fresh_until_unix_ms: request.now_unix_ms + 60_000,
        }
        .into())
    }
}

struct Standing;

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("ag-standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("ag-standing-current")),
            mandate: MandateRefV1::from_digest(digest("example-mandate")),
            key: request.key.clone(),
            observation: request.observation.clone(),
            proposal: request.proposal.clone(),
            subject: request.subject.clone(),
            scope: request.scope.clone(),
            resolver_id: STANDING_RESOLVER_ID.to_owned(),
            status: StandingStatusV1::Current,
            resolved_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms: request.now_unix_ms + 60_000,
        })
    }
}

struct Scenario {
    root: PathBuf,
    database: PathBuf,
    effect_path: PathBuf,
    plan_path: PathBuf,
    work: Digest,
    subject: Digest,
    scope: Digest,
    campaign: CampaignId,
}

impl Scenario {
    fn create(root: PathBuf, label: &str) -> Result<Self, String> {
        std::fs::create_dir(&root).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let content_bytes = format!("AG-ng + Docket permitted {label}\n").into_bytes();
        let artifact_path = root.join("proposed-content");
        let effect_path = root.join("observed-effect");
        std::fs::write(&artifact_path, &content_bytes).map_err(|error| error.to_string())?;
        let content = Digest::hash_bytes(&content_bytes);
        let subject = digest(&format!("{label}-subject"));
        let scope = digest(&format!("{label}-scope"));
        let attempt_store = root.join("executor-attempts.sqlite");
        let plan = EffectExecutorPlanV1 {
            schema: EFFECT_EXECUTOR_PLAN_SCHEMA_V1.to_owned(),
            attempt_store: attempt_store.clone(),
            subject: subject.clone(),
            scope: scope.clone(),
            effect_index: 0,
            effect: CanonicalEffectV1::ManagedFilePut {
                target: TargetId::parse(&format!("adoption-{label}"))
                    .map_err(|error| error.to_string())?,
                path: effect_path.display().to_string(),
                expected_content: None,
                content: content.clone(),
                mode: 0o600,
                uid: nix::unistd::Uid::current().as_raw(),
                gid: nix::unistd::Gid::current().as_raw(),
            },
            artifacts: vec![EffectArtifactFileV1 {
                digest: content,
                path: artifact_path,
            }],
            file_policy: EffectFilePolicyV1 {
                max_content_bytes: 4096,
                trusted_ancestor_uid: std::fs::metadata("/")
                    .map_err(|error| error.to_string())?
                    .uid(),
                trusted_parent_uid: nix::unistd::Uid::current().as_raw(),
                require_private_parent_writes: true,
            },
            preparation_checkpoint: None,
        };
        let plan_path = root.join("executor-plan.json");
        std::fs::write(
            &plan_path,
            JcsDocument::canonicalize(&plan)
                .map_err(|error| error.to_string())?
                .as_bytes(),
        )
        .map_err(|error| error.to_string())?;
        let work = plan.identity()?;
        Ok(Self {
            database: root.join("ag-campaign.sqlite"),
            effect_path,
            plan_path,
            work,
            subject,
            scope,
            campaign: CampaignId::from_digest(digest(&format!("{label}-campaign"))),
            root,
        })
    }

    fn engine(&self, occurrence: u128) -> Result<CampaignEngineV1, String> {
        CampaignEngineV1::create(
            &self.database,
            self.campaign.clone(),
            OccurrenceId::from_uuid(Uuid::from_u128(occurrence)),
            ProgramBasisRefV1::from_digest(digest("example-program")),
            self.work.clone(),
            ResidualSetV1::default(),
            LoopBudgetV1 {
                retry_limit: 1,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            1,
        )
        .map_err(|error| error.to_string())
    }

    fn proposal(&self) -> Result<ExactWorkProposalV1, String> {
        ExactWorkProposalV1::new(
            self.campaign.clone(),
            self.subject.clone(),
            self.scope.clone(),
            WORK_SCHEMA.to_owned(),
            self.work.clone(),
            None,
        )
        .map_err(|error| error.to_string())
    }

    fn catalog(&self, permit: bool) -> ExactWorkCatalogV1 {
        let schema = if permit {
            WORK_SCHEMA
        } else {
            "example.refused-work/v1"
        };
        ExactWorkCatalogV1 {
            schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
            entries: BTreeMap::from([(
                schema.to_owned(),
                ExactWorkCatalogEntryV1 {
                    work_schema: schema.to_owned(),
                    subject: self.subject.clone(),
                    scope: self.scope.clone(),
                    precondition: WorkPreconditionV1::default(),
                },
            )]),
        }
    }
}

struct DocketFiles {
    state: PathBuf,
    trust: PathBuf,
    resolver: PathBuf,
    signer: AgIssuanceSignerV1,
}

fn docket_files(root: &Path) -> Result<DocketFiles, String> {
    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "could not generate disposable Ed25519 key".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref())
        .map_err(|_| "could not parse disposable Ed25519 key".to_owned())?;
    let signer = AgIssuanceSignerV1::from_pkcs8(
        "ag-adoption-example",
        "disposable-key-1",
        key_document.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let trust = root.join("docket-trust.json");
    std::fs::write(
        &trust,
        serde_json::to_vec(&json!({"issuers":[{
            "issuer_principal":"ag-adoption-example",
            "key_id":"disposable-key-1",
            "public_key":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        }]}))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let resolver = root.join("docket-standing-resolver");
    std::fs::write(
        &resolver,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("resolution"),"currentness":d("currentness"),"execution_standing":d("execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .map_err(|error| error.to_string())?;
    std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    Ok(DocketFiles {
        state: root.join("docket-state"),
        trust,
        resolver,
        signer,
    })
}

fn port(
    docket: &Path,
    executor: &Path,
    scenario: &Scenario,
    files: DocketFiles,
) -> CommandDocketCustodyPortV1 {
    CommandDocketCustodyPortV1::new(
        docket,
        files.state,
        files.trust,
        files.resolver,
        executor,
        &scenario.plan_path,
        files.signer,
    )
}

fn authorize(
    engine: &mut CampaignEngineV1,
    scenario: &Scenario,
    permit: bool,
) -> Result<(), String> {
    let mut observation = Observation;
    let mut standing = Standing;
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation")),
            scenario.proposal()?,
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            2,
        )
        .map_err(|error| error.to_string())?;
    engine
        .require_standing(3)
        .map_err(|error| error.to_string())?;
    engine
        .decide(
            &mut observation,
            &mut standing,
            &scenario.catalog(permit),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            60_000,
            4,
        )
        .map_err(|error| error.to_string())?;
    engine
        .authorize(
            &mut observation,
            &mut standing,
            &scenario.catalog(permit),
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            60_000,
            5,
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn inspect_docket(docket: &Path, state: &Path, issuance: &str) -> Result<Value, String> {
    let output = Command::new(docket)
        .args([
            "governed-loop",
            "inspect",
            "--state",
            state.to_str().ok_or("Docket state path is not UTF-8")?,
            "--issuance",
            issuance,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\"'\"'"))
}

fn acknowledgement_loss_proxy(root: &Path, effectd: &Path) -> Result<PathBuf, String> {
    let proxy = root.join("acknowledgement-loss-executor");
    let program = format!(
        "#!/bin/sh\nset -eu\nreal={}\nop=$1\nplan=$2\ncase \"$op\" in\n  plan-id) exec \"$real\" plan-id \"$plan\";;\n  execute) \"$real\" execute \"$plan\" >/dev/null; echo 'simulated acknowledgement loss after executor outcome' >&2; exit 75;;\n  reconcile) exec \"$real\" reconcile \"$plan\";;\n  *) exit 64;;\nesac\n",
        shell_quote(effectd)
    );
    std::fs::write(&proxy, program).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    Ok(proxy)
}

fn require_absolute_executable(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("{label}: {error}"))?;
    let metadata = std::fs::metadata(&path).map_err(|error| format!("{label}: {error}"))?;
    if !path.is_absolute() || !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{label} is not an absolute executable file"));
    }
    Ok(path)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("adoption example failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let docket = require_absolute_executable(
        &PathBuf::from(
            args.next()
                .ok_or("usage: docket_file_harness DOCKET AG_EFFECTD OUTPUT")?,
        ),
        "Docket binary",
    )?;
    let effectd = require_absolute_executable(
        &PathBuf::from(
            args.next()
                .ok_or("usage: docket_file_harness DOCKET AG_EFFECTD OUTPUT")?,
        ),
        "ag-effectd binary",
    )?;
    let output = PathBuf::from(
        args.next()
            .ok_or("usage: docket_file_harness DOCKET AG_EFFECTD OUTPUT")?,
    );
    if args.next().is_some() || !output.is_absolute() || output.exists() {
        return Err("OUTPUT must be one absent absolute path".to_owned());
    }
    std::fs::create_dir(&output).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;

    let permitted = Scenario::create(output.join("permitted"), "permitted")?;
    let mut engine = permitted.engine(1)?;
    authorize(&mut engine, &permitted, true)?;
    let issuance = engine
        .current()
        .map_err(|error| error.to_string())?
        .issuance()
        .cloned()
        .ok_or("authorization did not retain an issuance")?;
    let files = docket_files(&permitted.root)?;
    let docket_state = files.state.clone();
    let mut custody_port = port(&docket, &effectd, &permitted, files);
    let dispatched = engine
        .dispatch(&mut custody_port, 6)
        .map_err(|error| error.to_string())?;
    let first_custody = dispatched
        .docket_custody()
        .cloned()
        .ok_or("Docket did not return custody")?;
    let DocketProgressV1::Settled(settled) = engine
        .poll_docket(&mut custody_port, 7)
        .map_err(|error| error.to_string())?
    else {
        return Err("permitted action did not settle".to_owned());
    };
    let permitted_replay = engine.replay().map_err(|error| error.to_string())?;
    if !permitted.effect_path.exists()
        || permitted_replay.ag_spends != 1
        || permitted_replay.docket_attempts != 1
        || permitted_replay.settlements != 1
    {
        return Err("permitted scenario cardinality or effect mismatch".to_owned());
    }

    use ag_campaign::governed::DocketCustodyPortV1 as _;
    let duplicate_custody = custody_port
        .accept_issuance(&issuance)
        .map_err(|error| format!("duplicate acceptance: {error:?}"))?;
    let duplicate_inspection = inspect_docket(&docket, &docket_state, issuance.issuance.as_str())?;
    if duplicate_custody != first_custody
        || duplicate_inspection["record"]["status"] != "settled"
        || engine
            .replay()
            .map_err(|error| error.to_string())?
            .docket_attempts
            != 1
    {
        return Err("duplicate issuance did not converge on retained custody".to_owned());
    }
    drop(engine);
    let reopened =
        CampaignEngineV1::open(&permitted.database).map_err(|error| error.to_string())?;
    if reopened
        .current()
        .map_err(|error| error.to_string())?
        .program_counter()
        != ProgramCounterV1::SettledObservationRequired
    {
        return Err("AG restart did not reconstruct the settled state".to_owned());
    }

    let refused = Scenario::create(output.join("refused"), "refused")?;
    let mut refused_engine = refused.engine(2)?;
    let refusal = authorize(&mut refused_engine, &refused, false);
    let refused_replay = refused_engine.replay().map_err(|error| error.to_string())?;
    if refusal.is_ok() || refused.effect_path.exists() || refused_replay.ag_spends != 0 {
        return Err("refused scenario reached authority or effect".to_owned());
    }

    let uncertain = Scenario::create(output.join("acknowledgement-loss"), "ack-loss")?;
    let proxy = acknowledgement_loss_proxy(&uncertain.root, &effectd)?;
    let mut uncertain_engine = uncertain.engine(3)?;
    authorize(&mut uncertain_engine, &uncertain, true)?;
    let uncertain_issuance = uncertain_engine
        .current()
        .map_err(|error| error.to_string())?
        .issuance()
        .cloned()
        .ok_or("uncertain scenario did not retain issuance")?;
    let files = docket_files(&uncertain.root)?;
    let uncertain_docket_state = files.state.clone();
    let mut uncertain_port = port(&docket, &proxy, &uncertain, files);
    uncertain_engine
        .dispatch(&mut uncertain_port, 6)
        .map_err(|error| error.to_string())?;
    let uncertain_inspection = inspect_docket(
        &docket,
        &uncertain_docket_state,
        uncertain_issuance.issuance.as_str(),
    )?;
    if uncertain_inspection["record"]["status"] != "indeterminate"
        || !uncertain.effect_path.exists()
    {
        return Err("simulated acknowledgement loss did not retain honest uncertainty".to_owned());
    }
    drop(uncertain_engine);
    let mut recovered =
        CampaignEngineV1::open(&uncertain.database).map_err(|error| error.to_string())?;
    let DocketProgressV1::Settled(reconciled) = recovered
        .poll_docket(&mut uncertain_port, 7)
        .map_err(|error| error.to_string())?
    else {
        return Err("read-only reconciliation did not settle retained evidence".to_owned());
    };
    let uncertain_replay = recovered.replay().map_err(|error| error.to_string())?;
    if uncertain_replay.ag_spends != 1
        || uncertain_replay.docket_attempts != 1
        || uncertain_replay.settlements != 1
    {
        return Err("reconciliation changed one-spend/one-attempt cardinality".to_owned());
    }

    let summary = json!({
        "schema": "ag-ng-docket-adoption-example/v1",
        "result": "passed",
        "output_root": output,
        "scenarios": {
            "permitted": {
                "effect": permitted.effect_path,
                "issuance": issuance.issuance.as_str(),
                "program_counter": format!("{:?}", settled.program_counter()),
                "ag_spends": permitted_replay.ag_spends,
                "docket_attempts": permitted_replay.docket_attempts,
                "settlements": permitted_replay.settlements
            },
            "refused_before_effect": {
                "effect_exists": refused.effect_path.exists(),
                "ag_spends": refused_replay.ag_spends,
                "reason": refusal.unwrap_err()
            },
            "duplicate": {
                "same_custody": duplicate_custody == first_custody,
                "docket_status": duplicate_inspection["record"]["status"],
                "docket_attempts": permitted_replay.docket_attempts
            },
            "acknowledgement_loss": {
                "fault": "executor outcome acknowledgement suppressed after ag-effectd durably recorded its result",
                "effect_existed_while_uncertain": true,
                "issuance": uncertain_issuance.issuance.as_str(),
                "docket_status_before_reconcile": uncertain_inspection["record"]["status"],
                "program_counter_after_restart_reconcile": format!("{:?}", reconciled.program_counter()),
                "ag_spends": uncertain_replay.ag_spends,
                "docket_attempts": uncertain_replay.docket_attempts,
                "settlements": uncertain_replay.settlements
            }
        }
    });
    let summary_path = output.join("summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summary).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?
    );
    Ok(())
}
