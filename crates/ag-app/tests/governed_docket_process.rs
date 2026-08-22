//! Opt-in adjacent-process development test for the canonical execution seam.
//!
//! The normal workspace suite does not build adjacent repositories. Run this
//! ignored test with exact `AG_DOCKET_BIN` and `AG_EFFECTD_BIN` paths after
//! building Docket and AG. It is development evidence, not qualification.

#![allow(
    clippy::too_many_lines,
    reason = "the opt-in cross-process test keeps the entire authority chain visible in one scenario"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

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
use uuid::Uuid;

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-process-test/v1", label.as_bytes())
}

/// The resolver identity this test configures the engine to expect.
const OBSERVATION_RESOLVER_ID: &str = "test.observation-resolver/v1";

fn clean_basis() -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.to_owned(),
        rule: DecisionBasisRuleV1 {
            id: DECISION_BASIS_RULE_ID_V1.to_owned(),
            version: DECISION_BASIS_RULE_VERSION_V1.to_owned(),
            digest: decision_basis_rule_digest_v1().as_str().to_owned(),
        },
        atoms: std::collections::BTreeSet::from([
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
                basis.decision_basis_digest().unwrap(),
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

/// The standing resolver identity this test configures the engine to expect.
const STANDING_RESOLVER_ID: &str = "test.standing-resolver/v1";
/// Maximum accepted standing-answer lifetime in this test.
const MAX_STANDING_TTL_MS: u64 = 60_000;

impl StandingResolverV1 for Standing {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        Ok(CurrentStandingResolutionV2 {
            schema: STANDING_RESOLUTION_SCHEMA_V2.to_owned(),
            resolution: StandingResolutionRefV1::from_digest(digest("ag-standing-resolution")),
            currentness: StandingCurrentnessRefV1::from_digest(digest("ag-standing-current")),
            mandate: MandateRefV1::from_digest(digest("mandate")),
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

#[test]
#[ignore = "requires adjacent Docket binary; see module documentation"]
fn signed_issuance_crosses_docket_and_effectd_once_then_settles() {
    let docket = PathBuf::from(std::env::var_os("AG_DOCKET_BIN").expect("AG_DOCKET_BIN"));
    let effectd = PathBuf::from(std::env::var_os("AG_EFFECTD_BIN").expect("AG_EFFECTD_BIN"));
    assert!(docket.is_absolute() && effectd.is_absolute());

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact_path = root.path().join("artifact");
    let target_path = root.path().join("target");
    std::fs::write(&artifact_path, b"governed-process-effect\n").unwrap();
    let content = Digest::hash_bytes(b"governed-process-effect\n");
    let subject = digest("subject");
    let scope = digest("scope");
    let plan = EffectExecutorPlanV1 {
        schema: EFFECT_EXECUTOR_PLAN_SCHEMA_V1.to_owned(),
        attempt_store: root.path().join("effect-attempts.sqlite"),
        subject: subject.clone(),
        scope: scope.clone(),
        effect_index: 0,
        effect: CanonicalEffectV1::ManagedFilePut {
            target: TargetId::parse("governed-process-test").unwrap(),
            path: target_path.display().to_string(),
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
            max_content_bytes: 1024,
            trusted_ancestor_uid: std::fs::metadata("/").unwrap().uid(),
            trusted_parent_uid: nix::unistd::Uid::current().as_raw(),
            require_private_parent_writes: true,
        },
        preparation_checkpoint: None,
    };
    let plan_path = root.path().join("effect-plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();
    let work = plan.identity().unwrap();

    let campaign = CampaignId::from_digest(digest("campaign"));
    let occurrence = OccurrenceId::from_uuid(Uuid::from_u128(1));
    let database = root.path().join("ag-campaign.sqlite");
    let mut engine = CampaignEngineV1::create(
        &database,
        campaign.clone(),
        occurrence,
        ProgramBasisRefV1::from_digest(digest("program")),
        work.clone(),
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
    .unwrap();
    let proposal = ExactWorkProposalV1::new(
        campaign,
        subject.clone(),
        scope.clone(),
        EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
        work,
        None,
    )
    .unwrap();
    let catalog = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        entries: BTreeMap::from([(
            EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
                subject,
                scope,
                precondition: WorkPreconditionV1::default(),
            },
        )]),
    };
    let mut observation = Observation;
    let mut standing = Standing;
    engine
        .record_proposal(
            ObservationRefV1::from_digest(digest("observation")),
            proposal,
            ProposalClassV1::Initial,
            &mut observation,
            OBSERVATION_RESOLVER_ID,
            2,
        )
        .unwrap();
    engine.require_standing(3).unwrap();
    engine
        .decide(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            4,
        )
        .unwrap();
    engine
        .authorize(
            &mut observation,
            &mut standing,
            &catalog,
            None,
            OBSERVATION_RESOLVER_ID,
            STANDING_RESOLVER_ID,
            MAX_STANDING_TTL_MS,
            5,
        )
        .unwrap();

    let resolver_path = root.path().join("docket-standing-resolver");
    std::fs::write(
        &resolver_path,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("resolution"),"currentness":d("currentness"),"execution_standing":d("execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    std::fs::set_permissions(&resolver_path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
    let signer = AgIssuanceSignerV1::from_pkcs8("ag-test", "key-1", key_document.as_ref()).unwrap();
    let trust_path = root.path().join("docket-trust.json");
    let trust = serde_json::json!({"issuers":[{
        "issuer_principal":"ag-test",
        "key_id":"key-1",
        "public_key":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
    }]});
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();
    let mut custody = CommandDocketCustodyPortV1::new(
        docket,
        root.path().join("docket-state"),
        trust_path,
        resolver_path,
        effectd,
        plan_path,
        signer,
    );

    let dispatched = engine.dispatch(&mut custody, 6).unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    let DocketProgressV1::Settled(settled) = engine.poll_docket(&mut custody, 7).unwrap() else {
        panic!("Docket must return its exact terminal executor settlement")
    };
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"governed-process-effect\n"
    );
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert_eq!(engine.replay().unwrap().docket_attempts, 1);
    assert_eq!(engine.replay().unwrap().settlements, 1);

    std::fs::write(&target_path, b"must-not-run-again\n").unwrap();
    assert!(matches!(
        engine.poll_docket(&mut custody, 8).unwrap(),
        DocketProgressV1::Settled(_)
    ));
    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"must-not-run-again\n"
    );
    drop(engine);
    let reopened = CampaignEngineV1::open(&database).unwrap();
    assert_eq!(
        reopened.current().unwrap().program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
}
