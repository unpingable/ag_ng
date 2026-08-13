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
    EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
};
use ag_app::governed_product::{
    CreateCampaignV1, GOVERNED_AG_POLICY_ROOT_SCHEMA_V1, GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1,
    GovernedAgPolicyRootV1, GovernedCampaignServiceV1, GovernedDocketAdapterRootV1,
    PinnedDeploymentFileV1,
};
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

fn pinned(path: PathBuf) -> PinnedDeploymentFileV1 {
    PinnedDeploymentFileV1 {
        identity: Digest::hash_bytes(&std::fs::read(&path).unwrap()),
        path,
    }
}

fn policy_root(
    directory: &std::path::Path,
    catalog: &ExactWorkCatalogV1,
) -> GovernedAgPolicyRootV1 {
    let clock = directory.join("ag-consequence-clock");
    std::fs::write(&clock, b"#!/bin/sh\nprintf '10000\\n'\n").unwrap();
    let observation = directory.join("ag-observation-resolver");
    std::fs::write(
        &observation,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.observation-resolution/v1","key":r["key"],"observation":r["observation"],"currentness":d("observation-current"),"normalized_preconditions":d("preconditions"),"subject":r["subject"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"fresh_until_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    let standing = directory.join("ag-standing-resolver");
    std::fs::write(
        &standing,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin)
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"ag.governed-loop.standing-resolution/v1","resolution":d("ag-standing-resolution"),"currentness":d("ag-standing-current"),"mandate":d("mandate"),"key":r["key"],"observation":r["observation"],"proposal":r["proposal"],"subject":r["subject"],"scope":r["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    for path in [&clock, &observation, &standing] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let catalog_path = directory.join("ag-exact-work-catalog.json");
    std::fs::write(
        &catalog_path,
        JcsDocument::canonicalize(catalog).unwrap().as_bytes(),
    )
    .unwrap();
    GovernedAgPolicyRootV1 {
        schema: GOVERNED_AG_POLICY_ROOT_SCHEMA_V1.to_owned(),
        policy_label: "qualification-fixture-not-human-authority".to_owned(),
        consequence_clock: pinned(clock),
        observation_resolver: pinned(observation),
        standing_resolver: pinned(standing),
        exact_work_catalog: pinned(catalog_path),
        controlling_review: None,
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
    let scope = CanonicalEffectScopeV1::new(
        "test-effect".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "fixtures/docket-process".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Create],
        }],
    )
    .unwrap();
    let plan = EffectExecutorPlanV1 {
        schema: EFFECT_EXECUTOR_PLAN_SCHEMA_V1.to_owned(),
        attempt_store: root.path().join("effect-attempts.sqlite"),
        subject: subject.clone(),
        scope: scope.digest(),
        journal_binding: ag_app::effect_executor_adapter::EffectExecutorJournalBindingV1 {
            resource: "repository".to_owned(),
            path: "fixtures/docket-process".to_owned(),
            operation: CanonicalEffectOperationV1::Create,
        },
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
    let proposal = ExactWorkProposalV1::new(
        campaign.clone(),
        subject.clone(),
        scope.clone(),
        EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
        work,
        ProposalGovernanceTermsV1 {
            nonclaims: vec![digest("development-process-fixture-not-authority")],
            expires_at_unix_ms: 4_000_000_000_000,
        },
        None,
    )
    .unwrap();
    let catalog = ExactWorkCatalogV1 {
        schema: EXACT_WORK_CATALOG_SCHEMA_V1.to_owned(),
        policy_basis: digest("policy"),
        entries: BTreeMap::from([(
            EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
                subject,
                scope: scope.digest(),
            },
        )]),
    };
    let resolver_path = root.path().join("docket-standing-resolver");
    std::fs::write(
        &resolver_path,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("resolution"),"currentness":d("currentness"),"execution_standing":d("execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["effect_scope_digest"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    std::fs::set_permissions(&resolver_path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
    let issuer_key = root.path().join("ag-issuance-key.pkcs8");
    std::fs::write(&issuer_key, key_document.as_ref()).unwrap();
    std::fs::set_permissions(&issuer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trust_path = root.path().join("docket-trust.json");
    let trust = serde_json::json!({"issuers":[{
        "issuer_principal":"ag-test",
        "key_id":"key-1",
        "public_key":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
    }]});
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();
    let state_directory = root.path().join("docket-state");
    std::fs::create_dir(&state_directory).unwrap();
    let docket_root = GovernedDocketAdapterRootV1 {
        schema: GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1.to_owned(),
        adapter_label: "qualification-fixture-not-human-authority".to_owned(),
        docket_program: pinned(docket),
        state_directory,
        trust_config: pinned(trust_path),
        standing_resolver: pinned(resolver_path),
        executor_adapter: pinned(effectd),
        executor_config: pinned(plan_path),
        checkpoint_verifier: None,
        issuer_principal: "ag-test".to_owned(),
        issuer_key_id: "key-1".to_owned(),
        issuer_key: pinned(issuer_key),
    };
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        CreateCampaignV1 {
            campaign,
            occurrence,
            program: ProgramBasisRefV1::from_digest(digest("program")),
            residuals: ResidualSetV1::default(),
            budget: LoopBudgetV1 {
                retry_limit: 1,
                retries_used: 0,
                probe_limit: 1,
                probes_used: 0,
                escalation_limit: 1,
                escalations_used: 0,
            },
            idempotency_key: digest("create-idempotency"),
            governed_ag_policy_root: policy_root(root.path(), &catalog),
            governed_repair_verifier_root: None,
            governed_docket_adapter_root: Some(docket_root),
        },
    )
    .unwrap();
    let state = service.state().unwrap().current;
    let state = service
        .record_proposal(
            state.state_digest(),
            ObservationRefV1::from_digest(digest("observation")),
            proposal,
            ProposalClassV1::Initial,
        )
        .unwrap();
    let state = service.require_standing(state.state_digest()).unwrap();
    let state = service.decide(state.state_digest()).unwrap();
    let state = service.authorize(state.state_digest()).unwrap();
    let dispatched = service.dispatch(state.state_digest()).unwrap();
    assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);
    let settled = service
        .reconcile_docket(dispatched.state_digest())
        .unwrap()
        .current;
    assert_eq!(
        settled.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"governed-process-effect\n"
    );
    assert_eq!(service.replay().unwrap().ag_spends, 1);
    assert_eq!(service.replay().unwrap().docket_attempts, 1);
    assert_eq!(service.replay().unwrap().settlements, 1);

    std::fs::write(&target_path, b"must-not-run-again\n").unwrap();
    let settled_again = service
        .reconcile_docket(settled.state_digest())
        .unwrap()
        .current;
    assert_eq!(settled_again.state_digest(), settled.state_digest());
    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"must-not-run-again\n"
    );
    drop(service);
    let reopened = GovernedCampaignServiceV1::open(&database).unwrap();
    assert_eq!(
        reopened.state().unwrap().current.program_counter(),
        ProgramCounterV1::SettledObservationRequired
    );
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
}
