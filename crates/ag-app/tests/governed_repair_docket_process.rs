//! Opt-in adjacent-process specimen for the governed-repair halt seam.
//!
//! Build Docket locally and set `AG_DOCKET_BIN` to its absolute binary path.
//! This is development evidence only: the verifier, Standing resolver, and
//! executor below are unmistakable fixtures and confer no production authority.

#![allow(
    clippy::too_many_lines,
    reason = "the ignored specimen keeps the complete cross-process lineage visible"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use ag_app::governed_loop::{
    EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
};
use ag_app::governed_product::{
    CreateCampaignV1, GOVERNED_AG_POLICY_ROOT_SCHEMA_V1, GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1,
    GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1, GovernedAgPolicyRootV1, GovernedCampaignServiceV1,
    GovernedDocketAdapterRootV1, PinnedDeploymentFileV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use uuid::Uuid;

const WORK_SCHEMA: &str = "qualification-fixture-not-human-authority/executor/v1";

fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-governed-repair-process-specimen/v1", label.as_bytes())
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
o={"schema":"ag.governed-loop.standing-resolution/v1","resolution":d("standing-resolution"),"currentness":d("standing-current"),"mandate":d("mandate"),"key":r["key"],"observation":r["observation"],"proposal":r["proposal"],"subject":r["subject"],"scope":r["scope"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
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
fn unknown_executor_then_restart_reconciles_to_exact_governed_halt() {
    let docket = PathBuf::from(std::env::var_os("AG_DOCKET_BIN").expect("AG_DOCKET_BIN"));
    assert!(docket.is_absolute());

    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let scope = CanonicalEffectScopeV1::new(
        "repository-write/v1".to_owned(),
        vec![CanonicalEffectResourceV1 {
            resource: "repository".to_owned(),
            path: "crates/nq-store/src/lib.rs".to_owned(),
            operations: vec![CanonicalEffectOperationV1::Modify],
        }],
    )
    .unwrap();
    let requested = "crates/nq-store/src/governed_projection_capacity.rs";
    let work = digest("executor-plan");

    let executor_config = root.path().join("executor-plan-id");
    std::fs::write(&executor_config, work.to_string()).unwrap();
    let executor = root.path().join("qualification-fixture-executor");
    std::fs::write(
        &executor,
        format!(
            r#"#!/usr/bin/python3
import hashlib,json,sys
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
def ag_hash(domain,payload):
    h=hashlib.sha256()
    h.update(b"ag-ng\0digest\0v1\0")
    d=domain.encode(); h.update(len(d).to_bytes(16,"big")); h.update(d)
    h.update(len(payload).to_bytes(16,"big")); h.update(payload)
    return "sha256:"+h.hexdigest()
if sys.argv[1] == "plan-id":
    sys.stdout.write(open(sys.argv[2],encoding="utf-8").read()); sys.exit(0)
r=json.load(sys.stdin)
if sys.argv[1] == "execute":
    sys.exit(75)
if sys.argv[1] == "reconcile":
    delta={{"schema":"ag.governed-loop.canonical-effect-scope/v1","effect_class":"repository-write/v1","resources":[{{"resource":"repository","path":"{requested}","operations":["modify"]}}]}}
    payload=json.dumps(delta,sort_keys=True,separators=(",",":")).encode()
    out={{"attempt":r["attempt"],"marker":r["marker"],"receipt":q("receipt"),"outcome":"scope_expansion_required","effect_journal":[],"immutable_work_checkpoint":None,"governed_repair":{{"requirement":"scope_expansion_required","requested_delta":delta,"requested_delta_digest":ag_hash("ag.governed-loop.canonical-effect-scope/v1",payload),"blocked_effect":{{"effect_class":"repository-write/v1","resource":"repository","path":"{requested}","operation":"modify"}},"reason":q("reason"),"dependency_evidence":[q("dependency")],"created_at_unix_ms":0,"expires_at_unix_ms":9223372036854775807,"idempotency":q("idempotency"),"limitations":[q("fixture-only")]}}}}
    sys.stdout.write(json.dumps(out,sort_keys=True,separators=(",",":"))); sys.exit(0)
sys.exit(64)
"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executor, std::fs::Permissions::from_mode(0o700)).unwrap();

    let standing_resolver = root.path().join("qualification-fixture-standing-resolver");
    std::fs::write(
        &standing_resolver,
        r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":q("resolution"),"currentness":q("currentness"),"execution_standing":q("execution-standing"),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["effect_scope_digest"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    )
    .unwrap();
    std::fs::set_permissions(&standing_resolver, std::fs::Permissions::from_mode(0o700)).unwrap();

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
    let issuer_key = root.path().join("ag-issuance-key.pkcs8");
    std::fs::write(&issuer_key, key_document.as_ref()).unwrap();
    std::fs::set_permissions(&issuer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trust = root.path().join("docket-trust.json");
    std::fs::write(
        &trust,
        serde_json::to_vec(&serde_json::json!({"issuers":[{
            "issuer_principal":"qualification-fixture-not-human-authority",
            "key_id":"fixture-key",
            "public_key":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
        }]}))
        .unwrap(),
    )
    .unwrap();
    let state_directory = root.path().join("docket-state");
    std::fs::create_dir(&state_directory).unwrap();
    let docket_root = GovernedDocketAdapterRootV1 {
        schema: GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1.to_owned(),
        adapter_label: "qualification-fixture-not-human-authority".to_owned(),
        docket_program: pinned(docket),
        state_directory,
        trust_config: pinned(trust),
        standing_resolver: pinned(standing_resolver),
        executor_adapter: pinned(executor),
        executor_config: pinned(executor_config),
        checkpoint_verifier: None,
        issuer_principal: "qualification-fixture-not-human-authority".to_owned(),
        issuer_key_id: "fixture-key".to_owned(),
        issuer_key: pinned(issuer_key),
    };

    let campaign = CampaignId::from_digest(digest("campaign"));
    let database = root.path().join("ag.sqlite");
    let subject = digest("subject");
    let proposal = ExactWorkProposalV1::new(
        campaign.clone(),
        subject.clone(),
        scope.clone(),
        WORK_SCHEMA.to_owned(),
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
            WORK_SCHEMA.to_owned(),
            ExactWorkCatalogEntryV1 {
                work_schema: WORK_SCHEMA.to_owned(),
                subject,
                scope: scope.digest(),
            },
        )]),
    };
    let mut service = GovernedCampaignServiceV1::create(
        &database,
        CreateCampaignV1 {
            campaign: campaign.clone(),
            occurrence: OccurrenceId::from_uuid(Uuid::from_u128(1)),
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
    let state = service.state().unwrap();
    assert_eq!(state.schema, GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1);
    let state = service
        .record_proposal(
            state.current.state_digest(),
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
    assert_eq!(service.replay().unwrap().ag_spends, 1);
    assert_eq!(service.replay().unwrap().docket_attempts, 1);

    drop(service);
    let mut reopened = GovernedCampaignServiceV1::open(&database).unwrap();
    let before = reopened.state().unwrap();
    let recovered = reopened.recover(before.current.state_digest()).unwrap();
    let halted = recovered.current;
    assert_eq!(halted.program_counter(), ProgramCounterV1::Halted);
    let requirement = halted
        .halted()
        .and_then(|value| value.governed_repair_requirement())
        .expect("exact governed requirement");
    let HumanDecisionRequirementV1::ScopeExpansion(required) = requirement else {
        panic!("scope expansion must remain distinct from readjudication")
    };
    assert_eq!(required.requested_delta.resources()[0].path, requested);
    assert!(required.unauthorized_effect_not_performed);
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
    assert_eq!(reopened.replay().unwrap().docket_attempts, 1);

    drop(reopened);
    let reopened = GovernedCampaignServiceV1::open(&database).unwrap();
    assert_eq!(
        reopened.state().unwrap().current.program_counter(),
        ProgramCounterV1::Halted
    );
    assert_eq!(reopened.replay().unwrap().ag_spends, 1);
}
