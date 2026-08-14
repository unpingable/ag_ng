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
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use crate::governed_product::{
    CreateCampaignV1, EXACT_WORK_CATALOG_SCHEMA_V1, ExactWorkCatalogEntryV1, ExactWorkCatalogV1,
    GOVERNED_AG_POLICY_ROOT_SCHEMA_V1, GOVERNED_CAMPAIGN_PRODUCT_SCHEMA_V1,
    GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1, GovernedAgPolicyRootV1, GovernedArtifactKindV1,
    GovernedCampaignServiceV1, GovernedDocketAdapterRootV1, PinnedDeploymentFileV1,
};
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rusqlite::Connection;
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

fn executable(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn successor_docket_root(
    directory: &std::path::Path,
    docket: PathBuf,
    checkpoint_diff: Option<&Digest>,
) -> (GovernedDocketAdapterRootV1, PathBuf) {
    let executor_config = directory.join("successor-executor-plan-id");
    let successor_work = Digest::hash_domain(
        "qualification-fixture-not-human-authority/product-support/v1",
        b"executor-work",
    );
    std::fs::write(&executor_config, successor_work.to_string()).unwrap();

    let executor = directory.join("qualification-fixture-successor-executor");
    let executor_source = r#"#!/usr/bin/env python3
import hashlib,json,sys
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
def ag_hash(domain,payload):
    h=hashlib.sha256(); h.update(b"ag-ng\0digest\0v1\0"); d=domain.encode()
    h.update(len(d).to_bytes(16,"big")); h.update(d)
    h.update(len(payload).to_bytes(16,"big")); h.update(payload)
    return "sha256:"+h.hexdigest()
if sys.argv[1] == "plan-id":
    sys.stdout.write(open(sys.argv[2],encoding="utf-8").read()); sys.exit(0)
r=json.load(sys.stdin)
entry={"resource":"repository","path":"bounded/original","operation":"modify","effect_identity":q("reported-authorized-effect")}
if sys.argv[1] == "execute" and r["work_schema"].endswith("/initial/v1"):
    delta={"schema":"ag.governed-loop.canonical-effect-scope/v1","effect_class":"repair","resources":[{"resource":"repository","path":"bounded/delta","operations":["modify"]}]}
    work={"repository_identity":q("repository"),"commit":"1"*40,"tree":"2"*40,"content_manifest_identity":q("checkpoint-content")}
    __DIFF_LINE__
    out={"attempt":r["attempt"],"marker":r["marker"],"receipt":q("scope-receipt"),"outcome":"scope_expansion_required","effect_journal":[],"immutable_work_checkpoint":work,"governed_repair":{"requirement":"scope_expansion_required","requested_delta":delta,"requested_delta_digest":ag_hash("ag.governed-loop.canonical-effect-scope/v1",json.dumps(delta,sort_keys=True,separators=(",",":")).encode()),"blocked_effect":{"effect_class":"repair","resource":"repository","path":"bounded/delta","operation":"modify"},"reason":q("scope-reason"),"dependency_evidence":[q("dependency")],"created_at_unix_ms":0,"expires_at_unix_ms":9007199254740991,"idempotency":q("scope-idempotency"),"limitations":[q("fixture-not-authority")]}}
elif sys.argv[1] == "execute":
    out={"attempt":r["attempt"],"marker":r["marker"],"receipt":q("indeterminate-receipt"),"outcome":"indeterminate","effect_journal":[entry]}
elif sys.argv[1] == "reconcile":
    out={"attempt":r["attempt"],"marker":r["marker"],"receipt":q("settlement-receipt"),"outcome":"success","effect_journal":[]}
else:
    sys.exit(64)
sys.stdout.write(json.dumps(out,sort_keys=True,separators=(",",":")))
"#
    .replace(
        "__DIFF_LINE__",
        &checkpoint_diff.map_or_else(String::new, |value| {
            format!("work[\"diff_identity\"]=\"{value}\"")
        }),
    );
    executable(&executor, &executor_source);

    let standing = directory.join("qualification-fixture-successor-standing");
    executable(
        &standing,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":q("standing-resolution:"+i["issuance"]),"currentness":q("standing-currentness:"+i["issuance"]),"execution_standing":q("execution-standing:"+i["issuance"]),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["effect_scope_digest"],"status":"current","resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );

    let checkpoint_verifier = directory.join("qualification-fixture-checkpoint-verifier");
    executable(
        &checkpoint_verifier,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin)
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-repair.checkpoint-verification/v1","verification":q("checkpoint-verification"),"issuance":r["issuance"],"checkpoint":r["checkpoint"],"status":"current","verified_at_unix_ms":0,"expires_at_unix_ms":9007199254740991}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );

    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref()).unwrap();
    let issuer_key = directory.join("successor-issuance-key.pkcs8");
    std::fs::write(&issuer_key, key_document.as_ref()).unwrap();
    std::fs::set_permissions(&issuer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trust = directory.join("successor-docket-trust.json");
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
    let state_directory = directory.join("successor-docket-state");
    std::fs::create_dir(&state_directory).unwrap();
    let database = state_directory.join("state.sqlite");
    (
        GovernedDocketAdapterRootV1 {
            schema: GOVERNED_DOCKET_ADAPTER_ROOT_SCHEMA_V1.to_owned(),
            adapter_label: "qualification-fixture-not-human-authority".to_owned(),
            docket_program: pinned(docket),
            state_directory,
            trust_config: pinned(trust),
            standing_resolver: pinned(standing),
            executor_adapter: pinned(executor),
            executor_config: pinned(executor_config),
            checkpoint_verifier: Some(pinned(checkpoint_verifier)),
            issuer_principal: "qualification-fixture-not-human-authority".to_owned(),
            issuer_key_id: "fixture-key".to_owned(),
            issuer_key: pinned(issuer_key),
        },
        database,
    )
}

fn refresh_wire_issuance_identity(value: &mut serde_json::Value) {
    let mut basis = value.as_object().unwrap().clone();
    basis.remove("issuance");
    let canonical = JcsDocument::canonicalize(&basis).unwrap();
    value["issuance"] = serde_json::Value::String(
        Digest::hash_domain("ag.governed-loop.issuance/v2", canonical.as_bytes()).to_string(),
    );
}

fn fixture_signed_envelope(root: &GovernedDocketAdapterRootV1, body: &[u8]) -> Vec<u8> {
    let key_bytes = std::fs::read(&root.issuer_key.path).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(&key_bytes).unwrap();
    let mut signed = b"ag-ng\0governed-loop-issuance-signature\0v2\0".to_vec();
    signed.extend_from_slice(body);
    let envelope = serde_json::json!({
        "schema": "ag.governed-loop.signed-issuance/v2",
        "body_b64": URL_SAFE_NO_PAD.encode(body),
        "authentication": {
            "issuer_principal": root.issuer_principal,
            "signer_key_id": root.issuer_key_id,
            "signer_public_key": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            "signature": URL_SAFE_NO_PAD.encode(pair.sign(&signed).as_ref())
        }
    });
    JcsDocument::canonicalize(&envelope)
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn raw_docket_accept(
    root: &GovernedDocketAdapterRootV1,
    state_directory: &std::path::Path,
    envelope: &[u8],
    executor: Option<&std::path::Path>,
    checkpoint_verifier: Option<&std::path::Path>,
) -> Output {
    std::fs::create_dir(state_directory).unwrap();
    let mut command = Command::new(&root.docket_program.path);
    command.args([
        "governed-loop",
        "accept",
        "--state",
        state_directory.to_str().unwrap(),
        "--trust",
        root.trust_config.path.to_str().unwrap(),
        "--standing-resolver",
        root.standing_resolver.path.to_str().unwrap(),
        "--executor",
        executor
            .unwrap_or(&root.executor_adapter.path)
            .to_str()
            .unwrap(),
        "--executor-config",
        root.executor_config.path.to_str().unwrap(),
        "--checkpoint-verifier",
        checkpoint_verifier
            .unwrap_or(&root.checkpoint_verifier.as_ref().unwrap().path)
            .to_str()
            .unwrap(),
    ]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(envelope).unwrap();
    child.wait_with_output().unwrap()
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
    out={{"attempt":r["attempt"],"marker":r["marker"],"receipt":q("receipt"),"outcome":"scope_expansion_required","effect_journal":[],"governed_repair":{{"requirement":"scope_expansion_required","requested_delta":delta,"requested_delta_digest":ag_hash("ag.governed-loop.canonical-effect-scope/v1",payload),"blocked_effect":{{"effect_class":"repository-write/v1","resource":"repository","path":"{requested}","operation":"modify"}},"reason":q("reason"),"dependency_evidence":[q("dependency")],"created_at_unix_ms":0,"expires_at_unix_ms":9007199254740991,"idempotency":q("idempotency"),"limitations":[q("fixture-only")]}}}}
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
    assert!(required.no_unauthorized_effect_reported);
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

#[test]
#[ignore = "requires adjacent Docket binary; see module documentation"]
fn real_product_successor_bytes_round_trip_through_docket_and_settle() {
    let docket = PathBuf::from(std::env::var_os("AG_DOCKET_BIN").expect("AG_DOCKET_BIN"));
    assert!(docket.is_absolute());

    for checkpoint_diff in [None, Some(digest("successor-checkpoint-diff"))] {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (docket_root, docket_database) =
            successor_docket_root(root.path(), docket.clone(), checkpoint_diff.as_ref());
        let fixture =
            crate::governed_product_fixture_support::authorized_successor_issuance_with_docket(
                root.path(),
                checkpoint_diff.clone(),
                Some(docket_root),
            );

        let issuance_document = JcsDocument::canonicalize(&fixture.issuance).unwrap();
        let issuance_bytes = issuance_document.as_bytes();
        let issuance_value: serde_json::Value = serde_json::from_slice(issuance_bytes).unwrap();
        let checkpoint = issuance_value["governed_repair_checkpoint"]
            .as_object()
            .unwrap();
        assert!(checkpoint.contains_key("content_manifest"));
        assert!(checkpoint.contains_key("docket_checkpoint"));
        assert_eq!(
            checkpoint.get("diff_identity"),
            checkpoint_diff
                .as_ref()
                .map(|value| serde_json::Value::String(value.to_string()))
                .as_ref(),
            "absent diff is omitted and present diff is exact"
        );

        let mut service = GovernedCampaignServiceV1::open(&fixture.database).unwrap();
        let dispatched = match service.dispatch(&fixture.successor.state_digest) {
            Ok(value) => value,
            Err(error) => {
                let reason = Connection::open(&docket_database)
                    .and_then(|connection| {
                        connection.query_row(
                            "SELECT reason_code FROM governed_loop_issuance_refusal LIMIT 1",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                    })
                    .unwrap_or_else(|query_error| format!("no refusal row: {query_error}"));
                panic!("actual Docket refused exact AG successor: {error}; {reason}");
            }
        };
        assert_eq!(dispatched.program_counter(), ProgramCounterV1::Dispatched);

        let reconciled = service
            .reconcile_docket(&dispatched.state_digest)
            .expect("checkpoint is freshly verified before reconciliation");
        assert_eq!(
            reconciled.current.program_counter(),
            ProgramCounterV1::SettledObservationRequired
        );

        let connection = Connection::open(&docket_database).unwrap();
        let rows = connection
            .prepare(
                "SELECT outcome,effect_journal_entries,cumulative_effect_journal_entries
                 FROM governed_executor_result ORDER BY sequence",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "indeterminate");
        assert_eq!(rows[1].0, "success");
        assert_ne!(
            rows[0].1, rows[1].1,
            "terminal response reports no new effect"
        );
        assert_eq!(
            rows[0].2, rows[1].2,
            "terminal settlement retains the prior cumulative authorized effect"
        );

        assert!(
            reconciled
                .current
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == GovernedArtifactKindV1::DocketSettlement)
        );
        let journal_link = reconciled
            .current
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == GovernedArtifactKindV1::EffectJournalReference)
            .expect("terminal AG projection exposes the cumulative journal reference");
        let journal_record = service
            .artifact(&journal_link.identity)
            .unwrap()
            .expect("cumulative journal reference is retrievable without Docket access");
        assert_eq!(
            journal_record.kind,
            GovernedArtifactKindV1::EffectJournalReference
        );
        assert!(journal_record.occurrences.contains(&reconciled.current.key));

        // The stable product surface exposes every artifact for both the
        // halted predecessor and completed successor. A future client needs
        // neither AG SQLite schema knowledge nor a direct Docket call.
        for key in [&fixture.predecessor.key, &reconciled.current.key] {
            let occurrence = service
                .occurrence(key)
                .unwrap()
                .expect("full lifecycle occurrence remains product-readable");
            for link in occurrence.artifacts {
                let record = service
                    .artifact(&link.identity)
                    .unwrap()
                    .expect("every advertised lifecycle artifact is retrievable");
                assert_eq!(record.kind, link.kind);
                assert!(record.occurrences.contains(key));
            }
        }
        drop(service);
        assert_eq!(
            GovernedCampaignServiceV1::open(&fixture.database)
                .unwrap()
                .state()
                .unwrap()
                .current
                .program_counter(),
            ProgramCounterV1::SettledObservationRequired
        );
    }
}

#[test]
#[ignore = "requires adjacent Docket binary; see module documentation"]
fn actual_docket_refuses_null_and_changed_successor_checkpoint_bytes_before_custody() {
    let docket = PathBuf::from(std::env::var_os("AG_DOCKET_BIN").expect("AG_DOCKET_BIN"));
    assert!(docket.is_absolute());
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (docket_root, _) = successor_docket_root(root.path(), docket, None);
    let fixture =
        crate::governed_product_fixture_support::authorized_successor_issuance_with_docket(
            root.path(),
            None,
            Some(docket_root.clone()),
        );
    let body = JcsDocument::canonicalize(&fixture.issuance).unwrap();
    let mut explicit_null: serde_json::Value = serde_json::from_slice(body.as_bytes()).unwrap();
    explicit_null["governed_repair_checkpoint"]["diff_identity"] = serde_json::Value::Null;
    let null_body = JcsDocument::canonicalize(&explicit_null).unwrap();
    let null_output = raw_docket_accept(
        &docket_root,
        &root.path().join("null-state"),
        &fixture_signed_envelope(&docket_root, null_body.as_bytes()),
        None,
        None,
    );
    assert!(!null_output.status.success());
    let null_stderr = String::from_utf8_lossy(&null_output.stderr);
    assert!(
        null_stderr.contains("issuance-body-json")
            && null_stderr.contains("explicit null is not canonical"),
        "strict refusal must identify the issuance-body boundary and null-spelling law: {null_stderr}"
    );
    let connection = Connection::open(root.path().join("null-state/state.sqlite")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0,
        "explicit-null checkpoint spelling is refused before custody"
    );

    let mismatching_verifier = root
        .path()
        .join("qualification-fixture-mismatching-checkpoint");
    executable(
        &mismatching_verifier,
        r#"#!/usr/bin/env python3
import hashlib,json,sys
r=json.load(sys.stdin); checkpoint=dict(r["checkpoint"]); checkpoint["tree"]="f"*40
def q(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
o={"schema":"docket.governed-repair.checkpoint-verification/v1","verification":q("mismatch"),"issuance":r["issuance"],"checkpoint":checkpoint,"status":"current","verified_at_unix_ms":0,"expires_at_unix_ms":9007199254740991}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
    );
    let exact_envelope = fixture_signed_envelope(&docket_root, body.as_bytes());
    let changed_output = raw_docket_accept(
        &docket_root,
        &root.path().join("changed-state"),
        &exact_envelope,
        None,
        Some(&mismatching_verifier),
    );
    assert!(changed_output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&changed_output.stdout).unwrap();
    assert_eq!(response["status"], "refused");
    assert_eq!(
        response["record"]["reason_code"],
        "governed-checkpoint-verification-mismatch"
    );
    let connection = Connection::open(root.path().join("changed-state/state.sqlite")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0,
        "changed checkpoint is refused before custody-bearing state"
    );

    let mut changed_scope: serde_json::Value = serde_json::from_slice(body.as_bytes()).unwrap();
    changed_scope["effect_scope"]["resources"][0]["path"] =
        serde_json::Value::String("bounded/neighbour".to_owned());
    refresh_wire_issuance_identity(&mut changed_scope);
    let changed_scope_body = JcsDocument::canonicalize(&changed_scope).unwrap();
    let scope_output = raw_docket_accept(
        &docket_root,
        &root.path().join("scope-state"),
        &fixture_signed_envelope(&docket_root, changed_scope_body.as_bytes()),
        None,
        None,
    );
    assert!(scope_output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&scope_output.stdout).unwrap();
    assert_eq!(response["status"], "refused");
    assert_eq!(
        response["record"]["reason_code"],
        "governed-repair-effect-scope-identity"
    );
    let connection = Connection::open(root.path().join("scope-state/state.sqlite")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM governed_loop_attempt", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0,
        "structured scope/claimed identity disagreement refuses before custody"
    );
}
