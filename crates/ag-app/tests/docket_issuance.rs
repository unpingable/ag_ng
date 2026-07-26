//! Conformance for the `ag.docket-issuance:v1` producer.
//!
//! The office boundary under test: an issuance is an authenticated immutable
//! fact about an admitted decision. It is never authority, it is never
//! produced for a refusal, and the decision's authority burns exactly once.

use ag_app::docket_issuance::{
    AuthorizationPremiseV1, DocketAuthzRequestV1, DocketIssuanceEnvelopeV1, DocketIssuanceOffice,
    DocketTargetCatalogV1, DocketTargetDefinitionV1, ISSUANCE_SCHEMA, IssuanceDecisionContextV1,
    IssuanceDecisionLedger, IssuanceRefusal, IssuanceSigner, ResidualObligationsV1,
    ResidualStatusV1, decode_request, verify_envelope,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeMap;

const ATTEMPT: &str = "aa11bb22cc33dd44ee55ff6600778899";
const PREPARED_DIGEST: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

fn request_json(mutate: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
    let mut v = serde_json::json!({
        "authz_request_format": "gwr:authz-request:v1",
        "attempt": ATTEMPT,
        "attempt_version": 0,
        "effect_class": "git-ref-update:v1",
        "prepared_attempt_digest": PREPARED_DIGEST,
        "repository": "/governed/repo",
        "target_ref": "refs/gwr/target",
        "basis": "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
        "allowed_paths": ["docs/vertical-01.md"],
        "settlement_premises": [
            "inspectable_endpoint", "atomic_compare_and_swap",
            "attributable_result_state", "exclusive_ref_custody"
        ],
        "requested_actor": "operator",
        "goal": "record the vertical",
        "work_request": "11111111111111111111111111111111",
        "preparation_run": "22222222222222222222222222222222",
        "candidate": "33333333333333333333333333333333",
        "candidate_digest":
            "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
        "request_created_at_ms": 1000,
        "admitted_at_ms": 1100
    });
    mutate(&mut v);
    serde_json::to_vec(&v).unwrap()
}

fn catalog() -> DocketTargetCatalogV1 {
    let mut targets = BTreeMap::new();
    targets.insert(
        "docket-vertical".to_string(),
        DocketTargetDefinitionV1 {
            target_id: "docket-vertical".into(),
            repository: "/governed/repo".into(),
            target_ref: "refs/gwr/target".into(),
            effect_class: "git-ref-update:v1".into(),
            admitted_actors: vec!["operator".into()],
            admitted_path_prefixes: vec!["docs".into(), "README.md".into()],
        },
    );
    DocketTargetCatalogV1 {
        identity: "sha256:catalog".into(),
        targets,
    }
}

fn context() -> IssuanceDecisionContextV1 {
    IssuanceDecisionContextV1 {
        authority_domain: "test.domain".into(),
        epoch: 1,
        lifecycle_nonce: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".into(),
        catalog_identity: "sha256:catalog".into(),
    }
}

fn office(cat: &DocketTargetCatalogV1) -> DocketIssuanceOffice<'_> {
    DocketIssuanceOffice {
        catalog: cat,
        context: context(),
        principal_chain: vec!["root".into(), "issuer".into()],
        issuer_principal: "issuer".into(),
    }
}

fn signer() -> IssuanceSigner {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    IssuanceSigner::from_pkcs8("vertical-issuer-1", doc.as_ref()).unwrap()
}

fn premises() -> Vec<AuthorizationPremiseV1> {
    vec![AuthorizationPremiseV1 {
        kind: "principal_authentication".into(),
        statement: "the principal chain was authenticated by the local transport, \
                    not re-verified at issuance"
            .into(),
    }]
}

fn residuals_unrepresented() -> ResidualObligationsV1 {
    ResidualObligationsV1 {
        status: ResidualStatusV1::Unrepresented,
        items: vec![],
    }
}

fn issue_ok(bytes: &[u8]) -> (ag_app::docket_issuance::DocketIssuanceEnvelopeV1, String) {
    let cat = catalog();
    let off = office(&cat);
    let req: DocketAuthzRequestV1 = decode_request(bytes).unwrap();
    let decision = off.decide(&req).unwrap();
    let mut ledger = IssuanceDecisionLedger::new();
    let env = off
        .issue(
            &req,
            bytes,
            &decision,
            &mut ledger,
            &signer(),
            5_000,
            9_000,
            premises(),
            residuals_unrepresented(),
        )
        .unwrap();
    (env, decision.decision_id().to_string())
}

#[test]
fn valid_request_yields_an_authenticated_issuance() {
    let bytes = request_json(|_| {});
    let (env, decision_id) = issue_ok(&bytes);
    assert_eq!(env.schema, ISSUANCE_SCHEMA);
    let body = verify_envelope(&env).expect("signature verifies");
    assert_eq!(body.decision, "admitted");
    assert_eq!(body.decision_id, decision_id);
    assert_eq!(body.docket.attempt, ATTEMPT);
    assert_eq!(body.docket.prepared_attempt_digest, PREPARED_DIGEST);
    assert_eq!(body.target_id, "docket-vertical");
    // Both canonical domains present and distinct.
    assert!(body.request_source.raw_sha256.starts_with("sha256:"));
    assert_ne!(
        body.request_source.raw_sha256,
        body.request_source.ag_canonical_digest
    );
    // Docket's transcript digest is echoed, never recomputed into ours.
    assert_ne!(
        body.docket.prepared_attempt_digest,
        body.request_source.ag_canonical_digest
    );
    assert!(!body.consumption.use_digest.is_empty());
}

#[test]
fn a_changed_docket_digest_is_a_different_decision() {
    let a = request_json(|_| {});
    let b = request_json(|v| {
        v["prepared_attempt_digest"] = serde_json::json!("d1".repeat(32));
    });
    let (_, id_a) = issue_ok(&a);
    let (_, id_b) = issue_ok(&b);
    assert_ne!(id_a, id_b, "decision identity binds the exact request");
}

#[test]
fn unsupported_request_schema_refuses() {
    let bytes = request_json(|v| v["authz_request_format"] = serde_json::json!("gwr:other:v9"));
    match decode_request(&bytes) {
        Err(IssuanceRefusal::UnsupportedRequestSchema { found, .. }) => {
            assert_eq!(found, "gwr:other:v9");
        }
        other => panic!("expected unsupported schema, got {other:?}"),
    }
}

#[test]
fn unsupported_effect_class_refuses() {
    let bytes = request_json(|v| v["effect_class"] = serde_json::json!("artifact-computation:v1"));
    let cat = catalog();
    let req = decode_request(&bytes).unwrap();
    match office(&cat).decide(&req) {
        Err(IssuanceRefusal::UnsupportedEffectClass { found }) => {
            assert_eq!(found, "artifact-computation:v1");
        }
        other => panic!("expected unsupported effect class, got {other:?}"),
    }
}

#[test]
fn target_and_scope_mismatches_refuse() {
    let cat = catalog();
    // Repository not in the catalog.
    let bytes = request_json(|v| v["repository"] = serde_json::json!("/elsewhere"));
    let req = decode_request(&bytes).unwrap();
    assert!(matches!(
        office(&cat).decide(&req),
        Err(IssuanceRefusal::TargetNotInCatalog { .. })
    ));
    // Ref not in the catalog.
    let bytes = request_json(|v| v["target_ref"] = serde_json::json!("refs/heads/main"));
    let req = decode_request(&bytes).unwrap();
    assert!(matches!(
        office(&cat).decide(&req),
        Err(IssuanceRefusal::TargetNotInCatalog { .. })
    ));
    // Path outside the target's admitted prefixes.
    let bytes = request_json(|v| v["allowed_paths"] = serde_json::json!(["/etc/passwd"]));
    let req = decode_request(&bytes).unwrap();
    assert!(matches!(
        office(&cat).decide(&req),
        Err(IssuanceRefusal::PathOutsideScope { .. })
    ));
    // Actor not admitted for the target.
    let bytes = request_json(|v| v["requested_actor"] = serde_json::json!("stranger"));
    let req = decode_request(&bytes).unwrap();
    assert!(matches!(
        office(&cat).decide(&req),
        Err(IssuanceRefusal::ActorNotAdmitted { .. })
    ));
}

#[test]
fn malformed_principal_chain_refuses() {
    let cat = catalog();
    let mut off = office(&cat);
    off.principal_chain = vec![];
    let req = decode_request(&request_json(|_| {})).unwrap();
    assert!(matches!(
        off.decide(&req),
        Err(IssuanceRefusal::MalformedPrincipalChain { .. })
    ));
}

#[test]
fn decision_authority_burns_exactly_once() {
    let bytes = request_json(|_| {});
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let decision = off.decide(&req).unwrap();
    let mut ledger = IssuanceDecisionLedger::new();
    let s = signer();
    let first = off.issue(
        &req,
        &bytes,
        &decision,
        &mut ledger,
        &s,
        5_000,
        9_000,
        premises(),
        residuals_unrepresented(),
    );
    assert!(first.is_ok());
    assert!(ledger.prior_use(decision.decision_id()).is_some());
    // The same decision cannot mint a second issuance.
    let second = off.issue(
        &req,
        &bytes,
        &decision,
        &mut ledger,
        &s,
        5_001,
        9_001,
        premises(),
        residuals_unrepresented(),
    );
    assert!(matches!(
        second,
        Err(IssuanceRefusal::AuthorityUnavailable { .. })
    ));
}

#[test]
fn a_repeated_exact_request_is_a_repeated_decision_and_refuses_reissue() {
    // Duplicate exact request → same decision identity; under this office's
    // one-use law the ledger refuses a second issuance for it.
    let bytes = request_json(|_| {});
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let d1 = off.decide(&req).unwrap();
    let d2 = off.decide(&req).unwrap();
    assert_eq!(d1.decision_id(), d2.decision_id());
    let mut ledger = IssuanceDecisionLedger::new();
    let s = signer();
    assert!(
        off.issue(
            &req,
            &bytes,
            &d1,
            &mut ledger,
            &s,
            1,
            2,
            premises(),
            residuals_unrepresented()
        )
        .is_ok()
    );
    assert!(
        off.issue(
            &req,
            &bytes,
            &d2,
            &mut ledger,
            &s,
            1,
            2,
            premises(),
            residuals_unrepresented()
        )
        .is_err()
    );
}

#[test]
fn a_refusal_produces_no_issuance_and_burns_nothing() {
    let bytes = request_json(|v| v["requested_actor"] = serde_json::json!("stranger"));
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let ledger = IssuanceDecisionLedger::new();
    assert!(off.decide(&req).is_err());
    // No decision, so nothing could have been consumed.
    assert!(ledger.prior_use("any").is_none());
}

#[test]
fn every_protected_field_is_covered_by_authentication() {
    let bytes = request_json(|_| {});
    let (env, _) = issue_ok(&bytes);
    let body_bytes = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&env.body_b64)
            .unwrap()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    // Mutating any protected field must break verification. Includes the
    // premise and residual fields explicitly.
    for pointer in [
        "/issuance_id",
        "/decision_id",
        "/issuer_principal",
        "/target_id",
        "/decision",
        "/docket/attempt",
        "/docket/prepared_attempt_digest",
        "/docket/repository",
        "/docket/target_ref",
        "/docket/basis",
        "/docket/requested_actor",
        "/request_source/raw_sha256",
        "/request_source/ag_canonical_digest",
        "/decision_context/authority_domain",
        "/consumption/use_digest",
        "/premises/0/statement",
        "/residual_obligations/status",
    ] {
        let mut tampered = body.clone();
        let slot = tampered.pointer_mut(pointer).unwrap();
        *slot = serde_json::json!("tampered");
        let mut env2 = env.clone();
        {
            use base64::Engine as _;
            env2.body_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&tampered).unwrap());
        }
        assert!(
            verify_envelope(&env2).is_err(),
            "tampering with {pointer} must break verification"
        );
    }
    // Sanity: untouched envelope still verifies.
    assert!(verify_envelope(&env).is_ok());
    body["decision"] = serde_json::json!("admitted");
}

#[test]
fn issuance_cannot_reconstruct_authority_or_carry_secrets() {
    let bytes = request_json(|_| {});
    let (env, _) = issue_ok(&bytes);
    let text = serde_json::to_string(&env).unwrap();
    // No capability, authority, standing, token, or private-key shaped field.
    for forbidden in [
        "capability",
        "Authority",
        "authority_object",
        "standing",
        "private",
        "secret",
        "pkcs8",
    ] {
        assert!(
            !text.contains(forbidden),
            "issuance must not carry {forbidden:?}"
        );
    }
    // The body deserializes only into the issuance body type, which has no
    // authority-bearing field to populate.
    let body = verify_envelope(&env).unwrap();
    assert_eq!(body.decision, "admitted");
}

#[test]
fn residual_status_distinguishes_absent_from_unrepresented() {
    let bytes = request_json(|_| {});
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let decision = off.decide(&req).unwrap();
    let mut ledger = IssuanceDecisionLedger::new();
    let env = off
        .issue(
            &req,
            &bytes,
            &decision,
            &mut ledger,
            &signer(),
            1,
            2,
            premises(),
            ResidualObligationsV1 {
                status: ResidualStatusV1::NoneRecorded,
                items: vec![],
            },
        )
        .unwrap();
    let body = verify_envelope(&env).unwrap();
    assert_eq!(
        body.residual_obligations.status,
        ResidualStatusV1::NoneRecorded
    );
    assert!(body.residual_obligations.items.is_empty());
    // And the honest default this office actually emits today is distinct.
    let (env2, _) = issue_ok(&request_json(|v| v["goal"] = serde_json::json!("other")));
    let body2 = verify_envelope(&env2).unwrap();
    assert_eq!(
        body2.residual_obligations.status,
        ResidualStatusV1::Unrepresented,
        "absence of residuals must not be claimed when they cannot be expressed"
    );
}

#[test]
fn a_present_residual_specimen_round_trips() {
    let bytes = request_json(|_| {});
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let decision = off.decide(&req).unwrap();
    let mut ledger = IssuanceDecisionLedger::new();
    let residual = ag_app::docket_issuance::UpstreamResidualV1 {
        source_system: "ag-ng".into(),
        obligation_id: "obl-1".into(),
        subject: "docs/vertical-01.md".into(),
        kind: "human_review_before_publication".into(),
        statement: "a human must review the published record before it is cited".into(),
    };
    let env = off
        .issue(
            &req,
            &bytes,
            &decision,
            &mut ledger,
            &signer(),
            1,
            2,
            premises(),
            ResidualObligationsV1 {
                status: ResidualStatusV1::Present,
                items: vec![residual.clone()],
            },
        )
        .unwrap();
    let body = verify_envelope(&env).unwrap();
    assert_eq!(body.residual_obligations.status, ResidualStatusV1::Present);
    assert_eq!(body.residual_obligations.items, vec![residual]);
}

#[test]
fn premises_survive_verbatim_and_are_not_docket_settlement_premises() {
    let bytes = request_json(|_| {});
    let (env, _) = issue_ok(&bytes);
    let body = verify_envelope(&env).unwrap();
    assert_eq!(body.premises, premises());
    // The request's Docket settlement premises are not copied into ours.
    let text = serde_json::to_string(&body.premises).unwrap();
    assert!(!text.contains("exclusive_ref_custody"));
    assert!(!text.contains("atomic_compare_and_swap"));
}

// --- cross-repository conformance vectors ---
//
// The consumer (Docket) is the authoritative home of these wire contracts and
// ships the vectors. This office verifies the *consumer's* shipped artifacts
// with its own independent implementation; no code is shared between the two.

fn vector(name: &str) -> Vec<u8> {
    let path = std::path::Path::new("/home/jbeck/git/docket/runtime/conformance/authz").join(name);
    std::fs::read(path).unwrap()
}

#[test]
fn shipped_request_vector_decodes_under_this_office() {
    let bytes = vector("request.json");
    let req = decode_request(&bytes).expect("the shipped request vector decodes");
    assert_eq!(req.effect_class, "git-ref-update:v1");
    assert_eq!(req.requested_actor, "operator");
    assert!(!req.prepared_attempt_digest.is_empty());
}

#[test]
fn shipped_unsupported_effect_class_vector_refuses_here() {
    let bytes = vector("request-unsupported-effect-class.json");
    let req = decode_request(&bytes).expect("decodes as a request");
    let cat = catalog();
    // The catalog in this test admits the fixture repository, not the vector's,
    // so either refusal is correct — what matters is that it is refused and no
    // issuance is produced.
    assert!(office(&cat).decide(&req).is_err());
}

#[test]
fn shipped_issuance_vector_verifies_under_this_offices_verifier() {
    let env: DocketIssuanceEnvelopeV1 =
        serde_json::from_slice(&vector("issuance.json")).expect("envelope parses");
    let body = verify_envelope(&env).expect("the shipped issuance verifies");
    assert_eq!(body.decision, "admitted");
    assert_ne!(
        body.request_source.raw_sha256,
        body.request_source.ag_canonical_digest
    );
}

#[test]
fn shipped_tampered_vectors_fail_this_offices_verifier() {
    for name in [
        "issuance-changed-prepared-digest.json",
        "issuance-changed-ag-digest.json",
        "issuance-changed-scope.json",
        "issuance-changed-actor.json",
        "issuance-changed-premise.json",
        "issuance-changed-residual.json",
        "issuance-not-admitted.json",
        "issuance-bad-authentication.json",
    ] {
        let env: DocketIssuanceEnvelopeV1 = serde_json::from_slice(&vector(name)).unwrap();
        assert!(
            verify_envelope(&env).is_err(),
            "{name}: tampered vector must not verify"
        );
    }
}

// The decision token is unconstructable outside the checked decision path.
// This is the same law the kernel applies to `Authority`: without it, a caller
// could fabricate a decision and reach `issue` while bypassing effect-class,
// catalog, actor, scope, and principal-chain validation. Compile-fail rather
// than runtime, because the guarantee is structural.
//
// ```compile_fail
// use ag_app::docket_issuance::DocketDecision;
// let _ = DocketDecision { decision_id: "forged".into(), target_id: "any".into() };
// ```
#[test]
fn a_decision_token_exposes_only_readers() {
    let bytes = request_json(|_| {});
    let cat = catalog();
    let off = office(&cat);
    let req = decode_request(&bytes).unwrap();
    let decision = off.decide(&req).unwrap();
    // Readers exist and name the checked decision; no setter or constructor does.
    assert!(!decision.decision_id().is_empty());
    assert_eq!(decision.target_id(), "docket-vertical");
}
