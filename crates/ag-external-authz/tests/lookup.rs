//! Exact read-only adjudication lookup and reconciliation semantics.

mod common;

use ag_app::governed_loop::CampaignEngineV1;
use ag_external_authz::adjudicate::{AdjudicationOutcomeV1, adjudicate};
use ag_external_authz::custody::OUTCOME_FILE_V1;
use ag_external_authz::lookup::{LookupOutcomeV1, exact_request_digest, lookup};
use ag_external_authz::protocol::{
    ErrorKindV1, ExternalAuthorizationLookupRequestV1, ExternalAuthorizationLookupResponseV1,
    ExternalAuthorizationRequestV1, ExternalDecisionV1, LOOKUP_REQUEST_SCHEMA_V1,
    LOOKUP_RESPONSE_SCHEMA_V1, LookupStatusV1,
};
use common::{NOW, active_fixture, default_request, fixture, socket_roundtrip, store_path};
use uuid::Uuid;

fn query(request: &ExternalAuthorizationRequestV1) -> ExternalAuthorizationLookupRequestV1 {
    ExternalAuthorizationLookupRequestV1 {
        schema: LOOKUP_REQUEST_SCHEMA_V1.to_owned(),
        lookup_request_id: Uuid::new_v4().to_string(),
        authorization_request_id: request.request_id.clone(),
        authorization_occurrence_id: request.occurrence.authorization_occurrence_id.clone(),
        request_digest: exact_request_digest(request).unwrap(),
    }
}

fn lookup_result(outcome: LookupOutcomeV1) -> ExternalAuthorizationLookupResponseV1 {
    match outcome {
        LookupOutcomeV1::Lookup(response) => response,
        LookupOutcomeV1::Rejected(error) => panic!("expected lookup result, got {error:?}"),
    }
}

#[test]
fn an_absent_occurrence_is_exactly_not_found_without_creating_state() {
    let fixture = fixture();
    let request = default_request(
        Uuid::new_v4(),
        &common::digest("subject"),
        &common::digest("scope"),
    );
    let occurrence_dir = fixture
        .state_dir
        .join(&request.occurrence.authorization_occurrence_id);

    let response = lookup_result(lookup(&fixture.config, &query(&request)));

    assert_eq!(response.status, LookupStatusV1::NotFound);
    assert!(response.outcome.is_none());
    assert!(!occurrence_dir.exists());
}

#[test]
fn a_durable_decision_resolves_exactly_without_another_spend() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);
    let AdjudicationOutcomeV1::Decision(expected) = adjudicate(&fixture.config, &request, NOW)
    else {
        panic!("expected decision");
    };
    assert_eq!(expected.decision, ExternalDecisionV1::Authorized);

    let first = lookup_result(lookup(&fixture.config, &query(&request)));
    let second = lookup_result(lookup(&fixture.config, &query(&request)));

    assert_eq!(first.status, LookupStatusV1::Resolved);
    assert_eq!(first.outcome, Some(expected.clone()));
    assert_eq!(second.status, LookupStatusV1::Resolved);
    assert_eq!(second.outcome, Some(expected));
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn request_custody_without_a_published_decision_is_outcome_unknown() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);
    assert!(matches!(
        adjudicate(&fixture.config, &request, NOW),
        AdjudicationOutcomeV1::Decision(_)
    ));
    std::fs::remove_file(
        fixture
            .state_dir
            .join(occurrence.hyphenated().to_string())
            .join(OUTCOME_FILE_V1),
    )
    .unwrap();

    let response = lookup_result(lookup(&fixture.config, &query(&request)));

    assert_eq!(response.status, LookupStatusV1::OutcomeUnknown);
    assert!(response.outcome.is_none());
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn a_substituted_complete_request_digest_is_invalid_not_not_found() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);
    assert!(matches!(
        adjudicate(&fixture.config, &request, NOW),
        AdjudicationOutcomeV1::Decision(_)
    ));
    let mut substituted = query(&request);
    substituted.request_digest = common::digest("substituted-request");

    let LookupOutcomeV1::Rejected(error) = lookup(&fixture.config, &substituted) else {
        panic!("expected invalid lookup");
    };

    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn lookup_round_trips_over_the_same_socket_without_adjudication() {
    let fixture = fixture();
    let request = default_request(
        Uuid::new_v4(),
        &common::digest("subject"),
        &common::digest("scope"),
    );
    let lookup_request = query(&request);
    let payload = serde_json::to_vec(&lookup_request).unwrap();

    let response: ExternalAuthorizationLookupResponseV1 =
        serde_json::from_slice(&socket_roundtrip(&fixture.config, &payload)).unwrap();

    assert_eq!(response.schema, LOOKUP_RESPONSE_SCHEMA_V1);
    assert_eq!(response.lookup_request_id, lookup_request.lookup_request_id);
    assert_eq!(response.status, LookupStatusV1::NotFound);
}
