//! Adjudication semantics: happy path, refusals, replay, substitution,
//! infrastructure failures, restart durability, and determinism.

mod common;

use ag_app::governed_loop::CampaignEngineV1;
use ag_app::standing_authority::MandateStatusV1;
use ag_campaign::governed::{ProgramCounterV1, RefusalCodeV1};
use ag_external_authz::adjudicate::{AdjudicationOutcomeV1, adjudicate};
use ag_external_authz::protocol::{
    ErrorKindV1, ExternalAuthorizationErrorV1, ExternalAuthorizationResponseV1, ExternalDecisionV1,
};
use ag_external_authz::standing::load_standing_store;
use common::{
    ANSWER_TTL_MS, NOW, active_fixture, default_request, digest, fixture, mandate, store_path,
    write_standing_store,
};
use uuid::Uuid;

fn decision(outcome: AdjudicationOutcomeV1) -> ExternalAuthorizationResponseV1 {
    match outcome {
        AdjudicationOutcomeV1::Decision(response) => response,
        AdjudicationOutcomeV1::Rejected(error) => panic!("expected a decision, got {error:?}"),
    }
}

fn rejected(outcome: AdjudicationOutcomeV1) -> ExternalAuthorizationErrorV1 {
    match outcome {
        AdjudicationOutcomeV1::Rejected(error) => error,
        AdjudicationOutcomeV1::Decision(response) => panic!("expected rejection, got {response:?}"),
    }
}

#[test]
fn happy_path_authorizes_and_commits_the_spend() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);
    let request_id = request.request_id.clone();

    let response = decision(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Authorized);
    assert_eq!(response.request_id, request_id);
    assert_eq!(response.occurrence_id, occurrence.to_string());
    assert_eq!(
        response.action_digest,
        request.action.action_digest.as_str()
    );
    assert_eq!(
        response.admissibility_receipt_digest,
        request.admissibility.receipt_digest.as_str()
    );
    assert_eq!(response.evaluated_at_unix_ms, NOW);
    assert!(response.refusal.is_none() && response.failure.is_none());
    let authorization = response.authorization.expect("authorization refs");
    for value in [
        &authorization.campaign_id,
        &authorization.ag_occurrence_id,
        &authorization.authorization_ref,
        &authorization.spend_ref,
        &authorization.issuance_ref,
        &authorization.standing_resolution_ref,
        &authorization.mandate_ref,
    ] {
        assert!(
            value.starts_with("sha256:") || Uuid::parse_str(value).is_ok(),
            "{value}"
        );
    }
    assert_eq!(authorization.ag_occurrence_id, occurrence.to_string());
    // The answer expiry is min(now + answer_ttl, mandate.valid_until).
    assert_eq!(
        authorization.standing_expires_at_unix_ms,
        NOW + ANSWER_TTL_MS
    );

    // The spend is durably committed and the occurrence parks in
    // AuthorizationConsumed; no Docket custody exists in this deployment.
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
    assert_eq!(
        engine.current().unwrap().program_counter(),
        ProgramCounterV1::AuthorizationConsumed
    );
    assert!(engine.current().unwrap().issuance().is_some());
    assert!(engine.refusal_history().unwrap().refusals.is_empty());
}

fn assert_admissibility_not_current(
    fixture: &common::Fixture,
    occurrence: Uuid,
    request: &ag_external_authz::protocol::ExternalAuthorizationRequestV1,
) {
    let response = decision(adjudicate(&fixture.config, request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Refused);
    assert_eq!(
        response.refusal.expect("refusal detail").code,
        "admissibility_not_current"
    );
    assert!(response.authorization.is_none());
    let engine = CampaignEngineV1::open(&store_path(fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    assert_eq!(
        engine.refusal_history().unwrap().refusals[0].outcome.code,
        RefusalCodeV1::StaleObservation
    );
}

#[test]
fn an_admissibility_receipt_from_the_future_is_not_current() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    request.admissibility.evaluation_time_unix_ms = NOW + 1;

    assert_admissibility_not_current(&fixture, occurrence, &request);
}

#[test]
fn a_stale_admissibility_receipt_is_not_refreshed() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    request.admissibility.evaluation_time_unix_ms =
        NOW - fixture.config.max_admissibility_age_ms - 1;

    assert_admissibility_not_current(&fixture, occurrence, &request);
}

#[test]
fn admissibility_expiring_exactly_at_consequence_time_is_not_current() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    request.admissibility.evaluation_time_unix_ms = NOW - fixture.config.max_admissibility_age_ms;

    assert_admissibility_not_current(&fixture, occurrence, &request);
}

#[test]
fn absent_mandate_is_refused_as_absent_standing() {
    let fixture = fixture();
    write_standing_store(&fixture.standing_store, &[]);
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &digest("subject"), &digest("scope"));

    let response = decision(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Refused);
    let refusal = response.refusal.expect("refusal detail");
    assert_eq!(refusal.code, "absent_standing");
    assert!(refusal.reason.len() <= 4000);
    assert!(response.authorization.is_none());

    // The refusal is durable and non-authorizing; no spend exists.
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    let refusals = engine.refusal_history().unwrap();
    assert_eq!(refusals.refusals.len(), 1);
    assert_eq!(
        refusals.refusals[0].outcome.code,
        RefusalCodeV1::AbsentStanding
    );
}

#[test]
fn revoked_mandate_is_refused_as_standing_not_current() {
    let fixture = fixture();
    let subject = digest("subject");
    let scope = digest("scope");
    write_standing_store(
        &fixture.standing_store,
        &[mandate(
            &subject,
            &scope,
            1,
            MandateStatusV1::Revoked,
            NOW + 60_000,
        )],
    );
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);

    let response = decision(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Refused);
    assert_eq!(response.refusal.unwrap().code, "standing_not_current");
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
    assert_eq!(
        engine.refusal_history().unwrap().refusals[0].outcome.code,
        RefusalCodeV1::StandingNotCurrent
    );
}

#[test]
fn a_mandate_expiring_exactly_now_is_expired() {
    let fixture = fixture();
    let subject = digest("subject");
    let scope = digest("scope");
    // Boundary: valid_until == now is expired.
    write_standing_store(
        &fixture.standing_store,
        &[mandate(&subject, &scope, 1, MandateStatusV1::Active, NOW)],
    );
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);

    let response = decision(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Refused);
    assert_eq!(response.refusal.unwrap().code, "standing_not_current");
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 0);
}

#[test]
fn a_mandate_for_a_different_subject_does_not_govern() {
    let fixture = fixture();
    let scope = digest("scope");
    write_standing_store(
        &fixture.standing_store,
        &[mandate(
            &digest("other-subject"),
            &scope,
            1,
            MandateStatusV1::Active,
            NOW + 60_000,
        )],
    );
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &digest("subject"), &scope);

    let response = decision(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(response.decision, ExternalDecisionV1::Refused);
    assert_eq!(response.refusal.unwrap().code, "absent_standing");
}

#[test]
fn replayed_occurrence_id_is_refused_without_a_second_spend() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();

    let first = decision(adjudicate(
        &fixture.config,
        &default_request(occurrence, &subject, &scope),
        NOW,
    ));
    assert_eq!(first.decision, ExternalDecisionV1::Authorized);

    // A fresh request id carrying the same occurrence id is still a replay.
    let second = decision(adjudicate(
        &fixture.config,
        &default_request(occurrence, &subject, &scope),
        NOW + 1,
    ));
    assert_eq!(second.decision, ExternalDecisionV1::Refused);
    assert_eq!(
        second.refusal.unwrap().code,
        "occurrence_already_adjudicated"
    );

    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn the_same_action_under_a_fresh_occurrence_id_is_independently_adjudicated() {
    let (fixture, subject, scope) = active_fixture();
    let first_occurrence = Uuid::new_v4();
    let second_occurrence = Uuid::new_v4();

    let first = decision(adjudicate(
        &fixture.config,
        &default_request(first_occurrence, &subject, &scope),
        NOW,
    ));
    let second = decision(adjudicate(
        &fixture.config,
        &default_request(second_occurrence, &subject, &scope),
        NOW,
    ));

    assert_eq!(first.decision, ExternalDecisionV1::Authorized);
    assert_eq!(second.decision, ExternalDecisionV1::Authorized);
    assert_ne!(
        first.authorization.as_ref().unwrap().ag_occurrence_id,
        second.authorization.as_ref().unwrap().ag_occurrence_id
    );
    // Same exact action digest on both; the replay guard keys on the
    // occurrence id, not the action.
    assert_eq!(first.action_digest, second.action_digest);
    for occurrence in [first_occurrence, second_occurrence] {
        let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
        assert_eq!(engine.replay().unwrap().ag_spends, 1);
    }
}

#[test]
fn adjudication_state_survives_a_daemon_restart() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();

    let first = decision(adjudicate(
        &fixture.config,
        &default_request(occurrence, &subject, &scope),
        NOW,
    ));
    assert_eq!(first.decision, ExternalDecisionV1::Authorized);

    // Simulate a restart: a fresh configuration over the same state dir.
    let restarted = fixture.config.clone();
    let second = decision(adjudicate(
        &restarted,
        &default_request(occurrence, &subject, &scope),
        NOW + 5_000,
    ));
    assert_eq!(second.decision, ExternalDecisionV1::Refused);
    assert_eq!(
        second.refusal.unwrap().code,
        "occurrence_already_adjudicated"
    );
    let engine = CampaignEngineV1::open(&store_path(&fixture, occurrence)).unwrap();
    assert_eq!(engine.replay().unwrap().ag_spends, 1);
}

#[test]
fn action_digest_substitution_is_invalid_input_not_a_decision() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    // Tamper: the digest no longer matches the canonical action bytes.
    request.action.canonical_json = "{\"args\":[\"bye\"],\"command\":\"echo\"}".to_owned();

    let error = rejected(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert_eq!(error.request_id, Some(request.request_id.clone()));
    // No decision was recorded: no per-occurrence state exists.
    assert!(!store_path(&fixture, occurrence).exists());
    assert!(
        std::fs::read_dir(&fixture.state_dir)
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn non_continue_admissibility_is_invalid_input_not_a_decision() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    request.admissibility.decision = "stop".to_owned();

    let error = rejected(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert!(!store_path(&fixture, occurrence).exists());
}

#[test]
fn stage_work_schema_inconsistency_is_invalid_input() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = default_request(occurrence, &subject, &scope);
    request.action.work_schema = "codex.prepared-apply-patch/v1".to_owned();

    let error = rejected(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert!(!store_path(&fixture, occurrence).exists());
}

#[test]
fn a_malformed_standing_store_at_request_time_is_infrastructure_never_a_refusal() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);
    // The store becomes malformed between startup and the request.
    std::fs::write(&fixture.standing_store, b"{not json").unwrap();

    let error = rejected(adjudicate(&fixture.config, &request, NOW));

    assert_eq!(error.kind, ErrorKindV1::Infrastructure);
    // No decision was recorded and no adjudication state exists.
    assert!(
        std::fs::read_dir(&fixture.state_dir)
            .unwrap()
            .next()
            .is_none()
    );

    // Same for a syntactically valid but non-conformant store document.
    std::fs::write(
        &fixture.standing_store,
        br#"{"schema":"other/v1","mandates":[]}"#,
    )
    .unwrap();
    let error = rejected(adjudicate(&fixture.config, &request, NOW));
    assert_eq!(error.kind, ErrorKindV1::Infrastructure);
    assert!(
        std::fs::read_dir(&fixture.state_dir)
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn two_daemons_with_identical_inputs_decide_identically() {
    // Determinism caveat: one occurrence id can never be adjudicated twice
    // (replay guard), so determinism is checked across two daemons with
    // identical fixtures and distinct occurrence ids. Decision-relevant
    // fields (decision, content-derived mandate ref, standing expiry) are
    // identical; occurrence-bound refs differ by construction.
    let (left, subject, scope) = active_fixture();
    let right = fixture();
    // The standing store content is identical even though the file differs.
    let store = load_standing_store(&left.standing_store).unwrap();
    write_standing_store(&right.standing_store, &store.mandates);

    let left_response = decision(adjudicate(
        &left.config,
        &default_request(Uuid::new_v4(), &subject, &scope),
        NOW,
    ));
    let right_response = decision(adjudicate(
        &right.config,
        &default_request(Uuid::new_v4(), &subject, &scope),
        NOW,
    ));

    assert_eq!(left_response.decision, ExternalDecisionV1::Authorized);
    assert_eq!(right_response.decision, ExternalDecisionV1::Authorized);
    let left = left_response.authorization.unwrap();
    let right = right_response.authorization.unwrap();
    assert_eq!(left.mandate_ref, right.mandate_ref);
    assert_eq!(
        left.standing_expires_at_unix_ms,
        right.standing_expires_at_unix_ms
    );
    // Occurrence-bound identities differ across distinct occurrence ids.
    assert_ne!(left.campaign_id, right.campaign_id);
    assert_ne!(left.issuance_ref, right.issuance_ref);
    assert_ne!(left.standing_resolution_ref, right.standing_resolution_ref);
}

// Catalog/work binding mismatch (a proposal work digest differing from the
// engine's expected work) is structurally unreachable in this daemon: the
// expected work digest and the proposal work digest are both the same
// `hash_domain("ag.external-authorization.work/v1", canonical_json)` value
// derived in one place, and step-1 validation already pins
// `action_digest == sha256(canonical_json)`. There is no request shape that
// separates them, so no test can express it; the kernel's binding check
// remains as defense in depth. Stale observation is likewise unreachable
// with the shipped fixture, which always answers `Current` with a fresh
// window.
