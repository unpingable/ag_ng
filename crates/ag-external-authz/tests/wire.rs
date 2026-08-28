//! Wire robustness: framing limits, malformed input, and strict decoding all
//! fail the connection closed without a decision.

mod common;

use std::io::Write as _;
use std::os::unix::net::UnixStream;

use ag_external_authz::daemon::handle_connection;
use ag_external_authz::protocol::{
    ERROR_SCHEMA_V1, ErrorKindV1, ExternalAuthorizationErrorV1, ExternalAuthorizationResponseV1,
    ExternalDecisionV1,
};
use ag_protocol::strict_json_from_slice;
use common::{NOW, active_fixture, default_request, fixture, store_path};
use uuid::Uuid;

fn error_response(payload: &[u8]) -> ExternalAuthorizationErrorV1 {
    let error: ExternalAuthorizationErrorV1 = strict_json_from_slice(payload).unwrap();
    assert_eq!(error.schema, ERROR_SCHEMA_V1);
    error
}

#[test]
fn a_valid_request_round_trips_over_the_socket() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let request = default_request(occurrence, &subject, &scope);

    let payload = common::socket_roundtrip(&fixture.config, &serde_json::to_vec(&request).unwrap());
    let response: ExternalAuthorizationResponseV1 = strict_json_from_slice(&payload).unwrap();

    assert_eq!(response.decision, ExternalDecisionV1::Authorized);
    assert_eq!(response.request_id, request.request_id);
    assert!(response.authorization.is_some());
    assert!(store_path(&fixture, occurrence).exists());
}

#[test]
fn an_oversized_frame_fails_closed_without_a_decision() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let config = fixture.config.clone();
    let server_thread = std::thread::spawn(move || handle_connection(&mut server, &config, NOW));
    // Declare a payload one byte over the 4 MiB request limit, then stop.
    let oversized = ag_external_authz::framing::MAX_REQUEST_FRAME_BYTES + 1;
    client.write_all(&oversized.to_be_bytes()).unwrap();

    let payload = ag_external_authz::framing::request_codec()
        .read_frame(&mut client)
        .unwrap();
    server_thread.join().unwrap();

    let error = error_response(&payload);
    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert_eq!(error.request_id, None);
    let _ = (subject, scope);
    assert!(!store_path(&fixture, occurrence).exists());
}

#[test]
fn malformed_json_fails_closed_without_a_decision() {
    let fixture = fixture();
    common::write_standing_store(&fixture.standing_store, &[]);

    let payload = common::socket_roundtrip(&fixture.config, b"{not json");

    let error = error_response(&payload);
    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert_eq!(error.request_id, None);
    assert!(
        std::fs::read_dir(&fixture.state_dir)
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn an_unknown_schema_is_rejected_as_invalid_input() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = serde_json::to_value(default_request(occurrence, &subject, &scope)).unwrap();
    request["schema"] = serde_json::json!("ag.something-else:v9");

    let payload = common::socket_roundtrip(&fixture.config, &serde_json::to_vec(&request).unwrap());

    let error = error_response(&payload);
    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    // The request decoded, so the request id is echoed.
    assert!(error.request_id.is_some());
    assert!(!store_path(&fixture, occurrence).exists());
}

#[test]
fn unknown_fields_fail_closed_without_a_decision() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = serde_json::to_value(default_request(occurrence, &subject, &scope)).unwrap();
    request["unexpected"] = serde_json::json!("field");

    let payload = common::socket_roundtrip(&fixture.config, &serde_json::to_vec(&request).unwrap());

    let error = error_response(&payload);
    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    // Strict decoding failed, so there is no request id to echo.
    assert_eq!(error.request_id, None);
    assert!(!store_path(&fixture, occurrence).exists());
}

#[test]
fn a_canonical_digest_must_be_canonical_text() {
    let (fixture, subject, scope) = active_fixture();
    let occurrence = Uuid::new_v4();
    let mut request = serde_json::to_value(default_request(occurrence, &subject, &scope)).unwrap();
    request["subject_digest"] = serde_json::json!("sha256:XYZ");

    let payload = common::socket_roundtrip(&fixture.config, &serde_json::to_vec(&request).unwrap());

    let error = error_response(&payload);
    assert_eq!(error.kind, ErrorKindV1::InvalidRequest);
    assert!(!store_path(&fixture, occurrence).exists());
}
