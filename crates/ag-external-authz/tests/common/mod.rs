//! Shared fixtures for the `ag-external-authz` integration tests.
//!
//! Each integration-test binary uses a different subset of these helpers.
#![allow(
    dead_code,
    reason = "shared across independently compiled test binaries"
)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use ag_app::standing_authority::{MandateStatusV1, StandingMandateStoreV1, StandingMandateV1};
use ag_external_authz::adjudicate::DaemonConfigV1;
use ag_external_authz::admissibility::computed_receipt_digest;
use ag_external_authz::protocol::{
    ActionDescriptorV1, AdmissibilityDescriptorV1, EvidenceUsedV1, ExternalAuthorizationRequestV1,
    OccurrenceDescriptorV1, OccurrenceStageV1, REQUEST_SCHEMA_V1,
};
use ag_primitives::Digest;
use tempfile::TempDir;
use uuid::Uuid;

/// One fixed consequence-time clock reading for all tests.
pub const NOW: u64 = 1_800_000_000_000;
/// Test observation resolver identity.
pub const OBSERVATION_RESOLVER_ID: &str = "ag-external-authz.test-observation-resolver/v1";
/// Test standing resolver identity.
pub const STANDING_RESOLVER_ID: &str = "ag-external-authz.test-standing-resolver/v1";
/// Standing answer lease used by the tests.
pub const ANSWER_TTL_MS: u64 = 1_000;
/// Kernel-accepted maximum standing-answer lifetime used by the tests.
pub const MAX_STANDING_TTL_MS: u64 = 60_000;

/// Derives one labeled test digest.
pub fn digest(label: &str) -> Digest {
    Digest::hash_domain("ag-external-authz-test/v1", label.as_bytes())
}

/// One daemon deployment under a temporary directory.
pub struct Fixture {
    /// Owns the temporary directory lifetime.
    pub directory: TempDir,
    /// Daemon state directory (mode 0700).
    pub state_dir: PathBuf,
    /// Standing mandate store path.
    pub standing_store: PathBuf,
    /// Daemon configuration pointing at the above.
    pub config: DaemonConfigV1,
}

/// Creates one deployment fixture with mode-0700 state directory.
pub fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let state_dir = directory.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let standing_store = directory.path().join("standing.json");
    let config = DaemonConfigV1 {
        state_dir: state_dir.clone(),
        standing_store: standing_store.clone(),
        observation_resolver_id: OBSERVATION_RESOLVER_ID.to_owned(),
        standing_resolver_id: STANDING_RESOLVER_ID.to_owned(),
        max_standing_ttl_ms: MAX_STANDING_TTL_MS,
        max_admissibility_age_ms: ANSWER_TTL_MS,
        answer_ttl_ms: ANSWER_TTL_MS,
    };
    Fixture {
        directory,
        state_dir,
        standing_store,
        config,
    }
}

/// Builds one mandate record.
pub fn mandate(
    subject: &Digest,
    scope: &Digest,
    generation: u64,
    status: MandateStatusV1,
    valid_until_unix_ms: u64,
) -> StandingMandateV1 {
    StandingMandateV1 {
        subject: subject.clone(),
        scope: scope.clone(),
        generation,
        status,
        valid_until_unix_ms,
    }
}

/// Writes a conformant mandate store, sorted into canonical order.
pub fn write_standing_store(path: &Path, mandates: &[StandingMandateV1]) {
    let mut mandates = mandates.to_vec();
    mandates.sort();
    let store = StandingMandateStoreV1 {
        schema: ag_app::standing_authority::STANDING_MANDATE_STORE_SCHEMA_V1.to_owned(),
        mandates,
    };
    std::fs::write(path, serde_json::to_vec_pretty(&store).unwrap()).unwrap();
}

/// The one canonical action payload used by default.
pub const DEFAULT_ACTION_JSON: &str = "{\"args\":[\"hello\"],\"command\":\"echo\"}";

/// Builds one valid request for `stage` with the given identities.
pub fn request(
    occurrence_id: Uuid,
    subject: &Digest,
    scope: &Digest,
    stage: OccurrenceStageV1,
    canonical_json: &str,
) -> ExternalAuthorizationRequestV1 {
    let mut request = ExternalAuthorizationRequestV1 {
        schema: REQUEST_SCHEMA_V1.to_owned(),
        request_id: Uuid::new_v4().to_string(),
        occurrence: OccurrenceDescriptorV1 {
            authorization_occurrence_id: occurrence_id.to_string(),
            session_id: "session-1".to_owned(),
            thread_id: "thread-1".to_owned(),
            turn_id: "turn-1".to_owned(),
            call_id: "call-1".to_owned(),
            stage,
        },
        action: ActionDescriptorV1 {
            work_schema: stage.work_schema().to_owned(),
            canonical_json: canonical_json.to_owned(),
            action_digest: Digest::hash_bytes(canonical_json.as_bytes()),
        },
        subject_digest: subject.clone(),
        scope_digest: scope.clone(),
        admissibility: AdmissibilityDescriptorV1 {
            profile_id: "codex.admissibility-profile/v1".to_owned(),
            profile_revision: "7".to_owned(),
            decision: "continue".to_owned(),
            evaluation_time_unix_ms: NOW,
            evidence_used: vec![EvidenceUsedV1 {
                requirement_id: "req-1".to_owned(),
                fact_id: "fact-1".to_owned(),
                receipt_id: Digest::parse(&format!("sha256:{}", "d".repeat(64))).unwrap(),
                qualifier_id: "qualifier-1".to_owned(),
                qualifier_revision: "rev-1".to_owned(),
            }],
            receipt_digest: Digest::hash_bytes(b"initialized below"),
        },
    };
    request.admissibility.receipt_digest = computed_receipt_digest(&request.admissibility).unwrap();
    request
}

/// Recomputes the exact receipt identity after an intentional semantic
/// fixture change.
pub fn rebind_admissibility(request: &mut ExternalAuthorizationRequestV1) {
    request.admissibility.receipt_digest = computed_receipt_digest(&request.admissibility).unwrap();
}

/// The default valid request: generic tool proposal over the default action.
pub fn default_request(
    occurrence_id: Uuid,
    subject: &Digest,
    scope: &Digest,
) -> ExternalAuthorizationRequestV1 {
    request(
        occurrence_id,
        subject,
        scope,
        OccurrenceStageV1::GenericToolProposal,
        DEFAULT_ACTION_JSON,
    )
}

/// The per-occurrence campaign store path under the fixture state dir.
pub fn store_path(fixture: &Fixture, occurrence_id: Uuid) -> PathBuf {
    fixture
        .state_dir
        .join(occurrence_id.hyphenated().to_string())
        .join("campaign.sqlite")
}

/// One fixture whose standing store carries an active generation-1 mandate
/// for the returned `(subject, scope)`, valid until `NOW + 60_000`.
pub fn active_fixture() -> (Fixture, Digest, Digest) {
    let fixture = fixture();
    let subject = digest("subject");
    let scope = digest("scope");
    write_standing_store(
        &fixture.standing_store,
        &[mandate(
            &subject,
            &scope,
            1,
            MandateStatusV1::Active,
            NOW + 60_000,
        )],
    );
    (fixture, subject, scope)
}

/// Sends one raw frame to `handle_connection` over a socket pair and returns
/// the raw response payload bytes.
pub fn socket_roundtrip(config: &DaemonConfigV1, frame_payload: &[u8]) -> Vec<u8> {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let config = config.clone();
    let server_thread = std::thread::spawn(move || {
        ag_external_authz::daemon::handle_connection(&mut server, &config, NOW);
    });
    let frame = ag_protocol::FrameCodec::new(ag_external_authz::framing::MAX_REQUEST_FRAME_BYTES)
        .unwrap()
        .encode_frame(frame_payload)
        .unwrap();
    client.write_all(&frame).unwrap();
    let response = ag_external_authz::framing::request_codec()
        .read_frame(&mut client)
        .unwrap();
    server_thread.join().unwrap();
    response
}
