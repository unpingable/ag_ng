//! Live, feature-gated fixture coverage for the generic worker ingress substrate.

#![cfg(feature = "worker-fixture")]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::agd::AgdCoreV1;
use ag_app::api::{
    ApiResultV1, EffectAdminRequestV1, EffectAdminResponseV1, EffectProposalRequestV1,
    EffectProposalResponseV1, WorkerCandidateBootstrapV1, WorkerCandidateRequestV1,
};
use ag_app::config::{
    AgdConfigV1, AgdLimitsV1, EffectTargetConfigV1, EffectdConfigV1, FilesystemNodeCustodyV1,
    PeerPolicyV1, SocketCustodyConfigV1, StoreConfigV1, StoreCustodyConfigV1,
    WorkerLauncherConfigV1, WorkerProfileConfigV1,
};
use ag_app::effectd::{EffectBrokerV1, RefusingEffectRunnerV1, configured_catalog_identity};
use ag_app::rpc_auth::{
    RpcKeyIdV1, RpcReplayGuardV1, RpcSignerV1, RpcSigningIdentityConfigV1, SystemRpcClockV1,
    VerifiedRpcPrincipalV1, verify_forwarded_signed_request,
};
use ag_app::signed_transport::{
    AcceptedSignedRequestV1, SocketPeerCheckV1, accept_signed_request, write_signed_response,
};
use ag_app::transport::bind_socket;
use ag_app::worker::{AdmittedWorkerInputV1, prepare_worker_launch};
use ag_app::worker_protocol::{
    CANDIDATE_BOOTSTRAP_PURPOSE, CANDIDATE_INGRESS_CREDENTIAL_PURPOSE,
    decode_exact_signed_worker_candidate,
};
use ag_primitives::{
    AuthorityDomain, Digest, Epoch, ExecutableIdentityV1, LifecycleNonce, PrincipalKindV1,
};
use ag_protocol::{FrameCodec, RequestId, canonical_json};
use ag_session::{
    SecurityProfileV1, SessionError, WorkerAuthorityStateV1, WorkerCandidateBrokerOutcomeV1,
    WorkerCandidateCustodyStateV1, WorkerCandidateRefusalCodeV1, WorkerCleanupStateV1,
    WorkerIngressContextV1, WorkerTerminationReasonV1,
};
use ag_store::{Store, StoreActivationIdentityV1, StoreIdentityV1, WriterIdentityV1};
use tempfile::TempDir;

const FIXTURE_WORKER: &str = env!("CARGO_BIN_EXE_ag-worker-fixture");
const BWRAP: &str = "/usr/bin/bwrap";
const MAXIMUM_CANDIDATE_FRAME_BYTES: u32 = 64 * 1024;
const CANDIDATE: &[u8] = b"candidate proposal material";

fn executable_identity(path: &Path) -> ExecutableIdentityV1 {
    let bytes = fs::read(path).expect("read executable fixture");
    ExecutableIdentityV1::new(Digest::hash_bytes(&bytes), bytes.len() as u64, None)
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock")
            .as_millis(),
    )
    .expect("wall clock fits u64")
}

fn filesystem_custody(path: &Path) -> FilesystemNodeCustodyV1 {
    let metadata = fs::metadata(path).expect("filesystem custody metadata");
    FilesystemNodeCustodyV1 {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    }
}

fn peer_policy(role: &str, signer: &RpcSignerV1, kind: PrincipalKindV1) -> PeerPolicyV1 {
    let enrollment = signer.enrollment(30_000).expect("peer enrollment");
    PeerPolicyV1 {
        role: role.to_owned(),
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
        executable_identity: None,
        cgroup_contains: None,
        stable_principal_root: enrollment.principal.clone(),
        principal_kind: kind,
        rpc_key: enrollment.key,
    }
}

fn ephemeral_signer(label: &str) -> RpcSignerV1 {
    RpcSignerV1::generate_ephemeral_candidate_ingress(
        Digest::hash_domain("ag-ng/live-worker-test-principal/v1", label.as_bytes()),
        RpcKeyIdV1::new(label).expect("test key id"),
    )
    .expect("ephemeral test signer")
    .0
}

fn open_agd_store(root: &TempDir, governor: &RpcSignerV1) -> Store {
    Store::open_activated(
        root.path().join("agd.sqlite"),
        root.path().join("objects"),
        StoreIdentityV1::current(0x4147_44f1, "agd-live-worker-test").expect("store identity"),
        &StoreActivationIdentityV1 {
            schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
            authority_domain: AuthorityDomain::new("test.live-worker").expect("authority domain"),
            epoch: Epoch::new(1).expect("epoch"),
            config_identity: Digest::hash_bytes(b"live-worker-test-config"),
            security_profile_identity: SecurityProfileV1::Development.identity(),
            build_identity: Digest::hash_bytes(b"live-worker-test-build"),
            authority_catalog_identity: None,
        },
        &WriterIdentityV1 {
            writer_id: "agd-live-worker-test-writer".to_owned(),
            principal_digest: governor.principal().clone(),
            process_nonce: "agd-live-worker-test-process".to_owned(),
            claimed_at_unix_ms: i64::try_from(now_unix_ms()).expect("test clock fits i64"),
        },
    )
    .expect("open activated agd store")
}

fn open_effectd_store(root: &TempDir, broker: &RpcSignerV1, catalog: &Digest) -> Store {
    Store::open_activated(
        root.path().join("effectd.sqlite"),
        root.path().join("objects"),
        StoreIdentityV1::current(0x4147_45f1, "effectd-live-worker-test")
            .expect("effectd store identity"),
        &StoreActivationIdentityV1 {
            schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
            authority_domain: AuthorityDomain::new("test.live-worker").expect("authority domain"),
            epoch: Epoch::new(1).expect("epoch"),
            config_identity: Digest::hash_bytes(b"live-worker-effectd-test-config"),
            security_profile_identity: SecurityProfileV1::Development.identity(),
            build_identity: Digest::hash_bytes(b"live-worker-effectd-test-build"),
            authority_catalog_identity: Some(catalog.clone()),
        },
        &WriterIdentityV1 {
            writer_id: "effectd-live-worker-test-writer".to_owned(),
            principal_digest: broker.principal().clone(),
            process_nonce: "effectd-live-worker-test-process".to_owned(),
            claimed_at_unix_ms: i64::try_from(now_unix_ms()).expect("test clock fits i64"),
        },
    )
    .expect("open activated effectd store")
}

fn socket_custody(parent: &Path) -> SocketCustodyConfigV1 {
    let parent_custody = filesystem_custody(parent);
    SocketCustodyConfigV1 {
        node: FilesystemNodeCustodyV1 {
            uid: parent_custody.uid,
            gid: parent_custody.gid,
            mode: 0o660,
        },
        parent: parent_custody,
    }
}

#[test]
// Keep the reviewed executable, activation inputs, release, and proof checks
// in one linear test so the live authority boundary remains directly auditable.
#[allow(clippy::too_many_lines)]
fn real_fixed_elf_enters_only_through_signed_candidate_ingress() {
    assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
    let temporary = TempDir::new().expect("temporary live worker fixture");
    let reviewed = temporary.path().join("reviewed");
    let workspace_root = temporary.path().join("workspaces");
    fs::create_dir(&reviewed).expect("review directory");
    fs::create_dir(&workspace_root).expect("workspace root");
    fs::set_permissions(&reviewed, fs::Permissions::from_mode(0o700))
        .expect("review directory mode");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("workspace root mode");

    let fixture_worker = reviewed.join("worker");
    fs::copy(FIXTURE_WORKER, &fixture_worker).expect("install reviewed fixture ELF");
    fs::set_permissions(&fixture_worker, fs::Permissions::from_mode(0o555))
        .expect("make fixture ELF non-writable");

    let governed_root = TempDir::new().expect("governed target root");
    let governed_target = governed_root.path().join("managed-target");
    fs::write(&governed_target, b"governed and unchanged").expect("write governed target");
    let governed_target_argument = governed_target
        .to_str()
        .expect("UTF-8 governed target")
        .to_owned();
    let candidate_argument = std::str::from_utf8(CANDIDATE)
        .expect("UTF-8 fixture candidate")
        .to_owned();

    let workspace_metadata = fs::metadata(&workspace_root).expect("workspace root metadata");
    let launcher = WorkerLauncherConfigV1 {
        governor_principal_root: Digest::hash_domain("ag-ng/test", b"governor"),
        governor_challenge_maximum_clock_skew_ms: 30_000,
        workspace_root,
        workspace_root_custody: FilesystemNodeCustodyV1 {
            uid: workspace_metadata.uid(),
            gid: workspace_metadata.gid(),
            mode: workspace_metadata.mode() & 0o7777,
        },
        sandbox_executable: PathBuf::from(BWRAP),
        sandbox_identity: executable_identity(Path::new(BWRAP)),
        runtime_roots: vec![PathBuf::from("/usr")],
        profiles: vec![WorkerProfileConfigV1 {
            profile_id: "signed-fixture".to_owned(),
            project: "fixture-project".to_owned(),
            executable: fixture_worker.clone(),
            executable_identity: executable_identity(&fixture_worker),
            fixed_arguments: vec![
                "--probe-governed-target".to_owned(),
                governed_target_argument,
                "--emit".to_owned(),
                candidate_argument,
            ],
            managed_file_target: "fixture.target".to_owned(),
            candidate_semantic_type: "managed_file_content_v1".to_owned(),
            timeout_ms: 2_000,
            output_budget_bytes: 1024,
        }],
    };

    let governor_principal = Digest::hash_bytes(b"fixture governor");
    let (governor, _governor_private) = RpcSignerV1::generate_ephemeral_candidate_ingress(
        governor_principal,
        RpcKeyIdV1::new("fixture-governor").expect("governor key id"),
    )
    .expect("governor signer");
    let worker_principal = Digest::hash_bytes(b"durably bound fixture worker principal");
    let (worker, worker_private) = RpcSignerV1::generate_ephemeral_candidate_ingress(
        worker_principal.clone(),
        RpcKeyIdV1::new("fixture-worker-session").expect("worker key id"),
    )
    .expect("worker candidate signer");
    let worker_enrollment = worker.enrollment(30_000).expect("worker enrollment");
    let issued_at = now_unix_ms();
    let challenge = governor
        .issue_challenge(&worker_enrollment, issued_at)
        .expect("worker challenge");
    let candidate_nonce = LifecycleNonce::new([7; 16]);
    let bootstrap = WorkerCandidateBootstrapV1 {
        schema: "ag.worker-candidate-bootstrap/v1".to_owned(),
        principal: worker_principal.clone(),
        key_id: worker.key_id().clone(),
        candidate_nonce,
        semantic_type: "managed_file_content_v1".to_owned(),
        request_id: RequestId::new("live-worker-candidate").expect("request id"),
        maximum_frame_bytes: MAXIMUM_CANDIDATE_FRAME_BYTES,
        maximum_candidate_bytes: 1024,
        server_challenge: challenge.clone(),
    };
    let bootstrap_payload = canonical_json(&bootstrap).expect("canonical bootstrap");
    let bootstrap_frame = FrameCodec::new(4096)
        .expect("bootstrap frame codec")
        .encode_frame(&bootstrap_payload)
        .expect("bootstrap frame");
    let admitted_inputs = [
        AdmittedWorkerInputV1 {
            descriptor: 3,
            purpose: CANDIDATE_INGRESS_CREDENTIAL_PURPOSE.to_owned(),
            maximum_bytes: 4096,
        },
        AdmittedWorkerInputV1 {
            descriptor: 4,
            purpose: CANDIDATE_BOOTSTRAP_PURPOSE.to_owned(),
            maximum_bytes: 4096,
        },
    ];

    let mut prepared = prepare_worker_launch(
        SecurityProfileV1::Development,
        &launcher,
        "signed-fixture",
        "live-worker-session",
        u64::from(MAXIMUM_CANDIDATE_FRAME_BYTES) + 4,
        &admitted_inputs,
    )
    .expect("prepare fixed worker ELF");
    let mut worker_private_bytes = Vec::new();
    worker_private
        .write_to(&mut worker_private_bytes)
        .expect("serialize ephemeral candidate credential");
    let mut pipes = std::mem::take(&mut prepared.admitted_inputs).into_iter();
    let mut credential_pipe = pipes.next().expect("credential pipe");
    let mut bootstrap_pipe = pipes.next().expect("bootstrap pipe");
    assert!(pipes.next().is_none());
    credential_pipe
        .write_all(&worker_private_bytes)
        .expect("populate credential descriptor");
    bootstrap_pipe
        .write_all(&bootstrap_frame)
        .expect("populate bootstrap descriptor");
    credential_pipe.close();
    bootstrap_pipe.close();
    let workspace_path = prepared.workspace.path.clone();
    prepared.release.release().expect("release live worker");

    let completed = prepared.process.wait().expect("collect live worker");
    assert!(
        completed.status.success(),
        "fixture worker returned bounded refusal marker: {}",
        workspace_path.join("fixture-error").is_file()
    );
    assert_eq!(
        fs::read(&governed_target).expect("reread governed target"),
        b"governed and unchanged"
    );
    assert!(
        !completed
            .candidate
            .windows(worker_private_bytes.len())
            .any(|window| window == worker_private_bytes),
        "private candidate-ingress key leaked into worker output"
    );
    worker_private_bytes.fill(0);

    let signed =
        decode_exact_signed_worker_candidate(&completed.candidate, MAXIMUM_CANDIDATE_FRAME_BYTES)
            .expect("decode one exact candidate frame");
    match &signed.request.body {
        WorkerCandidateRequestV1::Submit {
            candidate_nonce: observed_nonce,
            semantic_type,
            content,
        } => {
            assert_eq!(*observed_nonce, candidate_nonce);
            assert_eq!(semantic_type, "managed_file_content_v1");
            assert_eq!(content.as_slice(), CANDIDATE);
        }
    }
    let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
    let verified = verify_forwarded_signed_request(
        &challenge,
        &signed,
        &governor_enrollment,
        &worker_enrollment,
        &RpcReplayGuardV1::new(8).expect("replay guard"),
        now_unix_ms(),
    )
    .expect("verify live end-to-end worker signature");
    assert_eq!(verified.principal, worker_principal);
}

#[test]
#[allow(clippy::too_many_lines)]
fn agd_core_recovers_custodied_fixture_into_broker_owned_canonical_proposal() {
    assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
    let temporary = TempDir::new().expect("temporary core worker fixture");
    let reviewed = temporary.path().join("reviewed");
    let workspace_root = temporary.path().join("workspaces");
    fs::create_dir(&reviewed).expect("review directory");
    fs::create_dir(&workspace_root).expect("workspace root");
    fs::set_permissions(&reviewed, fs::Permissions::from_mode(0o700))
        .expect("review directory mode");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("workspace root mode");

    let fixture_worker = reviewed.join("worker");
    fs::copy(FIXTURE_WORKER, &fixture_worker).expect("install reviewed fixture ELF");
    fs::set_permissions(&fixture_worker, fs::Permissions::from_mode(0o555))
        .expect("make fixture ELF non-writable");

    let store_root = TempDir::new().expect("governor store root");
    let governor = std::sync::Arc::new(ephemeral_signer("agd-live-worker"));
    let proposer = ephemeral_signer("proposer-live-worker");
    let effectd = ephemeral_signer("effectd-live-worker");
    let store = open_agd_store(&store_root, &governor);
    let unused_custody = filesystem_custody(temporary.path());
    let unused_store_custody = StoreCustodyConfigV1 {
        database_parent: unused_custody.clone(),
        object_store: unused_custody.clone(),
        database: unused_custody.clone(),
        writer_lock: unused_custody.clone(),
    };
    let unused_socket_custody = SocketCustodyConfigV1 {
        parent: unused_custody.clone(),
        node: unused_custody,
    };
    let launcher = WorkerLauncherConfigV1 {
        governor_principal_root: governor.principal().clone(),
        governor_challenge_maximum_clock_skew_ms: 30_000,
        workspace_root: workspace_root.clone(),
        workspace_root_custody: filesystem_custody(&workspace_root),
        sandbox_executable: PathBuf::from(BWRAP),
        sandbox_identity: executable_identity(Path::new(BWRAP)),
        runtime_roots: vec![PathBuf::from("/usr")],
        profiles: vec![WorkerProfileConfigV1 {
            profile_id: "core-signed-fixture".to_owned(),
            project: "fixture-project".to_owned(),
            executable: fixture_worker.clone(),
            executable_identity: executable_identity(&fixture_worker),
            fixed_arguments: vec![
                "--emit".to_owned(),
                std::str::from_utf8(CANDIDATE)
                    .expect("UTF-8 fixture candidate")
                    .to_owned(),
            ],
            managed_file_target: "fixture.target".to_owned(),
            candidate_semantic_type: "managed_file_content_v1".to_owned(),
            timeout_ms: 30_000,
            output_budget_bytes: 1024,
        }],
    };
    let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
    let config = AgdConfigV1 {
        schema: "ag.config.agd.v1".to_owned(),
        security_profile: "development".to_owned(),
        authority_domain: "test.live-worker".to_owned(),
        epoch: "1".to_owned(),
        store: StoreConfigV1 {
            database: temporary.path().join("unused-agd.sqlite"),
            object_store: temporary.path().join("unused-objects"),
            store_custody: unused_store_custody,
        },
        control_socket: temporary.path().join("unused-control.sock"),
        control_socket_custody: unused_socket_custody,
        effectd_proposal_socket: temporary
            .path()
            .join("effectd-proposal")
            .join("proposal.sock"),
        providerd_socket: temporary.path().join("absent-providerd.sock"),
        rpc_signing_identity: RpcSigningIdentityConfigV1 {
            principal: governor_enrollment.principal,
            key_id: governor_enrollment.key.key_id,
            public_key: governor_enrollment.key.public_key,
            private_key_credential: PathBuf::from("/unused-test-credential"),
        },
        proposer_peer: peer_policy("proposal_ingress", &proposer, PrincipalKindV1::Service),
        effectd_peer: peer_policy("effect_broker", &effectd, PrincipalKindV1::Daemon),
        worker_launcher: Some(launcher),
        limits: AgdLimitsV1 {
            max_control_frame_bytes: 1024 * 1024,
            max_rpc_replay_entries: 4096,
            max_artifact_bytes: 1024 * 1024,
            max_active_sessions: 1,
            max_session_seconds: 30,
        },
    };
    let replay = std::sync::Arc::new(RpcReplayGuardV1::new(4096).expect("replay guard"));
    let mut core = AgdCoreV1::new(store, config, std::sync::Arc::clone(&governor), replay)
        .expect("governor core");

    let (session, _principal) = core
        .launch_worker("core-signed-fixture")
        .expect("launch fixture through governor core");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let final_report = loop {
        let report = core.poll_workers().expect("poll live worker");
        if report.accepted > 0 || report.failed > 0 {
            break report;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "governor worker did not terminate"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let record = core
        .inspect_worker_session(&session)
        .expect("inspect durable worker session");
    let fixture_refused = fs::read_dir(&workspace_root)
        .expect("list proposal workspaces")
        .filter_map(Result::ok)
        .any(|entry| entry.path().join("fixture-error").is_file());
    assert_eq!(
        final_report.accepted, 1,
        "unexpected report {final_report:?}, record {record:?}, bounded fixture refusal marker: {fixture_refused}"
    );
    assert_eq!(final_report.failed, 0);
    assert_eq!(final_report.deferred, 1);

    let WorkerCandidateCustodyStateV1::InCustody { candidate } = record.candidate else {
        panic!("candidate did not enter durable governor custody");
    };
    assert_eq!(candidate.content, Digest::hash_bytes(CANDIDATE));
    assert_eq!(candidate.byte_length, CANDIDATE.len() as u64);
    assert_eq!(candidate.semantic_type, "managed_file_content_v1");
    assert!(matches!(
        record.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::CandidateAccepted
    ));

    let proposal_parent = temporary.path().join("effectd-proposal");
    let admin_parent = temporary.path().join("effectd-admin");
    fs::create_dir(&proposal_parent).expect("proposal socket parent");
    fs::create_dir(&admin_parent).expect("admin socket parent");
    fs::set_permissions(&proposal_parent, fs::Permissions::from_mode(0o2700))
        .expect("proposal socket parent mode");
    fs::set_permissions(&admin_parent, fs::Permissions::from_mode(0o2700))
        .expect("admin socket parent mode");
    let proposal_socket = proposal_parent.join("proposal.sock");
    let admin_socket = admin_parent.join("admin.sock");
    let managed_target = temporary.path().join("broker-managed-target");
    let effectd_store_root = TempDir::new().expect("effectd store root");
    let effectd_enrollment = effectd.enrollment(30_000).expect("effectd enrollment");
    let admin = ephemeral_signer("operator-live-worker");
    let mut effectd_config: EffectdConfigV1 =
        toml::from_str(include_str!("../../../config/effectd.example.toml"))
            .expect("strict effectd example");
    effectd_config.security_profile = "development".to_owned();
    effectd_config.authority_domain = "test.live-worker".to_owned();
    effectd_config.epoch = "1".to_owned();
    effectd_config.store.database = effectd_store_root.path().join("effectd.sqlite");
    effectd_config.store.object_store = effectd_store_root.path().join("objects");
    effectd_config.proposal_socket = proposal_socket.clone();
    effectd_config.proposal_socket_custody = socket_custody(&proposal_parent);
    effectd_config.admin_socket = admin_socket;
    effectd_config.admin_socket_custody = socket_custody(&admin_parent);
    effectd_config.rpc_signing_identity = RpcSigningIdentityConfigV1 {
        principal: effectd_enrollment.principal.clone(),
        key_id: effectd_enrollment.key.key_id.clone(),
        public_key: effectd_enrollment.key.public_key.clone(),
        private_key_credential: PathBuf::from("/unused-effectd-test-credential"),
    };
    effectd_config.agd_peer = peer_policy("governor_proposer", &governor, PrincipalKindV1::Daemon);
    effectd_config.proposer_peer =
        peer_policy("proposal_ingress", &proposer, PrincipalKindV1::Service);
    effectd_config.admin_peer = peer_policy("effect_operator", &admin, PrincipalKindV1::Operator);
    effectd_config.targets = vec![EffectTargetConfigV1::ManagedFile {
        id: "fixture.target".to_owned(),
        path: managed_target.clone(),
        mode: 0o600,
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    }];
    effectd_config
        .validate()
        .expect("valid test effectd config");
    let catalog = configured_catalog_identity(&effectd_config.targets).expect("catalog identity");
    let effectd_store = open_effectd_store(&effectd_store_root, &effectd, &catalog);
    let effectd_replay = std::sync::Arc::new(
        RpcReplayGuardV1::new(effectd_config.limits.max_rpc_replay_entries as usize)
            .expect("effectd replay guard"),
    );
    let mut broker = EffectBrokerV1::new(
        &effectd_config,
        &catalog,
        effectd_store,
        RefusingEffectRunnerV1,
        std::sync::Arc::clone(&effectd_replay),
    )
    .expect("effect broker");
    let listener = bind_socket(
        &effectd_config.proposal_socket,
        &effectd_config.proposal_socket_custody,
    )
    .expect("bind effectd proposal socket");
    let agd_enrollment = effectd_config
        .agd_peer
        .rpc_enrollment()
        .expect("effectd agd enrollment");
    let admin_peer = VerifiedRpcPrincipalV1 {
        principal: effectd_config.admin_peer.rpc_key.principal.clone(),
        key_id: effectd_config.admin_peer.rpc_key.key_id.clone(),
    };
    let maximum_frame_bytes = effectd_config.limits.max_control_frame_bytes;
    let expected_credentials = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    let broker_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept governor proposal RPC");
        let accepted: AcceptedSignedRequestV1<EffectProposalRequestV1> = accept_signed_request(
            &mut stream,
            FrameCodec::new(maximum_frame_bytes).expect("effectd frame codec"),
            &effectd,
            &agd_enrollment,
            &effectd_replay,
            &SystemRpcClockV1,
            SocketPeerCheckV1::RequireUidGid {
                uid: expected_credentials.0,
                gid: expected_credentials.1,
            },
        )
        .expect("accept signed governor proposal");
        let response =
            broker.handle_proposal(accepted.body().clone(), &accepted.authenticated_peer);
        write_signed_response(
            &mut stream,
            FrameCodec::new(maximum_frame_bytes).expect("effectd response codec"),
            &effectd,
            &accepted,
            response.clone(),
            &SystemRpcClockV1,
        )
        .expect("write signed broker response");
        let proposals = broker.handle_admin(
            EffectAdminRequestV1::ListProposals { limit: 10 },
            &admin_peer,
            &Digest::hash_bytes(b"test-only authenticated inspection binding"),
        );
        (response, proposals)
    });

    let recovery = core
        .recover_worker_candidates()
        .expect("recover exact custodied worker candidate");
    assert_eq!(recovery.canonicalized, 1);
    assert_eq!(recovery.deferred, 0);
    let canonical_record = core
        .inspect_worker_session(&session)
        .expect("inspect canonicalized worker session");
    let WorkerCandidateCustodyStateV1::BrokerCompleted {
        outcome: WorkerCandidateBrokerOutcomeV1::Canonicalized { canonical_proposal },
        ..
    } = canonical_record.candidate
    else {
        panic!("broker response did not durably link canonical proposal");
    };
    assert!(matches!(
        canonical_record.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::CandidateAccepted
    ));

    let (proposal_response, proposal_listing) =
        broker_server.join().expect("effectd test server thread");
    let broker_digest = match proposal_response {
        ApiResultV1::Ok {
            response:
                EffectProposalResponseV1::Canonicalized {
                    proposal_digest, ..
                },
        } => proposal_digest,
        other => panic!("broker did not canonicalize worker ingress: {other:?}"),
    };
    assert_eq!(broker_digest, canonical_proposal);
    match proposal_listing {
        ApiResultV1::Ok {
            response: EffectAdminResponseV1::Proposals { proposals },
        } => {
            assert_eq!(proposals.len(), 1);
            assert_eq!(proposals[0].proposal_digest, canonical_proposal);
        }
        other => panic!("broker inspection did not return canonical proposal: {other:?}"),
    }
    assert!(
        !managed_target.exists(),
        "canonicalization alone must not execute the managed-file effect"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn wrong_live_semantic_is_fenced_before_candidate_custody() {
    assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
    let temporary = TempDir::new().expect("temporary hostile worker fixture");
    let reviewed = temporary.path().join("reviewed");
    let workspace_root = temporary.path().join("workspaces");
    fs::create_dir(&reviewed).expect("review directory");
    fs::create_dir(&workspace_root).expect("workspace root");
    fs::set_permissions(&reviewed, fs::Permissions::from_mode(0o700))
        .expect("review directory mode");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("workspace root mode");
    let fixture_worker = reviewed.join("worker");
    fs::copy(FIXTURE_WORKER, &fixture_worker).expect("install reviewed fixture ELF");
    fs::set_permissions(&fixture_worker, fs::Permissions::from_mode(0o555))
        .expect("make fixture ELF non-writable");

    let store_root = TempDir::new().expect("hostile governor store root");
    let governor = std::sync::Arc::new(ephemeral_signer("agd-wrong-semantic"));
    let proposer = ephemeral_signer("proposer-wrong-semantic");
    let effectd = ephemeral_signer("effectd-wrong-semantic");
    let store = open_agd_store(&store_root, &governor);
    let unused_custody = filesystem_custody(temporary.path());
    let launcher = WorkerLauncherConfigV1 {
        governor_principal_root: governor.principal().clone(),
        governor_challenge_maximum_clock_skew_ms: 30_000,
        workspace_root: workspace_root.clone(),
        workspace_root_custody: filesystem_custody(&workspace_root),
        sandbox_executable: PathBuf::from(BWRAP),
        sandbox_identity: executable_identity(Path::new(BWRAP)),
        runtime_roots: vec![PathBuf::from("/usr")],
        profiles: vec![WorkerProfileConfigV1 {
            profile_id: "wrong-semantic-fixture".to_owned(),
            project: "fixture-project".to_owned(),
            executable: fixture_worker.clone(),
            executable_identity: executable_identity(&fixture_worker),
            fixed_arguments: vec![
                "--emit-semantic".to_owned(),
                "hostile_wrong_semantic_v1".to_owned(),
                std::str::from_utf8(CANDIDATE)
                    .expect("UTF-8 fixture candidate")
                    .to_owned(),
            ],
            managed_file_target: "fixture.target".to_owned(),
            candidate_semantic_type: "managed_file_content_v1".to_owned(),
            timeout_ms: 30_000,
            output_budget_bytes: 1024,
        }],
    };
    let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
    let config = AgdConfigV1 {
        schema: "ag.config.agd.v1".to_owned(),
        security_profile: "development".to_owned(),
        authority_domain: "test.live-worker".to_owned(),
        epoch: "1".to_owned(),
        store: StoreConfigV1 {
            database: temporary.path().join("unused-hostile-agd.sqlite"),
            object_store: temporary.path().join("unused-hostile-objects"),
            store_custody: StoreCustodyConfigV1 {
                database_parent: unused_custody.clone(),
                object_store: unused_custody.clone(),
                database: unused_custody.clone(),
                writer_lock: unused_custody.clone(),
            },
        },
        control_socket: temporary.path().join("unused-hostile-control.sock"),
        control_socket_custody: SocketCustodyConfigV1 {
            parent: unused_custody.clone(),
            node: unused_custody,
        },
        effectd_proposal_socket: temporary.path().join("absent-hostile-effectd.sock"),
        providerd_socket: temporary.path().join("absent-hostile-providerd.sock"),
        rpc_signing_identity: RpcSigningIdentityConfigV1 {
            principal: governor_enrollment.principal,
            key_id: governor_enrollment.key.key_id,
            public_key: governor_enrollment.key.public_key,
            private_key_credential: PathBuf::from("/unused-hostile-test-credential"),
        },
        proposer_peer: peer_policy("proposal_ingress", &proposer, PrincipalKindV1::Service),
        effectd_peer: peer_policy("effect_broker", &effectd, PrincipalKindV1::Daemon),
        worker_launcher: Some(launcher),
        limits: AgdLimitsV1 {
            max_control_frame_bytes: 1024 * 1024,
            max_rpc_replay_entries: 4096,
            max_artifact_bytes: 1024 * 1024,
            max_active_sessions: 1,
            max_session_seconds: 30,
        },
    };
    let replay = std::sync::Arc::new(RpcReplayGuardV1::new(4096).expect("replay guard"));
    let mut core = AgdCoreV1::new(store, config, governor, replay).expect("hostile governor core");
    let (session, _) = core
        .launch_worker("wrong-semantic-fixture")
        .expect("launch wrong-semantic fixture");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let report = loop {
        let report = core.poll_workers().expect("poll wrong-semantic worker");
        if report.failed > 0 || report.accepted > 0 {
            break report;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "wrong-semantic worker did not terminate"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert_eq!(report.failed, 1);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, 0);
    let record = core
        .inspect_worker_session(&session)
        .expect("inspect hostile durable session");
    assert!(matches!(
        record.candidate,
        WorkerCandidateCustodyStateV1::Awaiting
    ));
    assert!(matches!(
        record.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::CandidateRefused {
            code: WorkerCandidateRefusalCodeV1::ReviewedProfileMismatch,
        }
    ));
    let recovery = core
        .recover_worker_candidates()
        .expect("governor remains usable after hostile worker refusal");
    assert_eq!(recovery.canonicalized, 0);
    assert_eq!(recovery.deferred, 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn supervisor_timeout_tombstones_reaps_and_releases_fresh_capacity() {
    assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
    let temporary = TempDir::new().expect("temporary timeout worker fixture");
    let reviewed = temporary.path().join("reviewed");
    let workspace_root = temporary.path().join("workspaces");
    fs::create_dir(&reviewed).expect("review directory");
    fs::create_dir(&workspace_root).expect("workspace root");
    fs::set_permissions(&reviewed, fs::Permissions::from_mode(0o700))
        .expect("review directory mode");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("workspace root mode");
    let fixture_worker = reviewed.join("worker");
    fs::copy(FIXTURE_WORKER, &fixture_worker).expect("install reviewed fixture ELF");
    fs::set_permissions(&fixture_worker, fs::Permissions::from_mode(0o555))
        .expect("make fixture ELF non-writable");

    let store_root = TempDir::new().expect("timeout governor store root");
    let governor = std::sync::Arc::new(ephemeral_signer("agd-timeout"));
    let proposer = ephemeral_signer("proposer-timeout");
    let effectd = ephemeral_signer("effectd-timeout");
    let store = open_agd_store(&store_root, &governor);
    let unused_custody = filesystem_custody(temporary.path());
    let unused_directory_custody = FilesystemNodeCustodyV1 {
        mode: 0o700,
        ..unused_custody.clone()
    };
    let unused_file_custody = FilesystemNodeCustodyV1 {
        mode: 0o600,
        ..unused_custody.clone()
    };
    let launcher = WorkerLauncherConfigV1 {
        governor_principal_root: governor.principal().clone(),
        governor_challenge_maximum_clock_skew_ms: 30_000,
        workspace_root: workspace_root.clone(),
        workspace_root_custody: filesystem_custody(&workspace_root),
        sandbox_executable: PathBuf::from(BWRAP),
        sandbox_identity: executable_identity(Path::new(BWRAP)),
        runtime_roots: vec![PathBuf::from("/usr")],
        profiles: vec![WorkerProfileConfigV1 {
            profile_id: "timeout-fixture".to_owned(),
            project: "fixture-project".to_owned(),
            executable: fixture_worker.clone(),
            executable_identity: executable_identity(&fixture_worker),
            fixed_arguments: vec![
                "--sleep-then-emit".to_owned(),
                "1500".to_owned(),
                std::str::from_utf8(CANDIDATE)
                    .expect("UTF-8 fixture candidate")
                    .to_owned(),
            ],
            managed_file_target: "fixture.target".to_owned(),
            candidate_semantic_type: "managed_file_content_v1".to_owned(),
            timeout_ms: 750,
            output_budget_bytes: 1024,
        }],
    };
    let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
    let config = AgdConfigV1 {
        schema: "ag.config.agd.v1".to_owned(),
        security_profile: "development".to_owned(),
        authority_domain: "test.live-worker".to_owned(),
        epoch: "1".to_owned(),
        store: StoreConfigV1 {
            database: temporary.path().join("unused-timeout-agd.sqlite"),
            object_store: temporary.path().join("unused-timeout-objects"),
            store_custody: StoreCustodyConfigV1 {
                database_parent: unused_directory_custody.clone(),
                object_store: unused_directory_custody,
                database: unused_file_custody.clone(),
                writer_lock: unused_file_custody,
            },
        },
        control_socket: temporary.path().join("unused-timeout-control.sock"),
        control_socket_custody: SocketCustodyConfigV1 {
            parent: FilesystemNodeCustodyV1 {
                mode: 0o2700,
                ..unused_custody.clone()
            },
            node: FilesystemNodeCustodyV1 {
                mode: 0o660,
                ..unused_custody
            },
        },
        effectd_proposal_socket: temporary.path().join("absent-timeout-effectd.sock"),
        providerd_socket: temporary.path().join("absent-timeout-providerd.sock"),
        rpc_signing_identity: RpcSigningIdentityConfigV1 {
            principal: governor_enrollment.principal,
            key_id: governor_enrollment.key.key_id,
            public_key: governor_enrollment.key.public_key,
            private_key_credential: PathBuf::from("/unused-timeout-test-credential"),
        },
        proposer_peer: peer_policy("proposal_ingress", &proposer, PrincipalKindV1::Service),
        effectd_peer: peer_policy("effect_broker", &effectd, PrincipalKindV1::Daemon),
        worker_launcher: Some(launcher),
        limits: AgdLimitsV1 {
            max_control_frame_bytes: 1024 * 1024,
            max_rpc_replay_entries: 4096,
            max_artifact_bytes: 1024 * 1024,
            max_active_sessions: 1,
            max_session_seconds: 5,
        },
    };
    config
        .validate()
        .expect("valid timeout worker configuration");
    let replay = std::sync::Arc::new(RpcReplayGuardV1::new(4096).expect("replay guard"));
    let mut core = AgdCoreV1::new(store, config, governor, replay).expect("timeout governor core");

    let (expired_session, expired_principal) = core
        .launch_worker("timeout-fixture")
        .expect("launch fixture which exceeds its reviewed timeout");
    let poll_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let report = loop {
        let report = core.poll_workers().expect("poll timeout worker");
        if report.failed > 0 || report.accepted > 0 {
            break report;
        }
        assert!(
            std::time::Instant::now() < poll_deadline,
            "timeout worker did not reach its supervisor deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert_eq!(report.failed, 1);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, 0);

    let expired = core
        .inspect_worker_session(&expired_session)
        .expect("inspect expired worker history");
    assert!(matches!(
        expired.candidate,
        WorkerCandidateCustodyStateV1::Awaiting
    ));
    assert!(matches!(
        &expired.authority,
        WorkerAuthorityStateV1::Tombstoned {
            launch_receipt: Some(_),
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
        } if tombstone.reason == WorkerTerminationReasonV1::DeadlineExpired
    ));
    let principal = &expired.spec.worker.principal;
    let exact_late_context = WorkerIngressContextV1 {
        authority_domain: expired.spec.authority_domain.clone(),
        epoch: expired.spec.epoch,
        principal_id: principal.id(),
        session_id: expired_session.clone(),
        proposal_workspace_identity: principal.proposal_workspace_identity.clone(),
        security_profile_identity: principal.security_profile_identity.clone(),
        executable: principal.executable.clone(),
        observed_uid: principal.observed_credentials.uid,
        observed_gid: principal.observed_credentials.gid,
        now_unix_ms: now_unix_ms(),
    };
    assert!(matches!(
        expired.validate_active_ingress(&exact_late_context),
        Err(SessionError::PrincipalTombstoned)
    ));
    let recovery = core
        .recover_worker_sessions()
        .expect("inspect terminal worker during startup-style recovery");
    assert_eq!(recovery.tombstoned, 0);
    assert_eq!(recovery.already_terminal, 1);
    assert_eq!(
        core.inspect_worker_session(&expired_session)
            .expect("terminal history remains unchanged"),
        expired
    );

    let (fresh_session, fresh_principal) = core
        .launch_worker("timeout-fixture")
        .expect("supervisor capacity is reusable only by a fresh lifecycle");
    assert_ne!(fresh_session, expired_session);
    assert_ne!(fresh_principal, expired_principal);
    let cancellation = Digest::hash_domain("ag-ng/timeout-test-cancellation/v1", b"fresh-session");
    core.cancel_worker(&fresh_session, cancellation.clone())
        .expect("cancel and reap fresh replacement worker");
    let fresh = core
        .inspect_worker_session(&fresh_session)
        .expect("inspect cancelled fresh lifecycle");
    assert!(matches!(
        fresh.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::Cancelled {
            reason_digest: cancellation,
        }
    ));
}
