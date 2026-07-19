//! Live, feature-gated fixture coverage for the generic worker ingress substrate.

#![cfg(feature = "worker-fixture")]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::agd::AgdCoreV1;
use ag_app::api::{
    ApiErrorCodeV1, ApiResultV1, EffectAdminRequestV1, EffectAdminResponseV1,
    EffectProposalRequestV1, EffectProposalResponseV1, WorkerCandidateBootstrapV1,
    WorkerCandidateRequestV1,
};
use ag_app::config::{
    AgdConfigV1, AgdLimitsV1, EffectTargetConfigV1, EffectdConfigV1, FilesystemNodeCustodyV1,
    PeerPolicyV1, SocketCustodyConfigV1, StoreConfigV1, StoreCustodyConfigV1,
    WorkerCandidateEffectV1, WorkerLauncherConfigV1, WorkerProfileConfigV1,
};
use ag_app::effectd::{EffectBrokerV1, RefusingEffectRunnerV1, configured_catalog_identity};
use ag_app::managed_pointer::{
    MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1, MANAGED_REPOSITORY_STATE_SCHEMA_V1,
    ManagedRepositoryIdentityEvidenceV1, ManagedRepositoryStateEvidenceV1,
    managed_pointer_launch_profile_identity,
};
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
use ag_effect::{CanonicalEffectV1, GitObjectFormatV1, ProposalStateV1, RatificationV1};
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
use base64::Engine as _;
use tempfile::TempDir;

const FIXTURE_WORKER: &str = env!("CARGO_BIN_EXE_ag-worker-fixture");
const BWRAP: &str = "/usr/bin/bwrap";
const GIT: &str = "/usr/bin/git";
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

struct PointerWorkerFixtureV1 {
    allowed_root: PathBuf,
    repository: PathBuf,
    staging_root: PathBuf,
    bundle: Vec<u8>,
    base_object: String,
    base_tree: String,
    genesis_state_identity: Digest,
    candidate_object: String,
    candidate_tree: String,
    repository_identity: Digest,
    git_identity: Digest,
    helper_launch_profile: Digest,
    uid: u32,
    gid: u32,
}

fn exact_git(arguments: impl IntoIterator<Item = OsString>) -> Output {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let output = Command::new(GIT)
        .args(&arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("execute exact /usr/bin/git fixture command");
    assert!(
        output.status.success(),
        "exact Git fixture command {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn exact_git_line(arguments: impl IntoIterator<Item = OsString>) -> String {
    let output = exact_git(arguments);
    let text = std::str::from_utf8(&output.stdout).expect("Git output is UTF-8");
    text.strip_suffix('\n')
        .expect("Git output has one trailing newline")
        .to_owned()
}

fn add_and_commit(source: &Path, message: &str) {
    exact_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("--"),
        OsString::from("governed.txt"),
    ]);
    exact_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("user.name=AG NG worker integration"),
        OsString::from("-c"),
        OsString::from("user.email=ag-ng@example.invalid"),
        OsString::from("commit"),
        OsString::from("--quiet"),
        OsString::from("-m"),
        OsString::from(message),
    ]);
}

fn remove_group_other_write(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("repository fixture metadata");
    assert!(
        !metadata.file_type().is_symlink(),
        "fixture contains a symlink"
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read repository fixture directory") {
            remove_group_other_write(&entry.expect("repository fixture entry").path());
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode() & !0o022))
        .expect("remove group/other write bits from repository fixture");
}

#[allow(clippy::too_many_lines)]
fn pointer_worker_fixture(root: &Path) -> PointerWorkerFixtureV1 {
    assert_ne!(
        nix::unistd::geteuid().as_raw(),
        0,
        "the managed-pointer contract deliberately refuses a root-owned target"
    );
    let source = root.join("promotion-source");
    let allowed_root = root.join("promotion-targets");
    let repository = allowed_root.join("governed.git");
    let staging_root = root.join("promotion-staging");
    fs::create_dir(&source).expect("source repository directory");
    fs::create_dir(&allowed_root).expect("allowed target root");
    fs::create_dir(&staging_root).expect("broker staging root");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).expect("source mode");
    fs::set_permissions(&allowed_root, fs::Permissions::from_mode(0o700))
        .expect("allowed-root mode");
    fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700))
        .expect("staging-root mode");

    exact_git([
        OsString::from("init"),
        OsString::from("--quiet"),
        OsString::from("--initial-branch=main"),
        OsString::from("--template="),
        source.as_os_str().to_owned(),
    ]);
    fs::write(source.join("governed.txt"), b"base\n").expect("base content");
    add_and_commit(&source, "base");
    let base_object = exact_git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{commit}"),
    ]);
    let base_tree = exact_git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{tree}"),
    ]);
    exact_git([
        OsString::from("clone"),
        OsString::from("--bare"),
        OsString::from("--quiet"),
        source.as_os_str().to_owned(),
        repository.as_os_str().to_owned(),
    ]);
    let loose_reference = repository.join("refs/heads/main");
    assert!(!loose_reference.exists());
    fs::write(&loose_reference, format!("{base_object}\n"))
        .expect("install enrolled loose target ref");
    fs::set_permissions(&loose_reference, fs::Permissions::from_mode(0o600))
        .expect("loose target ref mode");
    remove_group_other_write(&repository);

    fs::write(source.join("governed.txt"), b"candidate from live worker\n")
        .expect("candidate content");
    add_and_commit(&source, "candidate");
    let candidate_object = exact_git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{commit}"),
    ]);
    let candidate_tree = exact_git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{tree}"),
    ]);
    exact_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("branch"),
        OsString::from("--force"),
        OsString::from("ag-candidate"),
        OsString::from("HEAD"),
    ]);
    let bundle_path = root.join("live-worker-candidate.bundle");
    exact_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("bundle"),
        OsString::from("create"),
        OsString::from("--version=2"),
        bundle_path.as_os_str().to_owned(),
        OsString::from("refs/heads/ag-candidate"),
    ]);
    let bundle = fs::read(bundle_path).expect("strict self-contained candidate bundle");
    let expected_header =
        format!("# v2 git bundle\n{candidate_object} refs/heads/ag-candidate\n\n");
    assert!(bundle.starts_with(expected_header.as_bytes()));
    assert_eq!(
        &bundle[expected_header.len()..expected_header.len() + 4],
        b"PACK"
    );
    assert!(
        base64::engine::general_purpose::STANDARD
            .encode(&bundle)
            .len()
            <= 4096,
        "reviewed fixed argv must remain inside the worker-profile bound"
    );

    let metadata = fs::symlink_metadata(&repository).expect("repository metadata");
    let node = |name: &str, path: &Path| {
        let node = fs::symlink_metadata(path).expect("managed repository node metadata");
        ag_app::managed_pointer::ManagedFilesystemNodeEvidenceV1 {
            name: name.to_owned(),
            device: node.dev(),
            inode: node.ino(),
            uid: node.uid(),
            gid: node.gid(),
            mode: node.mode(),
            link_count: node.nlink(),
        }
    };
    assert_eq!(
        exact_git_line([
            OsString::from("--git-dir"),
            repository.as_os_str().to_owned(),
            OsString::from("rev-parse"),
            OsString::from("--show-object-format"),
        ]),
        "sha1"
    );
    let repository_identity = ManagedRepositoryIdentityEvidenceV1 {
        schema: MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1.to_owned(),
        allowed_root: allowed_root
            .to_str()
            .expect("UTF-8 allowed root")
            .to_owned(),
        repository: repository.to_str().expect("UTF-8 repository").to_owned(),
        bare: true,
        object_format: GitObjectFormatV1::Sha1,
        allowed_root_node: node("allowed-root", &allowed_root),
        repository_node: node("repository", &repository),
        git_directory_node: node("git-directory", &repository),
        config_node: node("config", &repository.join("config")),
        objects_node: node("objects", &repository.join("objects")),
        pack_directory_node: node("objects/pack", &repository.join("objects/pack")),
        reference_ancestry: vec![
            node("refs", &repository.join("refs")),
            node("refs/heads", &repository.join("refs/heads")),
        ],
        repository_device: metadata.dev(),
        repository_inode: metadata.ino(),
        git_directory_device: metadata.dev(),
        git_directory_inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        config_digest: Digest::hash_bytes(
            &fs::read(repository.join("config")).expect("bounded repository config"),
        ),
    }
    .identity()
    .expect("descriptor-bound repository identity");
    let genesis_state_identity = Digest::from_serializable(&ManagedRepositoryStateEvidenceV1 {
        schema: MANAGED_REPOSITORY_STATE_SCHEMA_V1.to_owned(),
        repository_identity: repository_identity.clone(),
        reference: node("refs/heads/main", &repository.join("refs/heads/main")),
        current_object: base_object.clone(),
        current_tree: base_tree.clone(),
        clean: true,
        reference_checked_out: false,
    })
    .expect("genesis state identity");
    let git_identity = Digest::hash_bytes(&fs::read(GIT).expect("exact Git bytes"));
    let helper_launch_profile = managed_pointer_launch_profile_identity(
        &Digest::hash_domain("ag-security-profile-identity-v1", b"development"),
        &git_identity,
    )
    .expect("closed Git launch profile");
    PointerWorkerFixtureV1 {
        allowed_root,
        repository,
        staging_root,
        bundle,
        base_object,
        base_tree,
        genesis_state_identity,
        candidate_object,
        candidate_tree,
        repository_identity,
        git_identity,
        helper_launch_profile,
        uid: metadata.uid(),
        gid: metadata.gid(),
    }
}

fn managed_ref_object(fixture: &PointerWorkerFixtureV1, suffix: &str) -> String {
    exact_git_line([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from(format!("refs/heads/main^{{{suffix}}}")),
    ])
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
            candidate_effect: WorkerCandidateEffectV1::ManagedFilePut,
            candidate_target: "fixture.target".to_owned(),
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
    let unused_socket_parent = temporary.path().join("unused-socket-parent");
    fs::create_dir(&unused_socket_parent).expect("unused socket parent");
    fs::set_permissions(&unused_socket_parent, fs::Permissions::from_mode(0o2700))
        .expect("unused socket parent mode");
    let socket_parent_custody = filesystem_custody(&unused_socket_parent);
    let unused_socket_custody = SocketCustodyConfigV1 {
        parent: socket_parent_custody.clone(),
        node: FilesystemNodeCustodyV1 {
            uid: socket_parent_custody.uid,
            gid: socket_parent_custody.gid,
            mode: 0o660,
        },
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
            candidate_effect: WorkerCandidateEffectV1::ManagedFilePut,
            candidate_target: "fixture.target".to_owned(),
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
fn live_worker_bundle_closes_the_managed_pointer_lifecycle() {
    assert!(Path::new(BWRAP).is_file(), "Bubblewrap fixture is required");
    assert!(Path::new(GIT).is_file(), "exact /usr/bin/git is required");
    let temporary = TempDir::new().expect("temporary joined-lifecycle fixture");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private joined-lifecycle root");
    let pointer = pointer_worker_fixture(temporary.path());
    let reviewed = temporary.path().join("reviewed-pointer-worker");
    let workspace_root = temporary.path().join("pointer-workspaces");
    fs::create_dir(&reviewed).expect("reviewed worker directory");
    fs::create_dir(&workspace_root).expect("proposal workspace root");
    fs::set_permissions(&reviewed, fs::Permissions::from_mode(0o700))
        .expect("reviewed worker directory mode");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("proposal workspace root mode");
    let fixture_worker = reviewed.join("worker");
    fs::copy(FIXTURE_WORKER, &fixture_worker).expect("install reviewed fixture ELF");
    fs::set_permissions(&fixture_worker, fs::Permissions::from_mode(0o555))
        .expect("make fixture ELF non-writable");
    let encoded_bundle = base64::engine::general_purpose::STANDARD.encode(&pointer.bundle);

    let agd_store_root = TempDir::new().expect("governor store root");
    let governor = std::sync::Arc::new(ephemeral_signer("pointer-worker-governor"));
    let proposer = ephemeral_signer("pointer-worker-static-proposer");
    let effectd = ephemeral_signer("pointer-worker-effectd");
    let admin = ephemeral_signer("pointer-worker-independent-admin");
    let agd_store = open_agd_store(&agd_store_root, &governor);
    let unused_custody = filesystem_custody(temporary.path());
    let unused_store_custody = StoreCustodyConfigV1 {
        database_parent: unused_custody.clone(),
        object_store: unused_custody.clone(),
        database: unused_custody.clone(),
        writer_lock: unused_custody.clone(),
    };
    let pointer_socket_parent = temporary.path().join("unused-pointer-socket-parent");
    fs::create_dir(&pointer_socket_parent).expect("unused pointer socket parent");
    fs::set_permissions(&pointer_socket_parent, fs::Permissions::from_mode(0o2700))
        .expect("unused pointer socket parent mode");
    let pointer_socket_parent_custody = filesystem_custody(&pointer_socket_parent);
    let unused_socket_custody = SocketCustodyConfigV1 {
        parent: pointer_socket_parent_custody.clone(),
        node: FilesystemNodeCustodyV1 {
            uid: pointer_socket_parent_custody.uid,
            gid: pointer_socket_parent_custody.gid,
            mode: 0o660,
        },
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
            profile_id: "pointer-bundle-fixture".to_owned(),
            project: "fixture-project".to_owned(),
            executable: fixture_worker.clone(),
            executable_identity: executable_identity(&fixture_worker),
            fixed_arguments: vec!["--emit-base64".to_owned(), encoded_bundle],
            candidate_effect: WorkerCandidateEffectV1::ManagedPointerPromotion,
            candidate_target: "repository-main".to_owned(),
            candidate_semantic_type: "git_bundle_promotion_v1".to_owned(),
            timeout_ms: 30_000,
            output_budget_bytes: u64::try_from(pointer.bundle.len())
                .expect("candidate bundle length fits u64"),
        }],
    };
    let governor_enrollment = governor.enrollment(30_000).expect("governor enrollment");
    let agd_config = AgdConfigV1 {
        schema: "ag.config.agd.v1".to_owned(),
        security_profile: "development".to_owned(),
        authority_domain: "test.live-worker".to_owned(),
        epoch: "1".to_owned(),
        store: StoreConfigV1 {
            database: temporary.path().join("unused-pointer-agd.sqlite"),
            object_store: temporary.path().join("unused-pointer-agd-objects"),
            store_custody: unused_store_custody,
        },
        control_socket: temporary.path().join("unused-pointer-control.sock"),
        control_socket_custody: unused_socket_custody,
        effectd_proposal_socket: temporary
            .path()
            .join("pointer-effectd-proposal")
            .join("proposal.sock"),
        providerd_socket: temporary.path().join("absent-pointer-providerd.sock"),
        rpc_signing_identity: RpcSigningIdentityConfigV1 {
            principal: governor_enrollment.principal,
            key_id: governor_enrollment.key.key_id,
            public_key: governor_enrollment.key.public_key,
            private_key_credential: PathBuf::from("/unused-pointer-governor-credential"),
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
    agd_config.validate().expect("joined worker configuration");
    let mut core = AgdCoreV1::new(
        agd_store,
        agd_config,
        std::sync::Arc::clone(&governor),
        std::sync::Arc::new(RpcReplayGuardV1::new(4096).expect("governor replay guard")),
    )
    .expect("governor core");
    let (session, worker_principal) = core
        .launch_worker("pointer-bundle-fixture")
        .expect("launch binary-safe bundle worker");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let final_report = loop {
        let report = core.poll_workers().expect("poll pointer worker");
        if report.accepted > 0 || report.failed > 0 {
            break report;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pointer worker did not terminate"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert_eq!(final_report.accepted, 1, "unexpected {final_report:?}");
    assert_eq!(final_report.failed, 0);
    assert_eq!(final_report.deferred, 1);
    let in_custody = core
        .inspect_worker_session(&session)
        .expect("inspect custodied bundle session");
    let WorkerCandidateCustodyStateV1::InCustody { candidate } = in_custody.candidate else {
        panic!("live bundle did not enter governor custody");
    };
    assert_eq!(candidate.content, Digest::hash_bytes(&pointer.bundle));
    assert_eq!(
        candidate.byte_length,
        u64::try_from(pointer.bundle.len()).expect("bundle length fits u64")
    );
    assert_eq!(candidate.semantic_type, "git_bundle_promotion_v1");
    assert!(matches!(
        in_custody.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::CandidateAccepted
    ));

    let proposal_parent = temporary.path().join("pointer-effectd-proposal");
    let admin_parent = temporary.path().join("pointer-effectd-admin");
    fs::create_dir(&proposal_parent).expect("proposal socket parent");
    fs::create_dir(&admin_parent).expect("admin socket parent");
    fs::set_permissions(&proposal_parent, fs::Permissions::from_mode(0o2700))
        .expect("proposal parent mode");
    fs::set_permissions(&admin_parent, fs::Permissions::from_mode(0o2700))
        .expect("admin parent mode");
    let effectd_store_root = TempDir::new().expect("effectd store root");
    let effectd_enrollment = effectd.enrollment(30_000).expect("effectd enrollment");
    let mut effectd_config: EffectdConfigV1 =
        toml::from_str(include_str!("../../../config/effectd.example.toml"))
            .expect("strict effectd example");
    "development".clone_into(&mut effectd_config.security_profile);
    "test.live-worker".clone_into(&mut effectd_config.authority_domain);
    "1".clone_into(&mut effectd_config.epoch);
    effectd_config.store.database = effectd_store_root.path().join("effectd.sqlite");
    effectd_config.store.object_store = effectd_store_root.path().join("objects");
    effectd_config.proposal_socket = proposal_parent.join("proposal.sock");
    effectd_config.proposal_socket_custody = socket_custody(&proposal_parent);
    effectd_config.admin_socket = admin_parent.join("admin.sock");
    effectd_config.admin_socket_custody = socket_custody(&admin_parent);
    effectd_config.rpc_signing_identity = RpcSigningIdentityConfigV1 {
        principal: effectd_enrollment.principal,
        key_id: effectd_enrollment.key.key_id,
        public_key: effectd_enrollment.key.public_key,
        private_key_credential: PathBuf::from("/unused-pointer-effectd-credential"),
    };
    effectd_config.agd_peer = peer_policy("governor_proposer", &governor, PrincipalKindV1::Daemon);
    effectd_config.proposer_peer =
        peer_policy("proposal_ingress", &proposer, PrincipalKindV1::Service);
    effectd_config.admin_peer = peer_policy("effect_operator", &admin, PrincipalKindV1::Operator);
    effectd_config.targets = vec![EffectTargetConfigV1::ManagedPointer {
        id: "repository-main".to_owned(),
        allowed_root: pointer.allowed_root.clone(),
        repository: pointer.repository.clone(),
        reference: "refs/heads/main".to_owned(),
        activation_genesis_object: pointer.base_object.clone(),
        activation_genesis_tree: pointer.base_tree.clone(),
        activation_genesis_state: pointer.genesis_state_identity.clone(),
        repository_identity: pointer.repository_identity.clone(),
        uid: pointer.uid,
        gid: pointer.gid,
        staging_root: pointer.staging_root.clone(),
        promotion_ttl_ms: 60_000,
        helper: PathBuf::from(GIT),
        helper_executable: pointer.git_identity.clone(),
        helper_launch_profile: pointer.helper_launch_profile.clone(),
    }];
    effectd_config
        .validate()
        .expect("joined pointer broker configuration");
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
    let (canonical_sender, canonical_receiver) = std::sync::mpsc::sync_channel(1);
    let (ratification_sender, ratification_receiver) = std::sync::mpsc::sync_channel(1);
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
        let proposal_response =
            broker.handle_proposal(accepted.body().clone(), &accepted.authenticated_peer);
        write_signed_response(
            &mut stream,
            FrameCodec::new(maximum_frame_bytes).expect("effectd response codec"),
            &effectd,
            &accepted,
            proposal_response.clone(),
            &SystemRpcClockV1,
        )
        .expect("write signed broker response");
        let proposal_digest = match &proposal_response {
            ApiResultV1::Ok {
                response:
                    EffectProposalResponseV1::Canonicalized {
                        proposal_digest, ..
                    },
            } => proposal_digest.clone(),
            other => panic!("broker did not canonicalize live bundle: {other:?}"),
        };
        canonical_sender
            .send(proposal_digest.clone())
            .expect("publish canonical digest");
        ratification_receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("governor did not commit broker response");

        let display = broker.handle_admin(
            EffectAdminRequestV1::InspectProposal {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &Digest::hash_bytes(b"live-pointer-admin-display"),
        );
        let ApiResultV1::Ok {
            response:
                EffectAdminResponseV1::Proposal {
                    proposal,
                    challenge,
                },
        } = display
        else {
            panic!("independent admin could not inspect canonical bytes: {display:?}");
        };
        let ratification = broker.handle_admin(
            EffectAdminRequestV1::Ratify {
                proposal: proposal_digest.clone(),
                challenge,
            },
            &admin_peer,
            &Digest::hash_bytes(b"live-pointer-admin-ratification"),
        );
        let record = broker.handle_admin(
            EffectAdminRequestV1::InspectRecord {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &Digest::hash_bytes(b"live-pointer-record-inspection"),
        );
        let replay_display = broker.handle_admin(
            EffectAdminRequestV1::InspectProposal {
                proposal: proposal_digest.clone(),
            },
            &admin_peer,
            &Digest::hash_bytes(b"live-pointer-replay-display"),
        );
        let ApiResultV1::Ok {
            response:
                EffectAdminResponseV1::Proposal {
                    challenge: replay_challenge,
                    ..
                },
        } = replay_display
        else {
            panic!("terminal proposal could not be inspected for replay: {replay_display:?}");
        };
        let replay = broker.handle_admin(
            EffectAdminRequestV1::Ratify {
                proposal: proposal_digest,
                challenge: replay_challenge,
            },
            &admin_peer,
            &Digest::hash_bytes(b"live-pointer-replay-ratification"),
        );
        (proposal_response, proposal, ratification, record, replay)
    });

    let recovery = core
        .recover_worker_candidates()
        .expect("forward live bundle through the normal broker boundary");
    assert_eq!(recovery.canonicalized, 1);
    assert_eq!(recovery.deferred, 0);
    let broker_digest = canonical_receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("receive broker canonical digest");
    ratification_sender
        .send(())
        .expect("release independent ratification");
    let canonical_record = core
        .inspect_worker_session(&session)
        .expect("inspect broker-completed worker session");
    let WorkerCandidateCustodyStateV1::BrokerCompleted {
        candidate,
        outcome: WorkerCandidateBrokerOutcomeV1::Canonicalized { canonical_proposal },
    } = canonical_record.candidate
    else {
        panic!("governor did not durably link broker-owned canonical bytes");
    };
    assert_eq!(candidate.content, Digest::hash_bytes(&pointer.bundle));
    assert_eq!(candidate.semantic_type, "git_bundle_promotion_v1");
    assert_eq!(canonical_proposal, broker_digest);
    assert!(matches!(
        canonical_record.authority,
        WorkerAuthorityStateV1::Tombstoned {
            tombstone,
            cleanup: WorkerCleanupStateV1::Complete { .. },
            ..
        } if tombstone.reason == WorkerTerminationReasonV1::CandidateAccepted
    ));

    let (proposal_response, proposal, ratification, record, replay) =
        broker_server.join().expect("effectd broker thread");
    assert!(matches!(
        proposal_response,
        ApiResultV1::Ok {
            response: EffectProposalResponseV1::Canonicalized {
                proposal_digest,
                ..
            }
        } if proposal_digest == canonical_proposal
    ));
    proposal
        .verify_digest()
        .expect("effectd-owned canonical bytes");
    assert_eq!(proposal.digest(), &canonical_proposal);
    assert_eq!(
        proposal.body().proposer.leaf().principal_id,
        worker_principal
    );
    let [
        CanonicalEffectV1::ManagedPointerPromotion {
            artifact,
            expected_object,
            expected_tree,
            new_object,
            expected_post_tree,
            repository_identity,
            helper_executable,
            helper_launch_profile,
            ..
        },
    ] = proposal.body().effects.as_slice()
    else {
        panic!("worker candidate did not compile to one closed promotion");
    };
    assert_eq!(*artifact, Digest::hash_bytes(&pointer.bundle));
    assert_eq!(expected_object, &pointer.base_object);
    assert_eq!(expected_tree, &pointer.base_tree);
    assert_eq!(new_object, &pointer.candidate_object);
    assert_eq!(expected_post_tree, &pointer.candidate_tree);
    assert_eq!(repository_identity, &pointer.repository_identity);
    assert_eq!(helper_executable, &pointer.git_identity);
    assert_eq!(helper_launch_profile, &pointer.helper_launch_profile);
    assert!(matches!(
        ratification,
        ApiResultV1::Ok {
            response: EffectAdminResponseV1::ExecutionReceipt {
                terminal_state,
                ..
            }
        } if terminal_state == "succeeded"
    ));
    let ApiResultV1::Ok {
        response: EffectAdminResponseV1::Record { record },
    } = record
    else {
        panic!("terminal pointer record was not inspectable: {record:?}");
    };
    assert!(matches!(record.state, ProposalStateV1::Succeeded { .. }));
    let Some(RatificationV1::HumanExact { ratifier, .. }) = &record.authorization else {
        panic!("terminal record did not retain exact human authority");
    };
    assert!(proposal.body().proposer.independent_from(ratifier));
    assert!(matches!(
        replay,
        ApiResultV1::Error {
            code: ApiErrorCodeV1::Conflict,
            ..
        }
    ));
    assert_eq!(
        managed_ref_object(&pointer, "commit"),
        pointer.candidate_object
    );
    assert_eq!(managed_ref_object(&pointer, "tree"), pointer.candidate_tree);
    let ref_metadata = fs::symlink_metadata(pointer.repository.join("refs/heads/main"))
        .expect("committed loose-ref metadata");
    assert_eq!(ref_metadata.nlink(), 1);
    assert_eq!(ref_metadata.uid(), pointer.uid);
    assert_eq!(ref_metadata.gid(), pointer.gid);
    assert_eq!(ref_metadata.mode() & 0o777, 0o600);
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
            candidate_effect: WorkerCandidateEffectV1::ManagedFilePut,
            candidate_target: "fixture.target".to_owned(),
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
            candidate_effect: WorkerCandidateEffectV1::ManagedFilePut,
            candidate_target: "fixture.target".to_owned(),
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
