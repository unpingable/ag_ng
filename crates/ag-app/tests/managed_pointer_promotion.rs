//! End-to-end broker coverage for one exact managed-Git-reference promotion.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::api::{
    AgdRequestV1, ApiErrorCodeV1, ApiResultV1, ArtifactTransferV1, EffectAdminRequestV1,
    EffectAdminResponseV1, EffectProposalRequestV1, EffectProposalResponseV1,
    GovernedProposalIngressV1, ProposalIngressProofV1,
};
use ag_app::config::{EffectTargetConfigV1, EffectdConfigV1, PeerPolicyV1};
use ag_app::effectd::{EffectBrokerV1, RefusingEffectRunnerV1, configured_catalog_identity};
use ag_app::managed_pointer::{
    MANAGED_REPOSITORY_IDENTITY_SCHEMA_V1, MANAGED_REPOSITORY_STATE_SCHEMA_V1,
    ManagedPointerRuntimeV1, ManagedRepositoryIdentityEvidenceV1, ManagedRepositoryStateEvidenceV1,
    managed_pointer_launch_profile_identity,
};
use ag_app::peer::signed_principal_chain;
use ag_app::rpc_auth::{
    RpcKeyIdV1, RpcReplayGuardV1, RpcSignerV1, RpcSigningIdentityConfigV1, VerifiedRpcPrincipalV1,
};
use ag_effect::{
    CanonicalEffectV1, EFFECT_SCHEMA_V1, EffectIntentV1, GitObjectFormatV1, ProposalIntentV1,
    ProposalStateV1, RatificationV1, TargetId,
};
use ag_primitives::{AuthorityDomain, Digest, Epoch, PrincipalKindV1};
use ag_protocol::{RequestEnvelopeV1, RequestId};
use ag_store::{Store, StoreActivationIdentityV1, StoreIdentityV1, WriterIdentityV1};
use base64::Engine as _;
use nix::unistd::{getegid, geteuid};
use tempfile::TempDir;

const GIT: &str = "/usr/bin/git";
const TARGET_ID: &str = "managed-main";
const FILE_TARGET_ID: &str = "managed-file";
const TARGET_REF: &str = "refs/heads/main";
const CANDIDATE_REF: &str = "refs/heads/ag-candidate";

struct GitFixtureV1 {
    _root: TempDir,
    allowed_root: PathBuf,
    repository: PathBuf,
    source: PathBuf,
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

struct BrokerHarnessV1 {
    _store_root: TempDir,
    broker: EffectBrokerV1<RefusingEffectRunnerV1>,
    config: EffectdConfigV1,
    catalog_identity: Digest,
    activation_identity: StoreActivationIdentityV1,
    daemon_principal: Digest,
    governor: RpcSignerV1,
    proposer: RpcSignerV1,
    governor_peer: VerifiedRpcPrincipalV1,
    admin_peer: VerifiedRpcPrincipalV1,
    proposer_chain: ag_primitives::PrincipalChainV1,
    admin_chain: ag_primitives::PrincipalChainV1,
    domain: AuthorityDomain,
    epoch: Epoch,
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

fn run_git(arguments: impl IntoIterator<Item = OsString>) -> Output {
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

fn git_line(arguments: impl IntoIterator<Item = OsString>) -> String {
    let output = run_git(arguments);
    let text = std::str::from_utf8(&output.stdout).expect("Git output is UTF-8");
    text.strip_suffix('\n')
        .expect("Git output has one trailing newline")
        .to_owned()
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
fn git_fixture() -> GitFixtureV1 {
    assert_ne!(
        geteuid().as_raw(),
        0,
        "the managed-pointer contract deliberately refuses a root-owned target"
    );
    let root = TempDir::new().expect("temporary Git fixture root");
    let source = root.path().join("source");
    let allowed_root = root.path().join("targets");
    let repository = allowed_root.join("governed.git");
    let staging_root = root.path().join("broker-staging");
    fs::create_dir(&source).expect("source repository directory");
    fs::create_dir(&allowed_root).expect("allowed target root");
    fs::create_dir(&staging_root).expect("broker staging root");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).expect("source mode");
    fs::set_permissions(&allowed_root, fs::Permissions::from_mode(0o700))
        .expect("allowed-root mode");
    fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700))
        .expect("staging-root mode");

    run_git([
        OsString::from("init"),
        OsString::from("--quiet"),
        OsString::from("--initial-branch=main"),
        OsString::from("--template="),
        source.as_os_str().to_owned(),
    ]);
    fs::write(source.join("governed.txt"), b"base\n").expect("base worktree content");
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("--"),
        OsString::from("governed.txt"),
    ]);
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("user.name=AG NG integration"),
        OsString::from("-c"),
        OsString::from("user.email=ag-ng@example.invalid"),
        OsString::from("commit"),
        OsString::from("--quiet"),
        OsString::from("-m"),
        OsString::from("base"),
    ]);
    let base_object = git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{commit}"),
    ]);
    let base_tree = git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{tree}"),
    ]);
    run_git([
        OsString::from("clone"),
        OsString::from("--bare"),
        OsString::from("--quiet"),
        source.as_os_str().to_owned(),
        repository.as_os_str().to_owned(),
    ]);
    let loose_reference = repository.join("refs/heads/main");
    assert!(
        !loose_reference.exists(),
        "bare clone unexpectedly created the enrolled loose ref"
    );
    fs::write(&loose_reference, format!("{base_object}\n"))
        .expect("install enrolled loose target ref");
    fs::set_permissions(&loose_reference, fs::Permissions::from_mode(0o600))
        .expect("enrolled loose-ref mode");
    remove_group_other_write(&repository);

    fs::write(source.join("governed.txt"), b"candidate\n").expect("candidate worktree content");
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("--"),
        OsString::from("governed.txt"),
    ]);
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("user.name=AG NG integration"),
        OsString::from("-c"),
        OsString::from("user.email=ag-ng@example.invalid"),
        OsString::from("commit"),
        OsString::from("--quiet"),
        OsString::from("-m"),
        OsString::from("candidate"),
    ]);
    let candidate_object = git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{commit}"),
    ]);
    let candidate_tree = git_line([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{tree}"),
    ]);
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("branch"),
        OsString::from("--force"),
        OsString::from("ag-candidate"),
        OsString::from("HEAD"),
    ]);
    let bundle_path = root.path().join("candidate.bundle");
    run_git([
        OsString::from("-C"),
        source.as_os_str().to_owned(),
        OsString::from("bundle"),
        OsString::from("create"),
        OsString::from("--version=2"),
        bundle_path.as_os_str().to_owned(),
        OsString::from(CANDIDATE_REF),
    ]);
    let bundle = fs::read(&bundle_path).expect("strict candidate bundle");
    let expected_header = format!("# v2 git bundle\n{candidate_object} {CANDIDATE_REF}\n\n");
    assert!(bundle.starts_with(expected_header.as_bytes()));
    assert_eq!(
        &bundle[expected_header.len()..expected_header.len() + 4],
        b"PACK"
    );

    assert_eq!(
        git_line([
            OsString::from("--git-dir"),
            repository.as_os_str().to_owned(),
            OsString::from("rev-parse"),
            OsString::from("refs/heads/main^{commit}"),
        ]),
        base_object
    );
    let metadata = fs::symlink_metadata(&repository).expect("repository metadata");
    let config_digest = Digest::hash_bytes(
        &fs::read(repository.join("config")).expect("bounded repository config"),
    );
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
    let evidence = ManagedRepositoryIdentityEvidenceV1 {
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
        config_digest,
    };
    let repository_identity = evidence.identity().expect("repository identity");
    let genesis_state_identity = Digest::from_serializable(&ManagedRepositoryStateEvidenceV1 {
        schema: MANAGED_REPOSITORY_STATE_SCHEMA_V1.to_owned(),
        repository_identity: repository_identity.clone(),
        reference: node(TARGET_REF, &repository.join(TARGET_REF)),
        current_object: base_object.clone(),
        current_tree: base_tree.clone(),
        clean: true,
        reference_checked_out: false,
    })
    .expect("genesis state identity");
    let git_identity = Digest::hash_bytes(&fs::read(GIT).expect("exact Git bytes"));
    let security_profile_identity =
        Digest::hash_domain("ag-security-profile-identity-v1", b"development");
    let helper_launch_profile =
        managed_pointer_launch_profile_identity(&security_profile_identity, &git_identity)
            .expect("closed Git launch profile");

    GitFixtureV1 {
        _root: root,
        allowed_root,
        repository,
        source,
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

fn signer(label: &str) -> RpcSignerV1 {
    RpcSignerV1::generate_ephemeral_candidate_ingress(
        Digest::hash_domain(
            "ag-ng/managed-pointer-integration-principal/v1",
            label.as_bytes(),
        ),
        RpcKeyIdV1::new(format!("managed-pointer-{label}.v1")).expect("RPC key ID"),
    )
    .expect("ephemeral integration signer")
    .0
}

fn peer_policy(role: &str, signer: &RpcSignerV1, kind: PrincipalKindV1) -> PeerPolicyV1 {
    let enrollment = signer.enrollment(30_000).expect("peer enrollment");
    PeerPolicyV1 {
        role: role.to_owned(),
        uid: geteuid().as_raw(),
        gid: getegid().as_raw(),
        executable_identity: None,
        cgroup_contains: None,
        stable_principal_root: enrollment.principal,
        principal_kind: kind,
        rpc_key: enrollment.key,
    }
}

#[allow(clippy::too_many_lines)]
fn broker_harness(fixture: &GitFixtureV1, label: &str) -> BrokerHarnessV1 {
    let store_root = TempDir::new().expect("temporary broker store");
    let governor = signer(&format!("{label}-governor"));
    let proposer = signer(&format!("{label}-proposer"));
    let admin = signer(&format!("{label}-admin"));
    let daemon = signer(&format!("{label}-effectd"));
    assert_ne!(governor.principal(), proposer.principal());
    assert_ne!(governor.principal(), admin.principal());
    assert_ne!(proposer.principal(), admin.principal());

    let mut config: EffectdConfigV1 =
        toml::from_str(include_str!("../../../config/effectd.example.toml"))
            .expect("effectd example config");
    "development".clone_into(&mut config.security_profile);
    "test.managed-pointer".clone_into(&mut config.authority_domain);
    "1".clone_into(&mut config.epoch);
    config.store.database = store_root.path().join("effectd.sqlite");
    config.store.object_store = store_root.path().join("objects");
    let daemon_enrollment = daemon.enrollment(30_000).expect("daemon enrollment");
    config.rpc_signing_identity = RpcSigningIdentityConfigV1 {
        principal: daemon_enrollment.principal,
        key_id: daemon_enrollment.key.key_id,
        public_key: daemon_enrollment.key.public_key,
        private_key_credential: PathBuf::from("/run/credentials/test-effectd/rpc-key"),
    };
    config.agd_peer = peer_policy("governor", &governor, PrincipalKindV1::Daemon);
    config.proposer_peer = peer_policy("proposer", &proposer, PrincipalKindV1::Service);
    config.admin_peer = peer_policy("ratifier", &admin, PrincipalKindV1::Operator);
    config.targets = vec![
        EffectTargetConfigV1::ManagedPointer {
            id: TARGET_ID.to_owned(),
            allowed_root: fixture.allowed_root.clone(),
            repository: fixture.repository.clone(),
            reference: TARGET_REF.to_owned(),
            activation_genesis_object: fixture.base_object.clone(),
            activation_genesis_tree: fixture.base_tree.clone(),
            activation_genesis_state: fixture.genesis_state_identity.clone(),
            repository_identity: fixture.repository_identity.clone(),
            uid: fixture.uid,
            gid: fixture.gid,
            staging_root: fixture.staging_root.clone(),
            promotion_ttl_ms: 60_000,
            helper: PathBuf::from(GIT),
            helper_executable: fixture.git_identity.clone(),
            helper_launch_profile: fixture.helper_launch_profile.clone(),
        },
        EffectTargetConfigV1::ManagedFile {
            id: FILE_TARGET_ID.to_owned(),
            path: fixture.allowed_root.join("managed-file.conf"),
            mode: 0o600,
            uid: fixture.uid,
            gid: fixture.gid,
        },
    ];
    config
        .validate()
        .expect("development pointer configuration");
    ManagedPointerRuntimeV1::from_config(&config)
        .expect("pinned managed-pointer runtime")
        .observe_candidate_bytes(
            &TargetId::parse(TARGET_ID).expect("target ID"),
            &Digest::hash_bytes(&fixture.bundle),
            &fixture.bundle,
        )
        .expect("exact candidate is observable before broker construction");

    let domain = AuthorityDomain::parse(&config.authority_domain).expect("authority domain");
    let epoch = Epoch::parse(&config.epoch).expect("epoch");
    let governor_peer = VerifiedRpcPrincipalV1 {
        principal: config.agd_peer.rpc_key.principal.clone(),
        key_id: config.agd_peer.rpc_key.key_id.clone(),
    };
    let proposer_peer = VerifiedRpcPrincipalV1 {
        principal: config.proposer_peer.rpc_key.principal.clone(),
        key_id: config.proposer_peer.rpc_key.key_id.clone(),
    };
    let admin_peer = VerifiedRpcPrincipalV1 {
        principal: config.admin_peer.rpc_key.principal.clone(),
        key_id: config.admin_peer.rpc_key.key_id.clone(),
    };
    let proposer_chain =
        signed_principal_chain(&proposer_peer, &config.proposer_peer, domain.clone(), epoch)
            .expect("proposer principal chain");
    let admin_chain =
        signed_principal_chain(&admin_peer, &config.admin_peer, domain.clone(), epoch)
            .expect("admin principal chain");
    assert!(proposer_chain.independent_from(&admin_chain));

    let catalog_identity =
        configured_catalog_identity(&config.targets).expect("exact configured catalog");
    let activation_identity = StoreActivationIdentityV1 {
        schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
        authority_domain: domain.clone(),
        epoch,
        config_identity: Digest::hash_domain(
            "ag-ng/managed-pointer-integration-config/v1",
            label.as_bytes(),
        ),
        security_profile_identity: Digest::hash_domain(
            "ag-security-profile-identity-v1",
            b"development",
        ),
        build_identity: Digest::hash_bytes(b"managed-pointer-integration-build"),
        authority_catalog_identity: Some(catalog_identity.clone()),
    };
    let daemon_principal = daemon.principal().clone();
    let store = Store::open_activated(
        &config.store.database,
        &config.store.object_store,
        StoreIdentityV1::current(0x4147_4550, "effectd-pointer-integration")
            .expect("store identity"),
        &activation_identity,
        &WriterIdentityV1 {
            writer_id: format!("effectd-pointer-integration-{label}"),
            principal_digest: daemon.principal().clone(),
            process_nonce: format!("effectd-pointer-integration-{label}-process"),
            claimed_at_unix_ms: i64::try_from(now_unix_ms()).expect("test clock fits i64"),
        },
    )
    .expect("activated broker store");
    let broker = EffectBrokerV1::new(
        &config,
        &catalog_identity,
        store,
        RefusingEffectRunnerV1,
        Arc::new(RpcReplayGuardV1::new(128).expect("RPC replay guard")),
    )
    .expect("managed-pointer broker");
    BrokerHarnessV1 {
        _store_root: store_root,
        broker,
        config,
        catalog_identity,
        activation_identity,
        daemon_principal,
        governor,
        proposer,
        governor_peer,
        admin_peer,
        proposer_chain,
        admin_chain,
        domain,
        epoch,
    }
}

fn restart_harness(harness: BrokerHarnessV1) -> BrokerHarnessV1 {
    let BrokerHarnessV1 {
        _store_root: store_root,
        broker,
        config,
        catalog_identity,
        activation_identity,
        daemon_principal,
        governor,
        proposer,
        governor_peer,
        admin_peer,
        proposer_chain,
        admin_chain,
        domain,
        epoch,
    } = harness;
    drop(broker);
    let store = Store::open_activated(
        &config.store.database,
        &config.store.object_store,
        StoreIdentityV1::current(0x4147_4550, "effectd-pointer-integration")
            .expect("store identity"),
        &activation_identity,
        &WriterIdentityV1 {
            writer_id: "effectd-pointer-integration-restart".to_owned(),
            principal_digest: daemon_principal.clone(),
            process_nonce: format!("effectd-pointer-restart-{}", uuid::Uuid::new_v4()),
            claimed_at_unix_ms: i64::try_from(now_unix_ms()).expect("test clock fits i64"),
        },
    )
    .expect("reopen activated broker store");
    let broker = EffectBrokerV1::new(
        &config,
        &catalog_identity,
        store,
        RefusingEffectRunnerV1,
        Arc::new(RpcReplayGuardV1::new(128).expect("RPC replay guard")),
    )
    .expect("restart managed-pointer broker");
    BrokerHarnessV1 {
        _store_root: store_root,
        broker,
        config,
        catalog_identity,
        activation_identity,
        daemon_principal,
        governor,
        proposer,
        governor_peer,
        admin_peer,
        proposer_chain,
        admin_chain,
        domain,
        epoch,
    }
}

fn proposal_ingress(
    harness: &BrokerHarnessV1,
    intent: ProposalIntentV1,
    request_id: &str,
) -> ProposalIngressProofV1 {
    let now = now_unix_ms();
    let proposer_enrollment = harness
        .proposer
        .enrollment(30_000)
        .expect("proposer enrollment");
    let challenge = harness
        .governor
        .issue_challenge(&proposer_enrollment, now)
        .expect("governor challenge");
    let request = RequestEnvelopeV1::new(
        RequestId::new(request_id).expect("request ID"),
        AgdRequestV1::SubmitProposal {
            intent: Box::new(intent),
        },
    )
    .expect("proposal request");
    ProposalIngressProofV1 {
        server_challenge: challenge.clone(),
        signed_request: Box::new(
            harness
                .proposer
                .sign_request(request, &challenge, now)
                .expect("proposer signature"),
        ),
    }
}

fn submit_pointer(
    harness: &mut BrokerHarnessV1,
    fixture: &GitFixtureV1,
    request_id: &str,
) -> Digest {
    let artifact = Digest::hash_bytes(&fixture.bundle);
    let intent = ProposalIntentV1 {
        schema: EFFECT_SCHEMA_V1.to_owned(),
        intent_id: format!("managed-pointer-{request_id}"),
        authority_domain: harness.domain.clone(),
        epoch: harness.epoch,
        proposer: harness.proposer_chain.clone(),
        judgment: Digest::hash_domain("ag-ng/integration-judgment/v1", request_id.as_bytes()),
        admitted_artifacts: BTreeSet::from([artifact.clone()]),
        effects: vec![EffectIntentV1::ManagedPointerPromotion {
            target: TargetId::parse(TARGET_ID).expect("target ID"),
            artifact: artifact.clone(),
        }],
    };
    let proof = proposal_ingress(harness, intent, request_id);
    let response = harness.broker.handle_proposal(
        EffectProposalRequestV1::SubmitAuthenticatedIntent {
            ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                proof: Box::new(proof),
            }),
            artifacts: vec![ArtifactTransferV1 {
                digest: artifact,
                byte_length: fixture.bundle.len() as u64,
                content_base64: base64::engine::general_purpose::STANDARD.encode(&fixture.bundle),
            }],
        },
        &harness.governor_peer,
    );
    let ApiResultV1::Ok {
        response:
            EffectProposalResponseV1::Canonicalized {
                proposal_digest, ..
            },
    } = response
    else {
        panic!("exact promotion intent did not canonicalize: {response:?}");
    };
    proposal_digest
}

fn inspect_pointer(
    harness: &mut BrokerHarnessV1,
    fixture: &GitFixtureV1,
    proposal_digest: &Digest,
    request_label: &str,
) -> String {
    let signed_request = Digest::hash_domain(
        "ag-ng/integration-admin-inspection/v1",
        request_label.as_bytes(),
    );
    let inspected = harness.broker.handle_admin(
        EffectAdminRequestV1::InspectProposal {
            proposal: proposal_digest.clone(),
        },
        &harness.admin_peer,
        &signed_request,
    );
    let ApiResultV1::Ok {
        response:
            EffectAdminResponseV1::Proposal {
                proposal,
                challenge,
            },
    } = inspected
    else {
        panic!("effect-plane inspection failed: {inspected:?}");
    };
    proposal
        .verify_digest()
        .expect("broker-owned canonical bytes");
    assert_eq!(proposal.digest(), proposal_digest);
    assert_eq!(proposal.body().proposer, harness.proposer_chain);
    let [
        CanonicalEffectV1::ManagedPointerPromotion {
            target,
            artifact,
            expected_object,
            expected_tree,
            new_object,
            expected_post_tree,
            repository_identity,
            helper_executable,
            helper_launch_profile,
            reference,
            ..
        },
    ] = proposal.body().effects.as_slice()
    else {
        panic!("broker did not compile one closed pointer promotion");
    };
    assert_eq!(target.as_str(), TARGET_ID);
    assert_eq!(reference, TARGET_REF);
    assert_eq!(*artifact, Digest::hash_bytes(&fixture.bundle));
    assert_eq!(expected_object, &fixture.base_object);
    assert_eq!(expected_tree, &fixture.base_tree);
    assert_eq!(new_object, &fixture.candidate_object);
    assert_eq!(expected_post_tree, &fixture.candidate_tree);
    assert_eq!(repository_identity, &fixture.repository_identity);
    assert_eq!(helper_executable, &fixture.git_identity);
    assert_eq!(helper_launch_profile, &fixture.helper_launch_profile);
    challenge
}

fn ratify(
    harness: &mut BrokerHarnessV1,
    proposal: &Digest,
    challenge: String,
    request_label: &str,
) -> ApiResultV1<EffectAdminResponseV1> {
    harness.broker.handle_admin(
        EffectAdminRequestV1::Ratify {
            proposal: proposal.clone(),
            challenge,
        },
        &harness.admin_peer,
        &Digest::hash_domain(
            "ag-ng/integration-admin-ratification/v1",
            request_label.as_bytes(),
        ),
    )
}

fn inspect_record(
    harness: &mut BrokerHarnessV1,
    proposal: &Digest,
    request_label: &str,
) -> Box<ag_app::api::EffectRecordV1> {
    let response = harness.broker.handle_admin(
        EffectAdminRequestV1::InspectRecord {
            proposal: proposal.clone(),
        },
        &harness.admin_peer,
        &Digest::hash_domain(
            "ag-ng/integration-record-inspection/v1",
            request_label.as_bytes(),
        ),
    );
    let ApiResultV1::Ok {
        response: EffectAdminResponseV1::Record { record },
    } = response
    else {
        panic!("effect record was not inspectable: {response:?}");
    };
    record
}

fn target_object(fixture: &GitFixtureV1) -> String {
    git_line([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("refs/heads/main^{commit}"),
    ])
}

fn target_tree(fixture: &GitFixtureV1) -> String {
    git_line([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("refs/heads/main^{tree}"),
    ])
}

fn assert_committed_reference_custody(fixture: &GitFixtureV1) {
    let metadata = fs::symlink_metadata(fixture.repository.join("refs/heads/main"))
        .expect("committed loose-ref metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), fixture.uid);
    assert_eq!(metadata.gid(), fixture.gid);
    assert_eq!(metadata.mode() & 0o777, 0o600);
}

#[test]
#[allow(clippy::too_many_lines)]
fn independently_ratified_bundle_promotes_exact_ref_once() {
    if !Path::new(GIT).is_file() {
        eprintln!("skipping managed-pointer integration: {GIT} is absent");
        return;
    }
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "success");
    let proposal = submit_pointer(&mut harness, &fixture, "success-proposal");
    let challenge = inspect_pointer(&mut harness, &fixture, &proposal, "success-display");
    let result = ratify(&mut harness, &proposal, challenge, "success-ratification");
    let failure_record = if matches!(
        &result,
        ApiResultV1::Ok {
            response: EffectAdminResponseV1::ExecutionReceipt { terminal_state, .. }
        } if terminal_state != "succeeded"
    ) {
        Some(inspect_record(
            &mut harness,
            &proposal,
            "unexpected-success-record",
        ))
    } else {
        None
    };
    assert!(
        matches!(
            &result,
            ApiResultV1::Ok {
                response: EffectAdminResponseV1::ExecutionReceipt {
                    terminal_state,
                    ..
                }
            } if terminal_state == "succeeded"
        ),
        "unexpected promotion result: {result:?}; record: {failure_record:?}"
    );
    assert_eq!(target_object(&fixture), fixture.candidate_object);
    assert_eq!(target_tree(&fixture), fixture.candidate_tree);
    assert_committed_reference_custody(&fixture);

    let record = inspect_record(&mut harness, &proposal, "success-record");
    assert!(matches!(record.state, ProposalStateV1::Succeeded { .. }));
    let Some(RatificationV1::HumanExact { ratifier, .. }) = &record.authorization else {
        panic!("success record is missing exact human ratification");
    };
    assert_eq!(ratifier, &harness.admin_chain);
    let candidate = record
        .prepared_candidates
        .get(&TargetId::parse(TARGET_ID).expect("target"))
        .expect("prepared candidate history");
    let binding = record
        .candidate_ratification
        .as_ref()
        .expect("candidate-and-basis ratification");
    binding
        .verify_bindings(
            &proposal,
            candidate,
            &Digest::from_serializable(
                record
                    .authorization
                    .as_ref()
                    .expect("authorization custody"),
            )
            .expect("authorization identity"),
        )
        .expect("exact candidate ratification binding");
    assert_eq!(
        candidate
            .preparation_receipt
            .effects
            .authoritative_pointer_writes,
        0
    );
    assert_eq!(
        candidate
            .preparation_receipt
            .effects
            .target_object_database_bytes,
        0
    );
    assert_eq!(record.step_receipts.len(), 1);
    let activation = record
        .managed_pointer_activation
        .as_ref()
        .expect("inspectable durable activation explanation");
    activation
        .identity(&record.canonical.body().effects[0])
        .expect("activation explanation binds canonical effect");
    assert_eq!(activation.execution.proposal, proposal);
    assert_eq!(activation.prepared_candidate, candidate.identity().unwrap());
    assert_eq!(
        activation.candidate_ratification,
        binding.identity().expect("candidate ratification identity")
    );
    assert_eq!(activation.artifact, Digest::hash_bytes(&fixture.bundle));
    assert_eq!(activation.previous_object, fixture.base_object);
    assert_eq!(activation.previous_tree, fixture.base_tree);
    assert_eq!(activation.installed_object, fixture.candidate_object);
    assert_eq!(activation.installed_tree, fixture.candidate_tree);
    assert!(activation.commit.reference_fsynced);
    assert_eq!(
        activation.poststate.state.current_object,
        fixture.candidate_object
    );

    let replay_challenge = inspect_pointer(&mut harness, &fixture, &proposal, "replay-display");
    assert!(matches!(
        ratify(
            &mut harness,
            &proposal,
            replay_challenge,
            "replay-ratification"
        ),
        ApiResultV1::Error {
            code: ApiErrorCodeV1::Conflict,
            ..
        }
    ));
    assert_eq!(target_object(&fixture), fixture.candidate_object);
    assert_eq!(target_tree(&fixture), fixture.candidate_tree);
    assert_committed_reference_custody(&fixture);
}

#[test]
fn divergent_pointer_blocks_managed_file_authority_before_burn() {
    if !Path::new(GIT).is_file() {
        eprintln!("skipping managed-pointer integration: {GIT} is absent");
        return;
    }
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "cross-family-activation-gate");
    let content = b"must remain uninstalled\n".to_vec();
    let artifact = Digest::hash_bytes(&content);
    let intent = ProposalIntentV1 {
        schema: EFFECT_SCHEMA_V1.to_owned(),
        intent_id: "cross-family-managed-file".to_owned(),
        authority_domain: harness.domain.clone(),
        epoch: harness.epoch,
        proposer: harness.proposer_chain.clone(),
        judgment: Digest::hash_bytes(b"managed-file-judgment"),
        admitted_artifacts: BTreeSet::from([artifact.clone()]),
        effects: vec![EffectIntentV1::ManagedFilePut {
            target: TargetId::parse(FILE_TARGET_ID).expect("file target ID"),
            content: artifact.clone(),
        }],
    };
    let proof = proposal_ingress(&harness, intent, "cross-family-file-proposal");
    let submitted = harness.broker.handle_proposal(
        EffectProposalRequestV1::SubmitAuthenticatedIntent {
            ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                proof: Box::new(proof),
            }),
            artifacts: vec![ArtifactTransferV1 {
                digest: artifact,
                byte_length: content.len() as u64,
                content_base64: base64::engine::general_purpose::STANDARD.encode(&content),
            }],
        },
        &harness.governor_peer,
    );
    let ApiResultV1::Ok {
        response:
            EffectProposalResponseV1::Canonicalized {
                proposal_digest, ..
            },
    } = submitted
    else {
        panic!("managed-file intent did not canonicalize: {submitted:?}");
    };
    let inspected = harness.broker.handle_admin(
        EffectAdminRequestV1::InspectProposal {
            proposal: proposal_digest.clone(),
        },
        &harness.admin_peer,
        &Digest::hash_bytes(b"cross-family-file-inspection"),
    );
    let ApiResultV1::Ok {
        response: EffectAdminResponseV1::Proposal { challenge, .. },
    } = inspected
    else {
        panic!("managed-file proposal was not inspectable: {inspected:?}");
    };

    // Preserve the enrolled object bytes while replacing the exact ref inode.
    // The managed pointer is no longer the governed activation head even
    // though its Git object value appears unchanged.
    let enrolled_ref = fixture.repository.join(TARGET_REF);
    let substituted_ref = fixture.repository.join("refs/heads/hostile-replacement");
    fs::write(&substituted_ref, format!("{}\n", fixture.base_object))
        .expect("write hostile same-object reference");
    fs::set_permissions(&substituted_ref, fs::Permissions::from_mode(0o600))
        .expect("hostile reference mode");
    fs::rename(&substituted_ref, &enrolled_ref).expect("replace enrolled reference inode");

    let result = ratify(
        &mut harness,
        &proposal_digest,
        challenge,
        "cross-family-file-ratification",
    );
    assert!(matches!(
        result,
        ApiResultV1::Error {
            code: ApiErrorCodeV1::Indeterminate,
            ..
        }
    ));
    let record = inspect_record(&mut harness, &proposal_digest, "cross-family-file-record");
    assert!(matches!(record.state, ProposalStateV1::Ready { .. }));
    assert!(record.authorization.is_none());
    assert!(record.execution_attempt.is_none());
    assert!(!fixture.allowed_root.join("managed-file.conf").exists());
}

#[test]
fn separately_canonicalized_same_predecessor_activations_serialize_first_wins() {
    if !Path::new(GIT).is_file() {
        eprintln!("skipping managed-pointer integration: {GIT} is absent");
        return;
    }
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "same-predecessor-contention");

    // Both broker-owned proposals bind the same exact predecessor before
    // either proposal receives ratification or reaches the managed ref.
    let first = submit_pointer(&mut harness, &fixture, "contention-first-proposal");
    let second = submit_pointer(&mut harness, &fixture, "contention-second-proposal");
    assert_ne!(first, second, "separate intents remain separate proposals");
    let first_challenge =
        inspect_pointer(&mut harness, &fixture, &first, "contention-first-display");
    let second_challenge =
        inspect_pointer(&mut harness, &fixture, &second, "contention-second-display");

    let first_result = ratify(
        &mut harness,
        &first,
        first_challenge,
        "contention-first-ratification",
    );
    assert!(
        matches!(
            &first_result,
            ApiResultV1::Ok {
                response: EffectAdminResponseV1::ExecutionReceipt {
                    terminal_state,
                    ..
                }
            } if terminal_state == "succeeded"
        ),
        "first exact activation did not win: {first_result:?}"
    );
    let winning_record = inspect_record(&mut harness, &first, "contention-first-record");
    assert!(matches!(
        winning_record.state,
        ProposalStateV1::Succeeded { .. }
    ));
    let winning_activation = winning_record
        .managed_pointer_activation
        .as_ref()
        .expect("winning proposal has one durable activation receipt");
    assert_eq!(winning_activation.previous_object, fixture.base_object);
    assert_eq!(
        winning_activation.installed_object,
        fixture.candidate_object
    );
    assert_eq!(target_object(&fixture), fixture.candidate_object);
    assert_eq!(target_tree(&fixture), fixture.candidate_tree);

    let stale_result = ratify(
        &mut harness,
        &second,
        second_challenge,
        "contention-second-ratification",
    );
    assert!(
        matches!(
            &stale_result,
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Conflict,
                ..
            }
        ),
        "stale contender did not fail closed: {stale_result:?}"
    );
    let stale_record = inspect_record(&mut harness, &second, "contention-second-record");
    assert!(matches!(stale_record.state, ProposalStateV1::Ready { .. }));
    assert!(stale_record.authorization.is_none());
    assert!(stale_record.candidate_ratification.is_none());
    assert!(stale_record.execution_attempt.is_none());
    assert!(stale_record.step_receipts.is_empty());
    assert!(stale_record.managed_pointer_activation.is_none());
    assert_eq!(stale_record.promotion_refusals.len(), 1);
    assert_eq!(
        stale_record.promotion_refusals[0].code,
        ag_effect::ManagedPointerPromotionRefusalCodeV1::CurrentBasisMismatch
    );

    // The losing activation neither overwrites the winner nor creates a
    // second authority-bearing transition.
    assert_eq!(target_object(&fixture), fixture.candidate_object);
    assert_eq!(target_tree(&fixture), fixture.candidate_tree);
    assert_committed_reference_custody(&fixture);
}

#[test]
fn restart_preserves_candidate_history_without_reminting_promotion_standing() {
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "restart-history");
    let proposal = submit_pointer(&mut harness, &fixture, "restart-history");
    let before = inspect_record(&mut harness, &proposal, "before-restart");
    assert!(matches!(before.state, ProposalStateV1::Ready { .. }));
    assert_eq!(before.prepared_candidates.len(), 1);
    assert!(before.authorization.is_none());
    assert!(before.candidate_ratification.is_none());

    harness = restart_harness(harness);
    let after = inspect_record(&mut harness, &proposal, "after-restart");
    assert_eq!(after.prepared_candidates, before.prepared_candidates);
    assert_eq!(after.promotion_refusals, before.promotion_refusals);
    assert!(matches!(after.state, ProposalStateV1::Ready { .. }));
    assert!(after.authorization.is_none());
    assert!(after.candidate_ratification.is_none());
    assert!(after.execution_attempt.is_none());
    assert!(after.step_receipts.is_empty());
    assert_eq!(target_object(&fixture), fixture.base_object);
}

#[test]
fn restart_preserves_ratification_history_without_reexecution() {
    if !Path::new(GIT).is_file() {
        eprintln!("skipping managed-pointer integration: {GIT} is absent");
        return;
    }
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "restart-ratification-history");
    let proposal = submit_pointer(&mut harness, &fixture, "restart-ratification-history");
    let challenge = inspect_pointer(
        &mut harness,
        &fixture,
        &proposal,
        "restart-ratification-display",
    );
    let result = ratify(
        &mut harness,
        &proposal,
        challenge,
        "restart-ratification-burn",
    );
    assert!(matches!(
        result,
        ApiResultV1::Ok {
            response: EffectAdminResponseV1::ExecutionReceipt {
                ref terminal_state,
                ..
            }
        } if terminal_state == "succeeded"
    ));
    let before = inspect_record(&mut harness, &proposal, "before-ratified-restart");
    assert!(matches!(before.state, ProposalStateV1::Succeeded { .. }));
    assert!(before.authorization.is_some());
    assert!(before.candidate_ratification.is_some());
    assert_eq!(before.prepared_candidates.len(), 1);
    let terminal_receipt = before.terminal_receipt.clone();
    let execution_attempt = before.execution_attempt.clone();

    harness = restart_harness(harness);
    let after = inspect_record(&mut harness, &proposal, "after-ratified-restart");
    assert_eq!(after.prepared_candidates, before.prepared_candidates);
    assert_eq!(after.candidate_ratification, before.candidate_ratification);
    assert_eq!(after.authorization, before.authorization);
    assert_eq!(
        after.managed_pointer_activation,
        before.managed_pointer_activation
    );
    assert_eq!(after.terminal_receipt, terminal_receipt);
    assert_eq!(after.execution_attempt, execution_attempt);
    assert!(matches!(after.state, ProposalStateV1::Succeeded { .. }));

    let replay_challenge = inspect_pointer(
        &mut harness,
        &fixture,
        &proposal,
        "restart-ratification-replay-display",
    );
    assert!(matches!(
        ratify(
            &mut harness,
            &proposal,
            replay_challenge,
            "restart-ratification-replay",
        ),
        ApiResultV1::Error {
            code: ApiErrorCodeV1::Conflict,
            ..
        }
    ));
    let after_replay = inspect_record(&mut harness, &proposal, "after-ratified-replay");
    assert_eq!(
        after_replay.candidate_ratification,
        before.candidate_ratification
    );
    assert_eq!(after_replay.execution_attempt, execution_attempt);
    assert_eq!(after_replay.terminal_receipt, terminal_receipt);
    assert_eq!(target_object(&fixture), fixture.candidate_object);
    assert_eq!(target_tree(&fixture), fixture.candidate_tree);
}

#[test]
fn ref_drift_after_canonicalization_refuses_shared_activation_before_burn() {
    if !Path::new(GIT).is_file() {
        eprintln!("skipping managed-pointer integration: {GIT} is absent");
        return;
    }
    let fixture = git_fixture();
    let mut harness = broker_harness(&fixture, "drift");
    let proposal = submit_pointer(&mut harness, &fixture, "drift-proposal");
    let challenge = inspect_pointer(&mut harness, &fixture, &proposal, "drift-display");

    fs::write(fixture.source.join("governed.txt"), b"foreign\n").expect("foreign worktree content");
    run_git([
        OsString::from("-C"),
        fixture.source.as_os_str().to_owned(),
        OsString::from("add"),
        OsString::from("--"),
        OsString::from("governed.txt"),
    ]);
    run_git([
        OsString::from("-C"),
        fixture.source.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("user.name=AG NG integration"),
        OsString::from("-c"),
        OsString::from("user.email=ag-ng@example.invalid"),
        OsString::from("commit"),
        OsString::from("--quiet"),
        OsString::from("-m"),
        OsString::from("foreign drift"),
    ]);
    let foreign = git_line([
        OsString::from("-C"),
        fixture.source.as_os_str().to_owned(),
        OsString::from("rev-parse"),
        OsString::from("HEAD^{commit}"),
    ]);
    run_git([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("fetch"),
        OsString::from("--quiet"),
        OsString::from("--no-tags"),
        fixture.source.as_os_str().to_owned(),
        OsString::from("refs/heads/main:refs/heads/ag-test-foreign"),
    ]);
    run_git([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("update-ref"),
        OsString::from(TARGET_REF),
        OsString::from(&foreign),
        OsString::from(&fixture.base_object),
    ]);
    run_git([
        OsString::from("--git-dir"),
        fixture.repository.as_os_str().to_owned(),
        OsString::from("update-ref"),
        OsString::from("-d"),
        OsString::from("refs/heads/ag-test-foreign"),
        OsString::from(&foreign),
    ]);
    assert_eq!(target_object(&fixture), foreign);

    let result = ratify(&mut harness, &proposal, challenge, "drift-ratification");
    assert!(
        matches!(
            &result,
            ApiResultV1::Error {
                code: ApiErrorCodeV1::Indeterminate,
                ..
            }
        ),
        "unexpected drift result: {result:?}"
    );
    assert_eq!(target_object(&fixture), foreign);
    assert_ne!(target_object(&fixture), fixture.candidate_object);
    let record = inspect_record(&mut harness, &proposal, "drift-record");
    assert!(matches!(record.state, ProposalStateV1::Ready { .. }));
    assert!(record.authorization.is_none());
    assert!(record.candidate_ratification.is_none());
    assert!(record.execution_attempt.is_none());
    assert!(record.step_receipts.is_empty());
    assert!(record.managed_pointer_activation.is_none());
    assert!(record.promotion_refusals.is_empty());
}
