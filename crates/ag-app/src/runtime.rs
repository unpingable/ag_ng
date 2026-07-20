//! Shared process startup helpers.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_primitives::{AuthorityDomainId, Digest, EpochId, JcsDocument};
use ag_store::{
    DatabaseFileCustodyV1, Store, StoreActivationIdentityV1, StoreIdentityV1, WriterIdentityV1,
    prepare_database,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::config::StoreConfigV1;
use crate::custody::{CustodyNodeKindV1, prepare_regular_file, validate_node};

/// Authority-bearing deployment inputs bound to a component store activation.
#[derive(Clone, Copy, Debug)]
pub struct ComponentActivationContextV1<'a> {
    /// Installation authority domain.
    pub authority_domain: &'a str,
    /// Active nonzero revocation epoch.
    pub epoch: &'a str,
    /// Exact configured security-profile identifier.
    pub security_profile: &'a str,
    /// Compiler-owned target catalog identity, when available before opening.
    pub authority_catalog_identity: Option<&'a Digest>,
}

/// Require the complete pre-activation store cut used by an enrollment
/// ceremony: protected database nodes are absent, the object store is empty,
/// and both pre-created directories have their enrolled custody and a
/// no-symlink ancestor chain.
///
/// # Errors
///
/// Returns an error for custody drift, symlink ancestry, any database,
/// `SQLite` sidecar, writer-lock node, object-store entry, or I/O failure.
pub fn require_uninitialized_component_store(config: &StoreConfigV1) -> anyhow::Result<()> {
    let database_parent = config
        .database
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent"))?;
    validate_node(
        database_parent,
        &config.store_custody.database_parent,
        CustodyNodeKindV1::Directory,
    )?;
    validate_node(
        &config.object_store,
        &config.store_custody.object_store,
        CustodyNodeKindV1::Directory,
    )?;

    for suffix in ["", "-journal", "-wal", "-shm", ".writer.lock"] {
        let path = database_sibling_path(&config.database, suffix)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => anyhow::bail!(
                "component store is already initialized or has a stale protected node at {}",
                path.display()
            ),
            Err(error) => return Err(error.into()),
        }
    }
    if fs::read_dir(&config.object_store)?
        .next()
        .transpose()?
        .is_some()
    {
        anyhow::bail!("component object store is not empty before initial activation");
    }
    // Repeat the descriptor-independent custody checks after enumeration so a
    // path replacement cannot turn a passing observation into an unchecked
    // final pathname for the immediately following store open.
    validate_node(
        database_parent,
        &config.store_custody.database_parent,
        CustodyNodeKindV1::Directory,
    )?;
    validate_node(
        &config.object_store,
        &config.store_custody.object_store,
        CustodyNodeKindV1::Directory,
    )?;
    Ok(())
}

/// Opens a component-specific, single-writer store after binding its writer
/// identity to the descriptor-bound digest of exact config bytes and a fresh
/// process lifecycle nonce.
///
/// # Errors
///
/// Returns an error if filesystem custody drifts, time cannot be represented,
/// store identity construction fails, or the writer fence/store cannot be
/// opened and verified.
pub fn open_component_store(
    application_id: u32,
    application_name: &str,
    config_identity: &Digest,
    activation_context: ComponentActivationContextV1<'_>,
    config: &StoreConfigV1,
) -> anyhow::Result<Store> {
    let database_parent = config
        .database
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent"))?;
    validate_node(
        database_parent,
        &config.store_custody.database_parent,
        CustodyNodeKindV1::Directory,
    )?;
    validate_node(
        &config.object_store,
        &config.store_custody.object_store,
        CustodyNodeKindV1::Directory,
    )?;

    let writer_lock_path = writer_lock_path(&config.database)?;
    let prepared_database = prepare_database(
        &config.database,
        DatabaseFileCustodyV1 {
            uid: config.store_custody.database.uid,
            gid: config.store_custody.database.gid,
            mode: config.store_custody.database.mode,
        },
    )?;
    let writer_lock_file =
        prepare_regular_file(&writer_lock_path, &config.store_custody.writer_lock)?;
    drop(writer_lock_file);

    let identity = StoreIdentityV1::current(application_id, application_name)?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let build_identity = component_build_identity(application_name)?;
    let activation = StoreActivationIdentityV1 {
        schema: StoreActivationIdentityV1::SCHEMA.to_owned(),
        authority_domain: AuthorityDomainId::parse(activation_context.authority_domain)?,
        epoch: EpochId::parse(activation_context.epoch)?,
        config_identity: config_identity.clone(),
        security_profile_identity: Digest::hash_domain(
            "ag-security-profile-identity-v1",
            activation_context.security_profile.as_bytes(),
        ),
        build_identity: build_identity.clone(),
        authority_catalog_identity: activation_context.authority_catalog_identity.cloned(),
    };
    let writer = WriterIdentityV1 {
        writer_id: format!("{application_name}:{}", uuid::Uuid::new_v4()),
        principal_digest: Digest::hash_domain(
            "ag-daemon-writer-config-and-build-v1",
            &[
                config_identity.as_str().as_bytes(),
                build_identity.as_str().as_bytes(),
                application_name.as_bytes(),
            ]
            .concat(),
        ),
        process_nonce: uuid::Uuid::new_v4().to_string(),
        claimed_at_unix_ms: now,
    };
    let store = Store::open_activated_prepared(
        prepared_database,
        &config.object_store,
        identity,
        &activation,
        &writer,
    )?;

    // The activated prepared open may initialize only its exclusively created
    // SQLite inode and claims the writer fence. Readiness is forbidden until
    // the resulting filesystem nodes still match the explicit startup policy.
    validate_node(
        &config.database,
        &config.store_custody.database,
        CustodyNodeKindV1::RegularFile,
    )?;
    validate_node(
        database_parent,
        &config.store_custody.database_parent,
        CustodyNodeKindV1::Directory,
    )?;
    validate_node(
        &writer_lock_path,
        &config.store_custody.writer_lock,
        CustodyNodeKindV1::RegularFile,
    )?;
    validate_node(
        &config.object_store,
        &config.store_custody.object_store,
        CustodyNodeKindV1::Directory,
    )?;
    validate_sqlite_sidecar_if_present(&config.database, "-wal", &config.store_custody.database)?;
    validate_sqlite_sidecar_if_present(&config.database, "-shm", &config.store_custody.database)?;
    Ok(store)
}

fn component_build_identity(application_name: &str) -> anyhow::Result<Digest> {
    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct BuildIdentityMaterialV1<'a> {
        schema: &'static str,
        application_name: &'a str,
        package_version: &'static str,
        build_id: &'static str,
        target_os: &'static str,
        target_arch: &'static str,
        executable_digest: Digest,
        executable_size: u64,
    }

    // `/proc/self/exe` is the one intentional magic-link observation in
    // startup: it resolves the inode actually executing, not a replaceable
    // pathname. This never observes a peer process.
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/self/exe")?;
    let before = executable.metadata()?;
    if !before.file_type().is_file() || before.len() == 0 || before.len() > MAX_EXECUTABLE_BYTES {
        anyhow::bail!("running executable is not a bounded regular file");
    }
    let mut hasher = Sha256::new();
    let mut observed_size = 0_u64;
    let mut chunk = [0_u8; 8192];
    loop {
        let count = executable.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| anyhow::anyhow!("running executable size overflow"))?;
        if observed_size > MAX_EXECUTABLE_BYTES {
            anyhow::bail!("running executable exceeds the build-identity bound");
        }
        hasher.update(&chunk[..count]);
    }
    let after = executable.metadata()?;
    if observed_size != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        anyhow::bail!("running executable changed during exact build observation");
    }
    let executable_digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))?;

    let material = BuildIdentityMaterialV1 {
        schema: "ag-component-build-identity-material-v1",
        application_name,
        package_version: env!("CARGO_PKG_VERSION"),
        build_id: option_env!("AG_BUILD_IDENTITY").unwrap_or(env!("CARGO_PKG_VERSION")),
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        executable_digest,
        executable_size: before.len(),
    };
    let canonical = JcsDocument::canonicalize(&material)?;
    Ok(Digest::hash_domain(
        "ag-component-build-identity-v1",
        canonical.as_bytes(),
    ))
}

fn writer_lock_path(database: &Path) -> anyhow::Result<PathBuf> {
    database_sibling_path(database, ".writer.lock")
}

fn database_sibling_path(database: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let file_name = database
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("database path must name a file"))?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(suffix);
    Ok(database.with_file_name(lock_name))
}

fn validate_sqlite_sidecar_if_present(
    database: &Path,
    suffix: &str,
    policy: &crate::config::FilesystemNodeCustodyV1,
) -> anyhow::Result<()> {
    let file_name = database
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("database path must name a file"))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(suffix);
    let sidecar = database.with_file_name(sidecar_name);
    match fs::symlink_metadata(&sidecar) {
        Ok(_) => {
            validate_node(&sidecar, policy, CustodyNodeKindV1::RegularFile)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use crate::config::{FilesystemNodeCustodyV1, StoreCustodyConfigV1};

    use super::*;

    fn policy(uid: u32, gid: u32, mode: u32) -> FilesystemNodeCustodyV1 {
        FilesystemNodeCustodyV1 { uid, gid, mode }
    }

    fn fixture() -> (tempfile::TempDir, Digest, StoreConfigV1) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("state-root mode");
        let root_metadata = fs::metadata(temporary.path()).expect("state-root metadata");
        let object_store = temporary.path().join("objects");
        fs::create_dir(&object_store).expect("object root");
        fs::set_permissions(&object_store, fs::Permissions::from_mode(0o700))
            .expect("object-root mode");
        let config_identity = Digest::hash_bytes(b"test-config-v1");
        let uid = root_metadata.uid();
        let gid = root_metadata.gid();
        let config = StoreConfigV1 {
            database: temporary.path().join("daemon.db"),
            object_store,
            store_custody: StoreCustodyConfigV1 {
                database_parent: policy(uid, gid, 0o700),
                object_store: policy(uid, gid, 0o700),
                database: policy(uid, gid, 0o600),
                writer_lock: policy(uid, gid, 0o600),
            },
        };
        (temporary, config_identity, config)
    }

    fn activation_context() -> ComponentActivationContextV1<'static> {
        ComponentActivationContextV1 {
            authority_domain: "domain:runtime-test",
            epoch: "1",
            security_profile: "production",
            authority_catalog_identity: None,
        }
    }

    #[test]
    fn store_is_not_returned_until_all_final_nodes_match_policy() {
        let (_temporary, config_identity, config) = fixture();
        let store = open_component_store(
            0x4147_7f01,
            "custody-test",
            &config_identity,
            activation_context(),
            &config,
        )
        .expect("open store");

        let database = fs::symlink_metadata(&config.database).expect("database metadata");
        assert_eq!(database.mode() & 0o7777, 0o600);
        let lock = writer_lock_path(&config.database).expect("lock path");
        let lock = fs::symlink_metadata(lock).expect("lock metadata");
        assert_eq!(lock.mode() & 0o7777, 0o600);
        let objects = fs::symlink_metadata(&config.object_store).expect("object metadata");
        assert_eq!(objects.mode() & 0o7777, 0o700);
        drop(store);
    }

    #[test]
    fn existing_store_permission_drift_is_not_repaired() {
        let (_temporary, config_identity, config) = fixture();
        let store = open_component_store(
            0x4147_7f02,
            "custody-drift",
            &config_identity,
            activation_context(),
            &config,
        )
        .expect("open store");
        drop(store);
        fs::set_permissions(&config.database, fs::Permissions::from_mode(0o640))
            .expect("drift database mode");

        assert!(
            open_component_store(
                0x4147_7f02,
                "custody-drift",
                &config_identity,
                activation_context(),
                &config,
            )
            .is_err()
        );
        assert_eq!(
            fs::symlink_metadata(&config.database)
                .expect("database metadata")
                .mode()
                & 0o7777,
            0o640
        );
    }

    #[test]
    fn object_root_must_be_precreated_with_enrolled_custody() {
        let (_temporary, config_identity, config) = fixture();
        fs::remove_dir(&config.object_store).expect("remove object root");
        assert!(
            open_component_store(
                0x4147_7f03,
                "custody-missing",
                &config_identity,
                activation_context(),
                &config,
            )
            .is_err()
        );
    }

    #[test]
    fn preexisting_empty_database_is_not_enrolled_by_daemon_startup() {
        let (_temporary, config_identity, config) = fixture();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config.database)
            .expect("pre-create empty database");

        assert!(
            open_component_store(
                0x4147_7f04,
                "custody-preexisting-empty",
                &config_identity,
                activation_context(),
                &config,
            )
            .is_err()
        );
        assert_eq!(fs::metadata(&config.database).expect("metadata").len(), 0);
    }

    #[test]
    fn uninitialized_store_preflight_is_exact_and_read_only() {
        let (_temporary, _config_identity, config) = fixture();
        require_uninitialized_component_store(&config).expect("pristine store cut");
        assert!(!config.database.exists());
        assert_eq!(
            fs::read_dir(&config.object_store).expect("objects").count(),
            0
        );

        for suffix in ["", "-journal", "-wal", "-shm", ".writer.lock"] {
            let (_temporary, _config_identity, config) = fixture();
            let protected = database_sibling_path(&config.database, suffix).expect("sibling path");
            fs::write(&protected, b"stale").expect("protected node");
            assert!(require_uninitialized_component_store(&config).is_err());
        }

        let (_temporary, _config_identity, config) = fixture();
        fs::write(config.object_store.join("foreign"), b"foreign").expect("foreign object");
        assert!(require_uninitialized_component_store(&config).is_err());

        let (_temporary, _config_identity, config) = fixture();
        fs::set_permissions(&config.object_store, fs::Permissions::from_mode(0o755))
            .expect("drift object-store mode");
        assert!(require_uninitialized_component_store(&config).is_err());
    }

    #[test]
    fn uninitialized_store_preflight_refuses_symlink_ancestry() {
        let (temporary, _config_identity, mut config) = fixture();
        let linked_parent = temporary.path().join("linked-state");
        symlink(temporary.path(), &linked_parent).expect("linked state parent");
        config.database = linked_parent.join("daemon.db");
        config.object_store = linked_parent.join("objects");
        assert!(require_uninitialized_component_store(&config).is_err());
    }

    #[test]
    fn build_identity_binds_the_running_executable_and_component_role() {
        let first = component_build_identity("runtime-test").expect("first observation");
        let repeated = component_build_identity("runtime-test").expect("repeated observation");
        let other_role = component_build_identity("runtime-test-other").expect("other role");

        assert_eq!(first, repeated);
        assert_ne!(first, other_role);
    }
}
