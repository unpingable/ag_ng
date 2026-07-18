//! Offline coherent-cut coordination, immutable publication, and evidence restore.
//!
//! This module deliberately implements no live quiescence RPC. Its coordinator
//! can run only after a caller has opened all three stores and therefore owns
//! all three exclusive writer fences. Every participant also supplies an exact
//! `OfflineServicesStopped` attestation bound to the common barrier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use ag_primitives::{AuthorityDomainId, Digest, EpochId, JcsDocument};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use tempfile::{Builder as TempBuilder, NamedTempFile};

use super::{
    BackupCheckpointV1, BackupCutStateV1, BackupParticipantRegistrationV1, BackupParticipantV1,
    BeginBackupCutV1, BlobDescriptorV1, CoherentBackupBundleV1, QuiescenceBarrierAttestationV1,
    REQUIRED_BACKUP_PARTICIPANTS, SealedDatabaseCaptureV1, Store, StoreError,
    absolute_normalized_path, backup_cut_from_connection, build_backup_manifest_from_connection,
    copy_and_hash_blob, create_and_validate_directory, digest_jcs, jcs, read_store_identity,
    verify_blob_file, verify_chain_connection,
};

const PUBLICATION_SCHEMA_V1: &str = "ag-store-backup-publication-v1";
const PUBLICATION_MANIFEST: &str = "manifest.json";
const MAX_PUBLICATION_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Component facts supplied to the offline coordinator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineBackupParticipantV1 {
    /// Component role.
    pub participant: BackupParticipantV1,
    /// Exact configured component/service identity.
    pub component_identity: Digest,
    /// Digest of exact active configuration bytes.
    pub config_identity: Digest,
    /// Digest of the exact compiled/persisted store identity.
    pub schema_identity: Digest,
    /// Digest of the effective security profile.
    pub profile_identity: Digest,
    /// Digest of exact executable build bytes and metadata.
    pub build_identity: Digest,
    /// Offline stopped-service declaration and boundary inventory.
    pub quiescence_attestation: QuiescenceBarrierAttestationV1,
}

/// Serializable, exact offline three-store cut request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineBackupCoordinatorV1 {
    /// Exact coordinator schema.
    pub schema: String,
    /// Globally unique cut ID.
    pub cut_id: String,
    /// Installation authority domain.
    pub authority_domain: AuthorityDomainId,
    /// Active authority epoch.
    pub epoch: EpochId,
    /// Globally unique quiescence barrier.
    pub quiescence_barrier_id: String,
    /// Exactly agd, ag-effectd, and ag-providerd, sorted by role.
    pub participants: Vec<OfflineBackupParticipantV1>,
    /// Coordinator-observed creation time.
    pub created_at_unix_ms: i64,
}

impl OfflineBackupCoordinatorV1 {
    /// Fence, checkpoint, and seal exactly three already-open offline stores.
    ///
    /// The caller must have stopped all daemon units before opening the stores.
    /// The stores' writer locks are the mechanical evidence that no daemon
    /// store writer remains. Attested config/profile/build and boundary facts
    /// are exact operator evidence; this function cannot independently discover
    /// them. A failure after any begin event is fail-closed: the durable barrier
    /// remains and the exact request must be resumed or explicitly aborted.
    ///
    /// # Errors
    ///
    /// Returns an error unless there is exactly one store and one valid offline
    /// attestation per role, all schema identities match the opened stores, and
    /// every local cut reaches `Sealed` with the same checkpoint bodies.
    pub fn seal(
        &self,
        stores: &mut BTreeMap<BackupParticipantV1, Store>,
        occurred_at_unix_ms: i64,
    ) -> Result<Vec<BackupCheckpointV1>, StoreError> {
        let participants = self.validate(stores)?;
        let request = BeginBackupCutV1 {
            cut_id: self.cut_id.clone(),
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            quiescence_barrier_id: self.quiescence_barrier_id.clone(),
            participants: participants
                .values()
                .map(|participant| BackupParticipantRegistrationV1 {
                    participant: participant.participant,
                    component_identity: participant.component_identity.clone(),
                })
                .collect(),
            created_at_unix_ms: self.created_at_unix_ms,
        };
        request.validate()?;

        for store in stores.values_mut() {
            store.begin_backup_cut(&request)?;
        }

        let mut checkpoints = Vec::with_capacity(REQUIRED_BACKUP_PARTICIPANTS.len());
        for role in REQUIRED_BACKUP_PARTICIPANTS {
            let participant = participants
                .get(&role)
                .ok_or(StoreError::InvalidBackupParticipants)?;
            let store = stores
                .get(&role)
                .ok_or(StoreError::InvalidBackupParticipants)?;
            checkpoints.push(BackupCheckpointV1 {
                participant: role,
                component_identity: participant.component_identity.clone(),
                chain_head: store.verify_chain()?,
                blob_root: store.blob_root()?,
                config_identity: participant.config_identity.clone(),
                schema_identity: participant.schema_identity.clone(),
                profile_identity: participant.profile_identity.clone(),
                build_identity: participant.build_identity.clone(),
                quiescence_attestation: participant.quiescence_attestation.clone(),
            });
        }

        for store in stores.values_mut() {
            for checkpoint in &checkpoints {
                store.prepare_backup_participant(&self.cut_id, checkpoint, occurred_at_unix_ms)?;
            }
            let manifest = store.build_backup_manifest(&self.cut_id)?;
            store.seal_backup_cut(&manifest, occurred_at_unix_ms)?;
            if store.backup_cut(&self.cut_id)?.state != BackupCutStateV1::Sealed {
                return Err(StoreError::Corrupt(
                    "offline coordinator did not leave every store sealed".to_owned(),
                ));
            }
        }
        Ok(checkpoints)
    }

    fn validate<'a>(
        &'a self,
        stores: &BTreeMap<BackupParticipantV1, Store>,
    ) -> Result<BTreeMap<BackupParticipantV1, &'a OfflineBackupParticipantV1>, StoreError> {
        if self.schema != "ag-store-offline-backup-coordinator-v1"
            || stores.keys().copied().ne(REQUIRED_BACKUP_PARTICIPANTS)
        {
            return Err(StoreError::InvalidBackupParticipants);
        }
        let mut participants = BTreeMap::new();
        let mut component_identities = BTreeSet::new();
        for participant in &self.participants {
            participant.quiescence_attestation.validate_for(
                &self.cut_id,
                &self.authority_domain,
                self.epoch,
                &self.quiescence_barrier_id,
                participant.participant,
            )?;
            if !component_identities.insert(participant.component_identity.clone())
                || participants
                    .insert(participant.participant, participant)
                    .is_some()
            {
                return Err(StoreError::InvalidBackupParticipants);
            }
            let store = stores
                .get(&participant.participant)
                .ok_or(StoreError::InvalidBackupParticipants)?;
            let actual_schema = Digest::from_serializable(store.identity())
                .map_err(|error| StoreError::Canonicalization(error.to_string()))?;
            if participant.schema_identity != actual_schema {
                return Err(StoreError::BackupSchemaIdentityMismatch(
                    participant.participant,
                ));
            }
        }
        if participants
            .keys()
            .copied()
            .ne(REQUIRED_BACKUP_PARTICIPANTS)
        {
            return Err(StoreError::InvalidBackupParticipants);
        }
        Ok(participants)
    }
}

/// One component's database capture and complete immutable-object catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPublicationComponentV1 {
    /// Component role.
    pub participant: BackupParticipantV1,
    /// Broker/store-owned sealed database capture.
    pub database_capture: SealedDatabaseCaptureV1,
    /// Exact sorted object catalog copied below the component's object root.
    pub blob_catalog: Vec<BlobDescriptorV1>,
}

/// Digest-bound immutable publication body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPublicationBodyV1 {
    /// Exact publication schema.
    pub schema: String,
    /// Coherent three-store database cut.
    pub coherent_cut: CoherentBackupBundleV1,
    /// Exact build/profile identity of the capture tool.
    pub capture_tool_identity: Digest,
    /// Exactly three database/object components sorted by role.
    pub components: Vec<BackupPublicationComponentV1>,
}

/// Immutable publication manifest stored as canonical `manifest.json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPublicationV1 {
    digest: Digest,
    body: BackupPublicationBodyV1,
}

impl BackupPublicationV1 {
    /// Construct and bind one complete database/object publication.
    ///
    /// # Errors
    ///
    /// Returns an error for any role, capture, ordering, catalog, or blob-root
    /// mismatch against the coherent cut.
    pub fn new(
        coherent_cut: CoherentBackupBundleV1,
        capture_tool_identity: Digest,
        mut components: Vec<BackupPublicationComponentV1>,
    ) -> Result<Self, StoreError> {
        coherent_cut.verify()?;
        components.sort_by_key(|component| component.participant);
        let body = BackupPublicationBodyV1 {
            schema: PUBLICATION_SCHEMA_V1.to_owned(),
            coherent_cut,
            capture_tool_identity,
            components,
        };
        validate_publication_body(&body)?;
        let digest = digest_jcs(PUBLICATION_SCHEMA_V1, &body)?.into_digest();
        Ok(Self { digest, body })
    }

    /// Exact digest released into all three local cut records.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Exact publication body.
    #[must_use]
    pub const fn body(&self) -> &BackupPublicationBodyV1 {
        &self.body
    }

    /// Revalidate the digest and every coherent-cut/catalog binding.
    ///
    /// # Errors
    ///
    /// Returns an error for any decoded mutation or mixed component.
    pub fn verify(&self) -> Result<(), StoreError> {
        validate_publication_body(&self.body)?;
        if digest_jcs(PUBLICATION_SCHEMA_V1, &self.body)?.as_digest() != &self.digest {
            return Err(StoreError::IncoherentBackupPublication);
        }
        Ok(())
    }
}

/// Capture one sealed store into its fixed publication component directory.
///
/// # Errors
///
/// Returns an error unless the cut remains sealed and every database/object
/// byte can be copied without replacement and reverified.
pub fn capture_publication_component(
    store: &Store,
    cut_id: &str,
    participant: BackupParticipantV1,
    staging_root: &Path,
) -> Result<BackupPublicationComponentV1, StoreError> {
    let component_root = component_root(staging_root, participant);
    create_and_validate_directory(&component_root)?;
    let database_capture = store.capture_sealed_database(
        cut_id,
        participant,
        &component_root.join("store.sqlite3"),
    )?;
    let blob_catalog = store.blob_catalog()?;
    if digest_jcs("ag-store-blob-root-v1", &blob_catalog)? != database_capture.blob_root {
        return Err(StoreError::IncoherentBackupPublication);
    }
    create_and_validate_directory(&component_root.join("objects"))?;
    for descriptor in &blob_catalog {
        copy_immutable_blob(
            &store.blob_path(&descriptor.digest),
            &object_path(&component_root, &descriptor.digest)?,
            descriptor,
        )?;
    }
    sync_tree_directories(&component_root)?;
    Ok(BackupPublicationComponentV1 {
        participant,
        database_capture,
        blob_catalog,
    })
}

/// Write canonical publication metadata and make the staging tree immutable.
///
/// # Errors
///
/// Returns an error if the exact manifest already exists, bytes do not match
/// the in-memory digest, the tree contains unexpected material, or fsync fails.
pub fn write_backup_publication(
    staging_root: &Path,
    publication: &BackupPublicationV1,
) -> Result<(), StoreError> {
    publication.verify()?;
    let staging_root = absolute_normalized_path(staging_root)?;
    let manifest_path = staging_root.join(PUBLICATION_MANIFEST);
    let bytes = jcs(publication)?;
    let mut temporary = NamedTempFile::new_in(&staging_root)?;
    temporary.as_file_mut().write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    match temporary.persist_noclobber(&manifest_path) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StoreError::BackupPublicationDestinationExists(
                manifest_path,
            ));
        }
        Err(error) => return Err(StoreError::Io(error.error)),
    }
    seal_tree_directories(&staging_root)?;
    verify_backup_publication(&staging_root).map(|_| ())
}

/// Strictly verify a complete immutable publication in place.
///
/// # Errors
///
/// Returns an error for non-canonical metadata, an unexpected path, mutable or
/// linked content, database corruption, chain drift, or any digest mismatch.
pub fn verify_backup_publication(root: &Path) -> Result<BackupPublicationV1, StoreError> {
    let root = absolute_normalized_path(root)?;
    validate_publication_directory(&root)?;
    let manifest_path = root.join(PUBLICATION_MANIFEST);
    let bytes = read_bounded_regular_file(&manifest_path, MAX_PUBLICATION_MANIFEST_BYTES)?;
    JcsDocument::from_canonical_bytes(&bytes).map_err(|error| {
        StoreError::Corrupt(format!("publication manifest is not canonical: {error}"))
    })?;
    let publication: BackupPublicationV1 = serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::InvalidStoredJson(error.to_string()))?;
    publication.verify()?;

    let (expected_files, expected_directories) = expected_publication_paths(&publication)?;
    let (actual_files, actual_directories) = publication_paths(&root)?;
    if actual_files != expected_files || actual_directories != expected_directories {
        return Err(StoreError::IncoherentBackupPublication);
    }

    for component in &publication.body.components {
        let component_root = component_root(&root, component.participant);
        verify_database_capture(
            &component_root.join("store.sqlite3"),
            &component.database_capture,
        )?;
        for descriptor in &component.blob_catalog {
            verify_blob_file(
                &object_path(&component_root, &descriptor.digest)?,
                descriptor,
            )?;
        }
    }
    Ok(publication)
}

/// Atomically publish a verified staging directory without replacement.
///
/// Staging and destination must be siblings so the operation is one
/// `renameat2(RENAME_NOREPLACE)` followed by a parent-directory fsync.
///
/// # Errors
///
/// Returns an error if verification fails, paths are not siblings, the final
/// name exists, the atomic rename is unavailable, or post-publication
/// verification differs.
pub fn publish_backup_staging(
    staging_root: &Path,
    destination: &Path,
) -> Result<BackupPublicationV1, StoreError> {
    let staging_root = absolute_normalized_path(staging_root)?;
    let destination = absolute_normalized_path(destination)?;
    let publication_parent = destination.parent().ok_or_else(|| {
        StoreError::InvalidIdentity("backup publication destination has no parent".to_owned())
    })?;
    if staging_root.parent() != Some(publication_parent) || staging_root == destination {
        return Err(StoreError::InvalidIdentity(
            "backup staging and publication paths must be distinct siblings".to_owned(),
        ));
    }
    let publication = verify_backup_publication(&staging_root)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(StoreError::BackupPublicationDestinationExists(destination));
    }
    rename_noreplace(&staging_root, &destination)?;
    File::open(publication_parent)?.sync_all()?;
    let published = verify_backup_publication(&destination)?;
    if published != publication {
        return Err(StoreError::IncoherentBackupPublication);
    }
    Ok(published)
}

/// Restore a verified publication as an immutable evidence tree.
///
/// This does **not** activate daemon stores, advance an epoch, or lift the
/// restored sealed barrier. It copies into a new sibling staging directory,
/// verifies it completely, and installs it under a previously absent name.
///
/// # Errors
///
/// Returns an error for a bad source, existing destination, copy drift,
/// verification failure, or atomic-install failure.
pub fn restore_backup_evidence(
    publication_root: &Path,
    destination: &Path,
) -> Result<BackupPublicationV1, StoreError> {
    let publication_root = absolute_normalized_path(publication_root)?;
    let destination = absolute_normalized_path(destination)?;
    let source = verify_backup_publication(&publication_root)?;
    let parent = destination.parent().ok_or_else(|| {
        StoreError::InvalidIdentity("restore destination has no parent".to_owned())
    })?;
    create_and_validate_directory(parent)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(StoreError::BackupPublicationDestinationExists(destination));
    }
    let temporary = TempBuilder::new()
        .prefix(".ag-restore-")
        .tempdir_in(parent)?;
    copy_publication_tree(&publication_root, temporary.path(), &source)?;
    seal_tree_directories(temporary.path())?;
    let restored = verify_backup_publication(temporary.path())?;
    if restored != source {
        return Err(StoreError::IncoherentBackupPublication);
    }
    let temporary_path = temporary.keep();
    rename_noreplace(&temporary_path, &destination)?;
    File::open(parent)?.sync_all()?;
    verify_backup_publication(&destination)
}

fn validate_publication_body(body: &BackupPublicationBodyV1) -> Result<(), StoreError> {
    body.coherent_cut.verify()?;
    if body.schema != PUBLICATION_SCHEMA_V1
        || body.components.len() != REQUIRED_BACKUP_PARTICIPANTS.len()
        || body
            .components
            .iter()
            .map(|component| component.participant)
            .ne(REQUIRED_BACKUP_PARTICIPANTS)
    {
        return Err(StoreError::IncoherentBackupPublication);
    }
    for (component, capture) in body
        .components
        .iter()
        .zip(&body.coherent_cut.body().components)
    {
        if component.participant != capture.participant
            || &component.database_capture != capture
            || component
                .blob_catalog
                .windows(2)
                .any(|pair| pair[0].digest >= pair[1].digest)
            || digest_jcs("ag-store-blob-root-v1", &component.blob_catalog)? != capture.blob_root
        {
            return Err(StoreError::IncoherentBackupPublication);
        }
    }
    Ok(())
}

fn verify_database_capture(
    path: &Path,
    capture: &SealedDatabaseCaptureV1,
) -> Result<(), StoreError> {
    verify_blob_file(path, &capture.database)?;
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" || read_store_identity(&connection)? != capture.store_identity {
        return Err(StoreError::IncoherentBackupPublication);
    }
    if verify_chain_connection(&connection, &capture.store_identity)? != capture.captured_chain_head
    {
        return Err(StoreError::IncoherentBackupPublication);
    }
    let cut = backup_cut_from_connection(&connection, &capture.cut_id)?;
    if cut.state != BackupCutStateV1::Sealed
        || cut.manifest_digest.as_ref() != Some(&capture.manifest_digest)
        || build_backup_manifest_from_connection(&connection, &capture.cut_id)?
            != capture.cut_manifest
    {
        return Err(StoreError::IncoherentBackupPublication);
    }
    Ok(())
}

fn copy_immutable_blob(
    source: &Path,
    destination: &Path,
    descriptor: &BlobDescriptorV1,
) -> Result<(), StoreError> {
    verify_blob_file(source, descriptor)?;
    let parent = destination.parent().ok_or_else(|| {
        StoreError::InvalidIdentity("backup object destination has no parent".to_owned())
    })?;
    create_and_validate_directory(parent)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err(StoreError::BackupCaptureDestinationExists(
            destination.to_owned(),
        ));
    }
    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    let actual = copy_and_hash_blob(
        &mut source_file,
        temporary.as_file_mut(),
        descriptor.byte_length,
    )?;
    if &actual != descriptor {
        return Err(StoreError::BlobMismatch {
            expected: descriptor.clone(),
            actual,
        });
    }
    temporary.as_file().sync_all()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    match temporary.persist_noclobber(destination) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StoreError::BackupCaptureDestinationExists(
                destination.to_owned(),
            ));
        }
        Err(error) => return Err(StoreError::Io(error.error)),
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn component_root(root: &Path, participant: BackupParticipantV1) -> PathBuf {
    root.join("components").join(participant.as_str())
}

fn object_path(component_root: &Path, digest: &Digest) -> Result<PathBuf, StoreError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| StoreError::InvalidDigest(digest.as_str().to_owned()))?;
    Ok(component_root
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..]))
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum
        || metadata.mode() & 0o222 != 0
    {
        return Err(StoreError::Corrupt(format!(
            "backup metadata is not an immutable bounded regular file: {}",
            path.display()
        )));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(StoreError::Corrupt(
            "backup metadata changed during bounded read".to_owned(),
        ));
    }
    Ok(bytes)
}

fn validate_publication_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.nlink() < 2
        || metadata.mode() & 0o222 != 0
        || fs::canonicalize(path)? != path
    {
        return Err(StoreError::Corrupt(format!(
            "backup publication directory is not immutable and canonical: {}",
            path.display()
        )));
    }
    Ok(())
}

fn expected_publication_paths(
    publication: &BackupPublicationV1,
) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>), StoreError> {
    let mut files = BTreeSet::from([PathBuf::from(PUBLICATION_MANIFEST)]);
    let mut directories = BTreeSet::from([PathBuf::new(), PathBuf::from("components")]);
    for component in &publication.body.components {
        let relative_root = PathBuf::from("components").join(component.participant.as_str());
        directories.insert(relative_root.clone());
        directories.insert(relative_root.join("objects"));
        files.insert(relative_root.join("store.sqlite3"));
        for descriptor in &component.blob_catalog {
            let hex = descriptor
                .digest
                .as_str()
                .strip_prefix("sha256:")
                .ok_or_else(|| StoreError::InvalidDigest(descriptor.digest.to_string()))?;
            directories.insert(relative_root.join("objects").join(&hex[..2]));
            files.insert(
                relative_root
                    .join("objects")
                    .join(&hex[..2])
                    .join(&hex[2..]),
            );
        }
    }
    Ok((files, directories))
}

fn publication_paths(root: &Path) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>), StoreError> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::from([PathBuf::new()]);
    let mut pending = vec![(root.to_owned(), PathBuf::new())];
    while let Some((absolute, relative)) = pending.pop() {
        let mut entries: Vec<_> = fs::read_dir(&absolute)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let child_relative = relative.join(name);
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_dir() {
                if metadata.mode() & 0o222 != 0 {
                    return Err(StoreError::IncoherentBackupPublication);
                }
                directories.insert(child_relative.clone());
                pending.push((entry.path(), child_relative));
            } else if metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.mode() & 0o222 == 0
            {
                files.insert(child_relative);
            } else {
                return Err(StoreError::IncoherentBackupPublication);
            }
        }
    }
    Ok((files, directories))
}

fn sync_tree_directories(root: &Path) -> Result<(), StoreError> {
    let mut directories = vec![root.to_owned()];
    let mut cursor = 0;
    while cursor < directories.len() {
        for entry in fs::read_dir(&directories[cursor])? {
            let entry = entry?;
            if fs::symlink_metadata(entry.path())?.file_type().is_dir() {
                directories.push(entry.path());
            }
        }
        cursor += 1;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn seal_tree_directories(root: &Path) -> Result<(), StoreError> {
    let mut directories = vec![root.to_owned()];
    let mut cursor = 0;
    while cursor < directories.len() {
        for entry in fs::read_dir(&directories[cursor])? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_dir() {
                directories.push(entry.path());
            } else if !metadata.file_type().is_file() {
                return Err(StoreError::IncoherentBackupPublication);
            }
        }
        cursor += 1;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))?;
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn rename_noreplace(source: &Path, destination: &Path) -> Result<(), StoreError> {
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE).map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            StoreError::BackupPublicationDestinationExists(destination.to_owned())
        } else {
            StoreError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
        }
    })
}

fn copy_publication_tree(
    source_root: &Path,
    destination_root: &Path,
    publication: &BackupPublicationV1,
) -> Result<(), StoreError> {
    let (files, directories) = expected_publication_paths(publication)?;
    for directory in directories {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let destination = destination_root.join(directory);
        fs::create_dir(&destination)?;
    }
    for relative in files {
        let source = source_root.join(&relative);
        let destination = destination_root.join(&relative);
        let metadata = fs::symlink_metadata(&source)?;
        let mut source_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&source)?;
        let mut destination_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&destination)?;
        io::copy(&mut source_file, &mut destination_file)?;
        destination_file.sync_all()?;
        if destination_file.metadata()?.len() != metadata.len() {
            return Err(StoreError::IncoherentBackupPublication);
        }
    }
    sync_tree_directories(destination_root)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{BlobInstallResult, StoreIdentityV1, WriterIdentityV1};
    use tempfile::TempDir;

    struct ComponentFixture {
        _root: TempDir,
        database: PathBuf,
        blobs: PathBuf,
        identity: StoreIdentityV1,
        participant: BackupParticipantV1,
    }

    impl ComponentFixture {
        fn new(participant: BackupParticipantV1, application_id: u32) -> Self {
            let root = tempfile::tempdir().unwrap();
            Self {
                database: root.path().join("store.sqlite3"),
                blobs: root.path().join("objects"),
                identity: StoreIdentityV1::current(application_id, participant.as_str()).unwrap(),
                _root: root,
                participant,
            }
        }

        fn open(&self) -> Store {
            Store::open(
                &self.database,
                &self.blobs,
                self.identity.clone(),
                &WriterIdentityV1 {
                    writer_id: format!("backup-test:{}", self.participant.as_str()),
                    principal_digest: Digest::hash_domain(
                        "backup-test-writer",
                        self.participant.as_str().as_bytes(),
                    ),
                    process_nonce: format!("nonce:{}", self.participant.as_str()),
                    claimed_at_unix_ms: 1,
                },
            )
            .unwrap()
        }
    }

    fn fixtures() -> [ComponentFixture; 3] {
        [
            ComponentFixture::new(BackupParticipantV1::Agd, 0x4147_1101),
            ComponentFixture::new(BackupParticipantV1::AgEffectd, 0x4147_1102),
            ComponentFixture::new(BackupParticipantV1::AgProviderd, 0x4147_1103),
        ]
    }

    fn coordinator(stores: &BTreeMap<BackupParticipantV1, Store>) -> OfflineBackupCoordinatorV1 {
        let authority_domain = AuthorityDomainId::new("domain:offline-test").unwrap();
        let epoch = EpochId::new(11).unwrap();
        let cut_id = "cut:offline-test";
        let barrier = "barrier:offline-services-stopped";
        OfflineBackupCoordinatorV1 {
            schema: "ag-store-offline-backup-coordinator-v1".to_owned(),
            cut_id: cut_id.to_owned(),
            authority_domain: authority_domain.clone(),
            epoch,
            quiescence_barrier_id: barrier.to_owned(),
            participants: REQUIRED_BACKUP_PARTICIPANTS
                .into_iter()
                .map(|participant| {
                    let store = stores.get(&participant).unwrap();
                    let for_role =
                        |domain: &str| Digest::hash_domain(domain, participant.as_str().as_bytes());
                    OfflineBackupParticipantV1 {
                        participant,
                        component_identity: for_role("component"),
                        config_identity: for_role("config"),
                        schema_identity: Digest::from_serializable(store.identity()).unwrap(),
                        profile_identity: for_role("profile"),
                        build_identity: for_role("build"),
                        quiescence_attestation: QuiescenceBarrierAttestationV1 {
                            schema: "ag-store-offline-quiescence-attestation-v1".to_owned(),
                            cut_id: cut_id.to_owned(),
                            authority_domain: authority_domain.clone(),
                            epoch,
                            quiescence_barrier_id: barrier.to_owned(),
                            participant,
                            boundary: crate::QuiescenceBoundaryV1::OfflineServicesStopped,
                            boundary_summary: for_role("boundary-inventory"),
                            attesting_principal: for_role("offline-attester"),
                            attested_at_unix_ms: 90,
                        },
                    }
                })
                .collect(),
            created_at_unix_ms: 100,
        }
    }

    fn sealed_publication() -> (
        Vec<ComponentFixture>,
        BTreeMap<BackupParticipantV1, Store>,
        TempDir,
        BackupPublicationV1,
    ) {
        let fixtures = Vec::from(fixtures());
        let mut stores: BTreeMap<_, _> = fixtures
            .iter()
            .map(|fixture| (fixture.participant, fixture.open()))
            .collect();
        for (participant, store) in &mut stores {
            let bytes = format!("immutable backup object for {}", participant.as_str());
            let descriptor = BlobDescriptorV1 {
                digest: Digest::hash_bytes(bytes.as_bytes()),
                byte_length: bytes.len() as u64,
            };
            assert_eq!(
                store
                    .install_blob(&descriptor, &mut Cursor::new(bytes), 20)
                    .unwrap(),
                BlobInstallResult::Installed
            );
        }
        let coordinator = coordinator(&stores);
        coordinator.seal(&mut stores, 101).unwrap();

        let publication_parent = tempfile::tempdir().unwrap();
        let staging = publication_parent.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let components: Vec<_> = REQUIRED_BACKUP_PARTICIPANTS
            .into_iter()
            .map(|participant| {
                capture_publication_component(
                    stores.get(&participant).unwrap(),
                    &coordinator.cut_id,
                    participant,
                    &staging,
                )
                .unwrap()
            })
            .collect();
        let coherent = CoherentBackupBundleV1::new(
            components
                .iter()
                .map(|component| component.database_capture.clone())
                .collect(),
        )
        .unwrap();
        let publication = BackupPublicationV1::new(
            coherent,
            Digest::hash_domain("capture-tool", b"ag-backup-test"),
            components,
        )
        .unwrap();
        write_backup_publication(&staging, &publication).unwrap();
        (fixtures, stores, publication_parent, publication)
    }

    #[test]
    fn coordinator_requires_exact_offline_barrier_attestations_before_mutation() {
        let fixtures = fixtures();
        let mut stores: BTreeMap<_, _> = fixtures
            .iter()
            .map(|fixture| (fixture.participant, fixture.open()))
            .collect();
        let mut request = coordinator(&stores);
        request.participants[1]
            .quiescence_attestation
            .quiescence_barrier_id = "barrier:other".to_owned();
        assert!(matches!(
            request.seal(&mut stores, 101),
            Err(StoreError::InvalidQuiescenceAttestation(
                BackupParticipantV1::AgEffectd
            ))
        ));
        assert!(
            stores
                .values()
                .all(|store| store.active_backup_cut().unwrap().is_none())
        );
    }

    #[test]
    fn publication_rejects_cross_mixed_component_and_object_cuts() {
        let (_fixtures, _stores, publication_parent, publication) = sealed_publication();
        let staging = publication_parent.path().join("staging");
        assert_eq!(verify_backup_publication(&staging).unwrap(), publication);

        let mut mixed_components = publication.body.components.clone();
        mixed_components.swap(0, 1);
        mixed_components[0].participant = BackupParticipantV1::Agd;
        mixed_components[1].participant = BackupParticipantV1::AgEffectd;
        assert!(matches!(
            BackupPublicationV1::new(
                publication.body.coherent_cut.clone(),
                publication.body.capture_tool_identity.clone(),
                mixed_components,
            ),
            Err(StoreError::IncoherentBackupPublication)
        ));

        let object = publication.body.components[0].blob_catalog[0].clone();
        let object_path = object_path(
            &component_root(&staging, BackupParticipantV1::Agd),
            &object.digest,
        )
        .unwrap();
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_backup_publication(&staging).is_err());
    }

    #[test]
    fn publication_and_evidence_restore_are_atomic_and_never_replace() {
        let (_fixtures, _stores, publication_parent, publication) = sealed_publication();
        let staging = publication_parent.path().join("staging");
        let published = publication_parent.path().join("published");
        fs::create_dir(&published).unwrap();
        fs::write(published.join("sentinel"), b"do not replace").unwrap();
        assert!(matches!(
            publish_backup_staging(&staging, &published),
            Err(StoreError::BackupPublicationDestinationExists(path)) if path == published
        ));
        assert!(staging.exists());
        assert_eq!(
            fs::read(published.join("sentinel")).unwrap(),
            b"do not replace"
        );

        fs::remove_file(published.join("sentinel")).unwrap();
        fs::remove_dir(&published).unwrap();
        assert_eq!(
            publish_backup_staging(&staging, &published).unwrap(),
            publication
        );
        assert!(!staging.exists());

        let restored = publication_parent.path().join("restored-evidence");
        assert_eq!(
            restore_backup_evidence(&published, &restored).unwrap(),
            publication
        );
        assert_eq!(verify_backup_publication(&restored).unwrap(), publication);
        assert!(matches!(
            restore_backup_evidence(&published, &restored),
            Err(StoreError::BackupPublicationDestinationExists(path)) if path == restored
        ));
    }
}
