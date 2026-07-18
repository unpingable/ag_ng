//! Verification of classic Agent Governor replacement claims and frozen archives.
//!
//! This crate deliberately has no Python, `SQLite`, classic-Agent-Governor, or
//! AG-ng runtime dependency. Classic bytes are opened as bounded opaque files
//! for digest verification only; they can never become runtime authority.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use ag_primitives::{Digest, JcsDocument, JcsError};
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact migration-ledger schema accepted by this build.
pub const MIGRATION_LEDGER_SCHEMA_V1: &str = "ag.migration-ledger/v1";
/// Exact frozen classic archive-manifest schema accepted by this build.
pub const ARCHIVE_MANIFEST_SCHEMA_V1: &str = "ag.classic-archive-manifest/v1";
/// Exact migration test-receipt schema accepted by this build.
pub const TEST_RECEIPT_SCHEMA_V1: &str = "ag.migration-test-receipt/v1";
/// Exact hostile absence-specimen schema accepted by this build.
pub const ABSENCE_SPECIMEN_SCHEMA_V1: &str = "ag.migration-hostile-absence-specimen/v1";

const MAX_CONTROL_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARCHIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 4096;
const MAX_ID_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 4096;

/// A machine-bound file identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileBindingV1 {
    /// SHA-256 digest of the exact bytes.
    pub digest: Digest,
    /// Exact byte length.
    pub length: u64,
    /// Slash-separated path relative to an explicitly supplied root.
    pub path: String,
}

/// Completeness claim made by the initial migration inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCompletenessV1 {
    /// Only the enumerated authority-critical surfaces are claimed complete.
    PartialAuthorityCritical,
}

/// Kind of classic surface inventoried in a ledger.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassicSurfaceKindV1 {
    /// Installed command-line entry point.
    CliEntry,
    /// Long-lived or agent-launching runtime entry point.
    RuntimeEntry,
    /// Receipt or database surface previously consulted as authority state.
    AuthorityStore,
    /// Persisted receipt/export representation.
    ExportShape,
}

/// One exact surface in the declared classic inventory scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassicSurfaceV1 {
    /// Stable inventory identifier.
    pub id: String,
    /// Surface category.
    pub kind: ClassicSurfaceKindV1,
    /// Exact pinned classic source file containing the entry or shape.
    pub source: FileBindingV1,
    /// Human-readable symbol or persisted path within that source.
    pub symbol: String,
}

/// Scope explicitly claimed by a migration ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryScopeV1 {
    /// Exact pinned classic commit.
    pub classic_revision: String,
    /// Must be false. Classic bytes are never AG-ng runtime authority.
    pub classic_runtime_authority: bool,
    /// Deliberately narrow completeness claim.
    pub completeness: InventoryCompletenessV1,
    /// Stable scope identifier.
    pub id: String,
    /// Manifest binding the classic files used to construct this inventory.
    pub source_manifest: FileBindingV1,
}

/// A replacement is bound to both an AG-ng schema and a passed test receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementV1 {
    /// AG-ng schema that owns the replacement semantics.
    pub ng_schema: String,
    /// Exact passed test receipt under the AG-ng evidence root.
    pub test_receipt: FileBindingV1,
}

/// A retirement is bound to an explicit rationale and hostile absence specimen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementV1 {
    /// Specimen proving a classic-runtime-authority claim is rejected.
    pub hostile_absence_specimen: FileBindingV1,
    /// Specific reason this surface does not survive into AG-ng.
    pub rationale: String,
}

/// A blocker has a stable code and an objective exit criterion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockerV1 {
    /// Machine-stable blocker identifier.
    pub code: String,
    /// Concrete condition required before replacement or retirement.
    pub exit_criterion: String,
}

/// Closed replacement/retirement disposition vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceDispositionV1 {
    /// The classic surface has an evidenced AG-ng replacement.
    Replaced {
        /// Replacement evidence.
        replacement: ReplacementV1,
        /// Exact inventory surface identifier.
        surface_id: String,
    },
    /// The classic surface is intentionally absent.
    Retired {
        /// Retirement evidence.
        retirement: RetirementV1,
        /// Exact inventory surface identifier.
        surface_id: String,
    },
    /// The surface is explicitly not yet replaced or retired.
    Blocked {
        /// Specific blocker and exit condition.
        blocker: BlockerV1,
        /// Exact inventory surface identifier.
        surface_id: String,
    },
}

impl SurfaceDispositionV1 {
    fn surface_id(&self) -> &str {
        match self {
            Self::Replaced { surface_id, .. }
            | Self::Retired { surface_id, .. }
            | Self::Blocked { surface_id, .. } => surface_id,
        }
    }
}

/// Versioned, exact migration ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationLedgerV1 {
    /// Exactly one disposition for every inventoried surface.
    pub dispositions: Vec<SurfaceDispositionV1>,
    /// Complete inventory within the explicitly partial scope.
    pub inventory: Vec<ClassicSurfaceV1>,
    /// Exact schema identifier.
    pub schema: String,
    /// Machine-bound scope and source manifest.
    pub scope: InventoryScopeV1,
}

/// How archive bytes may be used.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveAuthorityUseV1 {
    /// Digest/length verification only; no authority is imported.
    ArchiveEvidenceOnly,
}

/// Exact manifest for a bounded, read-only classic archive subset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifestV1 {
    /// Closed value that prevents runtime-authority claims.
    pub authority_use: ArchiveAuthorityUseV1,
    /// Exact classic commit from which files were captured.
    pub classic_revision: String,
    /// Honest completeness claim for the file set.
    pub completeness: InventoryCompletenessV1,
    /// Files to verify as opaque bytes.
    pub files: Vec<FileBindingV1>,
    /// Exact schema identifier.
    pub schema: String,
    /// Scope identifier shared with the migration ledger.
    pub scope_id: String,
}

/// Passed test receipt consumed by a replacement disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationTestReceiptV1 {
    /// Command that produced the result.
    pub command: String,
    /// Named test assertions covered by the receipt.
    pub covered_tests: Vec<String>,
    /// Closed success result.
    pub result: TestResultV1,
    /// Exact schema identifier.
    pub schema: String,
}

/// Closed migration test result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestResultV1 {
    /// The bound test command passed.
    Passed,
}

/// Hostile claim bound by retired surfaces.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostileClaimV1 {
    /// Claim that frozen classic bytes can become AG-ng runtime authority.
    ClassicBytesAreRuntimeAuthority,
}

/// Closed expected outcome for a hostile absence specimen.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostileExpectedV1 {
    /// The claim must be rejected.
    Refuse,
}

/// Exact hostile specimen required by retirement entries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostileAbsenceSpecimenV1 {
    /// Forbidden claim under test.
    pub claim: HostileClaimV1,
    /// Required result.
    pub expected: HostileExpectedV1,
    /// Exact schema identifier.
    pub schema: String,
}

/// Successful ledger verification summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerVerificationV1 {
    /// Number of blocked surfaces.
    pub blocked: usize,
    /// Number of inventoried surfaces.
    pub inventory: usize,
    /// Number of replaced surfaces.
    pub replaced: usize,
    /// Number of retired surfaces.
    pub retired: usize,
    /// Digest of exact canonical ledger bytes.
    pub ledger_digest: Digest,
}

/// Successful archive verification summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveVerificationV1 {
    /// Number of exact files verified.
    pub files: usize,
    /// Digest of exact canonical manifest bytes.
    pub manifest_digest: Digest,
    /// Total exact bytes verified.
    pub total_bytes: u64,
}

/// Parse exact canonical ledger bytes and validate their closed-world inventory.
///
/// # Errors
///
/// Returns an error for noncanonical/hostile JSON, unknown fields, schema drift,
/// duplicate or missing inventory entries, unsafe paths, vague blockers, or any
/// claim that classic bytes are runtime authority.
pub fn parse_and_validate_ledger(bytes: &[u8]) -> Result<MigrationLedgerV1, MigrationError> {
    if bytes.len() > usize::try_from(MAX_CONTROL_DOCUMENT_BYTES).unwrap_or(usize::MAX) {
        return Err(MigrationError::ControlDocumentTooLarge);
    }
    let document = parse_canonical_control(bytes)?;
    let ledger: MigrationLedgerV1 = document.decode()?;
    validate_ledger(&ledger)?;
    Ok(ledger)
}

/// Parse exact canonical archive-manifest bytes and validate bounded entries.
///
/// # Errors
///
/// Returns an error for hostile JSON, schema drift, duplicate/unsafe paths, or
/// any manifest exceeding fixed file and byte limits.
pub fn parse_and_validate_archive_manifest(
    bytes: &[u8],
) -> Result<ArchiveManifestV1, MigrationError> {
    if bytes.len() > usize::try_from(MAX_CONTROL_DOCUMENT_BYTES).unwrap_or(usize::MAX) {
        return Err(MigrationError::ControlDocumentTooLarge);
    }
    let document = parse_canonical_control(bytes)?;
    let manifest: ArchiveManifestV1 = document.decode()?;
    validate_archive_manifest(&manifest)?;
    Ok(manifest)
}

/// Verify ledger structure plus every AG-ng evidence artifact it binds.
///
/// This validates the source manifest's correspondence to the ledger inventory,
/// but does not read classic source files. Use [`verify_archive`] separately on
/// a frozen classic archive.
///
/// # Errors
///
/// Returns an error if a bound artifact drifts, is a symlink/non-regular file,
/// exceeds its declared size, has hostile JSON, or does not match its expected
/// evidence schema and closed outcome.
pub fn verify_ledger(
    ledger_bytes: &[u8],
    evidence_root: &Path,
) -> Result<LedgerVerificationV1, MigrationError> {
    let ledger = parse_and_validate_ledger(ledger_bytes)?;
    let root = open_root(evidence_root)?;

    let source_manifest_bytes = verify_bound_file(&root, &ledger.scope.source_manifest)?;
    let source_manifest = parse_and_validate_archive_manifest(&source_manifest_bytes)?;
    if source_manifest.scope_id != ledger.scope.id
        || source_manifest.classic_revision != ledger.scope.classic_revision
        || source_manifest.completeness != ledger.scope.completeness
    {
        return Err(MigrationError::SourceManifestScopeMismatch);
    }
    let manifest_files = source_manifest
        .files
        .iter()
        .map(|binding| (binding.path.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    for surface in &ledger.inventory {
        if manifest_files.get(surface.source.path.as_str()) != Some(&&surface.source) {
            return Err(MigrationError::InventorySourceNotManifested(
                surface.id.clone(),
            ));
        }
    }

    let mut replaced = 0;
    let mut retired = 0;
    let mut blocked = 0;
    for disposition in &ledger.dispositions {
        match disposition {
            SurfaceDispositionV1::Replaced { replacement, .. } => {
                let bytes = verify_bound_file(&root, &replacement.test_receipt)?;
                let document = parse_canonical_control(&bytes)?;
                let receipt: MigrationTestReceiptV1 = document.decode()?;
                if receipt.schema != TEST_RECEIPT_SCHEMA_V1
                    || receipt.covered_tests.is_empty()
                    || receipt.command.is_empty()
                {
                    return Err(MigrationError::InvalidTestReceipt);
                }
                replaced += 1;
            }
            SurfaceDispositionV1::Retired { retirement, .. } => {
                let bytes = verify_bound_file(&root, &retirement.hostile_absence_specimen)?;
                let document = parse_canonical_control(&bytes)?;
                let specimen: HostileAbsenceSpecimenV1 = document.decode()?;
                if specimen.schema != ABSENCE_SPECIMEN_SCHEMA_V1 {
                    return Err(MigrationError::InvalidAbsenceSpecimen);
                }
                retired += 1;
            }
            SurfaceDispositionV1::Blocked { .. } => blocked += 1,
        }
    }

    Ok(LedgerVerificationV1 {
        blocked,
        inventory: ledger.inventory.len(),
        replaced,
        retired,
        ledger_digest: Digest::hash_bytes(ledger_bytes),
    })
}

/// Verify every listed frozen classic file as bounded opaque bytes.
///
/// No file is interpreted, no database connection is opened, and no verified
/// bytes are returned to a runtime authority consumer.
///
/// # Errors
///
/// Returns an error for manifest drift, symlinks, non-regular/hard-linked files,
/// length or digest mismatch, path traversal, or fixed-limit exhaustion.
pub fn verify_archive(
    manifest_bytes: &[u8],
    archive_root: &Path,
) -> Result<ArchiveVerificationV1, MigrationError> {
    let manifest = parse_and_validate_archive_manifest(manifest_bytes)?;
    let root = open_root(archive_root)?;
    let mut total_bytes = 0_u64;
    for binding in &manifest.files {
        let bytes = verify_bound_file(&root, binding)?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| MigrationError::LengthOverflow)?)
            .ok_or(MigrationError::LengthOverflow)?;
    }
    Ok(ArchiveVerificationV1 {
        files: manifest.files.len(),
        manifest_digest: Digest::hash_bytes(manifest_bytes),
        total_bytes,
    })
}

/// Read one control document with same-descriptor, no-follow, fixed-size checks.
///
/// # Errors
///
/// Returns an error for a symlink, non-regular/hard-linked file, races, or size
/// limit exhaustion.
pub fn read_control_document(path: &Path) -> Result<Vec<u8>, MigrationError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    read_checked_fd(fd, MAX_CONTROL_DOCUMENT_BYTES, None)
}

fn validate_ledger(ledger: &MigrationLedgerV1) -> Result<(), MigrationError> {
    if ledger.schema != MIGRATION_LEDGER_SCHEMA_V1 {
        return Err(MigrationError::SchemaMismatch);
    }
    validate_revision(&ledger.scope.classic_revision)?;
    validate_id(&ledger.scope.id, "scope id")?;
    validate_binding(&ledger.scope.source_manifest, MAX_CONTROL_DOCUMENT_BYTES)?;
    if ledger.scope.classic_runtime_authority {
        return Err(MigrationError::ClassicRuntimeAuthorityClaim);
    }
    if ledger.inventory.is_empty() {
        return Err(MigrationError::EmptyInventory);
    }

    let mut inventory_ids = BTreeSet::new();
    for surface in &ledger.inventory {
        validate_id(&surface.id, "surface id")?;
        validate_text(&surface.symbol, "surface symbol")?;
        validate_binding(&surface.source, MAX_ARCHIVE_FILE_BYTES)?;
        if !inventory_ids.insert(surface.id.as_str()) {
            return Err(MigrationError::DuplicateInventoryId(surface.id.clone()));
        }
    }

    let mut disposition_ids = BTreeSet::new();
    for disposition in &ledger.dispositions {
        let surface_id = disposition.surface_id();
        validate_id(surface_id, "disposition surface id")?;
        if !disposition_ids.insert(surface_id) {
            return Err(MigrationError::DuplicateDispositionId(
                surface_id.to_owned(),
            ));
        }
        if !inventory_ids.contains(surface_id) {
            return Err(MigrationError::DispositionOutsideInventory(
                surface_id.to_owned(),
            ));
        }
        match disposition {
            SurfaceDispositionV1::Replaced { replacement, .. } => {
                validate_text(&replacement.ng_schema, "replacement schema")?;
                validate_binding(&replacement.test_receipt, MAX_CONTROL_DOCUMENT_BYTES)?;
            }
            SurfaceDispositionV1::Retired { retirement, .. } => {
                validate_text(&retirement.rationale, "retirement rationale")?;
                validate_binding(
                    &retirement.hostile_absence_specimen,
                    MAX_CONTROL_DOCUMENT_BYTES,
                )?;
            }
            SurfaceDispositionV1::Blocked { blocker, .. } => {
                validate_id(&blocker.code, "blocker code")?;
                validate_text(&blocker.exit_criterion, "blocker exit criterion")?;
            }
        }
    }
    if inventory_ids != disposition_ids {
        let missing = inventory_ids
            .difference(&disposition_ids)
            .next()
            .map_or_else(|| "unknown".to_owned(), |id| (*id).to_owned());
        return Err(MigrationError::MissingDisposition(missing));
    }
    Ok(())
}

fn parse_canonical_control(bytes: &[u8]) -> Result<JcsDocument, MigrationError> {
    // Repository control files may carry one POSIX text-file terminator. The
    // JSON payload before it must still be exact JCS; any other leading,
    // trailing, repeated, or CRLF whitespace is rejected.
    let payload = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    Ok(JcsDocument::from_canonical_bytes(payload)?)
}

fn validate_archive_manifest(manifest: &ArchiveManifestV1) -> Result<(), MigrationError> {
    if manifest.schema != ARCHIVE_MANIFEST_SCHEMA_V1 {
        return Err(MigrationError::SchemaMismatch);
    }
    validate_revision(&manifest.classic_revision)?;
    validate_id(&manifest.scope_id, "archive scope id")?;
    if manifest.files.is_empty() || manifest.files.len() > MAX_ARCHIVE_FILES {
        return Err(MigrationError::ArchiveFileCount);
    }
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    for binding in &manifest.files {
        validate_binding(binding, MAX_ARCHIVE_FILE_BYTES)?;
        if !paths.insert(binding.path.as_str()) {
            return Err(MigrationError::DuplicateArchivePath(binding.path.clone()));
        }
        total = total
            .checked_add(binding.length)
            .ok_or(MigrationError::LengthOverflow)?;
        if total > MAX_ARCHIVE_TOTAL_BYTES {
            return Err(MigrationError::ArchiveTotalTooLarge);
        }
    }
    Ok(())
}

fn validate_binding(binding: &FileBindingV1, maximum: u64) -> Result<(), MigrationError> {
    validate_relative_path(&binding.path)?;
    if binding.length > maximum {
        return Err(MigrationError::BoundFileTooLarge(binding.path.clone()));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), MigrationError> {
    if path.is_empty() || path.len() > 1024 || path.contains('\\') {
        return Err(MigrationError::UnsafeRelativePath(path.to_owned()));
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(MigrationError::UnsafeRelativePath(path.to_owned()));
    }
    Ok(())
}

fn validate_revision(revision: &str) -> Result<(), MigrationError> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MigrationError::InvalidClassicRevision);
    }
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), MigrationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ID_BYTES
        || bytes.first().is_some_and(|byte| !byte.is_ascii_lowercase())
        || bytes
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        || value.contains("..")
    {
        return Err(MigrationError::InvalidBoundedText(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), MigrationError> {
    if value.trim() != value || value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(MigrationError::InvalidBoundedText(field));
    }
    Ok(())
}

fn open_root(root: &Path) -> Result<OwnedFd, MigrationError> {
    let fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(MigrationError::ArchiveRootNotDirectory);
    }
    Ok(fd)
}

fn verify_bound_file(root: &OwnedFd, binding: &FileBindingV1) -> Result<Vec<u8>, MigrationError> {
    validate_binding(binding, MAX_ARCHIVE_FILE_BYTES)?;
    let fd = rustix::fs::openat2(
        root,
        binding.path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|source| MigrationError::OpenBoundFile {
        path: binding.path.clone(),
        source,
    })?;
    read_checked_fd(fd, binding.length, Some((&binding.path, &binding.digest)))
}

fn read_checked_fd(
    fd: OwnedFd,
    maximum: u64,
    expected: Option<(&str, &Digest)>,
) -> Result<Vec<u8>, MigrationError> {
    let before = rustix::fs::fstat(&fd)?;
    if !FileType::from_raw_mode(before.st_mode).is_file() || before.st_nlink != 1 {
        return Err(MigrationError::NotSinglyLinkedRegularFile);
    }
    let length = u64::try_from(before.st_size).map_err(|_| MigrationError::LengthOverflow)?;
    if length > maximum {
        return Err(MigrationError::BoundFileTooLarge(
            expected
                .map_or("control document", |(path, _)| path)
                .to_owned(),
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| MigrationError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(fd);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| MigrationError::LengthOverflow)? > maximum {
        return Err(MigrationError::BoundFileTooLarge(
            expected
                .map_or("control document", |(path, _)| path)
                .to_owned(),
        ));
    }
    let after = rustix::fs::fstat(&file)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(MigrationError::FileChangedDuringRead);
    }
    if let Some((path, digest)) = expected {
        if length != maximum {
            return Err(MigrationError::LengthMismatch(path.to_owned()));
        }
        if Digest::hash_bytes(&bytes) != *digest {
            return Err(MigrationError::DigestMismatch(path.to_owned()));
        }
    }
    Ok(bytes)
}

/// Migration ledger or frozen archive verification failure.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// Exact canonical JSON validation failed.
    #[error("canonical JSON validation failed: {0}")]
    CanonicalJson(#[from] JcsError),
    /// An operating-system file operation failed.
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// A Linux descriptor operation failed.
    #[error("descriptor operation failed: {0}")]
    Errno(#[from] rustix::io::Errno),
    /// A bound archive/evidence file could not be opened safely.
    #[error("could not safely open bound file {path}: {source}")]
    OpenBoundFile {
        /// Relative path from the explicit root.
        path: String,
        /// Linux open failure.
        #[source]
        source: rustix::io::Errno,
    },
    /// Input schema is not supported.
    #[error("schema mismatch")]
    SchemaMismatch,
    /// Canonical control input exceeds its fixed bound.
    #[error("control document exceeds fixed size bound")]
    ControlDocumentTooLarge,
    /// Classic revision is not exact lowercase 40-hex.
    #[error("classic revision is not exact lowercase 40-hex")]
    InvalidClassicRevision,
    /// A bounded identifier/text field is invalid.
    #[error("invalid bounded text in {0}")]
    InvalidBoundedText(&'static str),
    /// A relative path is empty, non-normal, absolute, or uses traversal.
    #[error("unsafe relative path {0:?}")]
    UnsafeRelativePath(String),
    /// Ledger attempts to import classic bytes as runtime authority.
    #[error("classic bytes may not be AG-ng runtime authority")]
    ClassicRuntimeAuthorityClaim,
    /// Ledger inventory is empty.
    #[error("migration inventory is empty")]
    EmptyInventory,
    /// An inventory ID occurs more than once.
    #[error("duplicate inventory id {0}")]
    DuplicateInventoryId(String),
    /// A disposition ID occurs more than once.
    #[error("duplicate disposition id {0}")]
    DuplicateDispositionId(String),
    /// A disposition references an ID outside inventory.
    #[error("disposition references non-inventoried surface {0}")]
    DispositionOutsideInventory(String),
    /// An inventoried surface has no exact disposition.
    #[error("missing disposition for inventoried surface {0}")]
    MissingDisposition(String),
    /// Archive manifest contains no files or too many files.
    #[error("archive manifest file count is outside fixed bounds")]
    ArchiveFileCount,
    /// Archive manifest repeats a path.
    #[error("duplicate archive path {0}")]
    DuplicateArchivePath(String),
    /// A bound file length exceeds its fixed limit.
    #[error("bound file exceeds limit: {0}")]
    BoundFileTooLarge(String),
    /// Archive manifest total exceeds its fixed limit.
    #[error("archive manifest exceeds aggregate byte bound")]
    ArchiveTotalTooLarge,
    /// Integer conversion/addition failed.
    #[error("file length arithmetic overflow")]
    LengthOverflow,
    /// Explicit root is not a directory.
    #[error("archive/evidence root is not a directory")]
    ArchiveRootNotDirectory,
    /// Opened bytes are not one regular, singly linked file.
    #[error("opened file is not a singly linked regular file")]
    NotSinglyLinkedRegularFile,
    /// File changed across same-descriptor verification.
    #[error("file changed during verification")]
    FileChangedDuringRead,
    /// Bound length differs from opened bytes.
    #[error("length mismatch for {0}")]
    LengthMismatch(String),
    /// Bound digest differs from opened bytes.
    #[error("digest mismatch for {0}")]
    DigestMismatch(String),
    /// Source manifest scope does not match ledger scope.
    #[error("source manifest does not match migration ledger scope")]
    SourceManifestScopeMismatch,
    /// Inventory source is absent or differs from the source manifest.
    #[error("inventory source is not exactly present in source manifest: {0}")]
    InventorySourceNotManifested(String),
    /// Replacement test receipt has an invalid schema/outcome.
    #[error("replacement test receipt is invalid")]
    InvalidTestReceipt,
    /// Retirement hostile specimen has an invalid schema/outcome.
    #[error("retirement hostile absence specimen is invalid")]
    InvalidAbsenceSpecimen,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use ag_primitives::JcsDocument;
    use tempfile::TempDir;

    use super::*;

    fn binding(path: &str, bytes: &[u8]) -> FileBindingV1 {
        FileBindingV1 {
            digest: Digest::hash_bytes(bytes),
            length: u64::try_from(bytes.len()).expect("fixture length"),
            path: path.to_owned(),
        }
    }

    fn fixture() -> (TempDir, Vec<u8>) {
        let root = TempDir::new().expect("tempdir");
        fs::create_dir(root.path().join("evidence")).expect("evidence directory");
        let source = b"classic source";
        fs::write(root.path().join("classic.py"), source).expect("classic fixture");
        let receipt = JcsDocument::canonicalize(&MigrationTestReceiptV1 {
            command: "cargo test -p ag-kernel --offline".to_owned(),
            covered_tests: vec!["refusal_is_lossless".to_owned()],
            result: TestResultV1::Passed,
            schema: TEST_RECEIPT_SCHEMA_V1.to_owned(),
        })
        .expect("receipt");
        fs::write(root.path().join("evidence/test.json"), receipt.as_bytes())
            .expect("receipt file");
        let specimen = JcsDocument::canonicalize(&HostileAbsenceSpecimenV1 {
            claim: HostileClaimV1::ClassicBytesAreRuntimeAuthority,
            expected: HostileExpectedV1::Refuse,
            schema: ABSENCE_SPECIMEN_SCHEMA_V1.to_owned(),
        })
        .expect("specimen");
        fs::write(
            root.path().join("evidence/absence.json"),
            specimen.as_bytes(),
        )
        .expect("specimen file");
        let manifest = ArchiveManifestV1 {
            authority_use: ArchiveAuthorityUseV1::ArchiveEvidenceOnly,
            classic_revision: "5d7089b1fd26510adddab808a7322e8ada4bf8bd".to_owned(),
            completeness: InventoryCompletenessV1::PartialAuthorityCritical,
            files: vec![binding("classic.py", source)],
            schema: ARCHIVE_MANIFEST_SCHEMA_V1.to_owned(),
            scope_id: "test.authority".to_owned(),
        };
        let manifest = JcsDocument::canonicalize(&manifest).expect("manifest");
        fs::write(
            root.path().join("evidence/source.json"),
            manifest.as_bytes(),
        )
        .expect("manifest file");
        let ledger = MigrationLedgerV1 {
            dispositions: vec![SurfaceDispositionV1::Replaced {
                replacement: ReplacementV1 {
                    ng_schema: "ag.effect/v1".to_owned(),
                    test_receipt: binding("evidence/test.json", receipt.as_bytes()),
                },
                surface_id: "classic.gate".to_owned(),
            }],
            inventory: vec![ClassicSurfaceV1 {
                id: "classic.gate".to_owned(),
                kind: ClassicSurfaceKindV1::AuthorityStore,
                source: binding("classic.py", source),
                symbol: "GateReceipt".to_owned(),
            }],
            schema: MIGRATION_LEDGER_SCHEMA_V1.to_owned(),
            scope: InventoryScopeV1 {
                classic_revision: "5d7089b1fd26510adddab808a7322e8ada4bf8bd".to_owned(),
                classic_runtime_authority: false,
                completeness: InventoryCompletenessV1::PartialAuthorityCritical,
                id: "test.authority".to_owned(),
                source_manifest: binding("evidence/source.json", manifest.as_bytes()),
            },
        };
        (
            root,
            JcsDocument::canonicalize(&ledger)
                .expect("ledger")
                .as_bytes()
                .to_vec(),
        )
    }

    #[test]
    fn exact_ledger_and_archive_verify_without_importing_authority() {
        let (root, ledger) = fixture();
        let result = verify_ledger(&ledger, root.path()).expect("ledger verifies");
        assert_eq!(result.inventory, 1);
        assert_eq!(result.replaced, 1);

        let manifest = fs::read(root.path().join("evidence/source.json")).expect("manifest");
        let result = verify_archive(&manifest, root.path()).expect("archive verifies");
        assert_eq!(result.files, 1);
        assert_eq!(result.total_bytes, 14);
    }

    #[test]
    fn missing_duplicate_and_outside_dispositions_fail_closed() {
        let (_, bytes) = fixture();
        let mut ledger = parse_and_validate_ledger(&bytes).expect("base ledger");
        ledger.dispositions.clear();
        let bytes = JcsDocument::canonicalize(&ledger).expect("missing");
        assert!(matches!(
            parse_and_validate_ledger(bytes.as_bytes()),
            Err(MigrationError::MissingDisposition(_))
        ));

        let (_, bytes) = fixture();
        let mut ledger = parse_and_validate_ledger(&bytes).expect("base ledger");
        ledger.dispositions.push(ledger.dispositions[0].clone());
        let bytes = JcsDocument::canonicalize(&ledger).expect("duplicate");
        assert!(matches!(
            parse_and_validate_ledger(bytes.as_bytes()),
            Err(MigrationError::DuplicateDispositionId(_))
        ));

        let (_, bytes) = fixture();
        let mut ledger = parse_and_validate_ledger(&bytes).expect("base ledger");
        let SurfaceDispositionV1::Replaced { surface_id, .. } = &mut ledger.dispositions[0] else {
            panic!("replacement fixture");
        };
        *surface_id = "classic.outside".to_owned();
        let bytes = JcsDocument::canonicalize(&ledger).expect("outside");
        assert!(matches!(
            parse_and_validate_ledger(bytes.as_bytes()),
            Err(MigrationError::DispositionOutsideInventory(_))
        ));
    }

    #[test]
    fn hostile_json_shapes_and_unknown_states_fail() {
        let (_, bytes) = fixture();
        let text = String::from_utf8(bytes).expect("utf8");
        let duplicate = text.replacen(
            "\"schema\":\"ag.migration-ledger/v1\"",
            "\"schema\":\"ag.migration-ledger/v1\",\"schema\":\"ag.migration-ledger/v1\"",
            1,
        );
        assert!(parse_and_validate_ledger(duplicate.as_bytes()).is_err());
        assert!(parse_and_validate_ledger(b"{\"float\":1.5}").is_err());
        assert!(parse_and_validate_ledger(b"{}{}").is_err());
        let unknown = text.replace(
            "\"schema\":\"ag.migration-ledger/v1\"",
            "\"mystery\":true,\"schema\":\"ag.migration-ledger/v1\"",
        );
        assert!(parse_and_validate_ledger(unknown.as_bytes()).is_err());
        let compatible = text.replace("\"status\":\"replaced\"", "\"status\":\"compatible\"");
        assert!(parse_and_validate_ledger(compatible.as_bytes()).is_err());
        let nested_unknown = text.replace(
            "\"status\":\"replaced\"",
            "\"smuggled\":true,\"status\":\"replaced\"",
        );
        assert!(parse_and_validate_ledger(nested_unknown.as_bytes()).is_err());
    }

    #[test]
    fn traversal_symlink_digest_drift_and_runtime_authority_fail() {
        let (root, bytes) = fixture();
        let mut ledger = parse_and_validate_ledger(&bytes).expect("base ledger");
        ledger.inventory[0].source.path = "../classic.py".to_owned();
        let hostile = JcsDocument::canonicalize(&ledger).expect("hostile ledger");
        assert!(matches!(
            parse_and_validate_ledger(hostile.as_bytes()),
            Err(MigrationError::UnsafeRelativePath(_))
        ));

        let mut ledger = parse_and_validate_ledger(&bytes).expect("base ledger");
        ledger.scope.classic_runtime_authority = true;
        let hostile = JcsDocument::canonicalize(&ledger).expect("authority claim");
        assert!(matches!(
            parse_and_validate_ledger(hostile.as_bytes()),
            Err(MigrationError::ClassicRuntimeAuthorityClaim)
        ));

        fs::write(root.path().join("evidence/test.json"), b"drift").expect("drift receipt");
        assert!(matches!(
            verify_ledger(&bytes, root.path()),
            Err(MigrationError::LengthMismatch(_) | MigrationError::DigestMismatch(_))
        ));

        let (root, bytes) = fixture();
        fs::remove_file(root.path().join("evidence/test.json")).expect("remove receipt");
        symlink(
            root.path().join("classic.py"),
            root.path().join("evidence/test.json"),
        )
        .expect("hostile symlink");
        assert!(verify_ledger(&bytes, root.path()).is_err());
    }

    #[test]
    fn manifest_rejects_duplicate_paths_and_runtime_authority_spelling() {
        let (root, _) = fixture();
        let bytes = fs::read(root.path().join("evidence/source.json")).expect("manifest");
        let mut manifest = parse_and_validate_archive_manifest(&bytes).expect("base manifest");
        manifest.files.push(manifest.files[0].clone());
        let bytes = JcsDocument::canonicalize(&manifest).expect("duplicate manifest");
        assert!(matches!(
            parse_and_validate_archive_manifest(bytes.as_bytes()),
            Err(MigrationError::DuplicateArchivePath(_))
        ));

        let hostile = String::from_utf8(
            JcsDocument::canonicalize(&manifest)
                .expect("manifest")
                .as_bytes()
                .to_vec(),
        )
        .expect("utf8")
        .replace("archive_evidence_only", "runtime_authority");
        assert!(parse_and_validate_archive_manifest(hostile.as_bytes()).is_err());
    }
}
