//! Fail-closed filesystem custody checks used during daemon startup.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::config::FilesystemNodeCustodyV1;

/// Filesystem node family expected by one custody check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CustodyNodeKindV1 {
    /// Directory.
    Directory,
    /// Unlinked regular file.
    RegularFile,
    /// Filesystem Unix socket.
    UnixSocket,
}

/// Fail-closed filesystem custody failure.
#[derive(Debug, Error)]
pub enum CustodyError {
    /// The configured path is not absolute and normalized.
    #[error("filesystem custody path is not absolute and normalized: {0}")]
    UnsafePath(PathBuf),
    /// An ancestor is absent, is a symlink, or is not a directory.
    #[error("filesystem custody ancestor is unsafe: {0}")]
    UnsafeAncestor(PathBuf),
    /// A final node has the wrong type, link count, owner, group, or mode.
    #[error("filesystem node does not match configured custody: {0}")]
    CustodyMismatch(PathBuf),
    /// Filesystem operation failed.
    #[error("filesystem custody I/O failed for {path}: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying failure.
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> CustodyError {
    CustodyError::Io {
        path: path.to_owned(),
        source,
    }
}

fn validate_absolute_normalized(path: &Path) -> Result<(), CustodyError> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute()
        || normalized != path
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(CustodyError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

/// Validate that every existing component through `path` is reached without
/// traversing a symlink. Intermediate components must all be directories.
pub(crate) fn validate_no_symlink_chain(path: &Path) -> Result<(), CustodyError> {
    validate_absolute_normalized(path)?;
    let mut current = PathBuf::from("/");
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => return Err(CustodyError::UnsafePath(path.to_owned())),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
        let is_final = index + 1 == components.len();
        if metadata.file_type().is_symlink() || (!is_final && !metadata.file_type().is_dir()) {
            return Err(CustodyError::UnsafeAncestor(current));
        }
    }
    Ok(())
}

fn metadata_matches(
    metadata: &Metadata,
    policy: &FilesystemNodeCustodyV1,
    kind: CustodyNodeKindV1,
) -> bool {
    let type_matches = match kind {
        CustodyNodeKindV1::Directory => metadata.file_type().is_dir(),
        CustodyNodeKindV1::RegularFile => metadata.file_type().is_file() && metadata.nlink() == 1,
        CustodyNodeKindV1::UnixSocket => metadata.file_type().is_socket() && metadata.nlink() == 1,
    };
    type_matches
        && metadata.uid() == policy.uid
        && metadata.gid() == policy.gid
        && metadata.mode() & 0o7777 == policy.mode
}

/// Validate one node and its complete no-symlink ancestor chain.
pub(crate) fn validate_node(
    path: &Path,
    policy: &FilesystemNodeCustodyV1,
    kind: CustodyNodeKindV1,
) -> Result<(), CustodyError> {
    validate_no_symlink_chain(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata_matches(&metadata, policy, kind) {
        Ok(())
    } else {
        Err(CustodyError::CustodyMismatch(path.to_owned()))
    }
}

/// Open or create one regular file without following its final component.
///
/// A new file is initially created owner-only and then changed to the exact
/// configured mode through its descriptor. Existing metadata drift is never
/// repaired implicitly; startup fails instead.
pub(crate) fn prepare_regular_file(
    path: &Path,
    policy: &FilesystemNodeCustodyV1,
) -> Result<File, CustodyError> {
    let parent = path
        .parent()
        .ok_or_else(|| CustodyError::UnsafePath(path.to_owned()))?;
    validate_no_symlink_chain(parent)?;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let (file, created) = match options.open(path) {
        Ok(file) => (file, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut create = OpenOptions::new();
            let file = create
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|source| io_error(path, source))?;
            (file, true)
        }
        Err(source) => return Err(io_error(path, source)),
    };

    if created {
        file.set_permissions(fs::Permissions::from_mode(policy.mode))
            .map_err(|source| io_error(path, source))?;
    }
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata_matches(&metadata, policy, CustodyNodeKindV1::RegularFile) {
        return Err(CustodyError::CustodyMismatch(path.to_owned()));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;

    fn current_policy(mode: u32) -> FilesystemNodeCustodyV1 {
        let metadata = fs::metadata(".").expect("working-directory metadata");
        FilesystemNodeCustodyV1 {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
        }
    }

    #[test]
    fn rejects_a_symlink_anywhere_in_the_chain() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let real = temporary.path().join("real");
        fs::create_dir(&real).expect("real directory");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let link = temporary.path().join("link");
        symlink(&real, &link).expect("directory symlink");

        let result = validate_node(&link, &current_policy(0o700), CustodyNodeKindV1::Directory);
        assert!(matches!(result, Err(CustodyError::UnsafeAncestor(_))));
    }

    #[test]
    fn new_regular_file_receives_exact_configured_mode() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("state.db");
        let policy = current_policy(0o640);
        let file = prepare_regular_file(&path, &policy).expect("prepare file");
        assert_eq!(file.metadata().expect("metadata").mode() & 0o7777, 0o640);
    }

    #[test]
    fn exact_owner_group_and_normalized_path_are_mandatory() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let metadata = fs::metadata(temporary.path()).expect("directory metadata");
        let wrong_owner = FilesystemNodeCustodyV1 {
            uid: metadata.uid().saturating_add(1),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        };
        assert!(matches!(
            validate_node(temporary.path(), &wrong_owner, CustodyNodeKindV1::Directory),
            Err(CustodyError::CustodyMismatch(_))
        ));

        let non_normalized = temporary.path().join("missing").join("..");
        assert!(matches!(
            validate_no_symlink_chain(&non_normalized),
            Err(CustodyError::UnsafePath(_))
        ));
    }
}
