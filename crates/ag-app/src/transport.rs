//! Safe filesystem Unix-socket binding shared by signed local RPC servers.

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::config::SocketCustodyConfigV1;
use crate::custody::{CustodyError, CustodyNodeKindV1, validate_node};

/// Local transport failures.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Socket path is unsafe to replace.
    #[error("refusing unsafe socket path: {0}")]
    UnsafeSocket(PathBuf),
    /// Explicit filesystem custody check failed.
    #[error(transparent)]
    Custody(#[from] CustodyError),
    /// I/O failure.
    #[error("local transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Binds a filesystem Unix socket under a pre-created, explicitly enrolled
/// parent, replacing only an existing socket with matching custody.
///
/// # Errors
///
/// Returns an error for a relative path, a symlink in the ancestor chain,
/// parent/node ownership or mode drift, an occupied non-socket path, socket
/// creation failure, or inability to install and verify the exact final mode.
pub fn bind_socket(
    path: &Path,
    custody: &SocketCustodyConfigV1,
) -> Result<UnixListener, TransportError> {
    if !path.is_absolute() {
        return Err(TransportError::UnsafeSocket(path.to_owned()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| TransportError::UnsafeSocket(path.to_owned()))?;
    validate_node(parent, &custody.parent, CustodyNodeKindV1::Directory)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            validate_node(path, &custody.node, CustodyNodeKindV1::UnixSocket)?;
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(TransportError::UnsafeSocket(path.to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    let validate_final = || -> Result<(), TransportError> {
        fs::set_permissions(path, fs::Permissions::from_mode(custody.node.mode))?;
        validate_node(parent, &custody.parent, CustodyNodeKindV1::Directory)?;
        validate_node(path, &custody.node, CustodyNodeKindV1::UnixSocket)?;
        Ok(())
    };
    if let Err(error) = validate_final() {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;
    use crate::config::FilesystemNodeCustodyV1;

    fn custody(parent: &Path) -> SocketCustodyConfigV1 {
        let metadata = fs::metadata(parent).expect("parent metadata");
        SocketCustodyConfigV1 {
            parent: FilesystemNodeCustodyV1 {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
            },
            node: FilesystemNodeCustodyV1 {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o660,
            },
        }
    }

    #[test]
    fn bind_verifies_final_socket_custody() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = temporary.path().join("socket-parent");
        fs::create_dir(&parent).expect("socket parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2700))
            .expect("setgid parent mode");
        let policy = custody(&parent);
        let socket = parent.join("control.sock");

        let listener = match bind_socket(&socket, &policy) {
            Ok(listener) => listener,
            // Some managed test sandboxes deny all filesystem AF_UNIX binds.
            // Outside that environment the assertions below exercise the
            // complete bind-and-revalidate path.
            Err(TransportError::Io(error)) if error.raw_os_error() == Some(libc::EPERM) => return,
            Err(error) => panic!("bind socket: {error}"),
        };
        let metadata = fs::symlink_metadata(&socket).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), policy.node.uid);
        assert_eq!(metadata.gid(), policy.node.gid);
        assert_eq!(metadata.mode() & 0o7777, policy.node.mode);
        drop(listener);
    }

    #[test]
    fn bind_rejects_symlinked_parent_and_mode_drift() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = temporary.path().join("socket-parent");
        fs::create_dir(&parent).expect("socket parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2700))
            .expect("setgid parent mode");
        let policy = custody(&parent);

        let link = temporary.path().join("socket-link");
        symlink(&parent, &link).expect("parent symlink");
        assert!(bind_socket(&link.join("control.sock"), &policy).is_err());

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2750))
            .expect("drift parent mode");
        assert!(bind_socket(&parent.join("control.sock"), &policy).is_err());
    }
}
