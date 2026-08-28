//! Startup custody checks: the daemon fails closed on custody violations.
//!
//! Ownership checks are euid-only; foreign-owned nodes cannot be constructed
//! by an unprivileged test, so those arms are exercised by code inspection
//! against the reviewer pattern, not here.

mod common;

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use ag_external_authz::daemon::{
    DaemonErrorV1, bind_socket, validate_standing_store, validate_state_dir,
};
use common::fixture;

#[test]
fn a_symlink_socket_path_is_refused() {
    let fixture = fixture();
    let real = fixture.directory.path().join("real.sock");
    let link = fixture.directory.path().join("link.sock");
    std::fs::write(&real, b"").unwrap();
    symlink(&real, &link).unwrap();

    let error = bind_socket(&link).unwrap_err();

    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
    assert!(!link.exists() || link.symlink_metadata().unwrap().file_type().is_symlink());
}

#[test]
fn an_occupied_non_socket_path_is_refused() {
    let fixture = fixture();
    let path = fixture.directory.path().join("occupied");
    std::fs::write(&path, b"regular file").unwrap();

    let error = bind_socket(&path).unwrap_err();

    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"regular file");
}

#[test]
fn a_relative_socket_path_is_refused() {
    let error = bind_socket(Path::new("relative.sock")).unwrap_err();
    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
}

#[test]
fn bind_socket_creates_a_mode_0600_socket_and_replaces_a_stale_one() {
    let fixture = fixture();
    let path = fixture.directory.path().join("daemon.sock");

    let first = bind_socket(&path).unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    drop(first);

    // A stale socket from a previous run is replaced.
    let _second = bind_socket(&path).unwrap();
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[test]
fn a_state_dir_with_wrong_mode_is_refused() {
    let fixture = fixture();
    let path = fixture.directory.path().join("permissive-state");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let error = validate_state_dir(&path).unwrap_err();

    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
}

#[test]
fn a_missing_state_dir_is_refused() {
    let fixture = fixture();
    let path = fixture.directory.path().join("absent");
    assert!(validate_state_dir(&path).is_err());
}

#[test]
fn a_symlink_state_dir_is_refused() {
    let fixture = fixture();
    let link = fixture.directory.path().join("state-link");
    symlink(&fixture.state_dir, &link).unwrap();

    let error = validate_state_dir(&link).unwrap_err();

    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
}

#[test]
fn a_well_formed_state_dir_is_accepted() {
    let fixture = fixture();
    validate_state_dir(&fixture.state_dir).unwrap();
}

#[test]
fn a_symlink_standing_store_is_refused() {
    let fixture = fixture();
    let real = fixture.directory.path().join("standing-real.json");
    std::fs::write(&real, b"{}").unwrap();
    let link = fixture.directory.path().join("standing-link.json");
    symlink(&real, &link).unwrap();

    let error = validate_standing_store(&link).unwrap_err();

    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
}

#[test]
fn a_directory_as_standing_store_is_refused() {
    let fixture = fixture();
    let error = validate_standing_store(&fixture.state_dir).unwrap_err();
    assert!(matches!(error, DaemonErrorV1::Custody(_)), "{error}");
}

#[test]
fn a_regular_euid_owned_standing_store_is_accepted() {
    let fixture = fixture();
    std::fs::write(&fixture.standing_store, b"{}").unwrap();
    validate_standing_store(&fixture.standing_store).unwrap();
}
