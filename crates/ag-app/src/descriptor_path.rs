//! Descriptor-rooted path opening compatible with service SUID/SGID confinement.
//!
//! `systemd` implements `RestrictSUIDSGID=yes` by returning `ENOSYS` from
//! `openat2(2)`: classic seccomp cannot inspect the pointed-to `open_how`
//! structure for creation modes.  The compatibility path below preserves the
//! required beneath/no-symlink semantics with one `openat(2)` per normalized
//! component, whose flags and mode remain inspectable by that filter.

use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// Open one normalized relative path beneath an already trusted descriptor.
///
/// The fast path uses `openat2(2)` with `RESOLVE_BENEATH`,
/// `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_SYMLINKS`.  Only `ENOSYS` selects
/// the compatibility path, which rejects every non-normal component, opens
/// each ancestor with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, and opens the final component
/// with the caller's flags plus `O_NOFOLLOW`.
///
/// # Errors
///
/// Returns the exact kernel error from the selected descriptor operation, or
/// `EINVAL` when `relative` is empty, absolute, or contains a non-normal
/// component.
pub fn open_beneath(
    parent: impl AsFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    validate_relative(relative)?;
    let flags = flags | OFlags::NOFOLLOW;
    let attempted = rustix::fs::openat2(
        &parent,
        relative,
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    );
    finish_open_beneath(parent, relative, flags, mode, attempted)
}

fn finish_open_beneath(
    parent: impl AsFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
    attempted: Result<OwnedFd, Errno>,
) -> Result<OwnedFd, Errno> {
    validate_relative(relative)?;
    match attempted {
        Err(Errno::NOSYS) => open_beneath_with_openat(parent, relative, flags, mode),
        result => result,
    }
}

fn open_beneath_with_openat(
    parent: impl AsFd,
    relative: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(Errno::INVAL),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (final_name, ancestors) = components.split_last().ok_or(Errno::INVAL)?;

    let parent = parent.as_fd();
    let mut current = None;
    for component in ancestors {
        let directory = current.as_ref().map_or(parent, AsFd::as_fd);
        current = Some(rustix::fs::openat(
            directory,
            *component,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
    }
    let directory = current.as_ref().map_or(parent, AsFd::as_fd);
    rustix::fs::openat(directory, *final_name, flags | OFlags::NOFOLLOW, mode)
}

fn validate_relative(relative: &Path) -> Result<(), Errno> {
    let raw = relative.as_os_str().as_bytes();
    if raw.is_empty()
        || raw
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(Errno::INVAL);
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Errno::INVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use tempfile::tempdir;

    use super::*;

    fn directory(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn component_fallback_opens_nested_files_and_creates_exact_mode() {
        let fixture = tempdir().unwrap();
        fs::create_dir(fixture.path().join("one")).unwrap();
        fs::create_dir(fixture.path().join("one/two")).unwrap();
        fs::write(fixture.path().join("one/two/value"), b"bound").unwrap();
        fs::set_permissions(
            fixture.path().join("one"),
            fs::Permissions::from_mode(0o111),
        )
        .unwrap();
        let root = directory(fixture.path());

        let opened = finish_open_beneath(
            &root,
            Path::new("one/two/value"),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            Err(Errno::NOSYS),
        )
        .unwrap();
        let mut bytes = Vec::new();
        fs::File::from(opened).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"bound");

        let created = finish_open_beneath(
            &root,
            Path::new("one/two/new"),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            Err(Errno::NOSYS),
        )
        .unwrap();
        let stat = rustix::fs::fstat(&created).unwrap();
        assert_eq!(stat.st_mode & 0o7777, 0o600);
        assert_eq!(
            fs::metadata(fixture.path().join("one/two/new"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        fs::set_permissions(
            fixture.path().join("one"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn component_fallback_refuses_symlinks_and_non_normal_paths() {
        let fixture = tempdir().unwrap();
        fs::create_dir(fixture.path().join("safe")).unwrap();
        fs::write(fixture.path().join("safe/value"), b"bound").unwrap();
        symlink("safe", fixture.path().join("redirect")).unwrap();
        symlink("value", fixture.path().join("safe/link")).unwrap();
        let root = directory(fixture.path());
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;

        let intermediate_symlink = finish_open_beneath(
            &root,
            Path::new("redirect/value"),
            flags,
            Mode::empty(),
            Err(Errno::NOSYS),
        )
        .unwrap_err();
        assert!(matches!(intermediate_symlink, Errno::LOOP | Errno::NOTDIR));
        assert_eq!(
            finish_open_beneath(
                &root,
                Path::new("safe/link"),
                flags,
                Mode::empty(),
                Err(Errno::NOSYS),
            )
            .unwrap_err(),
            Errno::LOOP
        );
        for hostile in [
            "",
            "/safe/value",
            "safe/../safe/value",
            "./safe/value",
            "safe//value",
            "safe/value/",
        ] {
            assert_eq!(
                finish_open_beneath(
                    &root,
                    Path::new(hostile),
                    flags,
                    Mode::empty(),
                    Err(Errno::NOSYS),
                )
                .unwrap_err(),
                Errno::INVAL
            );
            assert_eq!(
                open_beneath(&root, Path::new(hostile), flags, Mode::empty()).unwrap_err(),
                Errno::INVAL
            );
        }

        assert_eq!(
            finish_open_beneath(
                &root,
                Path::new("safe/value"),
                flags,
                Mode::empty(),
                Err(Errno::PERM),
            )
            .unwrap_err(),
            Errno::PERM
        );

        let metadata = fs::symlink_metadata(fixture.path().join("redirect")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_ne!(metadata.ino(), 0);
    }
}
