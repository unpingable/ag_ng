//! Narrow Linux child-launch primitive for exact descriptor inheritance.
//!
//! `std::process::Command` deliberately exposes its post-fork hook as unsafe:
//! after `fork` in a multithreaded process, only async-signal-safe operations
//! may run before `execve`. Keep that obligation confined to this module.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use rustix::fs::{FileType, Mode, OFlags};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ABI_V1_MUTATION_RIGHTS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Return the active kernel's Landlock ABI version.
pub(crate) fn landlock_abi_version() -> io::Result<u32> {
    // SAFETY: the version query passes a null attribute pointer and zero size,
    // exactly as required by landlock_create_ruleset(2).
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| io::Error::other("Landlock ABI version exceeds u32"))
    }
}

/// Install a child-local close-on-exec floor and admit only the named FDs.
///
/// The parent descriptors remain `CLOEXEC` throughout. In the post-fork child,
/// `close_range(CLOEXEC)` atomically marks every descriptor at or above three,
/// then `fcntl(F_SETFD)` clears that flag only for the reviewed allowlist. This
/// prevents both cross-thread descriptor leakage and admission into an
/// unrelated concurrent exec.
#[allow(clippy::too_many_lines)]
pub(crate) fn configure_exact_inherited_fds(
    command: &mut Command,
    inherited: &[RawFd],
    writable_roots: &[RawFd],
    minimum_landlock_abi: u32,
) -> io::Result<()> {
    if !(1..=3).contains(&minimum_landlock_abi) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "minimum Landlock ABI is outside the implemented contract",
        ));
    }
    let exact = inherited.iter().copied().collect::<BTreeSet<_>>();
    if exact.len() != inherited.len() || exact.iter().any(|descriptor| *descriptor < 3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exact inherited descriptor set is aliased or overlaps stdio",
        ));
    }
    let exact = exact.into_iter().collect::<Vec<_>>();
    let write_roots = writable_roots.iter().copied().collect::<BTreeSet<_>>();
    if write_roots.len() != writable_roots.len()
        || write_roots.iter().any(|descriptor| *descriptor < 3)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Landlock writable-root descriptor set is aliased or overlaps stdio",
        ));
    }
    let write_roots = write_roots.into_iter().collect::<Vec<_>>();
    let close_range_flags = libc::c_int::try_from(libc::CLOSE_RANGE_CLOEXEC)
        .map_err(|_| io::Error::other("close-range flag exceeds c_int"))?;
    let null_device = rustix::fs::open(
        "/dev/null",
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let null_stat = rustix::fs::fstat(&null_device).map_err(io::Error::from)?;
    if !FileType::from_raw_mode(null_stat.st_mode).is_char_device()
        || rustix::fs::major(null_stat.st_rdev) != 1
        || rustix::fs::minor(null_stat.st_rdev) != 3
        || null_stat.st_uid != 0
        || null_stat.st_gid != 0
        || null_stat.st_nlink != 1
        || null_stat.st_mode & 0o7777 != 0o666
    {
        return Err(io::Error::other(
            "exact root-owned /dev/null custody is unavailable",
        ));
    }
    // SAFETY: the closure performs only Linux async-signal-safe syscalls and
    // reads its already-allocated immutable Vec. It allocates nothing, takes
    // no locks, and touches no shared Rust state in the post-fork child.
    unsafe {
        command.pre_exec(move || {
            if libc::close_range(3, u32::MAX, close_range_flags) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let abi = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<LandlockRulesetAttr>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            );
            if abi < libc::c_long::from(minimum_landlock_abi) {
                return Err(if abi < 0 {
                    io::Error::last_os_error()
                } else {
                    io::Error::from_raw_os_error(libc::EOPNOTSUPP)
                });
            }
            let handled_access = LANDLOCK_ABI_V1_MUTATION_RIGHTS
                | if abi >= 2 {
                    LANDLOCK_ACCESS_FS_REFER
                } else {
                    0
                }
                | if abi >= 3 {
                    LANDLOCK_ACCESS_FS_TRUNCATE
                } else {
                    0
                };
            let ruleset_attr = LandlockRulesetAttr {
                handled_access_fs: handled_access,
            };
            let ruleset = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const ruleset_attr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            );
            if ruleset < 0 {
                return Err(io::Error::last_os_error());
            }
            let ruleset = i32::try_from(ruleset)
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            let null_path = LandlockPathBeneathAttr {
                allowed_access: LANDLOCK_ACCESS_FS_WRITE_FILE,
                parent_fd: null_device.as_raw_fd(),
            };
            if libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &raw const null_path,
                0,
            ) != 0
            {
                let error = io::Error::last_os_error();
                let _ = libc::close(ruleset);
                return Err(error);
            }
            for root in &write_roots {
                let path = LandlockPathBeneathAttr {
                    allowed_access: handled_access,
                    parent_fd: *root,
                };
                if libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &raw const path,
                    0,
                ) != 0
                {
                    let error = io::Error::last_os_error();
                    let _ = libc::close(ruleset);
                    return Err(error);
                }
            }
            if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) != 0 {
                let error = io::Error::last_os_error();
                let _ = libc::close(ruleset);
                return Err(error);
            }
            if libc::close(ruleset) != 0 {
                return Err(io::Error::last_os_error());
            }
            for descriptor in &exact {
                if libc::fcntl(*descriptor, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Stdio};

    use super::*;

    fn run_test_expression(arguments: &[String], inherited: RawFd) -> bool {
        let mut command = Command::new("/usr/bin/test");
        command
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_exact_inherited_fds(&mut command, &[inherited], &[], 3).expect("exact child FDs");
        command.status().expect("fixed test executable").success()
    }

    #[test]
    fn child_inherits_only_admitted_fd_without_mutating_parent_flags() {
        let source = File::open("/dev/null").expect("source FD");
        let admitted = rustix::io::fcntl_dupfd_cloexec(&source, 190).expect("admitted high FD");
        let sentinel = rustix::io::fcntl_dupfd_cloexec(&source, 200).expect("sentinel high FD");
        let admitted_fd = admitted.as_raw_fd();
        let sentinel_fd = sentinel.as_raw_fd();
        assert!(
            rustix::io::fcntl_getfd(&admitted)
                .expect("admitted parent flags")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(run_test_expression(
            &["-e".to_owned(), format!("/proc/self/fd/{admitted_fd}")],
            admitted_fd,
        ));
        assert!(run_test_expression(
            &[
                "!".to_owned(),
                "-e".to_owned(),
                format!("/proc/self/fd/{sentinel_fd}"),
            ],
            admitted_fd,
        ));
        assert!(
            rustix::io::fcntl_getfd(&admitted)
                .expect("admitted parent flags after spawn")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::io::fcntl_getfd(&sentinel)
                .expect("sentinel parent flags after spawn")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn child_mutation_is_confined_to_the_admitted_descriptor_root() {
        let temporary = tempfile::tempdir().expect("temporary Landlock fixture");
        let admitted_path = temporary.path().join("admitted");
        let forbidden_path = temporary.path().join("forbidden");
        fs::create_dir(&admitted_path).expect("admitted directory");
        fs::create_dir(&forbidden_path).expect("forbidden directory");
        let admitted = File::open(&admitted_path).expect("admitted root FD");

        let run_touch = |path: &std::path::Path| {
            let mut command = Command::new("/usr/bin/touch");
            command
                .arg(path)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            configure_exact_inherited_fds(&mut command, &[], &[admitted.as_raw_fd()], 3)
                .expect("descriptor-rooted child confinement");
            command.status().expect("fixed touch executable")
        };

        let admitted_file = admitted_path.join("created");
        assert!(run_touch(&admitted_file).success());
        assert!(admitted_file.is_file());

        let forbidden_file = forbidden_path.join("escaped");
        assert!(!run_touch(&forbidden_file).success());
        assert!(!forbidden_file.exists());

        let redirected_root = admitted_path.join("redirected");
        symlink(&forbidden_path, &redirected_root).expect("hostile redirect symlink");
        let redirected_file = redirected_root.join("via-symlink");
        assert!(!run_touch(&redirected_file).success());
        assert!(!forbidden_path.join("via-symlink").exists());
    }
}
