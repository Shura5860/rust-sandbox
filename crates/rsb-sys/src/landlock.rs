//! Direct Linux Landlock LSM syscall wrappers (ABI v1 through v6).
//!
//! Landlock provides unprivileged, stackable filesystem (and network in v4+)
//! access control directly in the kernel without root or complex bind-mount trees.

use crate::{RawErrno, syscall2, syscall3, syscall4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// Landlock syscall numbers are identical on x86_64, aarch64, and riscv64.
const SYS_LANDLOCK_CREATE_RULESET: usize = 444;
const SYS_LANDLOCK_ADD_RULE: usize = 445;
const SYS_LANDLOCK_RESTRICT_SELF: usize = 446;

/// Flag to probe the highest supported Landlock ABI version.
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// Rule type for filesystem path-beneath rules.
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
/// Rule type for TCP port network rules (ABI v4+).
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

/// Landlock TCP network access rights (ABI v4+).
pub mod access_net {
    pub const BIND_TCP: u64 = 1 << 0;
    pub const CONNECT_TCP: u64 = 1 << 1;

    /// All network access flags supported by `abi` (0 for ABI < 4).
    pub const fn handled_for_abi(abi: u32) -> u64 {
        if abi >= 4 {
            BIND_TCP | CONNECT_TCP
        } else {
            0
        }
    }
}

/// Landlock IPC scope flags (ABI v6+).
pub mod scope {
    pub const ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    pub const SIGNAL: u64 = 1 << 1;

    /// All IPC scope flags supported by `abi` (0 for ABI < 6).
    pub const fn handled_for_abi(abi: u32) -> u64 {
        if abi >= 6 {
            ABSTRACT_UNIX_SOCKET | SIGNAL
        } else {
            0
        }
    }
}

/// Landlock filesystem access rights (bitflags).
pub mod access_fs {
    // ABI v1
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;

    // ABI v2
    pub const REFER: u64 = 1 << 13;

    // ABI v3
    pub const TRUNCATE: u64 = 1 << 14;

    // ABI v5
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// All filesystem access flags supported by a given Landlock ABI version.
    pub const fn handled_for_abi(abi: u32) -> u64 {
        let mut mask = EXECUTE
            | WRITE_FILE
            | READ_FILE
            | READ_DIR
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        if abi >= 2 {
            mask |= REFER;
        }
        if abi >= 3 {
            mask |= TRUNCATE;
        }
        if abi >= 5 {
            mask |= IOCTL_DEV;
        }
        mask
    }

    /// Read-only + execute access (suitable for `/usr`, `/lib`, `/bin`, `/etc`).
    pub const fn read_exec_for_abi(_abi: u32) -> u64 {
        EXECUTE | READ_FILE | READ_DIR
    }

    /// Read-only (no execute) access.
    pub const fn read_only_for_abi(_abi: u32) -> u64 {
        READ_FILE | READ_DIR
    }

    /// Full read-write access (without device creation) for a workspace/tmp directory.
    pub const fn read_write_for_abi(abi: u32) -> u64 {
        let mut mask = EXECUTE
            | WRITE_FILE
            | READ_FILE
            | READ_DIR
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_SYM;
        if abi >= 2 {
            mask |= REFER;
        }
        if abi >= 3 {
            mask |= TRUNCATE;
        }
        mask
    }

    /// Access rights valid on a regular file (directory-only bits must be stripped
    /// or `landlock_add_rule` returns `EINVAL`).
    pub const fn file_only_mask(abi: u32) -> u64 {
        let mut mask = EXECUTE | WRITE_FILE | READ_FILE;
        if abi >= 3 {
            mask |= TRUNCATE;
        }
        if abi >= 5 {
            mask |= IOCTL_DEV;
        }
        mask
    }
}

/// Kernel `struct landlock_ruleset_attr` (ABI v1–v6+).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// Kernel `struct landlock_path_beneath_attr`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Kernel `struct landlock_net_port_attr` (ABI v4+).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

/// Probe the running kernel's highest supported Landlock ABI version.
///
/// Returns `Ok(abi_version)` (e.g. `1..=6`), or `Err(RawErrno)` if Landlock is
/// unsupported (`ENOSYS`) or disabled (`EOPNOTSUPP`).
pub fn abi_version() -> Result<u32, RawErrno> {
    let ret = unsafe {
        syscall3(
            SYS_LANDLOCK_CREATE_RULESET,
            0,
            0,
            LANDLOCK_CREATE_RULESET_VERSION as usize,
        )
    };
    RawErrno::from_raw_ret(ret).map(|v| v as u32)
}

/// Create a Landlock ruleset FD for the specified `handled_access_fs` mask.
pub fn create_ruleset(handled_access_fs: u64) -> Result<OwnedFd, RawErrno> {
    create_ruleset_ex(handled_access_fs, 0, 0)
}

/// Create a Landlock ruleset FD supporting FS (v1+), TCP network (v4+), and IPC scope (v6+).
///
/// Passes the minimal kernel struct size (`8`, `16`, or `24` bytes) required by the
/// non-zero masks so older kernels (ABI v1–v5) accept the call cleanly.
pub fn create_ruleset_ex(
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
) -> Result<OwnedFd, RawErrno> {
    let attr = RulesetAttr {
        handled_access_fs,
        handled_access_net,
        scoped,
    };
    let size = if scoped != 0 {
        24usize
    } else if handled_access_net != 0 {
        16usize
    } else {
        8usize
    };
    let ret = unsafe {
        syscall3(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr as usize,
            size,
            0,
        )
    };
    let fd = RawErrno::from_raw_ret(ret)? as RawFd;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Add a `LANDLOCK_RULE_NET_PORT` rule (ABI v4+) to an open ruleset FD.
pub fn add_net_port_rule(
    ruleset: &OwnedFd,
    port: u16,
    allowed_access: u64,
) -> Result<(), RawErrno> {
    let attr = NetPortAttr {
        allowed_access,
        port: port as u64,
    };
    let ret = unsafe {
        syscall4(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd() as usize,
            LANDLOCK_RULE_NET_PORT as usize,
            &attr as *const NetPortAttr as usize,
            0,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Add a `LANDLOCK_RULE_PATH_BENEATH` rule to an open ruleset FD.
pub fn add_path_beneath_rule(
    ruleset: &OwnedFd,
    parent_fd: RawFd,
    allowed_access: u64,
) -> Result<(), RawErrno> {
    let attr = PathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    let ret = unsafe {
        syscall4(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd() as usize,
            LANDLOCK_RULE_PATH_BENEATH as usize,
            &attr as *const PathBeneathAttr as usize,
            0,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Enforce the ruleset on the current thread (and all future children).
///
/// Caller must have already enabled `PR_SET_NO_NEW_PRIVS` (or hold `CAP_SYS_ADMIN`).
pub fn restrict_self(ruleset: &OwnedFd) -> Result<(), RawErrno> {
    let ret = unsafe { syscall2(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd() as usize, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}
