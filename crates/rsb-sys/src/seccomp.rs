//! Low-level `prctl`, `seccomp(2)`, `close_range(2)`, `capset(2)`, and `setrlimit(2)` primitives.
//!
//! All functions in this module are strictly async-signal-safe (zero heap allocation,
//! zero locks) for safe execution inside a post-`clone3` child before `execve`.

use crate::{RawErrno, syscall2, syscall3, syscall5};

#[cfg(target_arch = "x86_64")]
const SYS_PRCTL: usize = 157;
#[cfg(target_arch = "aarch64")]
const SYS_PRCTL: usize = 167;

#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: usize = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: usize = 277;

#[cfg(target_arch = "x86_64")]
const SYS_CAPSET: usize = 126;
#[cfg(target_arch = "aarch64")]
const SYS_CAPSET: usize = 91;

#[cfg(target_arch = "x86_64")]
const SYS_SETRLIMIT: usize = 160;
#[cfg(target_arch = "aarch64")]
const SYS_PRLIMIT64: usize = 261;

/// `SYS_close_range` is 436 on all modern Linux architectures (Linux 5.9+).
const SYS_CLOSE_RANGE: usize = 436;

const PR_SET_PDEATHSIG: usize = 1;
const PR_SET_DUMPABLE: usize = 4;
const PR_CAPBSET_DROP: usize = 24;
const PR_SET_NO_NEW_PRIVS: usize = 38;

/// Mark all FDs in `[first, last]` as `O_CLOEXEC` atomically.
pub const CLOSE_RANGE_CLOEXEC: usize = 1 << 2;

pub const SECCOMP_SET_MODE_FILTER: usize = 1;
pub const SECCOMP_FILTER_FLAG_TSYNC: usize = 1 << 0;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: usize = 1 << 3;

/// Standard Linux `rlimit` resource IDs.
pub mod rlimit {
    pub const RLIMIT_FSIZE: usize = 1;
    pub const RLIMIT_CORE: usize = 4;
    pub const RLIMIT_NPROC: usize = 6;
    pub const RLIMIT_NOFILE: usize = 7;
}

/// Kernel `struct rlimit64`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// Kernel `struct sock_filter` (single classic BPF instruction).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Kernel `struct sock_fprog` (BPF program descriptor).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Set `PR_SET_NO_NEW_PRIVS` on the calling thread.
///
/// Async-signal-safe; required before unprivileged `landlock_restrict_self` or
/// `seccomp(SECCOMP_SET_MODE_FILTER)`.
pub fn set_no_new_privs() -> Result<(), RawErrno> {
    let ret = unsafe { syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Set `PR_SET_DUMPABLE = 0` (`SUID_DUMP_DISABLE`) on the calling process.
///
/// Blocks same-UID `ptrace` attachment and core dumps during pre-`execve` setup.
pub fn set_non_dumpable() -> Result<(), RawErrno> {
    let ret = unsafe { syscall5(SYS_PRCTL, PR_SET_DUMPABLE, 0, 0, 0, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Request `signal` (typically `SIGKILL = 9`) if the parent process dies unexpectedly.
///
/// Caller MUST check `getppid() != expected_parent_pid` immediately after calling
/// this to close the classic fork/exit race window.
pub fn set_pdeathsig(signal: i32) -> Result<(), RawErrno> {
    let ret = unsafe { syscall5(SYS_PRCTL, PR_SET_PDEATHSIG, signal as usize, 0, 0, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Mark all open file descriptors in `[first, last]` as `O_CLOEXEC` via `close_range(2)`.
///
/// Prevents any leaked host file descriptors (e.g. non-CLOEXEC FDs from third-party
/// libraries in a host process) from surviving across `execve` into the sandbox.
pub fn close_range_cloexec(first: u32, last: u32) -> Result<(), RawErrno> {
    let ret = unsafe {
        syscall3(
            SYS_CLOSE_RANGE,
            first as usize,
            last as usize,
            CLOSE_RANGE_CLOEXEC,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Drop all Linux capabilities from the ambient set (`PR_CAP_AMBIENT_CLEAR_ALL`),
/// bounding set (`PR_CAPBSET_DROP`), and effective/permitted/inheritable sets (`capset`).
///
/// Essential both inside rootless user namespaces (where `uid=0` otherwise starts with
/// full capabilities) and when invoked from a privileged host process with `--no-ns`.
pub fn drop_all_capabilities() -> Result<(), RawErrno> {
    const PR_CAP_AMBIENT: usize = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;

    // Best-effort clear ambient capabilities (EINVAL on kernels < 4.3)
    let _ = unsafe { syscall5(SYS_PRCTL, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };

    // Drop bounding set capabilities (Linux currently defines caps 0..=40; stop on EINVAL)
    for cap in 0..=63usize {
        let ret = unsafe { syscall5(SYS_PRCTL, PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if let Err(RawErrno(22)) = RawErrno::from_raw_ret(ret) {
            // EINVAL: reached highest kernel capability number
            break;
        }
    }

    // Clear effective, permitted, inheritable sets via capset(v3)
    let hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapUserData::default(); 2];
    let ret = unsafe {
        syscall2(
            SYS_CAPSET,
            &hdr as *const CapUserHeader as usize,
            data.as_ptr() as usize,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Apply a POSIX/Linux `rlimit` (`RLIMIT_CORE`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, etc.).
pub fn setrlimit_raw(resource: usize, soft: u64, hard: u64) -> Result<(), RawErrno> {
    let lim = Rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    #[cfg(target_arch = "x86_64")]
    let ret = unsafe { syscall2(SYS_SETRLIMIT, resource, &lim as *const Rlimit as usize) };
    #[cfg(target_arch = "aarch64")]
    let ret = unsafe {
        crate::syscall4(
            SYS_PRLIMIT64,
            0,
            resource,
            &lim as *const Rlimit as usize,
            0,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Install a compiled Seccomp-BPF filter program on the calling thread.
///
/// # Safety
/// `prog` must point to a valid, kernel-verifiable BPF instruction slice.
pub unsafe fn install_seccomp_filter(flags: usize, prog: &SockFprog) -> Result<usize, RawErrno> {
    let ret = unsafe {
        syscall3(
            SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            flags,
            prog as *const SockFprog as usize,
        )
    };
    RawErrno::from_raw_ret(ret)
}
