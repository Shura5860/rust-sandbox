//! Raw `clone3(2)` syscall wrapper for rootless namespace creation.

use crate::{RawErrno, syscall2, syscall5};

/// Linux `SYS_clone3` is 435 on all modern architectures (x86_64, aarch64, riscv64).
const SYS_CLONE3: usize = 435;

#[cfg(target_arch = "x86_64")]
const SYS_CLONE: usize = 56;
#[cfg(target_arch = "aarch64")]
const SYS_CLONE: usize = 220;

const ENOSYS: i32 = 38;

/// Standard `SIGCHLD` signal number on Linux.
pub const SIGCHLD: u64 = 17;

/// Namespace and process creation flags for `clone3`.
pub mod flags {
    /// Time namespace flag — valid for `unshare(2)` / `setns(2)` only (Linux `clone3` rejects it with `EINVAL`).
    pub const CLONE_NEWTIME: u64 = 0x0000_0080;
    pub const CLONE_NEWNS: u64 = 0x0002_0000;
    pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    pub const CLONE_NEWUTS: u64 = 0x0400_0000;
    pub const CLONE_NEWIPC: u64 = 0x0800_0000;
    pub const CLONE_NEWUSER: u64 = 0x1000_0000;
    pub const CLONE_NEWPID: u64 = 0x2000_0000;
    pub const CLONE_NEWNET: u64 = 0x4000_0000;
    pub const CLONE_PIDFD: u64 = 0x0000_1000;
    pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
}

/// Kernel `struct clone_args` (Linux 5.3+, extended through 5.7).
#[repr(C, align(8))]
#[derive(Debug, Default, Clone, Copy)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Result of a successful `clone3` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneResult {
    /// Returned in the parent process with the child's PID.
    Parent { child_pid: i32 },
    /// Returned in the newly created child process.
    Child,
}

/// Invoke `clone3(2)` with fork-like semantics (`stack == 0 && stack_size == 0`),
/// automatically falling back to legacy `clone(2)` when an outer seccomp policy
/// returns `ENOSYS` for `clone3` (common in Docker / container runtimes).
///
/// # Safety
/// Same safety invariants as `fork(2)`: in a multithreaded parent process, the
/// child must only execute async-signal-safe operations (no heap allocation,
/// no mutex acquisition) until `execve` or `exit_group`.
pub unsafe fn clone3(args: &mut CloneArgs) -> Result<CloneResult, RawErrno> {
    let ret = unsafe {
        syscall2(
            SYS_CLONE3,
            args as *mut CloneArgs as usize,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    let val = match RawErrno::from_raw_ret(ret) {
        Ok(v) => v,
        Err(RawErrno(ENOSYS))
            if (args.flags >> 32) == 0
                && args.stack == 0
                && args.pidfd == 0
                && args.child_tid == 0
                && args.parent_tid == 0
                && args.tls == 0
                && args.set_tid == 0
                && args.exit_signal <= 0xff =>
        {
            let legacy_flags = (args.flags as usize) | ((args.exit_signal as usize) & 0xff);
            let fallback_ret = unsafe { syscall5(SYS_CLONE, legacy_flags, 0, 0, 0, 0) };
            RawErrno::from_raw_ret(fallback_ret)?
        }
        Err(e) => return Err(e),
    };
    if val == 0 {
        Ok(CloneResult::Child)
    } else {
        Ok(CloneResult::Parent {
            child_pid: val as i32,
        })
    }
}
