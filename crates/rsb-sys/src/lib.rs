//! Low-level Linux syscall primitives for `rust-sandbox`.
//!
//! Uses `rustix` (with its `linux_raw` backend — no libc) for standard POSIX/Linux
//! syscalls, paired with minimal, audited raw-syscall wrappers for kernel APIs
//! that require direct ABI control: `clone3`, Landlock LSM, and `seccomp`.

#![cfg(target_os = "linux")]

pub mod clone3;
pub mod landlock;
pub mod ptrace;
pub mod seccomp;
pub mod tap;
pub mod unotify;

pub use rustix;

/// Raw Linux syscall error (positive errno value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawErrno(pub i32);

impl RawErrno {
    #[inline]
    pub fn from_raw_ret(ret: isize) -> Result<usize, Self> {
        if (-4095..0).contains(&ret) {
            Err(Self((-ret) as i32))
        } else {
            Ok(ret as usize)
        }
    }

    #[inline]
    pub fn to_io_error(self) -> std::io::Error {
        std::io::Error::from_raw_os_error(self.0)
    }
}

impl std::fmt::Display for RawErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_io_error())
    }
}

impl std::error::Error for RawErrno {}

/// Direct Linux 2-argument syscall invocation without libc.
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 3-argument syscall invocation without libc.
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 4-argument syscall invocation without libc.
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 5-argument syscall invocation without libc.
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 2-argument syscall invocation without libc (`aarch64`).
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 3-argument syscall invocation without libc (`aarch64`).
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 4-argument syscall invocation without libc (`aarch64`).
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            options(nostack)
        );
    }
    ret
}

/// Direct Linux 5-argument syscall invocation without libc (`aarch64`).
///
/// # Safety
/// Caller must ensure `nr` and arguments uphold the Linux kernel ABI contract.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            options(nostack)
        );
    }
    ret
}

/// Immediately terminate the calling process without running atexit handlers or
/// flushing stdio buffers. Safe to call in a post-`clone3` child.
#[inline]
pub fn exit_group(code: i32) -> ! {
    #[cfg(target_arch = "x86_64")]
    const SYS_EXIT_GROUP: usize = 231;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXIT_GROUP: usize = 94;

    unsafe {
        let _ = syscall2(SYS_EXIT_GROUP, code as usize, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Raw `execve(pathname, argv, envp)` wrapper safe for post-`clone3` child use.
///
/// # Safety
/// `pathname`, `argv`, and `envp` must be valid null-terminated pointers / arrays.
#[inline]
pub unsafe fn execve_raw(
    pathname: *const core::ffi::c_char,
    argv: *const *const core::ffi::c_char,
    envp: *const *const core::ffi::c_char,
) -> RawErrno {
    #[cfg(target_arch = "x86_64")]
    const SYS_EXECVE: usize = 59;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXECVE: usize = 221;

    let ret = unsafe { syscall3(SYS_EXECVE, pathname as usize, argv as usize, envp as usize) };
    match RawErrno::from_raw_ret(ret) {
        Err(e) => e,
        Ok(_) => RawErrno(0), // unreachable on success
    }
}
