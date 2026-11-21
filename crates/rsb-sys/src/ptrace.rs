//! Raw `ptrace(2)` syscall wrappers for `rsb learn` (automatic policy generator).

use crate::{RawErrno, syscall4};

#[cfg(target_arch = "x86_64")]
const SYS_PTRACE: usize = 101;
#[cfg(target_arch = "aarch64")]
const SYS_PTRACE: usize = 117;

pub const PTRACE_TRACEME: usize = 0;
pub const PTRACE_PEEKDATA: usize = 2;
pub const PTRACE_GETREGS: usize = 12;
pub const PTRACE_SYSCALL: usize = 24;
pub const PTRACE_SETOPTIONS: usize = 0x4200;

pub const PTRACE_O_TRACESYSGOOD: usize = 0x0000_0001;
pub const PTRACE_O_TRACEFORK: usize = 0x0000_0002;
pub const PTRACE_O_TRACEVFORK: usize = 0x0000_0004;
pub const PTRACE_O_TRACECLONE: usize = 0x0000_0008;
pub const PTRACE_O_EXITKILL: usize = 0x0010_0000;

/// Linux `struct user_regs_struct` on `x86_64`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

/// Request that the parent trace this child process (`PTRACE_TRACEME`).
/// Async-signal-safe; intended for post-`clone3` child before `execve`.
pub fn traceme() -> Result<(), RawErrno> {
    let ret = unsafe { syscall4(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Set ptrace options on a stopped tracee (`PTRACE_SETOPTIONS`).
pub fn setoptions(pid: i32, options: usize) -> Result<(), RawErrno> {
    let ret = unsafe { syscall4(SYS_PTRACE, PTRACE_SETOPTIONS, pid as usize, 0, options) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Resume a stopped tracee until its next syscall entry or exit (`PTRACE_SYSCALL`).
pub fn syscall_continue(pid: i32, signal: i32) -> Result<(), RawErrno> {
    let ret = unsafe { syscall4(SYS_PTRACE, PTRACE_SYSCALL, pid as usize, 0, signal as usize) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Read general-purpose registers from a stopped `x86_64` tracee.
#[cfg(target_arch = "x86_64")]
pub fn getregs(pid: i32) -> Result<UserRegs, RawErrno> {
    let mut regs = UserRegs::default();
    let ret = unsafe {
        syscall4(
            SYS_PTRACE,
            PTRACE_GETREGS,
            pid as usize,
            0,
            &mut regs as *mut UserRegs as usize,
        )
    };
    RawErrno::from_raw_ret(ret)?;
    Ok(regs)
}

/// Read a single machine word from `addr` in `pid`'s address space via `PTRACE_PEEKDATA`.
///
/// Note: raw `SYS_ptrace(PTRACE_PEEKDATA, pid, addr, &data)` writes the word
/// into `data` and returns 0 on success (unlike the libc wrapper!).
pub fn peekdata(pid: i32, addr: usize) -> Result<usize, RawErrno> {
    let mut word: usize = 0;
    let ret = unsafe {
        syscall4(
            SYS_PTRACE,
            PTRACE_PEEKDATA,
            pid as usize,
            addr,
            &mut word as *mut usize as usize,
        )
    };
    RawErrno::from_raw_ret(ret)?;
    Ok(word)
}

/// Read a NUL-terminated byte string from a stopped tracee's memory using
/// word-aligned `PTRACE_PEEKDATA` reads so strings near an unmapped page boundary
/// never fail with `EIO`/`EFAULT`.
pub fn read_cstring(pid: i32, addr: u64, max_len: usize) -> Option<Vec<u8>> {
    if addr == 0 {
        return None;
    }
    let word_size = core::mem::size_of::<usize>();
    let mut out = Vec::with_capacity(64);
    let raw = addr as usize;
    let mut aligned = raw & !(word_size - 1);
    let mut skip = raw - aligned;

    while out.len() < max_len {
        let word = peekdata(pid, aligned).ok()?;
        let bytes = word.to_ne_bytes();
        for &b in &bytes[skip..] {
            if b == 0 {
                return Some(out);
            }
            out.push(b);
            if out.len() >= max_len {
                return Some(out);
            }
        }
        skip = 0;
        aligned = aligned.checked_add(word_size)?;
    }

    Some(out)
}
