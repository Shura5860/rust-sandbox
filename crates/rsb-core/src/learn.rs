//! `rsb learn` — Automatic least-privilege policy generator via pure-Rust `ptrace`.
//!
//! Runs a target command once under `PTRACE_SYSCALL` observation, records every
//! syscall number, every opened/written filesystem path, and whether network
//! sockets (`AF_INET`/`AF_INET6`) were created, then synthesizes a tight
//! `SandboxProfile` (`sandbox.toml`).

use crate::error::SandboxError;
use crate::policy::SandboxBuilder;
use crate::profile::SandboxProfile;
use rsb_sys::clone3::{CloneArgs, CloneResult, SIGCHLD, clone3};
use rsb_sys::ptrace::{
    self, PTRACE_O_EXITKILL, PTRACE_O_TRACECLONE, PTRACE_O_TRACEFORK, PTRACE_O_TRACESYSGOOD,
    PTRACE_O_TRACEVFORK,
};
use rsb_sys::rustix::io::Errno;
use rsb_sys::rustix::process::{
    Pid, Signal, WaitOptions, getpid, kill_process, setpgid, waitpgid, waitpid,
};
use rsb_sys::{RawErrno, execve_raw, exit_group};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// x86_64 syscall numbers monitored for filesystem & network policy synthesis
#[cfg(target_arch = "x86_64")]
mod trace_nr {
    pub const OPEN: u32 = 2;
    pub const SOCKET: u32 = 41;
    pub const EXECVE: u32 = 59;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const CREAT: u32 = 85;
    pub const UNLINK: u32 = 87;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const LINKAT: u32 = 265;
    pub const SYMLINKAT: u32 = 266;
    pub const RENAMEAT2: u32 = 316;
    pub const OPENAT2: u32 = 437;
}

const AT_FDCWD: i32 = -100;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

/// Result of running `learn_policy` on a target command.
#[derive(Debug, Clone)]
pub struct LearnReport {
    pub exit_code: Option<i32>,
    pub observed_syscalls: BTreeSet<u32>,
    pub read_paths: BTreeSet<PathBuf>,
    pub write_paths: BTreeSet<PathBuf>,
    pub network_used: bool,
    pub profile: SandboxProfile,
}

/// Run `program` with `args` under `ptrace` observation and synthesize a tight `SandboxProfile`.
#[cfg(target_arch = "x86_64")]
pub fn learn_policy<I, S>(program: impl Into<PathBuf>, args: I) -> Result<LearnReport, SandboxError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    learn_policy_with_options(program, args, false)
}

/// Run `program` with `args` under `ptrace` observation.
///
/// When `strict_allowlist` is `true`, the generated `SandboxProfile` includes
/// `[seccomp] mode = "allowlist"` with the exact set of observed syscall numbers
/// (all unlisted syscalls are rejected by the kernel with `EPERM`).
#[cfg(target_arch = "x86_64")]
pub fn learn_policy_with_options<I, S>(
    program: impl Into<PathBuf>,
    args: I,
    strict_allowlist: bool,
) -> Result<LearnReport, SandboxError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let prepared = SandboxBuilder::new(program)
        .args(args)
        .namespaces(false)
        .landlock(false)
        .seccomp(false)
        .prepare()?;

    let mut clone_args = CloneArgs {
        flags: 0,
        exit_signal: SIGCHLD,
        ..Default::default()
    };

    let root_pid = match unsafe { clone3(&mut clone_args) } {
        Ok(CloneResult::Child) => {
            // Isolate tracee tree into its own process group so concurrent `learn_policy`
            // calls in multithreaded hosts never steal each other's wait events.
            let _ = setpgid(None, None);
            if ptrace::traceme().is_err() {
                exit_group(127);
            }
            // Stop self so parent can attach PTRACE_SETOPTIONS before execve
            let _ = kill_process(getpid(), Signal::STOP);
            let _ = unsafe {
                execve_raw(
                    prepared.program.as_ptr(),
                    prepared.argv_ptrs.as_ptr(),
                    prepared.envp_ptrs.as_ptr(),
                )
            };
            exit_group(127);
        }
        Ok(CloneResult::Parent { child_pid }) => child_pid,
        Err(errno) => {
            return Err(SandboxError::Syscall {
                stage: "clone3(learn)",
                errno,
            });
        }
    };

    // Wait for initial SIGSTOP from root child
    let root_pid_t = Pid::from_raw(root_pid).ok_or(SandboxError::Syscall {
        stage: "learn(invalid pid)",
        errno: RawErrno(22),
    })?;
    loop {
        match waitpid(Some(root_pid_t), WaitOptions::empty()) {
            Ok(Some(_)) => break,
            Ok(None) => continue,
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "waitpid(learn init)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    }

    let opts = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_EXITKILL;
    if let Err(errno) = ptrace::setoptions(root_pid, opts) {
        let _ = kill_process(root_pid_t, Signal::KILL);
        let _ = waitpid(Some(root_pid_t), WaitOptions::empty());
        return Err(SandboxError::Syscall {
            stage: "ptrace(PTRACE_SETOPTIONS)",
            errno,
        });
    }
    if let Err(errno) = ptrace::syscall_continue(root_pid, 0) {
        let _ = kill_process(root_pid_t, Signal::KILL);
        let _ = waitpid(Some(root_pid_t), WaitOptions::empty());
        return Err(SandboxError::Syscall {
            stage: "ptrace(PTRACE_SYSCALL)",
            errno,
        });
    }

    let mut observed_syscalls = BTreeSet::new();
    let mut read_paths = BTreeSet::new();
    let mut write_paths = BTreeSet::new();
    let mut network_used = false;
    let mut root_exit_code: Option<i32> = None;

    // Track whether each traced TID is currently on syscall-entry vs syscall-exit
    let mut in_syscall: BTreeMap<i32, bool> = BTreeMap::new();

    // Linux `__WALL` (0x4000_0000): wait for both cloned threads and forked children
    // strictly inside this tracee's process group (`waitpgid(root_pid_t, __WALL)`).
    let wait_all = WaitOptions::from_bits_retain(0x4000_0000);

    loop {
        let wait_res = waitpgid(root_pid_t, wait_all);
        let (tid_pid, status) = match wait_res {
            Ok(Some(pair)) => pair,
            Ok(None) => continue,
            Err(Errno::CHILD) => break, // All traced processes have exited
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "waitpid(learn loop)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        };
        let tid = tid_pid.as_raw_nonzero().get();

        if status.exited() || status.signaled() {
            in_syscall.remove(&tid);
            if tid == root_pid {
                root_exit_code = status.exit_status();
            }
            continue;
        }

        if let Some(sig) = status.stopping_signal() {
            // `SIGTRAP | 0x80` (133) indicates a syscall-entry or syscall-exit stop
            if sig == (5 | 0x80) {
                let entering = !in_syscall.get(&tid).copied().unwrap_or(false);
                in_syscall.insert(tid, entering);

                if entering && let Ok(regs) = ptrace::getregs(tid) {
                    let nr = regs.orig_rax as u32;
                    observed_syscalls.insert(nr);
                    inspect_syscall(
                        tid,
                        nr,
                        &regs,
                        &mut read_paths,
                        &mut write_paths,
                        &mut network_used,
                    );
                }
                let _ = ptrace::syscall_continue(tid, 0);
            } else if sig == 5 {
                // ptrace event stop (fork/vfork/clone/exec) — don't inject SIGTRAP
                let _ = ptrace::syscall_continue(tid, 0);
            } else {
                // Deliver normal signal to tracee
                let _ = ptrace::syscall_continue(tid, sig);
            }
        } else {
            let _ = ptrace::syscall_continue(tid, 0);
        }
    }

    let mut profile = synthesize_profile(&read_paths, &write_paths, network_used);
    if strict_allowlist {
        profile.allow_syscalls = Some(observed_syscalls.iter().copied().collect());
    }

    Ok(LearnReport {
        exit_code: root_exit_code,
        observed_syscalls,
        read_paths,
        write_paths,
        network_used,
        profile,
    })
}

#[cfg(target_arch = "x86_64")]
fn inspect_syscall(
    tid: i32,
    nr: u32,
    regs: &ptrace::UserRegs,
    read_paths: &mut BTreeSet<PathBuf>,
    write_paths: &mut BTreeSet<PathBuf>,
    network_used: &mut bool,
) {
    match nr {
        trace_nr::OPENAT => {
            let dirfd = regs.rdi as i32;
            let flags = regs.rdx;
            if let Some(path) = read_and_resolve_path(tid, dirfd, regs.rsi) {
                if is_write_flags(flags) {
                    write_paths.insert(path);
                } else {
                    read_paths.insert(path);
                }
            }
        }
        trace_nr::OPENAT2 => {
            let dirfd = regs.rdi as i32;
            // `open_how.flags` is the first u64 at `regs.rdx`
            let flags = ptrace::peekdata(tid, regs.rdx as usize).unwrap_or(0) as u64;
            if let Some(path) = read_and_resolve_path(tid, dirfd, regs.rsi) {
                if is_write_flags(flags) {
                    write_paths.insert(path);
                } else {
                    read_paths.insert(path);
                }
            }
        }
        trace_nr::OPEN => {
            let flags = regs.rsi;
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, regs.rdi) {
                if is_write_flags(flags) {
                    write_paths.insert(path);
                } else {
                    read_paths.insert(path);
                }
            }
        }
        trace_nr::CREAT | trace_nr::MKDIR | trace_nr::UNLINK => {
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, regs.rdi) {
                write_paths.insert(path);
            }
        }
        trace_nr::RENAME => {
            if let Some(p) = read_and_resolve_path(tid, AT_FDCWD, regs.rdi) {
                write_paths.insert(p);
            }
            if let Some(p) = read_and_resolve_path(tid, AT_FDCWD, regs.rsi) {
                write_paths.insert(p);
            }
        }
        trace_nr::EXECVE => {
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, regs.rdi) {
                read_paths.insert(path);
            }
        }
        trace_nr::MKDIRAT | trace_nr::UNLINKAT => {
            let dirfd = regs.rdi as i32;
            if let Some(path) = read_and_resolve_path(tid, dirfd, regs.rsi) {
                write_paths.insert(path);
            }
        }
        trace_nr::SYMLINKAT => {
            let newdirfd = regs.rsi as i32;
            if let Some(path) = read_and_resolve_path(tid, newdirfd, regs.rdx) {
                write_paths.insert(path);
            }
        }
        trace_nr::RENAMEAT | trace_nr::RENAMEAT2 | trace_nr::LINKAT => {
            let old_dirfd = regs.rdi as i32;
            let new_dirfd = regs.rdx as i32;
            if let Some(p) = read_and_resolve_path(tid, old_dirfd, regs.rsi) {
                write_paths.insert(p);
            }
            if let Some(p) = read_and_resolve_path(tid, new_dirfd, regs.r10) {
                write_paths.insert(p);
            }
        }
        trace_nr::SOCKET if regs.rdi == AF_INET || regs.rdi == AF_INET6 => {
            *network_used = true;
        }
        _ => {}
    }
}

fn is_write_flags(flags: u64) -> bool {
    (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0
}

fn read_and_resolve_path(tid: i32, dirfd: i32, addr: u64) -> Option<PathBuf> {
    let bytes = ptrace::read_cstring(tid, addr, 4096)?;
    if bytes.is_empty() {
        return None;
    }
    let raw = PathBuf::from(OsStr::from_bytes(&bytes));
    if raw.is_absolute() {
        return Some(clean_path(&raw));
    }

    let base = if dirfd == AT_FDCWD {
        std::fs::read_link(format!("/proc/{tid}/cwd")).ok()?
    } else {
        std::fs::read_link(format!("/proc/{tid}/fd/{dirfd}")).ok()?
    };
    Some(clean_path(&base.join(raw)))
}

fn clean_path(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Convert raw observed read/write paths into a clean, minimal `SandboxProfile`.
fn synthesize_profile(
    read_paths: &BTreeSet<PathBuf>,
    write_paths: &BTreeSet<PathBuf>,
    network_used: bool,
) -> SandboxProfile {
    let mut profile = SandboxProfile {
        allow_network: network_used,
        ..Default::default()
    };

    let mut rw_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for p in write_paths {
        if is_ignored_or_system_path(p) {
            continue;
        }
        let dir = if p.is_dir() {
            p.clone()
        } else {
            p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.clone())
        };
        rw_dirs.insert(dir);
    }

    let mut ro_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for p in read_paths {
        if is_ignored_or_system_path(p) || !p.exists() {
            continue;
        }
        // Skip paths already covered by an rw rule
        if rw_dirs.iter().any(|rw| p.starts_with(rw)) {
            continue;
        }
        let target = if p.is_dir() {
            p.clone()
        } else {
            p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.clone())
        };
        ro_dirs.insert(target);
    }

    profile.ro = ro_dirs.into_iter().collect();
    profile.rw = rw_dirs.into_iter().collect();
    profile
}

fn is_ignored_or_system_path(p: &Path) -> bool {
    const PREFIXES: &[&str] = &[
        "/proc",
        "/sys",
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/dev/tty",
        "/etc/ld.so",
        "/etc/localtime",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ];
    let s = p.to_string_lossy();
    PREFIXES.iter().any(|pre| s == *pre || s.starts_with(&format!("{pre}/")) || s.starts_with("/etc/ld.so"))
}
