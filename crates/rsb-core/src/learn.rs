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
    self, PTRACE_O_EXITKILL, PTRACE_O_TRACECLONE, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEFORK,
    PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORK,
};
use rsb_sys::rustix::io::Errno;
use rsb_sys::rustix::process::{Pid, Signal, WaitOptions, getpid, kill_process, setpgid, waitpid};
use rsb_sys::{RawErrno, execve_raw, exit_group};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// Architecture-specific syscall numbers monitored for filesystem & network policy synthesis
#[cfg(target_arch = "x86_64")]
mod trace_nr {
    pub const OPEN: u32 = 2;
    pub const SOCKET: u32 = 41;
    pub const EXECVE: u32 = 59;
    pub const TRUNCATE: u32 = 76;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const RMDIR: u32 = 84;
    pub const CREAT: u32 = 85;
    pub const LINK: u32 = 86;
    pub const UNLINK: u32 = 87;
    pub const SYMLINK: u32 = 88;
    pub const CHMOD: u32 = 90;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const LINKAT: u32 = 265;
    pub const SYMLINKAT: u32 = 266;
    pub const FCHMODAT: u32 = 268;
    pub const RENAMEAT2: u32 = 316;
    pub const EXECVEAT: u32 = 322;
    pub const OPENAT2: u32 = 437;
}

#[cfg(target_arch = "aarch64")]
mod trace_nr {
    pub const MKDIRAT: u32 = 34;
    pub const UNLINKAT: u32 = 35;
    pub const SYMLINKAT: u32 = 36;
    pub const LINKAT: u32 = 37;
    pub const RENAMEAT: u32 = 38;
    pub const TRUNCATE: u32 = 45;
    pub const FCHMODAT: u32 = 53;
    pub const OPENAT: u32 = 56;
    pub const SOCKET: u32 = 198;
    pub const EXECVE: u32 = 221;
    pub const RENAMEAT2: u32 = 276;
    pub const EXECVEAT: u32 = 281;
    pub const OPENAT2: u32 = 437;
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_nr(r: &ptrace::UserRegs) -> u32 { r.orig_rax as u32 }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_nr(r: &ptrace::UserRegs) -> u32 { r.regs[8] as u32 }

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_arg0(r: &ptrace::UserRegs) -> u64 { r.rdi }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_arg0(r: &ptrace::UserRegs) -> u64 { r.regs[0] }

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_arg1(r: &ptrace::UserRegs) -> u64 { r.rsi }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_arg1(r: &ptrace::UserRegs) -> u64 { r.regs[1] }

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_arg2(r: &ptrace::UserRegs) -> u64 { r.rdx }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_arg2(r: &ptrace::UserRegs) -> u64 { r.regs[2] }

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_arg3(r: &ptrace::UserRegs) -> u64 { r.r10 }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_arg3(r: &ptrace::UserRegs) -> u64 { r.regs[3] }

#[cfg(target_arch = "x86_64")]
#[inline]
fn reg_ret(r: &ptrace::UserRegs) -> i64 { r.rax as i64 }
#[cfg(target_arch = "aarch64")]
#[inline]
fn reg_ret(r: &ptrace::UserRegs) -> i64 { r.regs[0] as i64 }

#[derive(Default)]
struct PendingSyscall {
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    net: bool,
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
        | PTRACE_O_TRACEEXEC
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

    // Track whether each traced TID is currently on syscall-entry vs syscall-exit,
    // which TIDs have passed their initial kernel `SIGSTOP`, pending entry observations
    // (committed only when `ret >= 0`), pending exec paths (committed on `PTRACE_EVENT_EXEC`),
    // and the exact set of tracked TIDs (so descendants calling `setsid()`/`setpgid()`
    // are never missed while never stealing unrelated children in multithreaded hosts).
    let mut in_syscall: BTreeMap<i32, bool> = BTreeMap::new();
    let mut pending_map: BTreeMap<i32, PendingSyscall> = BTreeMap::new();
    let mut pending_exec: BTreeMap<i32, Vec<PathBuf>> = BTreeMap::new();
    let mut seen_tids: BTreeSet<i32> = BTreeSet::new();
    let mut tracked_tids: BTreeSet<i32> = BTreeSet::new();
    seen_tids.insert(root_pid);
    tracked_tids.insert(root_pid);

    // Linux `__WALL` (0x4000_0000): wait for both cloned threads and forked children.
    let wait_all = WaitOptions::from_bits_retain(0x4000_0000);
    let wait_all_nohang = wait_all | WaitOptions::NOHANG;

    loop {
        if tracked_tids.is_empty() {
            break;
        }
        let (tid, status) = if tracked_tids.len() == 1 {
            let only_tid = *tracked_tids.iter().next().unwrap();
            let Some(pid_t) = Pid::from_raw(only_tid) else {
                tracked_tids.remove(&only_tid);
                continue;
            };
            match waitpid(Some(pid_t), wait_all) {
                Ok(Some((_, st))) => (only_tid, st),
                Ok(None) => continue,
                Err(Errno::CHILD) => {
                    tracked_tids.remove(&only_tid);
                    continue;
                }
                Err(Errno::INTR) => continue,
                Err(e) => {
                    return Err(SandboxError::Syscall {
                        stage: "waitpid(learn loop)",
                        errno: RawErrno(e.raw_os_error()),
                    });
                }
            }
        } else {
            let tids_snapshot: Vec<i32> = tracked_tids.iter().copied().collect();
            let mut found = None;
            let mut gone = Vec::new();
            for t in tids_snapshot {
                let Some(pid_t) = Pid::from_raw(t) else {
                    gone.push(t);
                    continue;
                };
                match waitpid(Some(pid_t), wait_all_nohang) {
                    Ok(Some((_, st))) => {
                        found = Some((t, st));
                        break;
                    }
                    Ok(None) | Err(Errno::INTR) => {}
                    Err(Errno::CHILD) => gone.push(t),
                    Err(e) => {
                        return Err(SandboxError::Syscall {
                            stage: "waitpid(learn loop)",
                            errno: RawErrno(e.raw_os_error()),
                        });
                    }
                }
            }
            for g in gone {
                tracked_tids.remove(&g);
                seen_tids.remove(&g);
                in_syscall.remove(&g);
                pending_map.remove(&g);
                pending_exec.remove(&g);
            }
            match found {
                Some(pair) => pair,
                None => {
                    if tracked_tids.is_empty() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_micros(250));
                    continue;
                }
            }
        };

        if status.exited() || status.signaled() {
            in_syscall.remove(&tid);
            pending_map.remove(&tid);
            pending_exec.remove(&tid);
            seen_tids.remove(&tid);
            tracked_tids.remove(&tid);
            if tid == root_pid {
                root_exit_code = status.exit_status();
            }
            continue;
        }

        if let Some(sig) = status.stopping_signal() {
            let ptrace_event = (status.as_raw() >> 16) & 0xff;
            // `SIGTRAP | 0x80` (133) indicates a syscall-entry or syscall-exit stop
            if sig == (5 | 0x80) {
                seen_tids.insert(tid);
                let entering = !in_syscall.get(&tid).copied().unwrap_or(false);
                in_syscall.insert(tid, entering);

                if entering {
                    if let Ok(regs) = ptrace::getregs(tid) {
                        let nr = reg_nr(&regs);
                        observed_syscalls.insert(nr);
                        let mut pending = PendingSyscall::default();
                        inspect_syscall_entry(tid, nr, &regs, &mut pending);
                        if nr == trace_nr::EXECVE || nr == trace_nr::EXECVEAT {
                            if !pending.read.is_empty() {
                                pending_exec.insert(tid, pending.read);
                            }
                        } else if !pending.read.is_empty() || !pending.write.is_empty() || pending.net {
                            pending_map.insert(tid, pending);
                        }
                    }
                } else {
                    pending_exec.remove(&tid);
                    if let Some(pending) = pending_map.remove(&tid)
                        && let Ok(regs) = ptrace::getregs(tid)
                        && reg_ret(&regs) >= 0
                    {
                        read_paths.extend(pending.read);
                        write_paths.extend(pending.write);
                        if pending.net {
                            network_used = true;
                        }
                    }
                }
                let _ = ptrace::syscall_continue(tid, 0);
            } else if sig == 19 && !seen_tids.contains(&tid) {
                // Initial kernel `SIGSTOP` for a newly attached fork/vfork/clone child/thread:
                // MUST NOT be re-injected or the new thread/child freezes permanently!
                seen_tids.insert(tid);
                let _ = ptrace::syscall_continue(tid, 0);
            } else if sig == 5 && ptrace_event != 0 {
                // Real ptrace event stop (FORK=1, VFORK=2, CLONE=3, EXEC=4, EXIT=6).
                seen_tids.insert(tid);
                match ptrace_event {
                    1..=3 => {
                        if let Ok(new_tid) = ptrace::geteventmsg(tid)
                            && new_tid > 0
                        {
                            tracked_tids.insert(new_tid as i32);
                        }
                    }
                    4 => {
                        // PTRACE_EVENT_EXEC: commit verified execve/execveat target path.
                        // If a non-leader thread called execve, PTRACE_GETEVENTMSG returns
                        // its former TID while the surviving thread takes the leader's PID.
                        if let Some(paths) = pending_exec.remove(&tid) {
                            read_paths.extend(paths);
                        }
                        if let Ok(old_tid_u64) = ptrace::geteventmsg(tid) {
                            let old_tid = old_tid_u64 as i32;
                            if old_tid > 0 && old_tid != tid {
                                if let Some(paths) = pending_exec.remove(&old_tid) {
                                    read_paths.extend(paths);
                                }
                                in_syscall.remove(&old_tid);
                                pending_map.remove(&old_tid);
                                seen_tids.remove(&old_tid);
                                tracked_tids.remove(&old_tid);
                            }
                        }
                        // Ensure the upcoming execve syscall-exit stop pairs cleanly.
                        in_syscall.insert(tid, true);
                    }
                    _ => {}
                }
                let _ = ptrace::syscall_continue(tid, 0);
            } else {
                // Deliver normal signal (including genuine user SIGTRAP when ptrace_event == 0)
                seen_tids.insert(tid);
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

fn inspect_syscall_entry(
    tid: i32,
    nr: u32,
    regs: &ptrace::UserRegs,
    pending: &mut PendingSyscall,
) {
    let a0 = reg_arg0(regs);
    let a1 = reg_arg1(regs);
    let a2 = reg_arg2(regs);
    let a3 = reg_arg3(regs);

    match nr {
        trace_nr::OPENAT => {
            let dirfd = a0 as i32;
            let flags = a2;
            if let Some(path) = read_and_resolve_path(tid, dirfd, a1) {
                if is_write_flags(flags) {
                    pending.write.push(path);
                } else {
                    pending.read.push(path);
                }
            }
        }
        trace_nr::OPENAT2 => {
            let dirfd = a0 as i32;
            if let Ok(flags_word) = ptrace::peekdata(tid, a2 as usize) {
                let flags = flags_word as u64;
                if let Some(path) = read_and_resolve_path(tid, dirfd, a1) {
                    if is_write_flags(flags) {
                        pending.write.push(path);
                    } else {
                        pending.read.push(path);
                    }
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        trace_nr::OPEN => {
            let flags = a1;
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, a0) {
                if is_write_flags(flags) {
                    pending.write.push(path);
                } else {
                    pending.read.push(path);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        trace_nr::CREAT
        | trace_nr::MKDIR
        | trace_nr::RMDIR
        | trace_nr::UNLINK
        | trace_nr::CHMOD => {
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, a0) {
                pending.write.push(path);
            }
        }
        #[cfg(target_arch = "x86_64")]
        trace_nr::RENAME | trace_nr::LINK => {
            if let Some(p) = read_and_resolve_path(tid, AT_FDCWD, a0) {
                pending.write.push(p);
            }
            if let Some(p) = read_and_resolve_path(tid, AT_FDCWD, a1) {
                pending.write.push(p);
            }
        }
        #[cfg(target_arch = "x86_64")]
        trace_nr::SYMLINK => {
            if let Some(p) = read_and_resolve_path(tid, AT_FDCWD, a1) {
                pending.write.push(p);
            }
        }
        trace_nr::TRUNCATE => {
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, a0) {
                pending.write.push(path);
            }
        }
        trace_nr::EXECVE => {
            if let Some(path) = read_and_resolve_path(tid, AT_FDCWD, a0) {
                pending.read.push(path);
            }
        }
        trace_nr::EXECVEAT => {
            let dirfd = a0 as i32;
            if let Some(path) = read_and_resolve_path(tid, dirfd, a1) {
                pending.read.push(path);
            }
        }
        trace_nr::MKDIRAT | trace_nr::UNLINKAT | trace_nr::FCHMODAT => {
            let dirfd = a0 as i32;
            if let Some(path) = read_and_resolve_path(tid, dirfd, a1) {
                pending.write.push(path);
            }
        }
        trace_nr::SYMLINKAT => {
            let newdirfd = a1 as i32;
            if let Some(path) = read_and_resolve_path(tid, newdirfd, a2) {
                pending.write.push(path);
            }
        }
        trace_nr::RENAMEAT | trace_nr::RENAMEAT2 | trace_nr::LINKAT => {
            let old_dirfd = a0 as i32;
            let new_dirfd = a2 as i32;
            if let Some(p) = read_and_resolve_path(tid, old_dirfd, a1) {
                pending.write.push(p);
            }
            if let Some(p) = read_and_resolve_path(tid, new_dirfd, a3) {
                pending.write.push(p);
            }
        }
        trace_nr::SOCKET if a0 == AF_INET || a0 == AF_INET6 => {
            pending.net = true;
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
    if base.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return None;
    }
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

    const NO_PROMOTE_DIRS: &[&str] = &["/", "/etc", "/var", "/dev", "/run", "/home"];
    let home_dir = std::env::var_os("HOME").map(PathBuf::from);
    let is_broad_dir = |dir: &Path| -> bool {
        NO_PROMOTE_DIRS.iter().any(|&d| dir == Path::new(d))
            || home_dir.as_deref() == Some(dir)
    };
    let coalesce_target = |p: &Path| -> PathBuf {
        if p.is_dir() {
            return p.to_path_buf();
        }
        match p.parent() {
            Some(parent) if !is_broad_dir(parent) => parent.to_path_buf(),
            _ => p.to_path_buf(),
        }
    };

    let mut rw_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for p in write_paths {
        if is_ignored_or_system_path(p) {
            continue;
        }
        let target = coalesce_target(p);
        if target.exists() {
            rw_dirs.insert(target);
        } else {
            // Walk up to the nearest existing non-broad ancestor (e.g. deleted temp files)
            // so the generated profile never fails Landlock `stat()` with ENOENT.
            let mut cur = target.parent();
            while let Some(anc) = cur {
                if is_broad_dir(anc) {
                    break;
                }
                if anc.exists() {
                    rw_dirs.insert(anc.to_path_buf());
                    break;
                }
                cur = anc.parent();
            }
        }
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
        ro_dirs.insert(coalesce_target(p));
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
