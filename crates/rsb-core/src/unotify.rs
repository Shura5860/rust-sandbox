//! Live userspace syscall supervision powered by Linux `seccomp_unotify`.
//!
//! Unlike `ptrace`, `seccomp_unotify` ONLY traps the specific syscalls you mark
//! with [`SeccompAction::UserNotif`], giving near-native performance for all
//! other syscalls while allowing dynamic Rust callbacks to inspect, allow, deny,
//! or spoof return values in real time!

use crate::error::SandboxError;
use crate::policy::SandboxBuilder;
use crate::seccomp_bpf::{SeccompAction, SeccompPolicy};
use rsb_sys::clone3::{CloneArgs, CloneResult, SIGCHLD, clone3};
use rsb_sys::rustix::event::{PollFd, PollFlags, Timespec, poll};
use rsb_sys::rustix::io::{Errno, close};
use rsb_sys::rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
use rsb_sys::seccomp::{
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SockFprog, install_seccomp_filter, set_no_new_privs,
};
use rsb_sys::unotify::{
    SECCOMP_USER_NOTIF_FLAG_CONTINUE, SeccompNotif, SeccompNotifResp, notif_id_valid, notif_recv,
    notif_send, recv_fd, send_fd, unix_socketpair,
};
use rsb_sys::{RawErrno, execve_raw, exit_group};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

/// Decision returned by a live `seccomp_unotify` supervisor callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnotifyDecision {
    /// Allow the kernel to execute the intercepted syscall normally.
    ///
    /// # Security Warning (TOCTOU)
    /// Do **not** use `Continue` as a security boundary after inspecting pointer
    /// arguments (such as file paths or `sockaddr` buffers) in the child's memory.
    /// Another thread in the target process can race and mutate that memory between
    /// inspection and kernel execution; `SECCOMP_IOCTL_NOTIF_ID_VALID` only confirms
    /// that the notification ID is still live, not that user memory is unchanged.
    /// For security-critical checks on pointer arguments, deny with [`Self::Errno`]
    /// or perform the operation in the supervisor and return [`Self::ReturnValue`].
    Continue,
    /// Fail the syscall immediately with the given positive Linux errno (e.g. `1` = `EPERM`).
    Errno(i32),
    /// Skip executing the syscall and return a synthetic success value directly to the child.
    ReturnValue(i64),
}

/// Summary returned after a `seccomp_unotify`-supervised command finishes.
#[derive(Debug, Clone)]
pub struct SupervisedReport {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub intercepted_count: u64,
}

/// Run `program` with `args` under live `seccomp_unotify` supervision for `trapped_syscalls`.
///
/// Every time the child invokes a syscall in `trapped_syscalls`, `handler` is called
/// on the host with the full [`SeccompNotif`] (`pid`, `nr`, `args[0..6]`) and returns
/// a [`UnotifyDecision`].
///
/// # Isolation Note
/// This helper installs only the `seccomp_unotify` filter (`namespaces(false)`,
/// `landlock(false)`) and does **not** provide filesystem, namespace, or network
/// isolation on its own. Combine with namespaces and Landlock when running untrusted code.
pub fn run_supervised<I, S, F>(
    program: impl Into<PathBuf>,
    args: I,
    trapped_syscalls: &[u32],
    mut handler: F,
) -> Result<SupervisedReport, SandboxError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    F: FnMut(&SeccompNotif) -> UnotifyDecision,
{
    #[cfg(target_arch = "x86_64")]
    const SYS_SENDMSG: u32 = 46;
    #[cfg(target_arch = "aarch64")]
    const SYS_SENDMSG: u32 = 211;

    if trapped_syscalls.contains(&SYS_SENDMSG) {
        return Err(SandboxError::InvalidPolicy(
            "cannot trap SYS_sendmsg in run_supervised (required to send seccomp_unotify listener FD via SCM_RIGHTS)".into(),
        ));
    }

    let mut sp = SeccompPolicy {
        enabled: true,
        block_dangerous_syscalls: false,
        block_network_sockets: false,
        block_tiocsti: true,
        extra_denied: Vec::new(),
        allowlist: None,
        default_deny_action: SeccompAction::Errno(1),
    };
    for &nr in trapped_syscalls {
        sp.extra_denied.push((nr, SeccompAction::UserNotif));
    }

    let prepared = SandboxBuilder::new(program)
        .args(args)
        .namespaces(false)
        .landlock(false)
        .seccomp_policy(sp)
        .prepare()?;

    let (parent_sock, child_sock) = unix_socketpair().map_err(|errno| SandboxError::Syscall {
        stage: "socketpair(unotify)",
        errno,
    })?;

    let mut clone_args = CloneArgs {
        flags: 0,
        exit_signal: SIGCHLD,
        ..Default::default()
    };

    let child_sock_raw = child_sock.as_raw_fd();
    let child_pid = match unsafe { clone3(&mut clone_args) } {
        Ok(CloneResult::Child) => {
            drop(parent_sock);
            if set_no_new_privs().is_err() {
                exit_group(127);
            }
            let prog = SockFprog {
                len: prepared.seccomp_bpf.len() as u16,
                filter: prepared.seccomp_bpf.as_ptr(),
            };
            let listener_fd = match unsafe {
                install_seccomp_filter(SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog)
            } {
                Ok(fd) => fd as RawFd,
                Err(e) => {
                    let _ = rsb_sys::rustix::io::write(&child_sock, &e.0.to_ne_bytes());
                    exit_group(127);
                }
            };
            if send_fd(child_sock_raw, listener_fd).is_err() {
                exit_group(127);
            }
            unsafe { close(listener_fd) };
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
                stage: "clone3(unotify)",
                errno,
            });
        }
    };
    drop(child_sock);

    let pid = Pid::from_raw(child_pid).ok_or(SandboxError::Syscall {
        stage: "unotify(invalid pid)",
        errno: RawErrno(22),
    })?;

    let listener_fd = match recv_fd(parent_sock.as_raw_fd()) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = kill_process(pid, Signal::KILL);
            let _ = waitpid(Some(pid), WaitOptions::empty());
            return Err(SandboxError::Syscall {
                stage: "recv_fd(seccomp_unotify listener)",
                errno,
            });
        }
    };
    drop(parent_sock);

    let mut intercepted_count: u64 = 0;
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000, // 10ms
    };

    let exit_status = loop {
        // Poll listener FD for incoming syscall notifications or HUP (child exited)
        let mut pfds = [PollFd::new(&listener_fd, PollFlags::IN)];
        let _ = poll(&mut pfds, Some(&ts));

        if pfds[0].revents().contains(PollFlags::IN) {
            match notif_recv(&listener_fd) {
                Ok(notif) => {
                    intercepted_count += 1;
                    let decision = handler(&notif);
                    // Validate notification ID before replying (TOCTOU protection)
                    if notif_id_valid(&listener_fd, notif.id).is_ok() {
                        let resp = match decision {
                            UnotifyDecision::Continue => SeccompNotifResp {
                                id: notif.id,
                                val: 0,
                                error: 0,
                                flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                            },
                            UnotifyDecision::Errno(e) => SeccompNotifResp {
                                id: notif.id,
                                val: 0,
                                error: -(e.abs()),
                                flags: 0,
                            },
                            UnotifyDecision::ReturnValue(v) => SeccompNotifResp {
                                id: notif.id,
                                val: v,
                                error: 0,
                                flags: 0,
                            },
                        };
                        let _ = notif_send(&listener_fd, &resp);
                    }
                }
                Err(RawErrno(2)) => {} // ENOENT: tracee died before recv
                Err(_) => {}
            }
        }

        match waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some((_p, st))) => break st,
            Ok(None) => continue,
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "waitpid(unotify)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    };

    Ok(SupervisedReport {
        exit_code: exit_status.exit_status(),
        signal: exit_status.terminating_signal(),
        intercepted_count,
    })
}
