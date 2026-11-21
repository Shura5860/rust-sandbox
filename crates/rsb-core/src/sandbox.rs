//! Parent-side sandbox lifecycle orchestration (`clone3`, UID/GID maps, Cgroups v2,
//! stdout/stderr capture, timeout enforcement, and `waitpid`).

use crate::cgroup::CgroupGuard;
use crate::child::child_main;
use crate::error::{ChildStage, SandboxError};
use crate::overlay::{CowChange, CowSession};
use crate::prepared::PreparedSandbox;
use rsb_sys::RawErrno;
use rsb_sys::clone3::{CloneArgs, CloneResult, SIGCHLD, clone3, flags};
use rsb_sys::rustix::event::{PollFd, PollFlags, Timespec, poll};
use rsb_sys::rustix::fd::OwnedFd;
use rsb_sys::rustix::io::{Errno, read, write};
use rsb_sys::rustix::pipe::{PipeFlags, pipe_with};
use rsb_sys::rustix::process::{
    Pid, Signal, WaitOptions, WaitStatus, getegid, geteuid, getpid, kill_process,
    kill_process_group, waitpid,
};
use rsb_sys::unotify::{recv_fd, unix_socketpair};
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static RESOLV_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

type TapAttachCallback = Box<dyn FnOnce(OwnedFd) -> Result<Box<dyn Send>, SandboxError>>;

/// Summary returned after a sandboxed process terminates.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionReport {
    /// Normal exit code (if the process exited via `exit`).
    pub exit_code: Option<i32>,
    /// Terminating signal number (if killed by a signal).
    pub signal: Option<i32>,
    /// `true` if the sandboxed process exceeded `timeout` and was terminated with `SIGKILL`.
    pub timed_out: bool,
    /// Cold-start latency: `clone3` + namespace/cgroup setup + Landlock + Seccomp + `execve`.
    pub setup_time: Duration,
    /// Total wall-clock time from launch until `waitpid` returns.
    pub total_time: Duration,
    /// Active Landlock ABI version (if Landlock was enabled).
    pub landlock_abi: Option<u32>,
    /// Number of installed Seccomp-BPF instructions (0 if disabled).
    pub seccomp_bpf_insns: usize,
    /// Whether Linux namespace isolation was active.
    pub namespaces_active: bool,
    /// Whether Cgroups v2 quotas were active.
    pub cgroup_active: bool,
    /// Peak memory usage in bytes reported by Cgroups v2 `memory.peak`, if available.
    pub memory_peak_bytes: Option<u64>,
}

impl ExecutionReport {
    /// Returns `true` if the sandboxed command exited normally with status 0 and did not time out.
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0) && self.signal.is_none()
    }
}

/// Execution report with captured `stdout`, `stderr`, and ephemeral CoW diffs.
#[derive(Debug, Clone)]
pub struct CapturedExecutionReport {
    pub report: ExecutionReport,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub cow_diffs: Vec<CowChange>,
}

impl CapturedExecutionReport {
    pub fn stdout_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    pub fn stderr_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

/// A running sandboxed child process with bidirectional `stdin`/`stdout`/`stderr` pipes.
///
/// Automatically kills and reaps the child process on `Drop` if still alive.
pub struct SpawnedSandbox {
    child_pid: i32,
    in_pid_ns: bool,
    pub stdin: Option<OwnedFd>,
    pub stdout: Option<OwnedFd>,
    pub stderr: Option<OwnedFd>,
    pub setup_time: Duration,
    _cgroup: Option<CgroupGuard>,
    _cow: Option<CowSession>,
    reaped: bool,
}

impl SpawnedSandbox {
    /// Returns the host PID of the spawned sandbox process.
    pub fn pid(&self) -> i32 {
        self.child_pid
    }

    /// Terminate the sandboxed process (and its process group) and reap it.
    pub fn kill_and_wait(&mut self) {
        if !self.reaped {
            self.stdin = None;
            kill_sandbox_child(self.child_pid, self.in_pid_ns);
            reap_child(self.child_pid);
            self.reaped = true;
        }
    }
}

impl Drop for SpawnedSandbox {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

impl PreparedSandbox {
    /// Spawn the sandboxed process in the background with piped `stdin`, `stdout`, and `stderr`.
    /// Used by `ZygotePool` and long-lived interactive sandboxed workers.
    pub fn spawn_piped(&self) -> Result<SpawnedSandbox, SandboxError> {
        let t_start = Instant::now();

        let cgroup = CgroupGuard::create(&self.limits)?;
        let cgroup_active = cgroup.is_some();
        let sync_needed = self.namespaces.enabled || cgroup_active;

        let cow_session = if self.namespaces.enabled {
            CowSession::create(&self.ephemeral_cow)?
        } else {
            None
        };
        let cow_mounts = cow_session
            .as_ref()
            .map(|s| s.mounts.as_slice())
            .unwrap_or(&[]);

        let (sync_rx, sync_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(sync)",
            errno: RawErrno(e.raw_os_error()),
        })?;
        let (err_rx, err_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(err)",
            errno: RawErrno(e.raw_os_error()),
        })?;
        let (in_rx, in_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(stdin)",
            errno: RawErrno(e.raw_os_error()),
        })?;
        let (out_rx, out_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(stdout)",
            errno: RawErrno(e.raw_os_error()),
        })?;
        let (se_rx, se_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(stderr)",
            errno: RawErrno(e.raw_os_error()),
        })?;

        let mut clone_flags = 0u64;
        if self.namespaces.enabled {
            clone_flags |= flags::CLONE_NEWUSER
                | flags::CLONE_NEWPID
                | flags::CLONE_NEWNS
                | flags::CLONE_NEWIPC
                | flags::CLONE_NEWUTS;
            if self.namespaces.isolate_network {
                clone_flags |= flags::CLONE_NEWNET;
            }
        }

        let cgroup_fd = cgroup.as_ref().and_then(|cg| cg.open_dir_fd().ok());
        let mut clone_args = CloneArgs {
            flags: clone_flags,
            exit_signal: SIGCHLD,
            ..Default::default()
        };
        let mut used_clone_into_cgroup = false;
        if let Some(ref fd) = cgroup_fd {
            clone_args.flags |= flags::CLONE_INTO_CGROUP;
            clone_args.cgroup = fd.as_raw_fd() as u64;
            used_clone_into_cgroup = true;
        }

        let parent_pid = getpid().as_raw_nonzero().get();
        let sync_rx_raw = sync_rx.as_raw_fd();
        let err_tx_raw = err_tx.as_raw_fd();
        let stdio_raw = (
            Some(in_rx.as_raw_fd()),
            Some(out_tx.as_raw_fd()),
            Some(se_tx.as_raw_fd()),
        );

        let clone_res = match unsafe { clone3(&mut clone_args) } {
            Err(RawErrno(38)) if used_clone_into_cgroup => {
                used_clone_into_cgroup = false;
                clone_args.flags &= !flags::CLONE_INTO_CGROUP;
                clone_args.cgroup = 0;
                unsafe { clone3(&mut clone_args) }
            }
            other => other,
        };
        drop(cgroup_fd);

        let child_pid = match clone_res {
            Ok(CloneResult::Child) => {
                drop(sync_tx);
                drop(err_rx);
                drop(in_tx);
                drop(out_rx);
                drop(se_rx);
                child_main(
                    self,
                    cow_mounts,
                    parent_pid,
                    sync_rx_raw,
                    sync_needed,
                    err_tx_raw,
                    stdio_raw,
                    None,
                    None,
                );
            }
            Ok(CloneResult::Parent { child_pid }) => child_pid,
            Err(errno) => {
                return Err(SandboxError::Syscall {
                    stage: "clone3",
                    errno,
                });
            }
        };

        drop(sync_rx);
        drop(err_tx);
        drop(in_rx);
        drop(out_tx);
        drop(se_tx);

        if sync_needed {
            let setup_res: Result<(), SandboxError> = (|| {
                if self.namespaces.enabled {
                    write_userns_maps(child_pid)?;
                }
                if !used_clone_into_cgroup
                    && let Some(ref cg) = cgroup
                {
                    cg.attach_pid(child_pid)?;
                }
                Ok(())
            })();

            if let Err(err) = setup_res {
                let _ = write(&sync_tx, b"E");
                drop(sync_tx);
                reap_child(child_pid);
                return Err(err);
            }
            if let Err(e) = write(&sync_tx, b"K") {
                drop(sync_tx);
                reap_child(child_pid);
                return Err(SandboxError::Syscall {
                    stage: "write(sync_tx)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
        drop(sync_tx);

        let mut err_buf = [0u8; 8];
        let mut filled = 0usize;
        while filled < err_buf.len() {
            match read(&err_rx, &mut err_buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(Errno::INTR) => continue,
                Err(e) => {
                    reap_child(child_pid);
                    return Err(SandboxError::Syscall {
                        stage: "read(err_rx)",
                        errno: RawErrno(e.raw_os_error()),
                    });
                }
            }
        }
        drop(err_rx);

        if filled == 8 {
            let stage_id = u32::from_ne_bytes([err_buf[0], err_buf[1], err_buf[2], err_buf[3]]);
            let errno = i32::from_ne_bytes([err_buf[4], err_buf[5], err_buf[6], err_buf[7]]);
            reap_child(child_pid);
            return Err(SandboxError::ChildSetupFailed {
                stage: ChildStage::from_u32(stage_id),
                errno: RawErrno(errno),
            });
        }

        let setup_time = t_start.elapsed();
        Ok(SpawnedSandbox {
            child_pid,
            in_pid_ns: self.namespaces.enabled,
            stdin: Some(in_tx),
            stdout: Some(out_rx),
            stderr: Some(se_rx),
            setup_time,
            _cgroup: cgroup,
            _cow: cow_session,
            reaped: false,
        })
    }

    /// Spawn the prepared sandbox (inheriting stdio), wait for completion, and return status.
    pub fn run(&self) -> Result<ExecutionReport, SandboxError> {
        self.run_internal(None, None).map(|c| c.report)
    }

    /// Spawn the prepared sandbox (inheriting stdio) with a live rootless TAP FD
    /// handed to `on_tap` (e.g. `SlirpBridge::spawn_on_tap`).
    pub fn run_with_tap<F, G>(&self, on_tap: F) -> Result<ExecutionReport, SandboxError>
    where
        F: FnOnce(OwnedFd) -> Result<G, SandboxError> + 'static,
        G: Send + 'static,
    {
        let cb: TapAttachCallback = Box::new(move |fd| Ok(Box::new(on_tap(fd)?) as Box<dyn Send>));
        self.run_internal(None, Some(cb)).map(|c| c.report)
    }

    /// Spawn the prepared sandbox while capturing `stdout` and `stderr` (bounded to
    /// `max_output_bytes` per stream to prevent memory exhaustion from noisy children).
    pub fn run_captured(
        &self,
        max_output_bytes: usize,
    ) -> Result<CapturedExecutionReport, SandboxError> {
        self.run_internal(Some(max_output_bytes), None)
    }

    /// Spawn the prepared sandbox with captured `stdout`/`stderr` AND a live rootless
    /// TAP FD handed to `on_tap` (e.g. `SlirpBridge::spawn_on_tap`).
    pub fn run_captured_with_tap<F, G>(
        &self,
        max_output_bytes: usize,
        on_tap: F,
    ) -> Result<CapturedExecutionReport, SandboxError>
    where
        F: FnOnce(OwnedFd) -> Result<G, SandboxError> + 'static,
        G: Send + 'static,
    {
        let cb: TapAttachCallback = Box::new(move |fd| Ok(Box::new(on_tap(fd)?) as Box<dyn Send>));
        self.run_internal(Some(max_output_bytes), Some(cb))
    }

    fn run_internal(
        &self,
        capture_limit: Option<usize>,
        on_tap: Option<TapAttachCallback>,
    ) -> Result<CapturedExecutionReport, SandboxError> {
        let t_start = Instant::now();

        // Prepare ephemeral Cgroups v2 leaf directory in parent (if limits configured)
        let cgroup = CgroupGuard::create(&self.limits)?;
        let cgroup_active = cgroup.is_some();
        let sync_needed = self.namespaces.enabled || cgroup_active;

        // Prepare ephemeral OverlayFS CoW staging dirs (active when mount namespace is enabled)
        let cow_session = if self.namespaces.enabled {
            CowSession::create(&self.ephemeral_cow)?
        } else {
            None
        };
        let cow_mounts = cow_session
            .as_ref()
            .map(|s| s.mounts.as_slice())
            .unwrap_or(&[]);

        // Sync pipe: parent -> child (signals UID/GID map + cgroup attachment completion)
        let (sync_rx, sync_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(sync)",
            errno: RawErrno(e.raw_os_error()),
        })?;

        // Error pipe: child -> parent (EOF on successful execve, 8 bytes on error)
        let (err_rx, err_tx) = pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
            stage: "pipe2(err)",
            errno: RawErrno(e.raw_os_error()),
        })?;

        // Optional stdout/stderr capture pipes (read ends non-blocking for poll loop)
        let capture_pipes = if capture_limit.is_some() {
            let (out_rx, out_tx) =
                pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
                    stage: "pipe2(stdout)",
                    errno: RawErrno(e.raw_os_error()),
                })?;
            let (se_rx, se_tx) =
                pipe_with(PipeFlags::CLOEXEC).map_err(|e| SandboxError::Syscall {
                    stage: "pipe2(stderr)",
                    errno: RawErrno(e.raw_os_error()),
                })?;
            set_nonblocking(&out_rx)?;
            set_nonblocking(&se_rx)?;
            Some((out_rx, out_tx, se_rx, se_tx))
        } else {
            None
        };

        let mut clone_flags = 0u64;
        if self.namespaces.enabled {
            clone_flags |= flags::CLONE_NEWUSER
                | flags::CLONE_NEWPID
                | flags::CLONE_NEWNS
                | flags::CLONE_NEWIPC
                | flags::CLONE_NEWUTS;
            if self.namespaces.isolate_network {
                clone_flags |= flags::CLONE_NEWNET;
            }
        }

        // Optional SCM_RIGHTS socketpair + temporary `/etc/resolv.conf` for live TAP bridge
        let tap_setup = if on_tap.is_some() && self.namespaces.enabled {
            let (parent_sock, child_sock) =
                unix_socketpair().map_err(|errno| SandboxError::Syscall {
                    stage: "socketpair(tap)",
                    errno,
                })?;
            let seq = RESOLV_SEQ.fetch_add(1, Ordering::Relaxed);
            let resolv_path = std::env::temp_dir().join(format!(
                "rsb-resolv-{}-{seq}.conf",
                getpid().as_raw_nonzero().get()
            ));
            let _ = std::fs::write(&resolv_path, b"nameserver 10.0.2.2\n");
            let resolv_cstr = CString::new(resolv_path.as_os_str().as_bytes()).ok();
            Some((parent_sock, child_sock, TempFileGuard(resolv_path), resolv_cstr))
        } else {
            None
        };

        // Attempt atomic `CLONE_INTO_CGROUP` (eliminates fork-bomb race before cgroup attach).
        let cgroup_fd = cgroup.as_ref().and_then(|cg| cg.open_dir_fd().ok());
        let mut clone_args = CloneArgs {
            flags: clone_flags,
            exit_signal: SIGCHLD,
            ..Default::default()
        };
        let mut used_clone_into_cgroup = false;
        if let Some(ref fd) = cgroup_fd {
            clone_args.flags |= flags::CLONE_INTO_CGROUP;
            clone_args.cgroup = fd.as_raw_fd() as u64;
            used_clone_into_cgroup = true;
        }

        let parent_pid = getpid().as_raw_nonzero().get();
        let sync_rx_raw = sync_rx.as_raw_fd();
        let err_tx_raw = err_tx.as_raw_fd();
        let stdio_raw = match capture_pipes.as_ref() {
            Some((_, out_tx, _, se_tx)) => (None, Some(out_tx.as_raw_fd()), Some(se_tx.as_raw_fd())),
            None => (None, None, None),
        };

        // SAFETY: `child_main` performs strictly async-signal-safe operations
        // with zero heap allocation before `execve` / `exit_group`.
        let clone_res = match unsafe { clone3(&mut clone_args) } {
            Err(RawErrno(38)) if used_clone_into_cgroup => {
                // Outer seccomp returned ENOSYS for clone3(CLONE_INTO_CGROUP); retry without it
                // and fall back to writing `cgroup.procs` before waking child.
                used_clone_into_cgroup = false;
                clone_args.flags &= !flags::CLONE_INTO_CGROUP;
                clone_args.cgroup = 0;
                unsafe { clone3(&mut clone_args) }
            }
            other => other,
        };
        drop(cgroup_fd);

        let tap_child_raw = tap_setup.as_ref().map(|(_, c, _, _)| c.as_raw_fd());
        let resolv_cstr_ref = tap_setup
            .as_ref()
            .and_then(|(_, _, _, cs)| cs.as_deref());

        let child_pid = match clone_res {
            Ok(CloneResult::Child) => {
                drop(sync_tx);
                drop(err_rx);
                if let Some((out_rx, _out_tx, se_rx, _se_tx)) = capture_pipes {
                    drop(out_rx);
                    drop(se_rx);
                    // Keep _out_tx and _se_tx open until dup2 + execve (O_CLOEXEC closes them)
                    child_main(
                        self,
                        cow_mounts,
                        parent_pid,
                        sync_rx_raw,
                        sync_needed,
                        err_tx_raw,
                        stdio_raw,
                        tap_child_raw,
                        resolv_cstr_ref,
                    );
                } else {
                    child_main(
                        self,
                        cow_mounts,
                        parent_pid,
                        sync_rx_raw,
                        sync_needed,
                        err_tx_raw,
                        (None, None, None),
                        tap_child_raw,
                        resolv_cstr_ref,
                    );
                }
            }
            Ok(CloneResult::Parent { child_pid }) => child_pid,
            Err(errno) => {
                return Err(SandboxError::Syscall {
                    stage: "clone3",
                    errno,
                });
            }
        };

        // Parent: drop child-only pipe ends so EOF works properly.
        drop(sync_rx);
        drop(err_tx);
        let mut capture_readers = capture_pipes.map(|(out_rx, out_tx, se_rx, se_tx)| {
            drop(out_tx);
            drop(se_tx);
            (Some(out_rx), Some(se_rx))
        });

        // Perform parent-side setup (userns maps + fallback cgroup attachment) before waking child.
        if sync_needed {
            let setup_res: Result<(), SandboxError> = (|| {
                if self.namespaces.enabled {
                    write_userns_maps(child_pid)?;
                }
                if !used_clone_into_cgroup
                    && let Some(ref cg) = cgroup
                {
                    cg.attach_pid(child_pid)?;
                }
                Ok(())
            })();

            if let Err(err) = setup_res {
                let _ = write(&sync_tx, b"E");
                drop(sync_tx);
                reap_child(child_pid);
                return Err(err);
            }

            if let Err(e) = write(&sync_tx, b"K") {
                drop(sync_tx);
                reap_child(child_pid);
                return Err(SandboxError::Syscall {
                    stage: "write(sync_tx)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
        drop(sync_tx);

        // If transparent TAP networking is active, receive `tap_fd` via SCM_RIGHTS
        // and attach the caller's live `SlirpBridge` before the child completes `execve`.
        let mut _tap_guard: Option<Box<dyn Send>> = None;
        let _resolv_guard: Option<TempFileGuard> = if let Some((parent_sock, child_sock, rguard, _)) =
            tap_setup
        {
            drop(child_sock);
            if let Some(cb) = on_tap {
                match recv_fd(parent_sock.as_raw_fd()) {
                    Ok(tap_fd) => {
                        _tap_guard = Some(cb(tap_fd)?);
                    }
                    Err(_) => {
                        // Child likely failed at TapSetup and wrote to `err_rx`; let `err_rx` report exact stage!
                    }
                }
            }
            drop(parent_sock);
            Some(rguard)
        } else {
            None
        };

        // Wait for either an 8-byte error packet or EOF (indicating successful execve).
        let mut err_buf = [0u8; 8];
        let mut filled = 0usize;
        while filled < err_buf.len() {
            match read(&err_rx, &mut err_buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(Errno::INTR) => continue,
                Err(e) => {
                    reap_child(child_pid);
                    return Err(SandboxError::Syscall {
                        stage: "read(err_rx)",
                        errno: RawErrno(e.raw_os_error()),
                    });
                }
            }
        }
        drop(err_rx);

        if filled == 8 {
            let stage_id = u32::from_ne_bytes([err_buf[0], err_buf[1], err_buf[2], err_buf[3]]);
            let errno = i32::from_ne_bytes([err_buf[4], err_buf[5], err_buf[6], err_buf[7]]);
            reap_child(child_pid);
            return Err(SandboxError::ChildSetupFailed {
                stage: ChildStage::from_u32(stage_id),
                errno: RawErrno(errno),
            });
        }

        // At this exact point, `execve` has succeeded inside the isolated sandbox.
        let setup_time = t_start.elapsed();
        let deadline = self.limits.timeout.map(|d| Instant::now() + d);

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut stdout_truncated = false;
        let mut stderr_truncated = false;

        let (status, timed_out) = if let (Some(max_bytes), Some((out_opt, err_opt))) =
            (capture_limit, capture_readers.as_mut())
        {
            wait_and_capture(
                child_pid,
                self.namespaces.enabled,
                deadline,
                out_opt,
                err_opt,
                max_bytes,
                &mut stdout_buf,
                &mut stderr_buf,
                &mut stdout_truncated,
                &mut stderr_truncated,
            )?
        } else {
            wait_with_timeout(child_pid, self.namespaces.enabled, deadline)?
        };

        let total_time = t_start.elapsed();
        let memory_peak_bytes = cgroup.as_ref().and_then(|cg| cg.read_memory_peak());
        drop(_tap_guard);
        drop(_resolv_guard);
        drop(cgroup);

        let cow_diffs = cow_session
            .as_ref()
            .map(|s| s.collect_diffs())
            .unwrap_or_default();
        drop(cow_session);

        let report = ExecutionReport {
            exit_code: status.exit_status(),
            signal: status.terminating_signal(),
            timed_out,
            setup_time,
            total_time,
            landlock_abi: self.landlock_abi,
            seccomp_bpf_insns: self.seccomp_bpf.len(),
            namespaces_active: self.namespaces.enabled,
            cgroup_active,
            memory_peak_bytes,
        };

        Ok(CapturedExecutionReport {
            report,
            stdout: stdout_buf,
            stderr: stderr_buf,
            stdout_truncated,
            stderr_truncated,
            cow_diffs,
        })
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), SandboxError> {
    use rsb_sys::rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(fd).map_err(|e| SandboxError::Syscall {
        stage: "fcntl(F_GETFL)",
        errno: RawErrno(e.raw_os_error()),
    })?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|e| SandboxError::Syscall {
        stage: "fcntl(F_SETFL, O_NONBLOCK)",
        errno: RawErrno(e.raw_os_error()),
    })
}

fn kill_sandbox_child(child_pid: i32, in_pid_ns: bool) {
    if let Some(pid) = Pid::from_raw(child_pid) {
        if !in_pid_ns {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        let _ = kill_process(pid, Signal::KILL);
    }
}

fn wait_with_timeout(
    child_pid: i32,
    in_pid_ns: bool,
    deadline: Option<Instant>,
) -> Result<(WaitStatus, bool), SandboxError> {
    let Some(deadline) = deadline else {
        return Ok((wait_for_child_blocking(child_pid)?, false));
    };

    let pid = make_pid(child_pid)?;
    loop {
        match waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some((_p, status))) => return Ok((status, false)),
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    kill_sandbox_child(child_pid, in_pid_ns);
                    let status = wait_for_child_blocking(child_pid)?;
                    return Ok((status, true));
                }
                let remaining = deadline.saturating_duration_since(now);
                std::thread::sleep(remaining.min(Duration::from_millis(2)));
            }
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "waitpid",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn wait_and_capture(
    child_pid: i32,
    in_pid_ns: bool,
    deadline: Option<Instant>,
    out_rx: &mut Option<OwnedFd>,
    err_rx: &mut Option<OwnedFd>,
    max_bytes: usize,
    stdout_buf: &mut Vec<u8>,
    stderr_buf: &mut Vec<u8>,
    stdout_truncated: &mut bool,
    stderr_truncated: &mut bool,
) -> Result<(WaitStatus, bool), SandboxError> {
    let pid = make_pid(child_pid)?;
    let mut exit_status: Option<WaitStatus> = None;
    let mut timed_out = false;
    let mut tmp = [0u8; 4096];

    loop {
        // 1. Check if child has already exited (non-blocking).
        if exit_status.is_none() {
            match waitpid(Some(pid), WaitOptions::NOHANG) {
                Ok(Some((_p, st))) => exit_status = Some(st),
                Ok(None) => {}
                Err(Errno::INTR) => continue,
                Err(e) => {
                    return Err(SandboxError::Syscall {
                        stage: "waitpid",
                        errno: RawErrno(e.raw_os_error()),
                    });
                }
            }
        }

        // 2. Enforce timeout if child is still alive.
        if exit_status.is_none()
            && let Some(dl) = deadline
            && Instant::now() >= dl
        {
            timed_out = true;
            kill_sandbox_child(child_pid, in_pid_ns);
            exit_status = Some(wait_for_child_blocking(child_pid)?);
        }

        // 3. Drain any available data from open pipes.
        drain_pipe(out_rx, &mut tmp, stdout_buf, max_bytes, stdout_truncated);
        drain_pipe(err_rx, &mut tmp, stderr_buf, max_bytes, stderr_truncated);

        // 4. Done when child has exited AND both pipes hit EOF.
        if let Some(status) = exit_status
            && out_rx.is_none()
            && err_rx.is_none()
        {
            return Ok((status, timed_out));
        }

        // 5. Poll open pipes with a short timeout so we stay responsive to deadlines.
        let poll_timeout_ms: i64 = match deadline {
            Some(dl) if exit_status.is_none() => {
                let rem = dl.saturating_duration_since(Instant::now());
                (rem.as_millis() as i64).clamp(1, 10)
            }
            _ => 10,
        };
        let ts = Timespec {
            tv_sec: poll_timeout_ms / 1000,
            tv_nsec: (poll_timeout_ms % 1000) * 1_000_000,
        };

        let mut poll_fds: Vec<PollFd<'_>> = Vec::with_capacity(2);
        if let Some(fd) = out_rx.as_ref() {
            poll_fds.push(PollFd::new(fd, PollFlags::IN));
        }
        if let Some(fd) = err_rx.as_ref() {
            poll_fds.push(PollFd::new(fd, PollFlags::IN));
        }

        if poll_fds.is_empty() {
            // Child closed stdout/stderr early but hasn't exited yet.
            std::thread::sleep(Duration::from_millis(2));
        } else {
            let _ = poll(&mut poll_fds, Some(&ts));
        }
    }
}

fn drain_pipe(
    fd_opt: &mut Option<OwnedFd>,
    tmp: &mut [u8],
    dest: &mut Vec<u8>,
    max_bytes: usize,
    truncated: &mut bool,
) {
    let Some(fd) = fd_opt.as_ref() else {
        return;
    };
    loop {
        match read(fd, &mut *tmp) {
            Ok(0) => {
                *fd_opt = None;
                break;
            }
            Ok(n) => {
                let remaining = max_bytes.saturating_sub(dest.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    dest.extend_from_slice(&tmp[..take]);
                    if take < n {
                        *truncated = true;
                    }
                } else {
                    *truncated = true;
                }
            }
            Err(Errno::AGAIN | Errno::INTR) => break,
            Err(_) => {
                *fd_opt = None;
                break;
            }
        }
    }
}

/// Write `/proc/<pid>/{setgroups,uid_map,gid_map}` to map host EUID/EGID -> 0 inside userns.
fn write_userns_maps(child_pid: i32) -> Result<(), SandboxError> {
    let euid = geteuid().as_raw();
    let egid = getegid().as_raw();

    std::fs::write(format!("/proc/{child_pid}/setgroups"), b"deny\n")?;
    std::fs::write(format!("/proc/{child_pid}/uid_map"), format!("0 {euid} 1\n"))?;
    std::fs::write(format!("/proc/{child_pid}/gid_map"), format!("0 {egid} 1\n"))?;
    Ok(())
}

fn make_pid(child_pid: i32) -> Result<Pid, SandboxError> {
    Pid::from_raw(child_pid).ok_or(SandboxError::Syscall {
        stage: "waitpid(invalid pid)",
        errno: RawErrno(22),
    })
}

fn wait_for_child_blocking(child_pid: i32) -> Result<WaitStatus, SandboxError> {
    let pid = make_pid(child_pid)?;
    loop {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_pid, status))) => return Ok(status),
            Ok(None) => continue,
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "waitpid",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    }
}

fn reap_child(child_pid: i32) {
    let _ = wait_for_child_blocking(child_pid);
}
