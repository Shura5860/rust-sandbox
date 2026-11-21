//! Async-signal-safe child process initialization (runs between `clone3` and `execve`).
//!
//! CRITICAL INVARIANT: Nothing in this module may allocate on the heap, acquire
//! locks, or panic. All failures are encoded into a fixed 8-byte packet written
//! to `err_tx` and terminated via `exit_group(127)`.

use crate::error::ChildStage;
use crate::overlay::PreparedCowMount;
use crate::prepared::PreparedSandbox;
use rsb_sys::clone3::{CloneArgs, CloneResult, SIGCHLD, clone3};
use rsb_sys::landlock;
use rsb_sys::rustix::fd::BorrowedFd;
use rsb_sys::rustix::fs::{CWD, Mode, OFlags, openat};
use rsb_sys::rustix::io::{Errno, close, read, write};
use rsb_sys::rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_bind, mount_bind_recursive,
    mount_change, unmount,
};
use rsb_sys::rustix::process::{WaitOptions, chdir, getppid, setpgid, waitpid};
use rsb_sys::rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};
use rsb_sys::seccomp::{
    SockFprog, close_range_cloexec, drop_all_capabilities, install_seccomp_filter, rlimit,
    set_no_new_privs, set_non_dumpable, set_pdeathsig, setrlimit_raw,
};
use rsb_sys::tap::{configure_tap_ipv4_raw, open_tap_raw};
use rsb_sys::unotify::send_fd;
use rsb_sys::{execve_raw, exit_group, syscall2};
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};

#[cfg(target_arch = "x86_64")]
const SYS_SETHOSTNAME: usize = 170;
#[cfg(target_arch = "aarch64")]
const SYS_SETHOSTNAME: usize = 161;

#[cfg(target_arch = "x86_64")]
const SYS_PIVOT_ROOT: usize = 155;
#[cfg(target_arch = "aarch64")]
const SYS_PIVOT_ROOT: usize = 41;

/// Write `[stage_id: u32, errno: i32]` to the parent error pipe and exit immediately.
fn fail_child(err_tx: RawFd, stage: ChildStage, errno: i32) -> ! {
    let mut packet = [0u8; 8];
    packet[0..4].copy_from_slice(&(stage as u32).to_ne_bytes());
    packet[4..8].copy_from_slice(&errno.to_ne_bytes());
    let fd = unsafe { BorrowedFd::borrow_raw(err_tx) };
    let _ = write(fd, &packet);
    exit_group(127);
}

/// Entrypoint executed inside the newly cloned child process.
#[allow(clippy::too_many_arguments)]
pub(crate) fn child_main(
    prepared: &PreparedSandbox,
    cow_mounts: &[PreparedCowMount],
    expected_parent_pid: i32,
    sync_rx: RawFd,
    sync_needed: bool,
    err_tx: RawFd,
    stdio_fds: (Option<RawFd>, Option<RawFd>, Option<RawFd>),
    tap_sock: Option<RawFd>,
    resolv_tmp: Option<&CStr>,
) -> ! {
    // 0a. Ensure child is killed with SIGKILL if host parent dies unexpectedly.
    //     Close the classic fork/exit race by checking `getppid()` right after
    //     (skipped in CLONE_NEWPID where parent is outside our PID namespace -> ppid 0).
    let _ = set_pdeathsig(9);
    if !prepared.namespaces.enabled
        && let Some(ppid) = getppid()
        && ppid.as_raw_nonzero().get() != expected_parent_pid
    {
        exit_group(127);
    }

    // 0b. If running without a dedicated PID namespace, put child in its own
    //     process group so timeout SIGKILL terminates all descendant processes.
    if !prepared.namespaces.enabled
        && let Err(e) = setpgid(None, None)
    {
        fail_child(err_tx, ChildStage::SetPgid, e.raw_os_error());
    }

    // 1. Wait for parent to finish UID/GID mapping and/or Cgroups v2 attachment.
    if sync_needed {
        let rx = unsafe { BorrowedFd::borrow_raw(sync_rx) };
        let mut token = [0u8; 1];
        match read(rx, &mut token) {
            Ok(1) if token[0] == b'K' => {}
            Ok(_) => exit_group(127),
            Err(e) => fail_child(err_tx, ChildStage::SyncRead, e.raw_os_error()),
        }
    }

    // 2. Wire redirected stdin/stdout/stderr pipes if requested.
    if let Some(in_fd) = stdio_fds.0 {
        let in_b = unsafe { BorrowedFd::borrow_raw(in_fd) };
        if let Err(e) = dup2_stdin(in_b) {
            fail_child(err_tx, ChildStage::DupStdio, e.raw_os_error());
        }
    }
    if let Some(out_fd) = stdio_fds.1 {
        let out_b = unsafe { BorrowedFd::borrow_raw(out_fd) };
        if let Err(e) = dup2_stdout(out_b) {
            fail_child(err_tx, ChildStage::DupStdio, e.raw_os_error());
        }
    }
    if let Some(err_fd) = stdio_fds.2 {
        let err_b = unsafe { BorrowedFd::borrow_raw(err_fd) };
        if let Err(e) = dup2_stderr(err_b) {
            fail_child(err_tx, ChildStage::DupStdio, e.raw_os_error());
        }
    }

    if prepared.namespaces.enabled {
        // 3. Make mount propagation private inside our new mount namespace.
        if let Err(e) = mount_change(
            c"/",
            MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
        ) {
            fail_child(err_tx, ChildStage::MountPrivate, e.raw_os_error());
        }

        // 3b. Mount ephemeral Copy-on-Write OverlayFS layers BEFORE Landlock
        //     so Landlock binds to the overlay mount and host directories stay untouched.
        for cow in cow_mounts {
            if let Err(e) = mount(
                c"overlay",
                cow.target_cstr.as_c_str(),
                c"overlay",
                MountFlags::empty(),
                cow.options_cstr.as_c_str(),
            ) {
                fail_child(err_tx, ChildStage::MountOverlay, e.raw_os_error());
            }
        }

        // 3c. Optional rootless TAP setup inside `CLONE_NEWNET` BEFORE `pivot_root` and
        //     BEFORE dropping capabilities: opens host `/dev/net/tun` (`tap0`), configures
        //     `10.0.2.15/24` + gw `10.0.2.2`, passes `tap_fd` to host `SlirpBridge` via
        //     `SCM_RIGHTS`, and closes child's `tap_fd` immediately.
        if let Some(sock_fd) = tap_sock {
            let (tap_fd, ifname) = match open_tap_raw(b"tap0") {
                Ok(pair) => pair,
                Err(e) => fail_child(err_tx, ChildStage::TapSetup, e.0),
            };
            if let Err(e) = configure_tap_ipv4_raw(
                &ifname,
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(255, 255, 255, 0),
                Ipv4Addr::new(10, 0, 2, 2),
            ) {
                fail_child(err_tx, ChildStage::TapSetup, e.0);
            }
            if prepared.rootfs.is_none()
                && let Some(resolv_src) = resolv_tmp
            {
                let _ = mount_bind(resolv_src, c"/etc/resolv.conf");
            }
            if let Err(e) = send_fd(sock_fd, tap_fd.as_raw_fd()) {
                fail_child(err_tx, ChildStage::TapSetup, e.0);
            }
            // Drop `tap_fd` immediately so untrusted code cannot touch raw L2 frames
            drop(tap_fd);
        }

        // 3d. Mount fresh `/proc` inside `CLONE_NEWPID` and mask sensitive `/proc` kernel
        //     interfaces. When `rootfs` is set, also bind-mount `resolv_tmp` into the
        //     rootfs BEFORE `pivot_root` detaches the host filesystem.
        if let Some(ref rootfs) = prepared.rootfs {
            if let Err(e) = mount_bind_recursive(rootfs.as_c_str(), rootfs.as_c_str()) {
                fail_child(err_tx, ChildStage::PivotRoot, e.raw_os_error());
            }
            if let Err(e) = chdir(rootfs.as_c_str()) {
                fail_child(err_tx, ChildStage::PivotRoot, e.raw_os_error());
            }
            if let Some(resolv_src) = resolv_tmp {
                let _ = mount_bind(resolv_src, c"./etc/resolv.conf");
            }
            let _ = mount(
                c"proc",
                c"./proc",
                c"proc",
                MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV,
                c"",
            );
            mask_proc_entries(true);

            let dot = c".";
            let ret = unsafe {
                syscall2(
                    SYS_PIVOT_ROOT,
                    dot.as_ptr() as usize,
                    dot.as_ptr() as usize,
                )
            };
            if let Err(e) = rsb_sys::RawErrno::from_raw_ret(ret) {
                fail_child(err_tx, ChildStage::PivotRoot, e.0);
            }
            if let Err(e) = unmount(c".", UnmountFlags::DETACH) {
                fail_child(err_tx, ChildStage::PivotRoot, e.raw_os_error());
            }
            if let Err(e) = chdir(c"/") {
                fail_child(err_tx, ChildStage::PivotRoot, e.raw_os_error());
            }
        } else {
            // Default mode (host rootfs): mount a fresh procfs for our PID namespace
            // and mask sensitive `/proc` subpaths so host PIDs and kernel knobs are hidden.
            let _ = mount(
                c"proc",
                c"/proc",
                c"proc",
                MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV,
                c"",
            );
            mask_proc_entries(false);
        }

        // 4. Set isolated UTS hostname if configured.
        if let Some(ref host) = prepared.hostname {
            let bytes = host.as_bytes();
            let ret = unsafe { syscall2(SYS_SETHOSTNAME, bytes.as_ptr() as usize, bytes.len()) };
            if let Err(e) = rsb_sys::RawErrno::from_raw_ret(ret) {
                fail_child(err_tx, ChildStage::SetHostname, e.0);
            }
        }

        // 4b. Drop all capabilities (bounding set + effective/permitted/inheritable)
        //     acquired by uid=0 inside the user namespace.
        drop_all_capabilities();
    }

    // 4c. Apply `setrlimit` + `PR_SET_DUMPABLE=0` defense-in-depth safety net:
    //     disable core dumps, block same-UID ptrace attach during setup, and cap open FDs.
    let _ = set_non_dumpable();
    let _ = setrlimit_raw(rlimit::RLIMIT_CORE, 0, 0);
    let nofile = prepared.limits.rlimit_nofile.unwrap_or(256);
    let _ = setrlimit_raw(rlimit::RLIMIT_NOFILE, nofile, nofile);

    // 5. Prevent privilege escalation (required for unprivileged Landlock & Seccomp).
    if let Err(e) = set_no_new_privs() {
        fail_child(err_tx, ChildStage::NoNewPrivs, e.0);
    }

    // 6. Apply Landlock LSM filesystem confinement AFTER CLONE_NEWNS so each
    //    `O_PATH` FD binds to the child's own mount namespace `vfsmount`.
    if prepared.landlock_abi.is_some() {
        let ruleset = match landlock::create_ruleset(prepared.landlock_handled_fs) {
            Ok(fd) => fd,
            Err(e) => fail_child(err_tx, ChildStage::LandlockCreate, e.0),
        };

        for rule in &prepared.landlock_rules {
            let path_fd = match openat(
                CWD,
                rule.path.as_c_str(),
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) => fail_child(err_tx, ChildStage::LandlockOpen, e.raw_os_error()),
            };

            if let Err(e) =
                landlock::add_path_beneath_rule(&ruleset, path_fd.as_raw_fd(), rule.allowed_access)
            {
                fail_child(err_tx, ChildStage::LandlockAddRule, e.0);
            }
        }

        if let Err(e) = landlock::restrict_self(&ruleset) {
            fail_child(err_tx, ChildStage::LandlockRestrict, e.0);
        }
    }

    // 7. Change working directory if requested.
    if let Some(ref dir) = prepared.cwd
        && let Err(e) = chdir(dir.as_c_str())
    {
        fail_child(err_tx, ChildStage::Chdir, e.raw_os_error());
    }

    // 8. If running inside our own PID namespace, act as a lightweight PID 1
    //    mini-init (subreaper): fork PID 2 to install Seccomp + execve, while
    //    PID 1 reaps all orphaned zombie grandchildren and propagates PID 2's exit status.
    if prepared.namespaces.enabled {
        let mut init_fork = CloneArgs {
            flags: 0,
            exit_signal: SIGCHLD,
            ..Default::default()
        };
        match unsafe { clone3(&mut init_fork) } {
            Ok(CloneResult::Child) => {
                // PID 2: fall through to Seccomp + close_range + execve!
            }
            Ok(CloneResult::Parent { child_pid: pid2 }) => {
                // Close PID 1's copies of stdio and all extra FDs (`err_tx`, `sync_rx`,
                // pipe ends) so host immediately sees EOF on `err_rx` when PID 2 execs
                // and `stdout`/`stderr` pipes close as soon as PID 2 closes them!
                unsafe {
                    close(0);
                    close(1);
                    close(2);
                    close(err_tx);
                }
                // Best-effort close remaining FDs >= 3 via close_range(3, MAX, 0)
                let _ = unsafe { rsb_sys::syscall3(436, 3, u32::MAX as usize, 0) };
                pid1_reap_loop(pid2);
            }
            Err(e) => fail_child(err_tx, ChildStage::Pid1Fork, e.0),
        }
    }

    // 8b. Install pre-compiled Seccomp-BPF filter immediately before `execve`.
    if !prepared.seccomp_bpf.is_empty() {
        let prog = SockFprog {
            len: prepared.seccomp_bpf.len() as u16,
            filter: prepared.seccomp_bpf.as_ptr(),
        };
        if let Err(e) = unsafe { install_seccomp_filter(0, &prog) } {
            fail_child(err_tx, ChildStage::SeccompInstall, e.0);
        }
    }

    // 8c. Atomically mark ALL file descriptors >= 3 as O_CLOEXEC via `close_range(2)`
    //     so no leaked host FDs can ever survive `execve` (while keeping `err_tx` open
    //     until `execve` succeeds).
    let _ = close_range_cloexec(3, u32::MAX);

    // 9. Replace process image with target binary. On success, the kernel
    //    auto-closes `err_tx` (O_CLOEXEC), signaling EOF to the parent.
    let err = unsafe {
        execve_raw(
            prepared.program.as_ptr(),
            prepared.argv_ptrs.as_ptr(),
            prepared.envp_ptrs.as_ptr(),
        )
    };
    fail_child(err_tx, ChildStage::Execve, err.0);
}

/// Zero-allocation OCI-style `/proc` masking inside `CLONE_NEWNS`.
///
/// Masks sensitive kernel directories with an empty read-only `tmpfs` and
/// sensitive files with `/dev/null` bind mounts (best-effort for paths that
/// may not exist on a given kernel or minimal rootfs).
fn mask_proc_entries(relative: bool) {
    let dirs: &[&core::ffi::CStr] = if relative {
        &[
            c"./proc/sys",
            c"./proc/irq",
            c"./proc/bus",
            c"./proc/fs",
            c"./proc/acpi",
            c"./proc/scsi",
            c"./proc/asound",
        ]
    } else {
        &[
            c"/proc/sys",
            c"/proc/irq",
            c"/proc/bus",
            c"/proc/fs",
            c"/proc/acpi",
            c"/proc/scsi",
            c"/proc/asound",
        ]
    };
    let files: &[&core::ffi::CStr] = if relative {
        &[
            c"./proc/kcore",
            c"./proc/keys",
            c"./proc/timer_list",
            c"./proc/sched_debug",
            c"./proc/sysrq-trigger",
            c"./proc/kallsyms",
            c"./proc/latency_stats",
        ]
    } else {
        &[
            c"/proc/kcore",
            c"/proc/keys",
            c"/proc/timer_list",
            c"/proc/sched_debug",
            c"/proc/sysrq-trigger",
            c"/proc/kallsyms",
            c"/proc/latency_stats",
        ]
    };
    let ro_tmpfs = MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;
    for &d in dirs {
        let _ = mount(c"tmpfs", d, c"tmpfs", ro_tmpfs, c"size=0,mode=0555");
    }
    for &f in files {
        let _ = mount_bind(c"/dev/null", f);
    }
}

/// Zero-allocation PID 1 subreaper loop inside `CLONE_NEWPID`.
///
/// Reaps all orphaned zombie grandchildren and exits with PID 2's status once
/// PID 2 terminates (or all children have exited).
fn pid1_reap_loop(pid2: i32) -> ! {
    let mut exit_code: i32 = 0;
    loop {
        match waitpid(None, WaitOptions::empty()) {
            Ok(Some((pid, status))) => {
                if pid.as_raw_nonzero().get() == pid2 {
                    if let Some(code) = status.exit_status() {
                        exit_code = code;
                    } else if let Some(sig) = status.terminating_signal() {
                        exit_code = 128 + sig;
                    }
                    // Continue reaping any remaining orphans until ECHILD
                }
            }
            Ok(None) => continue,
            Err(Errno::INTR) => continue,
            Err(Errno::CHILD) => exit_group(exit_code),
            Err(_) => exit_group(exit_code),
        }
    }
}
