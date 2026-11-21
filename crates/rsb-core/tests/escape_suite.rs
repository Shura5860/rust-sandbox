//! Adversarial Escape Test Suite for `rust-sandbox`.
//!
//! Actively attempts common container/sandbox escape vectors and verifies each
//! is blocked at the Linux kernel boundary:
//! 1. Leaked non-CLOEXEC host FD audit (`/proc/self/fd` + `close_range`)
//! 2. Host environment secret sanitization (`AWS_SECRET_ACCESS_KEY` etc.)
//! 3. Symlink escape attempt from `--rw` dir to unlisted secret file
//! 4. `TIOCSTI` terminal keystroke injection attempt (`ioctl(..., 0x5412, ...)`)
//! 5. Dangerous escape syscall (`ptrace`) killed immediately with `SIGSYS` (31)
//! 6. `RLIMIT_CORE = 0` & `RLIMIT_NOFILE = 256` safety-net enforcement

use rsb_core::{NodeZygoteConfig, Sandbox, ZygoteConfig, ZygotePool, landlock_abi_version};
use rsb_sys::rustix::fs::{CWD, Mode, OFlags, openat};
use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_escape_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rsb-escape-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create escape test dir");
    dir
}

#[test]
fn escape_leaked_host_fd_closed_by_close_range() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }

    let dir = temp_escape_dir("leaked-fd");
    let secret = dir.join("host_secret.txt");
    fs::write(&secret, "HOST_SECRET_FD_CONTENT").unwrap();

    // Intentionally open WITHOUT `O_CLOEXEC` to simulate a buggy host library leaking an FD!
    let leaked_fd = openat(CWD, &secret, OFlags::RDONLY, Mode::empty()).expect("open secret");
    let raw_num = leaked_fd.as_raw_fd();
    assert!(raw_num >= 3);

    // Child tries to read directly from the leaked FD number via os.read(raw_num, 64)
    let py_code = format!(
        "import os\ntry:\n    data = os.read({raw_num}, 64)\n    print('LEAKED:', data)\nexcept OSError as e:\n    print('BLOCKED_EBADF:', e.errno)"
    );

    let cap = Sandbox::builder("/usr/bin/python3")
        .args(["-c", &py_code])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("run leaked-fd test");

    drop(leaked_fd);
    let _ = fs::remove_dir_all(&dir);

    assert!(cap.report.success(), "stderr: {}", cap.stderr_lossy());
    assert!(
        cap.stdout_lossy().contains("BLOCKED_EBADF: 9"),
        "leaked host FD {raw_num} MUST be closed by close_range! stdout={}",
        cap.stdout_lossy()
    );
}

#[test]
fn escape_host_env_secrets_sanitized_by_default() {
    // SAFETY: single-value test env key unique to this test
    unsafe {
        std::env::set_var("RSB_TEST_AWS_SECRET", "DO_NOT_LEAK_12345");
    }

    let cap = Sandbox::builder("/bin/sh")
        .args(["-c", "env"])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("run env sanitization test");

    assert!(cap.report.success());
    let out = cap.stdout_lossy();
    assert!(
        !out.contains("RSB_TEST_AWS_SECRET") && !out.contains("DO_NOT_LEAK_12345"),
        "host secret environment variable leaked into sandbox! env:\n{out}"
    );
    assert!(out.contains("PATH=/usr/local/bin:/usr/bin:/bin"));
}

#[test]
fn escape_symlink_to_secret_blocked_by_landlock() {
    if landlock_abi_version().is_err() {
        return;
    }

    let root = temp_escape_dir("symlink");
    let work = root.join("work");
    let secret_dir = root.join("secret");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&secret_dir).unwrap();
    let secret_file = secret_dir.join("shadow_sim.txt");
    fs::write(&secret_file, "ROOT_HASH_SECRET").unwrap();

    // Plant symlink inside allowed `--rw work` pointing outside to `secret/shadow_sim.txt`
    let evil_link = work.join("evil_link");
    std::os::unix::fs::symlink(&secret_file, &evil_link).unwrap();

    let cap = Sandbox::builder("/bin/cat")
        .arg(&evil_link)
        .namespaces(false)
        .landlock(true)
        .seccomp(true)
        .allow_system_runtime()
        .rw(&work)
        .run_captured(64 * 1024)
        .expect("run symlink escape test");

    let _ = fs::remove_dir_all(&root);

    assert!(
        !cap.report.success(),
        "symlink pointing outside Landlock allowed dir MUST be denied"
    );
    assert!(cap.stderr_lossy().contains("Permission denied"));
}

#[test]
fn escape_tiocsti_terminal_injection_blocked() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }

    let cap = Sandbox::builder("/usr/bin/python3")
        .args([
            "-c",
            "import fcntl; fcntl.ioctl(0, 0x5412, b'x')",
        ])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("run TIOCSTI test");

    assert!(!cap.report.success(), "TIOCSTI ioctl MUST be blocked");
    let stderr = cap.stderr_lossy();
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("PermissionError"),
        "expected EPERM on TIOCSTI, got stderr: {stderr}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn escape_dangerous_syscall_killed_with_sigsys() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }

    // Invoke raw SYS_ptrace (101) via ctypes -> Seccomp MUST kill process with SIGSYS (31)
    let cap = Sandbox::builder("/usr/bin/python3")
        .args([
            "-c",
            "import ctypes; ctypes.CDLL(None).syscall(101, 0, 0, 0, 0)",
        ])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("run ptrace kill test");

    assert!(!cap.report.success());
    assert_eq!(
        cap.report.signal,
        Some(31),
        "dangerous syscall (ptrace) MUST terminate process with SIGSYS (31), got: {:?}",
        cap.report
    );
}

#[test]
fn escape_core_dumps_disabled_and_nofile_capped_by_rlimit() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }

    let cap = Sandbox::builder("/usr/bin/python3")
        .args([
            "-c",
            "import resource; print(resource.getrlimit(resource.RLIMIT_CORE), resource.getrlimit(resource.RLIMIT_NOFILE))",
        ])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("run rlimit test");

    assert!(cap.report.success(), "stderr: {}", cap.stderr_lossy());
    let out = cap.stdout_lossy();
    assert!(
        out.contains("(0, 0)"),
        "RLIMIT_CORE must be (0, 0), got: {out}"
    );
    assert!(
        out.contains("(256, 256)"),
        "RLIMIT_NOFILE must be (256, 256), got: {out}"
    );
}

#[test]
fn escape_python_zygote_worker_cannot_access_protocol_fds() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }

    let cfg = ZygoteConfig {
        namespaces: false,
        landlock: landlock_abi_version().is_ok(),
        seccomp: true,
        allow_network: false,
        ..Default::default()
    };
    let mut pool = ZygotePool::start_python(cfg).expect("start python zygote");

    // Untrusted worker probes FDs 3..32 AND tries reading from FD 0 (stdin)
    let probe = r#"
import os
leaked = []
for fd in range(3, 32):
    try:
        os.fstat(fd)
        leaked.append(fd)
    except OSError:
        pass
stdin_data = os.read(0, 64)
print("LEAKED_FDS:", leaked, "STDIN_LEN:", len(stdin_data))
"#;
    let r1 = pool.exec(probe, Duration::from_secs(2)).expect("exec probe");
    assert!(r1.success(), "stderr: {}", r1.stderr);
    assert_eq!(
        r1.stdout.trim(),
        "LEAKED_FDS: [] STDIN_LEN: 0",
        "Python Zygote worker MUST have closed proto_in/proto_out AND redirected stdin to /dev/null!"
    );

    // Verify pool is still completely healthy
    let r2 = pool
        .exec("print('still-clean')", Duration::from_secs(2))
        .expect("exec after probe");
    assert!(r2.success());
    assert_eq!(r2.stdout.trim(), "still-clean");
    pool.shutdown();
}

#[test]
fn escape_node_zygote_worker_cannot_kill_or_corrupt_zygote_pool() {
    if !Path::new("/usr/bin/node").exists() {
        return;
    }

    let cfg = NodeZygoteConfig {
        namespaces: false,
        landlock: landlock_abi_version().is_ok(),
        seccomp: true,
        allow_network: false,
        ..Default::default()
    };
    let mut pool = ZygotePool::start_node(cfg).expect("start node zygote");

    // Classic `node:vm` escape payload that would kill an in-process vm.createContext host:
    let attack = "this.constructor.constructor('return process')().kill(process.pid, 9);";
    let r1 = pool.exec(attack, Duration::from_secs(2)).expect("exec attack");
    assert!(!r1.success(), "self-killed worker should report non-zero exit");

    // Separate OS child process means the Zygote parent MUST still be alive and clean!
    let r2 = pool
        .exec("console.log('zygote-survived');", Duration::from_secs(2))
        .expect("exec after attack");
    assert!(r2.success(), "Node Zygote must survive worker crash/escape attempt: {r2:?}");
    assert_eq!(r2.stdout.trim(), "zygote-survived");
    pool.shutdown();
}
