//! Integration tests for `rsb-core` (Landlock, Seccomp-BPF, Timeout, Output Capture,
//! `rsb learn`, `sandbox.toml` profiles, and Rootless Namespaces).

use rsb_core::{
    ChildStage, NodeZygoteConfig, Sandbox, SandboxError, SandboxProfile, UnotifyDecision,
    ZygoteConfig, ZygotePool, landlock_abi_version, run_supervised,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rsb-test-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

#[test]
fn landlock_blocks_unlisted_secret_and_allows_rw_dir() {
    if landlock_abi_version().is_err() {
        eprintln!("skipping test: Landlock not supported on this kernel");
        return;
    }

    let root = temp_test_dir("landlock");
    let allowed = root.join("allowed");
    let secret = root.join("secret");
    fs::create_dir_all(&allowed).unwrap();
    fs::create_dir_all(&secret).unwrap();
    let secret_file = secret.join("token.txt");
    fs::write(&secret_file, "TOP_SECRET").unwrap();

    // 1. Attempt to read secret file (NOT in Landlock rules) -> must fail
    let cap_denied = Sandbox::builder("/bin/cat")
        .arg(&secret_file)
        .namespaces(false)
        .landlock(true)
        .seccomp(true)
        .allow_system_runtime()
        .rw(&allowed)
        .run_captured(64 * 1024)
        .expect("sandbox execution should complete");

    assert!(
        !cap_denied.report.success(),
        "cat on unlisted secret file must be denied by Landlock"
    );
    assert!(
        cap_denied.stderr_lossy().contains("Permission denied"),
        "expected Permission denied in stderr, got: {}",
        cap_denied.stderr_lossy()
    );

    // 2. Attempt to write inside `allowed` dir -> must succeed
    let target_file = allowed.join("hello.txt");
    let report_allowed = Sandbox::builder("/bin/sh")
        .args(["-c", &format!("echo ok > {}", target_file.display())])
        .namespaces(false)
        .landlock(true)
        .seccomp(true)
        .allow_system_runtime()
        .rw(&allowed)
        .run()
        .expect("sandbox execution should complete");

    assert!(
        report_allowed.success(),
        "writing to --rw allowed dir must succeed (report: {report_allowed:?})"
    );
    assert_eq!(fs::read_to_string(&target_file).unwrap().trim(), "ok");
    assert!(
        report_allowed.seccomp_bpf_insns > 20,
        "Seccomp-BPF filter should be active"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn seccomp_blocks_inet_socket_with_eperm() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping test: /usr/bin/python3 not found");
        return;
    }

    let cap = Sandbox::builder("/usr/bin/python3")
        .args([
            "-c",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        ])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_network(false)
        .allow_system_runtime()
        .run_captured(64 * 1024)
        .expect("sandbox execution should complete");

    assert!(
        !cap.report.success(),
        "AF_INET socket must be blocked by Seccomp-BPF"
    );
    let stderr = cap.stderr_lossy();
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("PermissionError"),
        "expected EPERM from Seccomp-BPF, got stderr: {stderr}"
    );
}

#[test]
fn timeout_kills_infinite_loop_and_captures_output() {
    let cap = Sandbox::builder("/bin/sh")
        .args(["-c", "echo starting; sleep 10; echo never"])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .timeout(Duration::from_millis(120))
        .run_captured(64 * 1024)
        .expect("sandbox execution should complete");

    assert!(cap.report.timed_out, "expected timed_out = true");
    assert!(!cap.report.success());
    assert!(
        cap.report.total_time < Duration::from_secs(2),
        "timeout should kill promptly, took {:?}",
        cap.report.total_time
    );
    assert_eq!(cap.stdout_lossy().trim(), "starting");
}

#[test]
fn captured_output_truncates_at_limit() {
    let cap = Sandbox::builder("/bin/sh")
        .args(["-c", "printf '0123456789abcdef'"])
        .namespaces(false)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run_captured(8)
        .expect("sandbox execution should complete");

    assert!(cap.report.success());
    assert!(cap.stdout_truncated);
    assert_eq!(cap.stdout, b"01234567");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn learn_policy_discovers_read_and_write_paths_and_replays_with_profile() {
    let root = temp_test_dir("learn");
    let in_dir = root.join("input");
    let out_dir = root.join("output");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    let in_file = in_dir.join("data.txt");
    let out_file = out_dir.join("result.txt");
    fs::write(&in_file, "learned-payload").unwrap();

    let script = format!("cat {} > {}", in_file.display(), out_file.display());
    let learn_res = rsb_core::learn_policy("/bin/sh", ["-c", &script]);

    let report = match learn_res {
        Ok(r) => r,
        Err(SandboxError::Syscall { errno, .. }) if matches!(errno.0, 1 | 13 | 38) => {
            eprintln!(
                "skipping learn test: outer environment restricts ptrace (errno={})",
                errno.0
            );
            let _ = fs::remove_dir_all(&root);
            return;
        }
        Err(e) => panic!("unexpected learn_policy error: {e}"),
    };

    assert_eq!(report.exit_code, Some(0));
    assert!(!report.observed_syscalls.is_empty());
    assert!(!report.network_used);
    assert!(
        report.profile.ro.iter().any(|p| p == &in_dir),
        "expected learned ro to contain {}, got {:?}",
        in_dir.display(),
        report.profile.ro
    );
    assert!(
        report.profile.rw.iter().any(|p| p == &out_dir),
        "expected learned rw to contain {}, got {:?}",
        out_dir.display(),
        report.profile.rw
    );

    // Round-trip through TOML and replay under Landlock + Seccomp!
    let toml_text = report.profile.to_toml();
    let mut parsed = SandboxProfile::from_toml(&toml_text).expect("parse learned toml");
    parsed.namespaces = false; // run in Landlock + Seccomp mode so it works inside nested sandboxes

    fs::remove_file(&out_file).unwrap();
    let replay = Sandbox::builder("/bin/sh")
        .args(["-c", &script])
        .with_profile(&parsed)
        .run()
        .expect("replay with learned profile");
    assert!(replay.success(), "replay with learned profile must succeed");
    assert_eq!(fs::read_to_string(&out_file).unwrap().trim(), "learned-payload");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn zygote_pool_isolates_memory_inherits_seccomp_and_survives_timeout() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping zygote test: /usr/bin/python3 not found");
        return;
    }

    let cfg = ZygoteConfig {
        namespaces: false,
        landlock: landlock_abi_version().is_ok(),
        seccomp: true,
        allow_network: false,
        ..Default::default()
    };
    let mut pool = ZygotePool::start_python(cfg).expect("start python zygote pool");

    // 1. Mutate global state in worker #1
    let r1 = pool
        .exec(
            "import sys, math; sys._rsb_test_secret = 999; print(math.factorial(6))",
            Duration::from_secs(2),
        )
        .expect("zygote exec 1");
    assert!(r1.success(), "r1 failed: {r1:?}");
    assert_eq!(r1.stdout.trim(), "720");

    // 2. Worker #2 must NOT see worker #1's mutated global (CoW isolation)
    let r2 = pool
        .exec(
            "import sys; print(hasattr(sys, '_rsb_test_secret'))",
            Duration::from_secs(2),
        )
        .expect("zygote exec 2");
    assert!(r2.success(), "r2 failed: {r2:?}");
    assert_eq!(r2.stdout.trim(), "False");

    // 3. Worker #3 must inherit Seccomp-BPF and block AF_INET with EPERM
    let r3 = pool
        .exec(
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
            Duration::from_secs(2),
        )
        .expect("zygote exec 3");
    assert!(!r3.success(), "AF_INET must be blocked inside zygote worker");
    assert!(
        r3.stderr.contains("Operation not permitted") || r3.stderr.contains("PermissionError"),
        "expected EPERM in zygote stderr, got: {}",
        r3.stderr
    );

    // 4. Worker #4 times out, and worker #5 still succeeds on the same warm pool!
    let r4 = pool
        .exec("import time; time.sleep(5)", Duration::from_millis(100))
        .expect("zygote exec 4");
    assert!(r4.timed_out, "expected worker 4 to time out");

    let r5 = pool
        .exec("print('pool-alive')", Duration::from_secs(2))
        .expect("zygote exec 5");
    assert!(r5.success(), "pool must remain healthy after worker timeout");
    assert_eq!(r5.stdout.trim(), "pool-alive");

    pool.shutdown();
}

#[cfg(target_arch = "x86_64")]
#[test]
fn strict_syscall_allowlist_replays_target_and_blocks_unobserved_syscalls() {
    let learn_res = rsb_core::learn_policy_with_options("/bin/sh", ["-c", "echo allowlist-ok"], true);
    let report = match learn_res {
        Ok(r) => r,
        Err(SandboxError::Syscall { errno, .. }) if matches!(errno.0, 1 | 13 | 38) => {
            eprintln!("skipping strict allowlist test: ptrace restricted (errno={})", errno.0);
            return;
        }
        Err(e) => panic!("unexpected learn_policy_with_options error: {e}"),
    };

    assert!(
        report.profile.allow_syscalls.is_some(),
        "strict mode must populate allow_syscalls"
    );

    // Round-trip through TOML
    let toml_str = report.profile.to_toml();
    assert!(toml_str.contains("[seccomp]"));
    assert!(toml_str.contains("mode = \"allowlist\""));
    let mut parsed = SandboxProfile::from_toml(&toml_str).expect("parse strict allowlist toml");
    parsed.namespaces = false;

    // 1. Replaying the exact learned command succeeds under strict allowlist!
    let ok_run = Sandbox::builder("/bin/sh")
        .args(["-c", "echo allowlist-ok"])
        .with_profile(&parsed)
        .run_captured(64 * 1024)
        .expect("replay under strict allowlist");
    assert!(
        ok_run.report.success(),
        "learned command must succeed under its own allowlist: stderr={}",
        ok_run.stderr_lossy()
    );
    assert_eq!(ok_run.stdout_lossy().trim(), "allowlist-ok");

    // 2. Attempting an unobserved syscall (`mkdir` = SYS_mkdir 83 / SYS_mkdirat 258) is blocked with EPERM!
    let tmp_dir = temp_test_dir("strict-allowlist");
    parsed.rw.push(tmp_dir.clone());
    let target_sub = tmp_dir.join("should_fail");
    let blocked_run = Sandbox::builder("/bin/sh")
        .args(["-c", &format!("/bin/mkdir {}", target_sub.display())])
        .with_profile(&parsed)
        .run_captured(64 * 1024)
        .expect("run unobserved syscall under strict allowlist");
    assert!(
        !blocked_run.report.success(),
        "unobserved mkdir syscall must be blocked by strict allowlist"
    );
    assert!(!target_sub.exists(), "mkdir must not have created directory");

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn seccomp_unotify_intercepts_and_dynamically_denies_syscall() {
    // Trap SYS_getpid (39) and return a synthetic PID (4242) via live seccomp_unotify!
    const SYS_GETPID: u32 = 39;
    let res = run_supervised(
        "/bin/sh",
        ["-c", "test $$ -eq 4242"],
        &[SYS_GETPID],
        |notif| {
            assert_eq!(notif.data.nr as u32, SYS_GETPID);
            UnotifyDecision::ReturnValue(4242)
        },
    );

    match res {
        Ok(report) => {
            assert!(
                report.intercepted_count >= 1,
                "expected at least 1 intercepted getpid syscall"
            );
            assert_eq!(
                report.exit_code,
                Some(0),
                "shell $$ should observe spoofed PID 4242 from seccomp_unotify"
            );
        }
        Err(SandboxError::Syscall { errno, .. }) if matches!(errno.0, 1 | 13 | 16 | 38) => {
            eprintln!(
                "skipping unotify test: outer environment restricts or already holds seccomp_unotify listener (errno={})",
                errno.0
            );
        }
        Err(e) => panic!("unexpected run_supervised error: {e}"),
    }
}

#[test]
fn node_zygote_executes_isolated_js_if_node_installed() {
    if !Path::new("/usr/bin/node").exists() {
        eprintln!("skipping node zygote test: /usr/bin/node not installed");
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

    let r1 = pool
        .exec("globalThis.leaked = 123; console.log(6 * 7);", Duration::from_secs(2))
        .expect("node zygote 1");
    assert!(r1.success(), "node r1 failed: {r1:?}");
    assert_eq!(r1.stdout.trim(), "42");

    let r2 = pool
        .exec("console.log(typeof globalThis.leaked);", Duration::from_secs(2))
        .expect("node zygote 2");
    assert!(r2.success());
    assert_eq!(r2.stdout.trim(), "undefined");

    pool.shutdown();
}

#[test]
fn full_rootless_namespaces_and_landlock() {
    let report = Sandbox::builder("/bin/true")
        .namespaces(true)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_system_runtime()
        .run();

    match report {
        Ok(r) => {
            assert!(r.success(), "true inside full sandbox should exit 0: {r:?}");
            assert!(r.namespaces_active);
            eprintln!(
                "full rootless sandbox cold-start setup: {:.3}ms (total {:.3}ms)",
                r.setup_time.as_secs_f64() * 1000.0,
                r.total_time.as_secs_f64() * 1000.0
            );
        }
        Err(SandboxError::Syscall { stage: "clone3", errno })
            if matches!(errno.0, 1 | 13 | 38) =>
        {
            eprintln!(
                "skipping full namespace assertion: outer environment blocks clone3(CLONE_NEWUSER) (errno={})",
                errno.0
            );
        }
        Err(SandboxError::ChildSetupFailed {
            stage: ChildStage::MountPrivate,
            errno,
        }) if matches!(errno.0, 1 | 13) => {
            eprintln!(
                "skipping full namespace assertion: host AppArmor restricts unprivileged userns mount capabilities (errno={})",
                errno.0
            );
        }
        Err(other) => panic!("unexpected sandbox error: {other}"),
    }
}
