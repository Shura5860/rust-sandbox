//! Example: Using `rsb-core` as an embeddable AI agent sandbox SDK.
//!
//! Run with:
//!   cargo run -p rsb-core --example ai_sandbox

use rsb_core::{Sandbox, ZygoteConfig, ZygotePool, landlock_abi_version};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let landlock_ok = landlock_abi_version().is_ok();

    // 1. One-shot captured execution (network blocked, 2s timeout, Landlock + Seccomp-BPF)
    let cap = Sandbox::builder("/usr/bin/python3")
        .args(["-c", "print('sum =', sum(range(101)))"])
        .namespaces(false) // set to `true` on standard Linux hosts for full rootless namespaces
        .landlock(landlock_ok)
        .seccomp(true)
        .allow_network(false)
        .allow_system_runtime()
        .timeout(Duration::from_secs(2))
        .run_captured(64 * 1024)?;

    println!(
        "[one-shot] ok={} setup={:.3}ms total={:.3}ms stdout={}",
        cap.report.success(),
        cap.report.setup_time.as_secs_f64() * 1000.0,
        cap.report.total_time.as_secs_f64() * 1000.0,
        cap.stdout_lossy().trim()
    );

    // 2. Pre-warmed Zygote fork server for repeated sub-2ms Python executions
    let cfg = ZygoteConfig {
        namespaces: false,
        landlock: landlock_ok,
        seccomp: true,
        allow_network: false,
        ..Default::default()
    };
    let mut pool = ZygotePool::start_python(cfg)?;
    for n in [5, 8, 10] {
        let code = format!("import math; print(f'{n}! = {{math.factorial({n})}}')");
        let res = pool.exec(&code, Duration::from_secs(2))?;
        println!(
            "[zygote]   ok={} roundtrip={:.3}ms stdout={}",
            res.success(),
            res.roundtrip_time.as_secs_f64() * 1000.0,
            res.stdout.trim()
        );
    }
    pool.shutdown();

    Ok(())
}
