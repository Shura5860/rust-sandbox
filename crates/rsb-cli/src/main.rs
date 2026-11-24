//! `rsb` — Zero-C-dependency Linux sandbox CLI.
//!
//! Usage:
//!   rsb info
//!   rsb run [OPTIONS] -- <CMD> [ARGS...]
//!   rsb ai-exec [OPTIONS] -- <CMD> [ARGS...]
//!   rsb learn [--out sandbox.toml] -- <CMD> [ARGS...]

use rsb_core::{
    CapturedExecutionReport, CowChangeKind, Sandbox, SandboxError, SandboxProfile, ZygoteConfig,
    ZygotePool, find_writable_cgroup_v2_dir, landlock_abi_version,
};
use rsb_net::{EgressPolicy, EgressProxy, SlirpBridge};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_AI_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_AI_MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB per stream

fn print_usage() {
    eprintln!(
        "\
rsb — rust-sandbox (zero-C-dependency Linux isolation engine)

USAGE:
  rsb info
  rsb run [OPTIONS] -- <COMMAND> [ARGS...]
  rsb ai-exec [OPTIONS] -- <COMMAND> [ARGS...]
  rsb learn [--strict] [--merge] [--out <PATH>] -- <COMMAND> [ARGS...]
  rsb session <start|exec|ls|stop> [ARGS...]
  rsb completions <bash|zsh|fish>
  rsb zygote-bench [--no-ns] [--iters <N>]

OPTIONS (rsb run / rsb ai-exec):
  --profile <PATH>      Load declarative sandbox.toml profile
  --preset <NAME>       Built-in preset (python-ai, node-build, strict-offline)
  --audit-log <PATH>    Append structured JSONL audit events to PATH
  --ro <PATH>           Allow read + execute access to PATH (repeatable)
  --ro-data <PATH>      Allow read-only (no execute) access to PATH (repeatable)
  --rw <PATH>           Allow read + write + execute access to PATH (repeatable)
  --cow <PATH>          Mount PATH as ephemeral Copy-on-Write OverlayFS (repeatable)
  --rootfs <PATH>       Pivot into a dedicated rootfs (pivot_root + masked /proc)
  --cwd <PATH>          Set working directory inside sandbox
  --hostname <NAME>     Set hostname inside UTS namespace (default: rsb)
  --net                 Allow unrestricted host network access (default: blocked)
  --allow-domain <HOST> Allow filtered egress only to HOST[:PORT] (repeatable, SSRF+SNI)
  --allow-cidr <CIDR>   Allow filtered egress only to IP/CIDR[:PORT] (repeatable)
  --transparent-tap     Use rootless CLONE_NEWNET + tap0 + smoltcp L2/L3 bridge (no HTTP_PROXY)
  --no-ns               Disable Linux namespaces (Landlock + Seccomp mode)
  --no-landlock         Disable Landlock LSM
  --no-seccomp          Disable Seccomp-BPF syscall filtering
  --no-sys-libs         Do not auto-allow standard read-only system runtime paths
  --mem-mb <MiB>        Cgroups v2 memory.max limit in MiB
  --pids <N>            Cgroups v2 pids.max limit (fork-bomb protection)
  --cpu-pct <PCT>       Cgroups v2 cpu.max quota (% of 1 core, e.g. 25)
  --timeout-ms <MS>     Wall-clock timeout in ms (ai-exec default: 5000ms)
  --max-output <BYTES>  Max captured stdout/stderr bytes per stream (ai-exec default: 1 MiB)
  --stats               Print setup/total timing & active layers to stderr (rsb run)
  -h, --help            Show this help message"
    );
}

fn cmd_info() -> ExitCode {
    println!("rust-sandbox (rsb) v{}", env!("CARGO_PKG_VERSION"));
    println!("arch:               {}", env::consts::ARCH);

    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        println!("kernel:             {}", release.trim());
    }

    match landlock_abi_version() {
        Ok(abi) => println!("landlock_abi:       v{abi} (supported)"),
        Err(e) => println!("landlock_abi:       unavailable ({e})"),
    }

    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(val) => println!(
            "unpriv_userns:      {}",
            if val.trim() == "1" {
                "enabled"
            } else {
                "disabled"
            }
        ),
        Err(_) => println!("unpriv_userns:      unknown (sysctl not exposed)"),
    }

    if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    {
        println!(
            "apparmor_userns:    {}",
            if val.trim() == "1" {
                "restricted (1 — Ubuntu AppArmor may block rootless mount)"
            } else {
                "unrestricted (0)"
            }
        );
    }

    match find_writable_cgroup_v2_dir() {
        Some(dir) => println!("cgroup_v2:          delegated ({})", dir.display()),
        None => println!("cgroup_v2:          not delegated (quotas will gracefully skip)"),
    }

    ExitCode::SUCCESS
}

struct ParsedRunArgs {
    profile_path: Option<PathBuf>,
    preset: Option<String>,
    audit_log: Option<PathBuf>,
    ro_paths: Vec<PathBuf>,
    ro_data_paths: Vec<PathBuf>,
    rw_paths: Vec<PathBuf>,
    cow_paths: Vec<PathBuf>,
    rootfs: Option<PathBuf>,
    cwd: Option<PathBuf>,
    hostname: Option<String>,
    allow_net: Option<bool>,
    allow_domains: Vec<String>,
    allow_cidrs: Vec<String>,
    transparent_tap: Option<bool>,
    use_ns: Option<bool>,
    use_landlock: Option<bool>,
    use_seccomp: Option<bool>,
    auto_sys_libs: Option<bool>,
    mem_mb: Option<u64>,
    pids_max: Option<u32>,
    cpu_pct: Option<u32>,
    timeout_ms: Option<u64>,
    ai_mode: bool,
    max_output_bytes: usize,
    show_stats: bool,
    command: Vec<String>,
}

fn parse_run_args(args: &[String], ai_mode: bool) -> Result<Option<ParsedRunArgs>, String> {
    let mut parsed = ParsedRunArgs {
        profile_path: None,
        preset: None,
        audit_log: None,
        ro_paths: Vec::new(),
        ro_data_paths: Vec::new(),
        rw_paths: Vec::new(),
        cow_paths: Vec::new(),
        rootfs: None,
        cwd: None,
        hostname: None,
        allow_net: None,
        allow_domains: Vec::new(),
        allow_cidrs: Vec::new(),
        transparent_tap: None,
        use_ns: None,
        use_landlock: None,
        use_seccomp: None,
        auto_sys_libs: None,
        mem_mb: None,
        pids_max: None,
        cpu_pct: None,
        timeout_ms: None,
        ai_mode,
        max_output_bytes: DEFAULT_AI_MAX_OUTPUT_BYTES,
        show_stats: false,
        command: Vec::new(),
    };

    let mut i = 0;
    let mut cmd_start: Option<usize> = None;

    while i < args.len() {
        let raw = args[i].as_str();
        if raw == "--" {
            cmd_start = Some(i + 1);
            break;
        }
        let (flag, eq_val) = if raw.starts_with("--") {
            match raw.split_once('=') {
                Some((f, v)) => (f, Some(v)),
                None => (raw, None),
            }
        } else {
            (raw, None)
        };
        let take_val = |idx: &mut usize, eq: Option<&str>, err: &str| -> Result<String, String> {
            if let Some(v) = eq {
                Ok(v.to_string())
            } else {
                *idx += 1;
                args.get(*idx).cloned().ok_or_else(|| err.to_string())
            }
        };
        let reject_eq = |flag_name: &str, eq: Option<&str>| -> Result<(), String> {
            if eq.is_some() {
                Err(format!("option '{flag_name}' does not take a value"))
            } else {
                Ok(())
            }
        };

        match flag {
            "-h" | "--help" => {
                reject_eq(flag, eq_val)?;
                print_usage();
                return Ok(None);
            }
            "--profile" => {
                parsed.profile_path = Some(PathBuf::from(take_val(
                    &mut i,
                    eq_val,
                    "--profile requires a path",
                )?));
            }
            "--preset" => {
                parsed.preset = Some(take_val(
                    &mut i,
                    eq_val,
                    "--preset requires a name (python-ai, node-build, strict-offline)",
                )?);
            }
            "--audit-log" => {
                parsed.audit_log = Some(PathBuf::from(take_val(
                    &mut i,
                    eq_val,
                    "--audit-log requires a file path",
                )?));
            }
            "--ro" => {
                parsed
                    .ro_paths
                    .push(PathBuf::from(take_val(&mut i, eq_val, "--ro requires a path")?));
            }
            "--ro-data" => {
                parsed.ro_data_paths.push(PathBuf::from(take_val(
                    &mut i,
                    eq_val,
                    "--ro-data requires a path",
                )?));
            }
            "--rw" => {
                parsed
                    .rw_paths
                    .push(PathBuf::from(take_val(&mut i, eq_val, "--rw requires a path")?));
            }
            "--cow" => {
                parsed
                    .cow_paths
                    .push(PathBuf::from(take_val(&mut i, eq_val, "--cow requires a path")?));
            }
            "--rootfs" => {
                parsed.rootfs = Some(PathBuf::from(take_val(
                    &mut i,
                    eq_val,
                    "--rootfs requires a path",
                )?));
            }
            "--cwd" => {
                parsed.cwd = Some(PathBuf::from(take_val(
                    &mut i,
                    eq_val,
                    "--cwd requires a path",
                )?));
            }
            "--hostname" => {
                parsed.hostname = Some(take_val(&mut i, eq_val, "--hostname requires a value")?);
            }
            "--mem-mb" => {
                let v = take_val(&mut i, eq_val, "--mem-mb requires an integer")?;
                parsed.mem_mb = Some(v.parse().map_err(|_| format!("invalid --mem-mb: {v}"))?);
            }
            "--pids" => {
                let v = take_val(&mut i, eq_val, "--pids requires an integer")?;
                parsed.pids_max = Some(v.parse().map_err(|_| format!("invalid --pids: {v}"))?);
            }
            "--cpu-pct" => {
                let v = take_val(&mut i, eq_val, "--cpu-pct requires an integer")?;
                parsed.cpu_pct = Some(v.parse().map_err(|_| format!("invalid --cpu-pct: {v}"))?);
            }
            "--timeout-ms" => {
                let v = take_val(&mut i, eq_val, "--timeout-ms requires an integer")?;
                parsed.timeout_ms =
                    Some(v.parse().map_err(|_| format!("invalid --timeout-ms: {v}"))?);
            }
            "--max-output" => {
                let v = take_val(&mut i, eq_val, "--max-output requires an integer")?;
                parsed.max_output_bytes =
                    v.parse().map_err(|_| format!("invalid --max-output: {v}"))?;
            }
            "--net" => {
                reject_eq(flag, eq_val)?;
                parsed.allow_net = Some(true);
            }
            "--allow-domain" => {
                parsed.allow_domains.push(take_val(
                    &mut i,
                    eq_val,
                    "--allow-domain requires a hostname",
                )?);
            }
            "--allow-cidr" => {
                parsed.allow_cidrs.push(take_val(
                    &mut i,
                    eq_val,
                    "--allow-cidr requires a CIDR rule",
                )?);
            }
            "--transparent-tap" => {
                reject_eq(flag, eq_val)?;
                parsed.transparent_tap = Some(true);
            }
            "--no-transparent-tap" => {
                reject_eq(flag, eq_val)?;
                parsed.transparent_tap = Some(false);
            }
            "--no-net" => {
                reject_eq(flag, eq_val)?;
                parsed.allow_net = Some(false);
            }
            "--no-ns" => {
                reject_eq(flag, eq_val)?;
                parsed.use_ns = Some(false);
            }
            "--no-landlock" => {
                reject_eq(flag, eq_val)?;
                parsed.use_landlock = Some(false);
            }
            "--no-seccomp" => {
                reject_eq(flag, eq_val)?;
                parsed.use_seccomp = Some(false);
            }
            "--no-sys-libs" => {
                reject_eq(flag, eq_val)?;
                parsed.auto_sys_libs = Some(false);
            }
            "--stats" => {
                reject_eq(flag, eq_val)?;
                parsed.show_stats = true;
            }
            other if other.starts_with('-') => return Err(format!("unknown option '{raw}'")),
            _ => {
                cmd_start = Some(i);
                break;
            }
        }
        i += 1;
    }

    let start = cmd_start.ok_or("missing command to execute (use `-- <CMD> [ARGS...]`)")?;
    if start >= args.len() {
        return Err("missing command after `--`".into());
    }
    parsed.command = args[start..].to_vec();
    Ok(Some(parsed))
}

fn build_sandbox(
    p: &ParsedRunArgs,
) -> Result<
    (
        rsb_core::SandboxBuilder,
        Option<EgressProxy>,
        Option<EgressPolicy>,
    ),
    String,
> {
    let mut profile = match (&p.profile_path, &p.preset) {
        (Some(_), Some(_)) => return Err("cannot combine --profile and --preset".into()),
        (Some(path), None) => SandboxProfile::from_file(path).map_err(|e| e.to_string())?,
        (None, Some(name)) => SandboxProfile::preset(name).map_err(|e| e.to_string())?,
        (None, None) => SandboxProfile::default(),
    };

    if let Some(v) = p.allow_net {
        profile.allow_network = v;
    }
    if let Some(v) = p.use_ns {
        profile.namespaces = v;
    }
    if let Some(v) = p.use_landlock {
        profile.landlock = v;
    }
    if let Some(v) = p.use_seccomp {
        profile.seccomp = v;
    }
    if let Some(v) = p.auto_sys_libs {
        profile.auto_system_runtime = v;
    }
    if let Some(ref h) = p.hostname {
        profile.hostname = Some(h.clone());
    }
    if let Some(mb) = p.mem_mb {
        profile.memory_mb = Some(mb);
    }
    if let Some(pids) = p.pids_max {
        profile.pids = Some(pids);
    }
    if let Some(pct) = p.cpu_pct {
        profile.cpu_pct = Some(pct);
    }
    if let Some(ms) = p.timeout_ms {
        profile.timeout_ms = Some(ms);
    }
    // Apply `rsb ai-exec` safety defaults ONLY when neither `--profile` nor CLI set them
    if p.ai_mode {
        profile.memory_mb.get_or_insert(256);
        profile.pids.get_or_insert(32);
        profile.timeout_ms.get_or_insert(DEFAULT_AI_TIMEOUT_MS);
    }

    let mut all_domains = profile.allow_domains.clone();
    all_domains.extend(p.allow_domains.iter().cloned());
    let mut all_cidrs = profile.allow_cidrs.clone();
    all_cidrs.extend(p.allow_cidrs.iter().cloned());
    let use_transparent_tap = p.transparent_tap.unwrap_or(profile.transparent_tap);

    let has_egress_rules = !all_domains.is_empty() || !all_cidrs.is_empty();
    let egress_policy = if has_egress_rules || use_transparent_tap {
        let mut epol = EgressPolicy::default();
        for d in &all_domains {
            epol = epol.allow_domain(d)?;
        }
        for c in &all_cidrs {
            epol = epol.allow_cidr(c)?;
        }
        Some(epol)
    } else {
        None
    };

    // Either attach kernel-enforced transparent L2/L3 `SlirpBridge` over rootless `tap0`
    // (default whenever namespaces are enabled and `--allow-domain`/`--allow-cidr` are set),
    // OR fall back to advisory HTTP/HTTPS CONNECT `EgressProxy` only when `--no-ns` is requested.
    let effective_tap =
        use_transparent_tap || (egress_policy.is_some() && profile.namespaces);
    let (egress_proxy, tap_policy) = if effective_tap {
        if !profile.namespaces {
            return Err("--transparent-tap requires namespaces (remove --no-ns)".into());
        }
        (None, egress_policy)
    } else if let Some(epol) = egress_policy {
        eprintln!(
            "rsb: warning: --allow-domain/--allow-cidr with --no-ns uses advisory HTTP_PROXY only; direct sockets are NOT blocked without namespaces"
        );
        let proxy = EgressProxy::start(epol)
            .map_err(|e| format!("failed to start egress filter proxy: {e}"))?;
        profile.allow_network = true;
        (Some(proxy), None)
    } else {
        (None, None)
    };

    let mut builder = Sandbox::builder(&p.command[0])
        .args(&p.command[1..])
        .with_profile(&profile);

    if tap_policy.is_some() {
        builder = builder.transparent_tap();
    }

    if let Some(ref proxy) = egress_proxy {
        let url = proxy.proxy_url();
        builder = builder
            .env("HTTP_PROXY", &url)
            .env("HTTPS_PROXY", &url)
            .env("ALL_PROXY", &url)
            .env("http_proxy", &url)
            .env("https_proxy", &url);
    }

    for path in &p.ro_paths {
        builder = builder.ro(path);
    }
    for path in &p.ro_data_paths {
        builder = builder.ro_data(path);
    }
    for path in &p.rw_paths {
        builder = builder.rw(path);
    }
    for path in &p.cow_paths {
        builder = builder.ephemeral_cow(path);
    }
    if let Some(ref root) = p.rootfs {
        builder = builder.rootfs(root);
    }
    if let Some(ref dir) = p.cwd {
        builder = builder.cwd(dir);
    }
    if let Some(ms) = p.timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }

    Ok((builder, egress_proxy, tap_policy))
}

fn cmd_run(args: &[String]) -> ExitCode {
    let parsed = match parse_run_args(args, false) {
        Ok(Some(p)) => p,
        Ok(None) => return ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("rsb: {msg}");
            return ExitCode::from(2);
        }
    };

    let (builder, _proxy, tap_policy) = match build_sandbox(&parsed) {
        Ok(triple) => triple,
        Err(msg) => {
            eprintln!("rsb: {msg}");
            return ExitCode::from(2);
        }
    };

    let run_res = if let Some(epol) = tap_policy {
        builder.prepare().and_then(|prep| {
            prep.run_with_tap(move |tap_fd| {
                SlirpBridge::new(epol)
                    .spawn_on_tap(tap_fd)
                    .map_err(SandboxError::Io)
            })
        })
    } else {
        builder.run()
    };

    match run_res {
        Ok(report) => {
            if let Some(ref audit_path) = parsed.audit_log {
                let exit_code = report
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".into());
                let signal = report
                    .signal
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "null".into());
                let ev = format!(
                    "{{\"ok\":{},\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"setup_ms\":{:.3},\"total_ms\":{:.3}}}",
                    report.success(),
                    exit_code,
                    signal,
                    report.timed_out,
                    report.setup_time.as_secs_f64() * 1000.0,
                    report.total_time.as_secs_f64() * 1000.0,
                );
                append_audit_log(audit_path, &parsed.command, &ev);
            }
            if parsed.show_stats {
                eprintln!(
                    "[rsb] setup={:.3}ms total={:.3}ms timed_out={} ns={} landlock={} seccomp_insns={} cgroup={}",
                    report.setup_time.as_secs_f64() * 1000.0,
                    report.total_time.as_secs_f64() * 1000.0,
                    report.timed_out,
                    report.namespaces_active,
                    report
                        .landlock_abi
                        .map(|v| format!("v{v}"))
                        .unwrap_or_else(|| "off".into()),
                    report.seccomp_bpf_insns,
                    report.cgroup_active,
                );
            }
            if report.timed_out {
                ExitCode::from(124)
            } else if let Some(code) = report.exit_code {
                ExitCode::from((code & 0xFF) as u8)
            } else if let Some(sig) = report.signal {
                ExitCode::from(((128 + sig) & 0xFF) as u8)
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            if let Some(ref audit_path) = parsed.audit_log {
                let ev = format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                append_audit_log(audit_path, &parsed.command, &ev);
            }
            eprintln!("rsb error: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_ai_exec(args: &[String]) -> ExitCode {
    let parsed = match parse_run_args(args, true) {
        Ok(Some(p)) => p,
        Ok(None) => return ExitCode::SUCCESS,
        Err(msg) => {
            println!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&msg));
            return ExitCode::from(2);
        }
    };

    let (builder, _proxy, tap_policy) = match build_sandbox(&parsed) {
        Ok(triple) => triple,
        Err(msg) => {
            let err_json = format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&msg));
            if let Some(ref audit_path) = parsed.audit_log {
                append_audit_log(audit_path, &parsed.command, &err_json);
            }
            println!("{err_json}");
            return ExitCode::from(2);
        }
    };

    let cap_res = if let Some(epol) = tap_policy {
        builder.prepare().and_then(|prep| {
            prep.run_captured_with_tap(parsed.max_output_bytes, move |tap_fd| {
                SlirpBridge::new(epol)
                    .spawn_on_tap(tap_fd)
                    .map_err(SandboxError::Io)
            })
        })
    } else {
        builder.run_captured(parsed.max_output_bytes)
    };

    match cap_res {
        Ok(cap) => {
            let json = format_ai_exec_json(&cap);
            if let Some(ref audit_path) = parsed.audit_log {
                append_audit_log(audit_path, &parsed.command, &json);
            }
            println!("{json}");
            if cap.report.success() {
                ExitCode::SUCCESS
            } else if cap.report.timed_out {
                ExitCode::from(124)
            } else if let Some(code) = cap.report.exit_code {
                ExitCode::from((code & 0xFF) as u8)
            } else if let Some(sig) = cap.report.signal {
                ExitCode::from(((128 + sig) & 0xFF) as u8)
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            let err_json = format!(
                "{{\"ok\":false,\"error\":\"{}\"}}",
                json_escape(&e.to_string())
            );
            if let Some(ref audit_path) = parsed.audit_log {
                append_audit_log(audit_path, &parsed.command, &err_json);
            }
            println!("{err_json}");
            ExitCode::from(1)
        }
    }
}

fn cmd_learn(args: &[String]) -> ExitCode {
    let mut out_path: Option<PathBuf> = None;
    let mut strict_allowlist = false;
    let mut merge = false;
    let mut i = 0;
    let mut cmd_start: Option<usize> = None;

    while i < args.len() {
        let raw = args[i].as_str();
        if raw == "--" {
            cmd_start = Some(i + 1);
            break;
        }
        let (flag, eq_val) = if raw.starts_with("--") {
            match raw.split_once('=') {
                Some((f, v)) => (f, Some(v)),
                None => (raw, None),
            }
        } else {
            (raw, None)
        };
        match flag {
            "-h" | "--help" => {
                if eq_val.is_some() {
                    eprintln!("rsb learn: option '{flag}' does not take a value");
                    return ExitCode::from(2);
                }
                print_usage();
                return ExitCode::SUCCESS;
            }
            "--strict" => {
                if eq_val.is_some() {
                    eprintln!("rsb learn: option '--strict' does not take a value");
                    return ExitCode::from(2);
                }
                strict_allowlist = true;
            }
            "--merge" => {
                if eq_val.is_some() {
                    eprintln!("rsb learn: option '--merge' does not take a value");
                    return ExitCode::from(2);
                }
                merge = true;
            }
            "--out" | "-o" => {
                let p = if let Some(v) = eq_val {
                    v.to_string()
                } else {
                    i += 1;
                    let Some(v) = args.get(i) else {
                        eprintln!("rsb learn: --out requires a file path");
                        return ExitCode::from(2);
                    };
                    v.clone()
                };
                out_path = Some(PathBuf::from(p));
            }
            other if other.starts_with('-') => {
                eprintln!("rsb learn: unknown option '{raw}'");
                return ExitCode::from(2);
            }
            _ => {
                cmd_start = Some(i);
                break;
            }
        }
        i += 1;
    }

    if merge && out_path.is_none() {
        eprintln!("rsb learn: --merge requires --out <PATH>");
        return ExitCode::from(2);
    }

    let Some(start) = cmd_start else {
        eprintln!(
            "rsb learn: missing command (use `rsb learn [--strict] [--merge] [--out sandbox.toml] -- <CMD>`)"
        );
        return ExitCode::from(2);
    };
    let cmd = &args[start..];
    if cmd.is_empty() {
        eprintln!("rsb learn: missing command after `--`");
        return ExitCode::from(2);
    }

    // Load existing profile BEFORE tracing when `--merge` is requested so we can
    // keep `seccomp` mode consistent (`allowlist` vs `denylist`).
    let existing_for_merge = if merge
        && let Some(ref path) = out_path
        && path.exists()
    {
        let existing = match SandboxProfile::from_file(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "rsb learn: failed to load existing {} for --merge: {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        };
        if existing.allow_syscalls.is_some() && !strict_allowlist {
            eprintln!(
                "[rsb learn] existing profile uses seccomp allowlist; auto-enabling --strict for --merge"
            );
            strict_allowlist = true;
        } else if existing.allow_syscalls.is_none() && strict_allowlist {
            eprintln!(
                "rsb learn: cannot merge --strict allowlist into existing denylist profile {} (re-learn without --merge or without --strict)",
                path.display()
            );
            return ExitCode::from(2);
        }
        Some(existing)
    } else {
        None
    };

    match rsb_core::learn_policy_with_options(&cmd[0], &cmd[1..], strict_allowlist) {
        Ok(report) => {
            eprintln!(
                "[rsb learn] observed {} unique syscalls, {} read paths, {} write paths, network={}, seccomp_mode={}",
                report.observed_syscalls.len(),
                report.read_paths.len(),
                report.write_paths.len(),
                report.network_used,
                if strict_allowlist { "allowlist" } else { "denylist" }
            );
            let final_profile = if let Some(mut existing) = existing_for_merge {
                existing.merge(&report.profile);
                existing
            } else {
                report.profile
            };

            let toml = final_profile.to_toml();
            if let Some(path) = out_path {
                if let Err(e) = std::fs::write(&path, &toml) {
                    eprintln!("rsb learn: failed to write {}: {e}", path.display());
                    return ExitCode::from(1);
                }
                if merge {
                    eprintln!("[rsb learn] merged profile into {}", path.display());
                } else {
                    eprintln!("[rsb learn] wrote profile to {}", path.display());
                }
            } else {
                print!("{toml}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rsb learn error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Zero-dependency JSON serializer for `rsb ai-exec`.
fn format_ai_exec_json(cap: &CapturedExecutionReport) -> String {
    let r = &cap.report;
    let exit_code = r
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "null".into());
    let signal = r
        .signal
        .map(|s| s.to_string())
        .unwrap_or_else(|| "null".into());
    let landlock_abi = r
        .landlock_abi
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".into());
    let mem_peak = r
        .memory_peak_bytes
        .map(|b| b.to_string())
        .unwrap_or_else(|| "null".into());

    let mut diffs_json = String::from("[");
    for (idx, d) in cap.cow_diffs.iter().enumerate() {
        if idx > 0 {
            diffs_json.push(',');
        }
        let kind = match d.kind {
            CowChangeKind::Added => "added",
            CowChangeKind::Modified => "modified",
            CowChangeKind::Deleted => "deleted",
        };
        diffs_json.push_str(&format!(
            "{{\"target\":\"{}\",\"path\":\"{}\",\"kind\":\"{}\"}}",
            json_escape(&d.target.to_string_lossy()),
            json_escape(&d.rel_path.to_string_lossy()),
            kind,
        ));
    }
    diffs_json.push(']');

    format!(
        "{{\
\"ok\":{},\
\"exit_code\":{},\
\"signal\":{},\
\"timed_out\":{},\
\"setup_ms\":{:.3},\
\"total_ms\":{:.3},\
\"stdout\":\"{}\",\
\"stderr\":\"{}\",\
\"stdout_truncated\":{},\
\"stderr_truncated\":{},\
\"cow_diffs\":{},\
\"isolation\":{{\
\"namespaces\":{},\
\"landlock_abi\":{},\
\"seccomp_bpf_insns\":{},\
\"cgroup_v2\":{},\
\"memory_peak_bytes\":{}\
}}\
}}",
        r.success(),
        exit_code,
        signal,
        r.timed_out,
        r.setup_time.as_secs_f64() * 1000.0,
        r.total_time.as_secs_f64() * 1000.0,
        json_escape(&cap.stdout_lossy()),
        json_escape(&cap.stderr_lossy()),
        cap.stdout_truncated,
        cap.stderr_truncated,
        diffs_json,
        r.namespaces_active,
        landlock_abi,
        r.seccomp_bpf_insns,
        r.cgroup_active,
        mem_peak,
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn cmd_zygote_bench(args: &[String]) -> ExitCode {
    let mut use_ns = true;
    let mut iters: usize = 10;
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_str();
        let (flag, eq_val) = if raw.starts_with("--") {
            match raw.split_once('=') {
                Some((f, v)) => (f, Some(v)),
                None => (raw, None),
            }
        } else {
            (raw, None)
        };
        match flag {
            "-h" | "--help" => {
                if eq_val.is_some() {
                    eprintln!("rsb zygote-bench: option '{flag}' does not take a value");
                    return ExitCode::from(2);
                }
                println!("USAGE: rsb zygote-bench [--no-ns] [--iters <N>]");
                return ExitCode::SUCCESS;
            }
            "--no-ns" => {
                if eq_val.is_some() {
                    eprintln!("rsb zygote-bench: option '--no-ns' does not take a value");
                    return ExitCode::from(2);
                }
                use_ns = false;
            }
            "--iters" => {
                let v = if let Some(val) = eq_val {
                    val.to_string()
                } else {
                    i += 1;
                    let Some(val) = args.get(i) else {
                        eprintln!("rsb zygote-bench: --iters requires an integer");
                        return ExitCode::from(2);
                    };
                    val.clone()
                };
                match v.parse::<usize>() {
                    Ok(n) if n > 0 => iters = n,
                    _ => {
                        eprintln!("rsb zygote-bench: invalid --iters value '{v}'");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!("rsb zygote-bench: unknown option '{raw}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let code = "import json, math; print(json.dumps({'v': math.factorial(10)}))";

    // 1. Measure cold Python inside rsb
    let cold = match Sandbox::builder("/usr/bin/python3")
        .args(["-c", code])
        .namespaces(use_ns)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_network(false)
        .allow_system_runtime()
        .run_captured(64 * 1024)
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rsb zygote-bench (cold) error: {e}");
            return ExitCode::from(1);
        }
    };
    if !cold.report.success() {
        eprintln!(
            "rsb zygote-bench (cold) failed: exit={:?} signal={:?} stderr={}",
            cold.report.exit_code,
            cold.report.signal,
            String::from_utf8_lossy(&cold.stderr)
        );
        return ExitCode::from(1);
    }
    let cold_ms = cold.report.total_time.as_secs_f64() * 1000.0;

    // 2. Start warm Zygote pool
    let cfg = ZygoteConfig {
        namespaces: use_ns,
        landlock: landlock_abi_version().is_ok(),
        ..Default::default()
    };
    let mut pool = match ZygotePool::start_python(cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rsb zygote-bench (zygote start) error: {e}");
            return ExitCode::from(1);
        }
    };

    let mut total_rt_us: u128 = 0;
    let mut total_fork_us: u64 = 0;
    let mut min_rt_us: u128 = u128::MAX;
    let mut min_fork_us: u64 = u64::MAX;

    for _ in 0..iters {
        match pool.exec(code, Duration::from_secs(5)) {
            Ok(res) if res.success() => {
                let rt = res.roundtrip_time.as_micros();
                total_rt_us += rt;
                total_fork_us += res.fork_exec_us;
                min_rt_us = min_rt_us.min(rt);
                min_fork_us = min_fork_us.min(res.fork_exec_us);
            }
            Ok(res) => {
                eprintln!("zygote worker failed: exit={} stderr={}", res.exit_code, res.stderr);
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("zygote exec error: {e}");
                return ExitCode::from(1);
            }
        }
    }

    let avg_rt_ms = (total_rt_us as f64) / (iters as f64) / 1000.0;
    let avg_fork_ms = (total_fork_us as f64) / (iters as f64) / 1000.0;
    let min_fork_ms = (min_fork_us as f64) / 1000.0;
    let speedup = cold_ms / avg_rt_ms.max(0.001);

    println!("=== rsb Zygote Benchmark ({iters} warm runs, ns={use_ns}) ===");
    println!("cold Python (rsb ai-exec):  {cold_ms:.3} ms");
    println!(
        "zygote one-time warmup:     {:.3} ms",
        pool.warmup_time.as_secs_f64() * 1000.0
    );
    println!("warm zygote avg roundtrip:  {avg_rt_ms:.3} ms (min {:.3} ms)", min_rt_us as f64 / 1000.0);
    println!("warm zygote avg fork+exec:  {avg_fork_ms:.3} ms (min {min_fork_ms:.3} ms)");
    println!("speedup vs cold start:      {speedup:.1}x");

    pool.shutdown();
    ExitCode::SUCCESS
}

fn append_audit_log(path: &std::path::Path, cmd: &[String], event_json: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prog = cmd.first().map(String::as_str).unwrap_or("");
    let line = format!(
        "{{\"ts\":{ts},\"program\":\"{}\",\"event\":{event_json}}}\n",
        json_escape(prog)
    );
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!(
                    "rsb: warning: failed to write audit log {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "rsb: warning: failed to open audit log {}: {e}",
                path.display()
            );
        }
    }
}

fn cmd_completions(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("bash") => {
            println!(
                "_rsb() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  if [[ $COMP_CWORD -eq 1 ]]; then\n    COMPREPLY=( $(compgen -W \"info run ai-exec learn session completions zygote-bench\" -- \"$cur\") )\n  else\n    COMPREPLY=( $(compgen -W \"--profile --preset --audit-log --ro --ro-data --rw --cow --rootfs --cwd --hostname --net --no-net --allow-domain --allow-cidr --transparent-tap --no-transparent-tap --no-ns --no-landlock --no-seccomp --no-sys-libs --mem-mb --pids --cpu-pct --timeout-ms --max-output --stats --strict --merge --out\" -- \"$cur\") )\n  fi\n}}\ncomplete -F _rsb rsb"
            );
            ExitCode::SUCCESS
        }
        Some("zsh") => {
            println!(
                "#compdef rsb\n_arguments '1:command:(info run ai-exec learn session completions zygote-bench)' '*:args:_files'"
            );
            ExitCode::SUCCESS
        }
        Some("fish") => {
            println!(
                "complete -c rsb -n '__fish_use_subcommand' -a 'info run ai-exec learn session completions zygote-bench'"
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("USAGE: rsb completions <bash|zsh|fish>");
            ExitCode::from(2)
        }
    }
}

fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn ensure_secure_sessions_root() -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let uid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0);
    let root = if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR")
        && !xdg.is_empty()
        && PathBuf::from(&xdg).is_absolute()
    {
        PathBuf::from(xdg).join("rsb-sessions")
    } else {
        std::env::temp_dir().join(format!("rsb-sessions-{uid}"))
    };

    match std::fs::symlink_metadata(&root) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!(
                    "sessions root '{}' is not a regular directory",
                    root.display()
                ));
            }
            if meta.uid() != uid {
                return Err(format!(
                    "sessions root '{}' is owned by uid {}, expected {uid}",
                    root.display(),
                    meta.uid()
                ));
            }
            if (meta.mode() & 0o077) != 0 {
                return Err(format!(
                    "sessions root '{}' has unsafe permissions {:o} (expected 0700)",
                    root.display(),
                    meta.mode() & 0o777
                ));
            }
            Ok(root)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|err| format!("failed to create sessions root '{}': {err}", root.display()))?;
            Ok(root)
        }
        Err(e) => Err(format!(
            "failed to inspect sessions root '{}': {e}",
            root.display()
        )),
    }
}

fn generate_session_id() -> String {
    use std::io::Read as _;
    let mut bytes = [0u8; 8];
    let val = if let Ok(mut f) = std::fs::File::open("/dev/urandom")
        && f.read_exact(&mut bytes).is_ok()
    {
        u64::from_ne_bytes(bytes)
    } else {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ ((std::process::id() as u64) << 32) ^ (&bytes as *const [u8; 8] as usize as u64)
    };
    format!("s{val:016x}")
}

fn cmd_session(args: &[String]) -> ExitCode {
    let Some(action) = args.first().map(String::as_str) else {
        eprintln!("USAGE: rsb session <start|exec|ls|stop> [ARGS...]");
        return ExitCode::from(2);
    };
    let root = match ensure_secure_sessions_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rsb session: {e}");
            return ExitCode::from(1);
        }
    };
    match action {
        "start" => {
            let mut preset = "python-ai".to_string();
            let mut i = 1;
            while i < args.len() {
                let raw = args[i].as_str();
                let (flag, eq_val) = if raw.starts_with("--") {
                    match raw.split_once('=') {
                        Some((f, v)) => (f, Some(v)),
                        None => (raw, None),
                    }
                } else {
                    (raw, None)
                };
                match flag {
                    "--preset" => {
                        let p = if let Some(v) = eq_val {
                            v.to_string()
                        } else {
                            i += 1;
                            let Some(v) = args.get(i) else {
                                eprintln!("rsb session start: --preset requires a name");
                                return ExitCode::from(2);
                            };
                            v.clone()
                        };
                        preset = p;
                    }
                    "-h" | "--help" => {
                        println!("USAGE: rsb session start [--preset <NAME>]");
                        return ExitCode::SUCCESS;
                    }
                    _ => {
                        eprintln!("rsb session start: unknown option '{raw}'");
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            let mut profile = match SandboxProfile::preset(&preset) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("rsb session start: {e}");
                    return ExitCode::from(2);
                }
            };
            let id = generate_session_id();
            let sdir = root.join(&id);
            let work = sdir.join("work");
            {
                use std::os::unix::fs::DirBuilderExt;
                if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&sdir) {
                    eprintln!("rsb session start: failed to create session dir: {e}");
                    return ExitCode::from(1);
                }
                if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&work) {
                    let _ = std::fs::remove_dir_all(&sdir);
                    eprintln!("rsb session start: failed to create work dir: {e}");
                    return ExitCode::from(1);
                }
            }
            profile.rw.push(work.clone());
            if let Err(e) = std::fs::write(sdir.join("profile.toml"), profile.to_toml()) {
                let _ = std::fs::remove_dir_all(&sdir);
                eprintln!("rsb session start: {e}");
                return ExitCode::from(1);
            }
            println!("{id}");
            ExitCode::SUCCESS
        }
        "ls" => {
            if let Ok(entries) = std::fs::read_dir(&root) {
                for e in entries.flatten() {
                    if e.path().is_dir() {
                        println!("{}", e.file_name().to_string_lossy());
                    }
                }
            }
            ExitCode::SUCCESS
        }
        "stop" => {
            let Some(id) = args.get(1) else {
                eprintln!("USAGE: rsb session stop <SESSION_ID>");
                return ExitCode::from(2);
            };
            if !is_valid_session_id(id) {
                eprintln!("rsb session stop: invalid session id '{id}'");
                return ExitCode::from(2);
            }
            let sdir = root.join(id);
            if !sdir.exists() {
                eprintln!("rsb session stop: session '{id}' not found");
                return ExitCode::from(1);
            }
            if let Err(e) = std::fs::remove_dir_all(&sdir) {
                eprintln!("rsb session stop: failed to remove session '{id}': {e}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        "exec" => {
            let Some(id) = args.get(1) else {
                eprintln!("USAGE: rsb session exec <SESSION_ID> -- <CMD> [ARGS...]");
                return ExitCode::from(2);
            };
            if !is_valid_session_id(id) {
                eprintln!("rsb session exec: invalid session id '{id}'");
                return ExitCode::from(2);
            }
            for arg in &args[2..] {
                if arg == "--" {
                    break;
                }
                if !arg.starts_with('-') {
                    break;
                }
                let flag = arg.split_once('=').map(|(f, _)| f).unwrap_or(arg.as_str());
                if flag == "--profile" || flag == "--preset" {
                    eprintln!(
                        "rsb session exec: cannot override session profile with '{flag}'"
                    );
                    return ExitCode::from(2);
                }
            }
            let sdir = root.join(id);
            let prof_path = sdir.join("profile.toml");
            let work = sdir.join("work");
            if !prof_path.is_file() {
                eprintln!("rsb session exec: session '{id}' not found");
                return ExitCode::from(1);
            }
            let mut forwarded = vec![
                "--profile".to_string(),
                prof_path.to_string_lossy().into_owned(),
                "--cwd".to_string(),
                work.to_string_lossy().into_owned(),
            ];
            forwarded.extend(args[2..].iter().cloned());
            cmd_ai_exec(&forwarded)
        }
        other => {
            eprintln!("rsb session: unknown action '{other}' (expected start, exec, ls, stop)");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(subcmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };

    match subcmd {
        "info" => cmd_info(),
        "run" => cmd_run(&args[1..]),
        "ai-exec" => cmd_ai_exec(&args[1..]),
        "learn" => cmd_learn(&args[1..]),
        "session" => cmd_session(&args[1..]),
        "completions" => cmd_completions(&args[1..]),
        "zygote-bench" => cmd_zygote_bench(&args[1..]),
        "-h" | "--help" => {
            print_usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("rsb: unknown subcommand '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}
