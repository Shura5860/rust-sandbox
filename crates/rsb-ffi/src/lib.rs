//! C ABI (`librsb_ffi.so`) for embedding `rust-sandbox` in C, C++, Python, Go, or Zig.
//!
//! All returned heap strings must be freed with [`rsb_string_free`].

use rsb_core::{Sandbox, ZygoteConfig, ZygotePool, landlock_abi_version};
use std::ffi::{CStr, CString, c_char};
use std::time::Duration;

static VERSION_CSTR: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// Return the static NUL-terminated version string of `rust-sandbox`. Do NOT free.
#[unsafe(no_mangle)]
pub extern "C" fn rsb_version() -> *const c_char {
    VERSION_CSTR.as_ptr().cast::<c_char>()
}

/// Probe the running kernel's Landlock ABI version, or `-1` if unavailable.
#[unsafe(no_mangle)]
pub extern "C" fn rsb_landlock_abi() -> i32 {
    landlock_abi_version().map(|v| v as i32).unwrap_or(-1)
}

/// Execute a sandboxed command and return a heap-allocated JSON report string.
///
/// - `program`: NUL-terminated path or executable name (required).
/// - `argv`: optional array of `argc` NUL-terminated argument strings (excluding `program`).
/// - `rw_dir`: optional NUL-terminated writable directory path (may be NULL).
/// - `timeout_ms`: execution timeout in milliseconds (`0` = no timeout).
/// - `allow_network`: `0` = blocked (default), non-zero = allowed.
/// - `use_namespaces`: `0` = Landlock+Seccomp only, non-zero = full rootless namespaces.
///
/// Caller MUST free the returned pointer using [`rsb_string_free`].
///
/// # Safety
/// - `program` must be a valid NUL-terminated C string (or NULL, which returns a JSON error).
/// - If `argv` is non-NULL and `argc > 0`, `argv` must point to at least `argc` valid pointers.
/// - If `rw_dir` is non-NULL, it must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rsb_exec_json(
    program: *const c_char,
    argv: *const *const c_char,
    argc: usize,
    rw_dir: *const c_char,
    timeout_ms: u64,
    allow_network: i32,
    use_namespaces: i32,
) -> *mut c_char {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_ffi_impl(
            program,
            argv,
            argc,
            rw_dir,
            timeout_ms,
            allow_network != 0,
            use_namespaces != 0,
        )
    }));
    let json = match res {
        Ok(Ok(s)) => s,
        Ok(Err(msg)) => format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&msg)),
        Err(_) => "{\"ok\":false,\"error\":\"internal panic in rsb_exec_json\"}".to_string(),
    };

    CString::new(json)
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"nul in output\"}").unwrap())
        .into_raw()
}

/// Free a string pointer previously returned by [`rsb_exec_json`] or [`rsb_zygote_exec_json`].
///
/// # Safety
/// `ptr` must either be NULL or a pointer previously returned by `rsb_exec_json` /
/// `rsb_zygote_exec_json` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rsb_string_free(ptr: *mut c_char) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !ptr.is_null() {
            drop(unsafe { CString::from_raw(ptr) });
        }
    }));
}

/// Start a pre-warmed, sandboxed Python 3 Zygote fork server and return an opaque handle.
/// Returns NULL on failure. Free with [`rsb_zygote_free`].
#[unsafe(no_mangle)]
pub extern "C" fn rsb_zygote_start_python(allow_network: i32, use_namespaces: i32) -> *mut ZygotePool {
    let res = std::panic::catch_unwind(|| {
        let cfg = ZygoteConfig {
            namespaces: use_namespaces != 0,
            landlock: landlock_abi_version().is_ok(),
            seccomp: true,
            allow_network: allow_network != 0,
            ..Default::default()
        };
        match ZygotePool::start_python(cfg) {
            Ok(pool) => Box::into_raw(Box::new(pool)),
            Err(_) => core::ptr::null_mut(),
        }
    });
    res.unwrap_or(core::ptr::null_mut())
}

/// Execute Python `code` inside a live `ZygotePool` handle and return a heap-allocated JSON report.
///
/// # Safety
/// - `pool` must be a valid non-NULL handle returned by [`rsb_zygote_start_python`].
/// - `pool` is NOT thread-safe; callers must serialize concurrent calls on the same handle.
/// - `code` must be a valid NUL-terminated UTF-8 C string.
/// - Caller MUST free the returned string with [`rsb_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rsb_zygote_exec_json(
    pool: *mut ZygotePool,
    code: *const c_char,
    timeout_ms: u64,
) -> *mut c_char {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if pool.is_null() || code.is_null() {
            "{\"ok\":false,\"error\":\"null pool or code pointer\"}".to_string()
        } else {
            let pool_ref = unsafe { &mut *pool };
            match unsafe { CStr::from_ptr(code) }.to_str() {
                Ok(src) => {
                    let dur = if timeout_ms > 0 {
                        Duration::from_millis(timeout_ms)
                    } else {
                        Duration::from_secs(5)
                    };
                    match pool_ref.exec(src, dur) {
                        Ok(res) => format!(
                            "{{\"ok\":{},\"exit_code\":{},\"timed_out\":{},\"roundtrip_ms\":{:.3},\"fork_exec_us\":{},\"stdout\":\"{}\",\"stderr\":\"{}\"}}",
                            res.success(),
                            res.exit_code,
                            res.timed_out,
                            res.roundtrip_time.as_secs_f64() * 1000.0,
                            res.fork_exec_us,
                            json_escape(&res.stdout),
                            json_escape(&res.stderr),
                        ),
                        Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string())),
                    }
                }
                Err(_) => "{\"ok\":false,\"error\":\"code is not valid UTF-8\"}".to_string(),
            }
        }
    }));
    let json = res.unwrap_or_else(|_| {
        "{\"ok\":false,\"error\":\"internal panic in rsb_zygote_exec_json\"}".to_string()
    });

    CString::new(json)
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"nul in output\"}").unwrap())
        .into_raw()
}

/// Shut down and free a `ZygotePool` handle previously returned by [`rsb_zygote_start_python`].
///
/// # Safety
/// `pool` must either be NULL or a valid handle that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rsb_zygote_free(pool: *mut ZygotePool) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !pool.is_null() {
            let boxed = unsafe { Box::from_raw(pool) };
            boxed.shutdown();
        }
    }));
}

fn run_ffi_impl(
    program: *const c_char,
    argv: *const *const c_char,
    argc: usize,
    rw_dir: *const c_char,
    timeout_ms: u64,
    allow_network: bool,
    use_namespaces: bool,
) -> Result<String, String> {
    const MAX_ARGC: usize = 65_536;
    if program.is_null() {
        return Err("program pointer is null".into());
    }
    if argv.is_null() && argc > 0 {
        return Err("argv is null while argc > 0".into());
    }
    if argc > MAX_ARGC {
        return Err(format!("argc ({argc}) exceeds maximum allowed ({MAX_ARGC})"));
    }
    let prog_str = unsafe { CStr::from_ptr(program) }
        .to_str()
        .map_err(|_| "program is not valid UTF-8")?;

    let mut args = Vec::new();
    if !argv.is_null() && argc > 0 {
        args.reserve_exact(argc);
        for i in 0..argc {
            let p = unsafe { *argv.add(i) };
            if p.is_null() {
                return Err(format!("argv[{i}] is null"));
            }
            let s = unsafe { CStr::from_ptr(p) }
                .to_str()
                .map_err(|_| "argument is not valid UTF-8")?;
            args.push(s.to_string());
        }
    }

    let mut builder = Sandbox::builder(prog_str)
        .args(&args)
        .namespaces(use_namespaces)
        .landlock(landlock_abi_version().is_ok())
        .seccomp(true)
        .allow_network(allow_network)
        .allow_system_runtime();

    if !rw_dir.is_null() {
        let dir_str = unsafe { CStr::from_ptr(rw_dir) }
            .to_str()
            .map_err(|_| "rw_dir is not valid UTF-8")?;
        if !dir_str.is_empty() {
            builder = builder.rw(dir_str);
        }
    }
    if timeout_ms > 0 {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }

    let cap = builder
        .run_captured(1024 * 1024)
        .map_err(|e| e.to_string())?;
    let r = &cap.report;

    let exit_code = r
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "null".into());
    let signal = r
        .signal
        .map(|s| s.to_string())
        .unwrap_or_else(|| "null".into());

    Ok(format!(
        "{{\"ok\":{},\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"setup_ms\":{:.3},\"total_ms\":{:.3},\"stdout\":\"{}\",\"stderr\":\"{}\"}}",
        r.success(),
        exit_code,
        signal,
        r.timed_out,
        r.setup_time.as_secs_f64() * 1000.0,
        r.total_time.as_secs_f64() * 1000.0,
        json_escape(&cap.stdout_lossy()),
        json_escape(&cap.stderr_lossy()),
    ))
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
