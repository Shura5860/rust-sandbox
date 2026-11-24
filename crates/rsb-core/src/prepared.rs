//! Pre-compiled sandbox state built in the parent process.
//!
//! Because `rsb-core` is designed to be embedded in multithreaded Rust programs
//! (e.g. Tokio runtimes), the child process created by `clone3` must NEVER
//! allocate heap memory or acquire locks before `execve`.
//!
//! `PreparedSandbox` resolves executables, constructs null-terminated `argv`/`envp`
//! pointer arrays, probes Landlock ABI support, compiles Landlock rule masks,
//! and assembles the Seccomp-BPF bytecode upfront so `child::child_main` is
//! strictly async-signal-safe.

use crate::cgroup::ResourceLimits;
use crate::error::SandboxError;
use crate::policy::{AccessMode, NamespaceConfig, SandboxPolicy};
use rsb_sys::landlock::{self, access_fs, access_net, scope};
use rsb_sys::seccomp::SockFilter;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString, c_char};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A pre-compiled Landlock rule ready for zero-alloc application in the child.
#[derive(Debug)]
pub(crate) struct PreparedLandlockRule {
    pub path: CString,
    pub allowed_access: u64,
}

/// Pre-compiled, reusable sandbox blueprint.
///
/// Can be executed repeatedly without re-resolving paths, re-allocating buffers,
/// or re-compiling Seccomp-BPF bytecode.
#[derive(Debug)]
pub struct PreparedSandbox {
    pub(crate) program: CString,
    // Kept alive so `argv_ptrs` and `envp_ptrs` remain valid.
    _argv_storage: Vec<CString>,
    pub(crate) argv_ptrs: Vec<*const c_char>,
    _envp_storage: Vec<CString>,
    pub(crate) envp_ptrs: Vec<*const c_char>,
    pub(crate) cwd: Option<CString>,
    pub(crate) rootfs: Option<CString>,
    pub(crate) hostname: Option<CString>,
    pub(crate) namespaces: NamespaceConfig,
    pub(crate) landlock_abi: Option<u32>,
    pub(crate) landlock_handled_fs: u64,
    pub(crate) landlock_handled_net: u64,
    pub(crate) landlock_scoped: u64,
    pub(crate) landlock_rules: Vec<PreparedLandlockRule>,
    pub(crate) ephemeral_cow: Vec<PathBuf>,
    pub(crate) seccomp_bpf: Vec<SockFilter>,
    pub(crate) limits: ResourceLimits,
}

// SAFETY: Raw pointers in `argv_ptrs` and `envp_ptrs` point exclusively into
// immutable `CString` buffers owned by `_argv_storage` and `_envp_storage`
// inside the same struct, which are never mutated after construction.
unsafe impl Send for PreparedSandbox {}
unsafe impl Sync for PreparedSandbox {}

impl PreparedSandbox {
    /// Compile a declarative `SandboxPolicy` into a `PreparedSandbox`.
    pub fn from_policy(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        if !policy.ephemeral_cow.is_empty() && !policy.namespaces.enabled {
            return Err(SandboxError::InvalidPolicy(
                "ephemeral_cow (--cow) requires namespaces(true); refusing to write directly to host directory".into(),
            ));
        }
        if policy.rootfs.is_some() && !policy.namespaces.enabled {
            return Err(SandboxError::InvalidPolicy(
                "rootfs (--rootfs) requires namespaces(true) for pivot_root".into(),
            ));
        }

        let resolved_program =
            resolve_executable(&policy.program, policy.rootfs.as_deref())?;
        let program_cstr = os_to_cstring(resolved_program.as_os_str())?;

        // Build argv: [program, arg1, arg2, ..., NULL]
        let mut argv_storage = Vec::with_capacity(1 + policy.args.len());
        argv_storage.push(os_to_cstring(policy.program.as_os_str())?);
        for arg in &policy.args {
            argv_storage.push(os_to_cstring(arg)?);
        }
        let mut argv_ptrs: Vec<*const c_char> = argv_storage.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(core::ptr::null());

        // Build envp: clean whitelisted defaults unless `inherit_env` is explicitly enabled.
        let mut env_map: BTreeMap<OsString, OsString> = BTreeMap::new();
        if policy.inherit_env {
            for (k, v) in std::env::vars_os() {
                env_map.insert(k, v);
            }
        } else {
            env_map.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
            env_map.insert("HOME".into(), "/tmp".into());
            env_map.insert("TERM".into(), "xterm-256color".into());
            env_map.insert("LANG".into(), "C.UTF-8".into());
        }
        for (k, v) in policy.env {
            env_map.insert(k, v);
        }
        let mut envp_storage = Vec::with_capacity(env_map.len());
        for (k, v) in env_map {
            if k.is_empty() || k.as_bytes().contains(&b'=') {
                return Err(SandboxError::InvalidPolicy(
                    "environment variable key must be non-empty and cannot contain '='".into(),
                ));
            }
            let mut bytes = Vec::with_capacity(k.len() + 1 + v.len());
            bytes.extend_from_slice(k.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
            let cstr = CString::new(bytes).map_err(|_| {
                SandboxError::InvalidPolicy("environment variable contains interior NUL byte".into())
            })?;
            envp_storage.push(cstr);
        }
        let mut envp_ptrs: Vec<*const c_char> = envp_storage.iter().map(|s| s.as_ptr()).collect();
        envp_ptrs.push(core::ptr::null());

        let cwd = match policy.cwd {
            Some(ref p) => Some(os_to_cstring(p.as_os_str())?),
            None => None,
        };

        let rootfs = match policy.rootfs {
            Some(ref p) => Some(os_to_cstring(p.as_os_str())?),
            None => None,
        };

        let hostname = match policy.hostname {
            Some(ref h) if !h.is_empty() => Some(CString::new(h.as_bytes()).map_err(|_| {
                SandboxError::InvalidPolicy("hostname contains interior NUL byte".into())
            })?),
            _ => None,
        };

        // Compile Landlock ruleset metadata & per-path access masks in parent
        let (landlock_abi, landlock_handled_fs, landlock_handled_net, landlock_scoped, landlock_rules) =
            if policy.landlock_enabled {
                let abi = landlock::abi_version().map_err(SandboxError::LandlockUnsupported)?;
                let handled = access_fs::handled_for_abi(abi);
                // ABI v4+: also block TCP bind/connect in Landlock when network is disabled
                // (defense-in-depth alongside Seccomp even in `--no-ns` mode).
                let handled_net = if policy.seccomp.block_network_sockets {
                    access_net::handled_for_abi(abi)
                } else {
                    0
                };
                // ABI v6+: scope abstract UNIX sockets and signals to this Landlock domain.
                let scoped = scope::handled_for_abi(abi);
                let file_mask = access_fs::file_only_mask(abi);

            let mut rules = Vec::with_capacity(policy.fs_rules.len());
            for rule in &policy.fs_rules {
                // When pivoting into a dedicated `rootfs`, reject `..` traversal and resolve
                // metadata against the rootfs directory (using symlink_metadata fallback so
                // absolute symlinks like `/bin/sh -> /bin/busybox` inside rootfs still work).
                let host_check_path = match policy.rootfs {
                    Some(ref root) => {
                        if rule
                            .path
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir))
                        {
                            return Err(SandboxError::InvalidPolicy(format!(
                                "Landlock rule path '{}' cannot contain '..' when rootfs is set",
                                rule.path.display()
                            )));
                        }
                        let rel = rule.path.strip_prefix("/").unwrap_or(&rule.path);
                        root.join(rel)
                    }
                    None => rule.path.clone(),
                };

                let meta = match std::fs::metadata(&host_check_path) {
                    Ok(m) => m,
                    Err(_) if policy.rootfs.is_some() => {
                        match std::fs::symlink_metadata(&host_check_path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        }
                    }
                    Err(e) => {
                        return Err(SandboxError::InvalidPolicy(format!(
                            "cannot stat Landlock rule path '{}': {e}",
                            rule.path.display()
                        )));
                    }
                };

                let mut allowed = match rule.access {
                    AccessMode::ReadOnly => access_fs::read_only_for_abi(abi),
                    AccessMode::ReadExec => access_fs::read_exec_for_abi(abi),
                    AccessMode::ReadWrite => access_fs::read_write_for_abi(abi),
                };

                // Landlock returns EINVAL if directory-only access bits are attached
                // to a non-directory file descriptor.
                if !meta.is_dir() {
                    allowed &= file_mask;
                }

                if allowed == 0 {
                    continue;
                }

                rules.push(PreparedLandlockRule {
                    path: os_to_cstring(rule.path.as_os_str())?,
                    allowed_access: allowed,
                });
            }

            // When pivoting into a dedicated `rootfs` that has a `/dev` mountpoint,
            // `child_main::setup_minimal_dev()` populates a fresh tmpfs `/dev` with safe
            // virtual devices before Landlock runs. Emit file-only Landlock rules for them
            // without requiring them to exist on disk in `<rootfs>` at `prepare()` time.
            if let Some(ref root) = policy.rootfs
                && root.join("dev").is_dir()
            {
                let virtual_devs: &[(&str, u64)] = &[
                    ("/dev/null", access_fs::read_write_for_abi(abi) & file_mask),
                    ("/dev/zero", access_fs::read_only_for_abi(abi) & file_mask),
                    ("/dev/full", access_fs::read_write_for_abi(abi) & file_mask),
                    ("/dev/random", access_fs::read_only_for_abi(abi) & file_mask),
                    ("/dev/urandom", access_fs::read_only_for_abi(abi) & file_mask),
                    ("/dev/tty", access_fs::read_write_for_abi(abi) & file_mask),
                ];
                for &(dev_path, access) in virtual_devs {
                    if access == 0 || !Path::new(dev_path).exists() {
                        continue;
                    }
                    let cpath = os_to_cstring(OsStr::new(dev_path))?;
                    if !rules.iter().any(|r| r.path == cpath) {
                        rules.push(PreparedLandlockRule {
                            path: cpath,
                            allowed_access: access,
                        });
                    }
                }
            }

            (Some(abi), handled, handled_net, scoped, rules)
        } else {
            (None, 0, 0, 0, Vec::new())
        };

        // Compile pure-Rust Seccomp-BPF bytecode in parent (zero-alloc in child).
        // Linux `seccomp(SECCOMP_SET_MODE_FILTER)` enforces `BPF_MAXINSNS` (4096).
        const BPF_MAXINSNS: usize = 4096;
        let seccomp_bpf = policy.seccomp.compile();
        if seccomp_bpf.len() > BPF_MAXINSNS {
            return Err(SandboxError::InvalidPolicy(format!(
                "compiled Seccomp-BPF program ({} instructions) exceeds kernel BPF_MAXINSNS ({BPF_MAXINSNS})",
                seccomp_bpf.len()
            )));
        }

        Ok(Self {
            program: program_cstr,
            _argv_storage: argv_storage,
            argv_ptrs,
            _envp_storage: envp_storage,
            envp_ptrs,
            cwd,
            rootfs,
            hostname,
            namespaces: policy.namespaces,
            landlock_abi,
            landlock_handled_fs,
            landlock_handled_net,
            landlock_scoped,
            landlock_rules,
            ephemeral_cow: policy.ephemeral_cow,
            seccomp_bpf,
            limits: policy.limits,
        })
    }

    /// Returns the detected Landlock ABI version if Landlock is enabled.
    pub fn landlock_abi(&self) -> Option<u32> {
        self.landlock_abi
    }

    /// Returns the number of compiled Seccomp-BPF instructions (0 if disabled).
    pub fn seccomp_bpf_len(&self) -> usize {
        self.seccomp_bpf.len()
    }
}

fn os_to_cstring(s: &OsStr) -> Result<CString, SandboxError> {
    CString::new(s.as_bytes())
        .map_err(|_| SandboxError::InvalidPolicy("path or argument contains interior NUL byte".into()))
}

fn resolve_executable(program: &Path, rootfs: Option<&Path>) -> Result<PathBuf, SandboxError> {
    if let Some(root) = rootfs {
        if program.components().count() > 1 || program.is_absolute() {
            let rel = program.strip_prefix("/").unwrap_or(program);
            let candidate = root.join(rel);
            if candidate.exists() || std::fs::symlink_metadata(&candidate).is_ok() {
                return Ok(PathBuf::from("/").join(rel));
            }
            return Err(SandboxError::CommandNotFound(program.to_path_buf()));
        }
        for dir in ["usr/local/bin", "usr/bin", "bin"] {
            let candidate = root.join(dir).join(program);
            if candidate.is_file()
                || std::fs::symlink_metadata(&candidate)
                    .is_ok_and(|m| m.file_type().is_symlink())
            {
                return Ok(PathBuf::from("/").join(dir).join(program));
            }
        }
        return Err(SandboxError::CommandNotFound(program.to_path_buf()));
    }

    if program.components().count() > 1 || program.is_absolute() {
        if program.exists() {
            return Ok(program.to_path_buf());
        }
        return Err(SandboxError::CommandNotFound(program.to_path_buf()));
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        use std::os::unix::fs::PermissionsExt;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(program);
            if let Ok(meta) = std::fs::metadata(&candidate)
                && meta.is_file()
                && (meta.permissions().mode() & 0o111) != 0
            {
                return Ok(candidate);
            }
        }
    }

    Err(SandboxError::CommandNotFound(program.to_path_buf()))
}
