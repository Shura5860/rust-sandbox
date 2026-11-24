//! Declarative sandbox policy and builder API.

use crate::cgroup::ResourceLimits;
use crate::error::SandboxError;
use crate::prepared::PreparedSandbox;
use crate::sandbox::{CapturedExecutionReport, ExecutionReport};
use crate::seccomp_bpf::{SeccompAction, SeccompPolicy};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Filesystem access level for a Landlock rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read files and list directories (no execute).
    ReadOnly,
    /// Read files, list directories, and execute binaries/shared libraries.
    ReadExec,
    /// Full read, write, create, remove, and execute access.
    ReadWrite,
}

/// A single filesystem access rule enforced by Landlock LSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: AccessMode,
}

/// Linux namespace isolation configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceConfig {
    /// Master switch for `clone3` namespace isolation (User, PID, Mount, IPC, UTS).
    pub enabled: bool,
    /// Isolate network in a new empty network namespace (`CLONE_NEWNET`).
    pub isolate_network: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            isolate_network: true,
        }
    }
}

/// Complete declarative specification for a sandboxed execution.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub inherit_env: bool,
    pub cwd: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub hostname: Option<String>,
    pub namespaces: NamespaceConfig,
    pub landlock_enabled: bool,
    pub fs_rules: Vec<FsRule>,
    pub ephemeral_cow: Vec<PathBuf>,
    pub seccomp: SeccompPolicy,
    pub limits: ResourceLimits,
}

/// Ergonomic builder for constructing and running a sandbox.
#[derive(Debug, Clone)]
pub struct SandboxBuilder {
    policy: SandboxPolicy,
}

impl SandboxBuilder {
    /// Create a new sandbox builder targeting `program`.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            policy: SandboxPolicy {
                program: program.into(),
                args: Vec::new(),
                env: Vec::new(),
                inherit_env: false,
                cwd: None,
                rootfs: None,
                hostname: Some("rsb".to_string()),
                namespaces: NamespaceConfig::default(),
                landlock_enabled: true,
                fs_rules: Vec::new(),
                ephemeral_cow: Vec::new(),
                seccomp: SeccompPolicy::default(),
                limits: ResourceLimits::default(),
            },
        }
    }

    /// Append a single command-line argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.policy.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.policy.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable inside the sandbox.
    pub fn env(mut self, key: impl Into<OsString>, val: impl Into<OsString>) -> Self {
        self.policy.env.push((key.into(), val.into()));
        self
    }

    /// Control whether the parent's environment variables are inherited.
    pub fn inherit_env(mut self, inherit: bool) -> Self {
        self.policy.inherit_env = inherit;
        self
    }

    /// Set the working directory inside the sandbox.
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.policy.cwd = Some(dir.into());
        self
    }

    /// Pivot into a dedicated root filesystem directory (`pivot_root(".", ".")` +
    /// `umount2(".", MNT_DETACH)` + masked `/proc`) inside the mount namespace.
    pub fn rootfs(mut self, dir: impl Into<PathBuf>) -> Self {
        self.policy.rootfs = Some(dir.into());
        self
    }

    /// Set the hostname inside the sandbox's UTS namespace.
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.policy.hostname = Some(name.into());
        self
    }

    /// Allow read + execute access to `path` (typical for `/usr`, `/lib`, binaries).
    pub fn ro(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy.fs_rules.push(FsRule {
            path: path.into(),
            access: AccessMode::ReadExec,
        });
        self
    }

    /// Allow read-only (non-executable) access to `path`.
    pub fn ro_data(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy.fs_rules.push(FsRule {
            path: path.into(),
            access: AccessMode::ReadOnly,
        });
        self
    }

    /// Allow read + write + execute access to `path`.
    pub fn rw(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy.fs_rules.push(FsRule {
            path: path.into(),
            access: AccessMode::ReadWrite,
        });
        self
    }

    /// Mount `path` as an ephemeral Copy-on-Write OverlayFS layer (inside mount namespace).
    /// All writes/deletes go to a temporary upperdir and vanish when the sandbox exits.
    pub fn ephemeral_cow(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.policy.ephemeral_cow.push(p.clone());
        self.policy.fs_rules.push(FsRule {
            path: p,
            access: AccessMode::ReadWrite,
        });
        self
    }

    /// Apply a loaded `SandboxProfile` (`sandbox.toml`) onto this builder.
    pub fn with_profile(self, profile: &crate::profile::SandboxProfile) -> Self {
        profile.apply_to(self)
    }

    /// Convenience helper: allow standard read-only system runtime paths that exist
    /// on this host so dynamically linked binaries (glibc/musl) can start.
    pub fn allow_system_runtime(mut self) -> Self {
        const SYSTEM_RO_EXEC: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];
        const SYSTEM_RO_DATA: &[&str] = &[
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/ssl/openssl.cnf",
            "/etc/ssl/certs",
            "/etc/ca-certificates",
            "/etc/pki",
            "/etc/localtime",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/dev/zero",
            "/dev/urandom",
            "/dev/random",
        ];

        for p in SYSTEM_RO_EXEC {
            if Path::new(p).exists() {
                self.policy.fs_rules.push(FsRule {
                    path: PathBuf::from(p),
                    access: AccessMode::ReadExec,
                });
            }
        }
        for p in SYSTEM_RO_DATA {
            if Path::new(p).exists() {
                self.policy.fs_rules.push(FsRule {
                    path: PathBuf::from(p),
                    access: AccessMode::ReadOnly,
                });
            }
        }
        if Path::new("/dev/null").exists() {
            self.policy.fs_rules.push(FsRule {
                path: PathBuf::from("/dev/null"),
                access: AccessMode::ReadWrite,
            });
        }
        self
    }

    /// Allow network access (`true`) or block it (`false`, default).
    /// Controls both `CLONE_NEWNET` (namespaces) and `socket()` BPF filtering (Seccomp).
    pub fn allow_network(mut self, allow: bool) -> Self {
        self.policy.namespaces.isolate_network = !allow;
        self.policy.seccomp.block_network_sockets = !allow;
        self
    }

    /// Enable transparent rootless TAP networking (`CLONE_NEWNET` + `tap0` `10.0.2.15/24`,
    /// gateway `10.0.2.2`, passed to host via `SCM_RIGHTS` for `SlirpBridge::spawn_on_tap`).
    /// Keeps `CLONE_NEWNET` isolated while allowing `AF_INET` sockets inside the netns.
    pub fn transparent_tap(mut self) -> Self {
        self.policy.namespaces.enabled = true;
        self.policy.namespaces.isolate_network = true;
        self.policy.seccomp.block_network_sockets = false;
        self
    }

    /// Enable or disable Linux namespace isolation (`clone3`).
    pub fn namespaces(mut self, enabled: bool) -> Self {
        self.policy.namespaces.enabled = enabled;
        self
    }

    /// Enable or disable Landlock LSM filesystem confinement.
    pub fn landlock(mut self, enabled: bool) -> Self {
        self.policy.landlock_enabled = enabled;
        self
    }

    /// Enable or disable Seccomp-BPF syscall filtering.
    pub fn seccomp(mut self, enabled: bool) -> Self {
        self.policy.seccomp.enabled = enabled;
        self
    }

    /// Provide a custom `SeccompPolicy`.
    pub fn seccomp_policy(mut self, policy: SeccompPolicy) -> Self {
        self.policy.seccomp = policy;
        self
    }

    /// Deny an additional architecture-specific syscall number via Seccomp-BPF.
    pub fn deny_syscall(mut self, syscall_nr: u32, action: SeccompAction) -> Self {
        self.policy.seccomp.extra_denied.push((syscall_nr, action));
        self
    }

    /// Enable strict Seccomp-BPF allowlist mode: ONLY these syscall numbers (plus
    /// `execve`, `exit`, `exit_group`) are allowed; all others fail with `EPERM`.
    pub fn allow_syscalls(mut self, syscalls: impl Into<Vec<u32>>) -> Self {
        self.policy.seccomp.enabled = true;
        self.policy.seccomp.allowlist = Some(syscalls.into());
        self
    }

    /// Set maximum memory quota in bytes (enforced via Cgroups v2 `memory.max`).
    pub fn memory_limit_bytes(mut self, bytes: u64) -> Self {
        self.policy.limits.memory_max_bytes = Some(bytes);
        self
    }

    /// Set maximum memory quota in MiB (enforced via Cgroups v2 `memory.max`).
    pub fn memory_limit_mb(self, mib: u64) -> Self {
        self.memory_limit_bytes(mib.saturating_mul(1024 * 1024))
    }

    /// Set maximum process/thread count (enforced via Cgroups v2 `pids.max`).
    pub fn pids_limit(mut self, max_pids: u32) -> Self {
        self.policy.limits.pids_max = Some(max_pids);
        self
    }

    /// Set CPU quota as a percentage of one core (e.g., `25` = 25% of 1 core).
    pub fn cpu_quota_percent(mut self, percent: u32) -> Self {
        self.policy.limits.cpu_quota_percent = Some(percent);
        self
    }

    /// Set block I/O bandwidth limit (`io.max` in Cgroups v2): `None` emits `max`.
    pub fn io_max_bps(
        mut self,
        major: u32,
        minor: u32,
        rbps: Option<u64>,
        wbps: Option<u64>,
    ) -> Self {
        self.policy.limits.io_max_bps = Some((major, minor, rbps, wbps));
        self
    }

    /// Set wall-clock execution timeout; child process group is killed with `SIGKILL` on expiry.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.policy.limits.timeout = Some(duration);
        self
    }

    /// Override the open file descriptor limit (`RLIMIT_NOFILE`, defaults to `256`).
    pub fn rlimit_nofile(mut self, max_fds: u64) -> Self {
        self.policy.limits.rlimit_nofile = Some(max_fds);
        self
    }

    /// If `true`, return an error when Cgroups v2 limits are requested without delegation.
    pub fn strict_cgroup(mut self, strict: bool) -> Self {
        self.policy.limits.strict_cgroup = strict;
        self
    }

    /// Pre-compile the policy into a zero-allocation-child `PreparedSandbox`.
    pub fn prepare(self) -> Result<PreparedSandbox, SandboxError> {
        PreparedSandbox::from_policy(self.policy)
    }

    /// Prepare and immediately execute the sandbox (inheriting stdio), waiting for completion.
    pub fn run(self) -> Result<ExecutionReport, SandboxError> {
        self.prepare()?.run()
    }

    /// Prepare and execute the sandbox while capturing `stdout` and `stderr` up to
    /// `max_output_bytes` per stream (ideal for AI agent code execution).
    pub fn run_captured(
        self,
        max_output_bytes: usize,
    ) -> Result<CapturedExecutionReport, SandboxError> {
        self.prepare()?.run_captured(max_output_bytes)
    }
}

/// Entrypoint namespace for creating sandboxes.
pub struct Sandbox;

impl Sandbox {
    /// Start building a new sandboxed execution for `program`.
    pub fn builder(program: impl Into<PathBuf>) -> SandboxBuilder {
        SandboxBuilder::new(program)
    }
}
