//! Error types for `rsb-core`.

use rsb_sys::RawErrno;
use std::fmt;
use std::path::PathBuf;

/// Stage inside the post-`clone3` child process where a setup failure occurred.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStage {
    SyncRead = 1,
    MountPrivate = 2,
    SetHostname = 3,
    NoNewPrivs = 4,
    LandlockCreate = 5,
    LandlockOpen = 6,
    LandlockAddRule = 7,
    LandlockRestrict = 8,
    Chdir = 9,
    Execve = 10,
    SeccompInstall = 11,
    DupStdio = 12,
    SetPgid = 13,
    MountOverlay = 14,
    PivotRoot = 15,
    Pid1Fork = 16,
    TapSetup = 17,
    Unknown = 255,
}

impl ChildStage {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::SyncRead,
            2 => Self::MountPrivate,
            3 => Self::SetHostname,
            4 => Self::NoNewPrivs,
            5 => Self::LandlockCreate,
            6 => Self::LandlockOpen,
            7 => Self::LandlockAddRule,
            8 => Self::LandlockRestrict,
            9 => Self::Chdir,
            10 => Self::Execve,
            11 => Self::SeccompInstall,
            12 => Self::DupStdio,
            13 => Self::SetPgid,
            14 => Self::MountOverlay,
            15 => Self::PivotRoot,
            16 => Self::Pid1Fork,
            17 => Self::TapSetup,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for ChildStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SyncRead => "parent/child namespace sync",
            Self::MountPrivate => "mount propagation (MS_PRIVATE)",
            Self::SetHostname => "UTS sethostname",
            Self::NoNewPrivs => "prctl(PR_SET_NO_NEW_PRIVS)",
            Self::LandlockCreate => "landlock_create_ruleset",
            Self::LandlockOpen => "openat(O_PATH) for Landlock rule",
            Self::LandlockAddRule => "landlock_add_rule",
            Self::LandlockRestrict => "landlock_restrict_self",
            Self::Chdir => "chdir",
            Self::Execve => "execve",
            Self::SeccompInstall => "seccomp(SECCOMP_SET_MODE_FILTER)",
            Self::DupStdio => "dup2(stdout/stderr capture)",
            Self::SetPgid => "setpgid",
            Self::MountOverlay => "mount(overlayfs ephemeral CoW)",
            Self::PivotRoot => "pivot_root / proc masking",
            Self::Pid1Fork => "PID 1 mini-init fork(PID 2)",
            Self::TapSetup => "rootless TAP (/dev/net/tun) + SCM_RIGHTS setup",
            Self::Unknown => "unknown child stage",
        };
        f.write_str(name)
    }
}

/// Top-level error type returned by `rust-sandbox`.
#[derive(Debug)]
pub enum SandboxError {
    InvalidPolicy(String),
    CommandNotFound(PathBuf),
    LandlockUnsupported(RawErrno),
    Syscall {
        stage: &'static str,
        errno: RawErrno,
    },
    ChildSetupFailed {
        stage: ChildStage,
        errno: RawErrno,
    },
    Io(std::io::Error),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(msg) => write!(f, "invalid sandbox policy: {msg}"),
            Self::CommandNotFound(p) => write!(f, "executable not found: {}", p.display()),
            Self::LandlockUnsupported(e) => {
                write!(f, "Landlock LSM is not supported on this kernel: {e}")
            }
            Self::Syscall { stage, errno } => {
                write!(f, "syscall failed at {stage}: {errno} (errno={})", errno.0)
            }
            Self::ChildSetupFailed { stage, errno } => {
                write!(
                    f,
                    "sandbox child failed at {stage}: {errno} (errno={})",
                    errno.0
                )
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::LandlockUnsupported(e)
            | Self::Syscall { errno: e, .. }
            | Self::ChildSetupFailed { errno: e, .. } => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
