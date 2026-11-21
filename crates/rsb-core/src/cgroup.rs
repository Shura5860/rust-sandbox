//! Rootless Cgroups v2 resource quota controller (`memory.max`, `cpu.max`, `pids.max`).
//!
//! Discovers the calling process's current cgroup v2 path via `/proc/self/cgroup`.
//! If that subtree is delegated and writable (e.g., under a `systemd` user slice
//! or container cgroup), creates an ephemeral leaf cgroup for each sandboxed child,
//! enforces quotas *before* the child executes user code, reads `memory.peak` on exit,
//! and removes the leaf cgroup on `Drop`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static CGROUP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Resource limits enforced on a sandboxed execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum memory in bytes (`memory.max` in Cgroups v2).
    pub memory_max_bytes: Option<u64>,
    /// Maximum number of processes/threads (`pids.max` — stops fork bombs).
    pub pids_max: Option<u32>,
    /// CPU quota as percentage of a single core (e.g. `25` = 25% of 1 core, `200` = 2 cores).
    pub cpu_quota_percent: Option<u32>,
    /// Wall-clock execution timeout enforced by parent (`SIGKILL` on expiry).
    pub timeout: Option<Duration>,
    /// Open file descriptor soft/hard limit (`RLIMIT_NOFILE`, defaults to `256`).
    pub rlimit_nofile: Option<u64>,
    /// If `true`, fail when Cgroups v2 limits are requested but the host cgroup is not writable.
    /// If `false` (default), gracefully skip cgroup enforcement and report `cgroup_active = false`.
    pub strict_cgroup: bool,
}

impl ResourceLimits {
    /// Returns `true` if any Cgroups v2 quota (`memory`, `pids`, or `cpu`) is configured.
    pub fn has_cgroup_quotas(&self) -> bool {
        self.memory_max_bytes.is_some()
            || self.pids_max.is_some()
            || self.cpu_quota_percent.is_some()
    }
}

/// Active ephemeral Cgroups v2 leaf directory. Automatically cleaned up on `Drop`.
#[derive(Debug)]
pub struct CgroupGuard {
    dir: PathBuf,
}

impl CgroupGuard {
    /// Attempt to create an ephemeral leaf cgroup and apply `limits`.
    ///
    /// Returns `Ok(Some(guard))` if created, `Ok(None)` if no cgroup quotas were
    /// requested or if cgroup v2 is not delegated and `strict_cgroup == false`.
    pub fn create(limits: &ResourceLimits) -> Result<Option<Self>, std::io::Error> {
        if !limits.has_cgroup_quotas() {
            return Ok(None);
        }

        let Some(parent_dir) = find_writable_cgroup_v2_dir() else {
            if limits.strict_cgroup {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "no writable delegated Cgroups v2 directory found under /sys/fs/cgroup",
                ));
            }
            return Ok(None);
        };

        let seq = CGROUP_SEQ.fetch_add(1, Ordering::Relaxed);
        let leaf = parent_dir.join(format!("rsb-{}-{}", std::process::id(), seq));
        if let Err(e) = fs::create_dir(&leaf) {
            if limits.strict_cgroup {
                return Err(e);
            }
            return Ok(None);
        }

        let guard = Self { dir: leaf };
        let mut applied_any = false;

        // Apply configured limits. Track whether at least one quota file actually succeeded
        // so we never falsely report `cgroup_active = true` when the parent cgroup lacks
        // delegated controllers (e.g. Cgroups v2 "no internal processes" rule).
        if let Some(mem) = limits.memory_max_bytes {
            match fs::write(guard.dir.join("memory.max"), format!("{mem}\n")) {
                Ok(()) => applied_any = true,
                Err(e) if limits.strict_cgroup => return Err(e),
                Err(_) => {}
            }
        }

        if let Some(pids) = limits.pids_max {
            match fs::write(guard.dir.join("pids.max"), format!("{pids}\n")) {
                Ok(()) => applied_any = true,
                Err(e) if limits.strict_cgroup => return Err(e),
                Err(_) => {}
            }
        }

        if let Some(pct) = limits.cpu_quota_percent {
            // Standard 100ms (100_000us) CFS period
            let period_us: u64 = 100_000;
            let quota_us: u64 = (pct as u64).saturating_mul(1_000).max(1_000);
            match fs::write(guard.dir.join("cpu.max"), format!("{quota_us} {period_us}\n")) {
                Ok(()) => applied_any = true,
                Err(e) if limits.strict_cgroup => return Err(e),
                Err(_) => {}
            }
        }

        if !applied_any {
            // Drop `guard` to remove the empty leaf directory and report cgroup inactive.
            drop(guard);
            return Ok(None);
        }

        Ok(Some(guard))
    }

    /// Move `pid` into this cgroup by writing to `cgroup.procs`.
    pub fn attach_pid(&self, pid: i32) -> Result<(), std::io::Error> {
        fs::write(self.dir.join("cgroup.procs"), format!("{pid}\n"))
    }

    /// Open an `O_PATH | O_CLOEXEC` directory FD for atomic `clone3(CLONE_INTO_CGROUP)`.
    pub fn open_dir_fd(&self) -> Result<rsb_sys::rustix::fd::OwnedFd, std::io::Error> {
        use rsb_sys::rustix::fs::{CWD, Mode, OFlags, openat};
        openat(
            CWD,
            &self.dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
    }

    /// Read peak memory usage in bytes (`memory.peak`, Linux 5.19+), if available.
    pub fn read_memory_peak(&self) -> Option<u64> {
        fs::read_to_string(self.dir.join("memory.peak"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    }

    /// Path to the ephemeral cgroup directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Best-effort kill any lingering processes in the cgroup (Linux 5.14+)
        // so `remove_dir` does not fail with EBUSY and leak the cgroup directory.
        let _ = fs::write(self.dir.join("cgroup.kill"), b"1");
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Probe `/proc/self/cgroup` and check if the unified v2 hierarchy is writable.
pub fn find_writable_cgroup_v2_dir() -> Option<PathBuf> {
    let content = fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in content.lines() {
        // Unified cgroup v2 entry has format: `0::/path/to/cgroup`
        if let Some(rel) = line.strip_prefix("0::") {
            let rel_trimmed = rel.trim_start_matches('/');
            let full = if rel_trimmed.is_empty() {
                PathBuf::from("/sys/fs/cgroup")
            } else {
                PathBuf::from("/sys/fs/cgroup").join(rel_trimmed)
            };
            if full.is_dir() && is_dir_writable(&full) {
                return Some(full);
            }
        }
    }
    None
}

fn is_dir_writable(dir: &Path) -> bool {
    let seq = CGROUP_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".rsb-probe-{}-{seq}", std::process::id()));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_have_no_cgroup_quotas() {
        let lim = ResourceLimits::default();
        assert!(!lim.has_cgroup_quotas());
        assert!(CgroupGuard::create(&lim).unwrap().is_none());
    }
}
