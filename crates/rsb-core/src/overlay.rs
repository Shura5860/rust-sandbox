//! Ephemeral Copy-on-Write (CoW) OverlayFS layer & filesystem diff reporter.
//!
//! When running inside a rootless mount namespace (`CLONE_NEWUSER | CLONE_NEWNS`),
//! each configured `ephemeral_cow` directory is mounted with Linux kernel OverlayFS
//! (`userxattr` enabled for rootless Linux 5.11+ support):
//! - `lowerdir` = the real host directory (never modified!)
//! - `upperdir` = ephemeral staging directory under `/tmp/rsb-cow-.../upper`
//! - `workdir`  = ephemeral OverlayFS workdir under `/tmp/rsb-cow-.../work`
//!
//! After the sandboxed process exits, `CowSession::collect_diffs()` inspects `upperdir`
//! to produce a structured `Vec<CowChange>` (`Added`, `Modified`, `Deleted`), and `Drop`
//! removes the ephemeral staging directories so all changes evaporate without a trace.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COW_SEQ: AtomicU64 = AtomicU64::new(1);

/// Kind of filesystem mutation observed in an ephemeral CoW layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowChangeKind {
    Added,
    Modified,
    Deleted,
}

/// A single file or directory mutation recorded by the ephemeral CoW layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowChange {
    /// Path relative to the protected target directory (or combined target/rel).
    pub target: PathBuf,
    pub rel_path: PathBuf,
    pub kind: CowChangeKind,
}

/// Pre-compiled OverlayFS mount arguments for zero-allocation use in `child_main`.
#[derive(Debug)]
pub(crate) struct PreparedCowMount {
    pub target_path: PathBuf,
    pub target_cstr: CString,
    pub upper_dir: PathBuf,
    pub options_cstr: CString,
}

/// Owns the ephemeral staging root for all OverlayFS mounts in a single sandbox run.
/// Automatically cleans up all `upper`/`work` directories on `Drop`.
#[derive(Debug)]
pub(crate) struct CowSession {
    staging_root: PathBuf,
    pub mounts: Vec<PreparedCowMount>,
}

impl CowSession {
    /// Create ephemeral `upper/` and `work/` directories for each CoW target.
    pub fn create(targets: &[PathBuf]) -> Result<Option<Self>, std::io::Error> {
        if targets.is_empty() {
            return Ok(None);
        }

        let seq = COW_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let staging_root = std::env::temp_dir().join(format!(
            "rsb-cow-{}-{}-{:x}",
            std::process::id(),
            seq,
            nanos ^ (&seq as *const u64 as usize as u64),
        ));
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&staging_root)?;
        }

        let mut mounts = Vec::with_capacity(targets.len());
        for (idx, raw_target) in targets.iter().enumerate() {
            let target = fs::canonicalize(raw_target)?;
            let slot = staging_root.join(format!("m{idx}"));
            let upper = slot.join("upper");
            let work = slot.join("work");
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().mode(0o700).create(&slot)?;
                std::fs::DirBuilder::new().mode(0o700).create(&upper)?;
                std::fs::DirBuilder::new().mode(0o700).create(&work)?;
            }

            let target_cstr = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "CoW target path contains NUL byte",
                )
            })?;

            // `userxattr` enables unprivileged OverlayFS inside a user namespace (Linux 5.11+).
            let options = format!(
                "lowerdir={},upperdir={},workdir={},userxattr",
                escape_mount_opt(&target),
                escape_mount_opt(&upper),
                escape_mount_opt(&work),
            );
            let options_cstr = CString::new(options.as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "OverlayFS mount options contain NUL byte",
                )
            })?;

            mounts.push(PreparedCowMount {
                target_path: target,
                target_cstr,
                upper_dir: upper,
                options_cstr,
            });
        }

        Ok(Some(Self {
            staging_root,
            mounts,
        }))
    }

    /// Walk all `upper` directories and compute the list of Added / Modified / Deleted paths.
    pub fn collect_diffs(&self) -> Vec<CowChange> {
        let mut changes = Vec::new();
        for m in &self.mounts {
            collect_upper_diff(&m.target_path, &m.upper_dir, Path::new(""), &mut changes);
        }
        changes.sort_by(|a, b| (&a.target, &a.rel_path).cmp(&(&b.target, &b.rel_path)));
        changes
    }
}

impl Drop for CowSession {
    fn drop(&mut self) {
        // Restore owner rwx on directories in case the sandbox ran `chmod 0000` / `0555`
        // inside `upperdir`, which would otherwise cause `remove_dir_all` to fail with EACCES.
        make_tree_removable(&self.staging_root);
        let _ = fs::remove_dir_all(&self.staging_root);
    }
}

fn make_tree_removable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::symlink_metadata(dir)
        && meta.is_dir()
    {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                make_tree_removable(&entry.path());
            }
        }
    }
}

/// Recursively inspect an OverlayFS `upperdir` against `lower_root`.
pub(crate) fn collect_upper_diff(
    lower_root: &Path,
    upper_root: &Path,
    rel_dir: &Path,
    out: &mut Vec<CowChange>,
) {
    let cur_upper = upper_root.join(rel_dir);
    let Ok(entries) = fs::read_dir(&cur_upper) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let rel = if rel_dir.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            rel_dir.join(&name)
        };
        let upper_path = upper_root.join(&rel);
        let lower_path = lower_root.join(&rel);

        let Ok(meta) = fs::symlink_metadata(&upper_path) else {
            continue;
        };

        // OverlayFS encodes deleted files as 0/0 character devices (whiteouts).
        if meta.file_type().is_char_device() && meta.rdev() == 0 {
            out.push(CowChange {
                target: lower_root.to_path_buf(),
                rel_path: rel,
                kind: CowChangeKind::Deleted,
            });
            continue;
        }

        let lower_exists = fs::symlink_metadata(&lower_path).is_ok();
        if meta.is_dir() {
            if !lower_exists {
                out.push(CowChange {
                    target: lower_root.to_path_buf(),
                    rel_path: rel.clone(),
                    kind: CowChangeKind::Added,
                });
            }
            collect_upper_diff(lower_root, upper_root, &rel, out);
        } else {
            let kind = if lower_exists {
                CowChangeKind::Modified
            } else {
                CowChangeKind::Added
            };
            out.push(CowChange {
                target: lower_root.to_path_buf(),
                rel_path: rel,
                kind,
            });
        }
    }
}

/// Escape commas and colons in OverlayFS mount option paths.
fn escape_mount_opt(path: &Path) -> String {
    let s = path.to_string_lossy();
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ',' | ':' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_upper_diff_detects_added_and_modified_files() {
        let base = std::env::temp_dir().join(format!("rsb-cow-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let lower = base.join("lower");
        let upper = base.join("upper");
        fs::create_dir_all(&lower).unwrap();
        fs::create_dir_all(upper.join("sub")).unwrap();

        fs::write(lower.join("existing.txt"), "old").unwrap();
        fs::write(upper.join("existing.txt"), "new").unwrap();
        fs::write(upper.join("sub/created.txt"), "hi").unwrap();

        let mut changes = Vec::new();
        collect_upper_diff(&lower, &upper, Path::new(""), &mut changes);
        changes.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].rel_path, PathBuf::from("existing.txt"));
        assert_eq!(changes[0].kind, CowChangeKind::Modified);
        assert_eq!(changes[1].rel_path, PathBuf::from("sub"));
        assert_eq!(changes[1].kind, CowChangeKind::Added);
        assert_eq!(changes[2].rel_path, PathBuf::from("sub/created.txt"));
        assert_eq!(changes[2].kind, CowChangeKind::Added);

        let _ = fs::remove_dir_all(&base);
    }
}
