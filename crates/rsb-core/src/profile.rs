//! Zero-dependency `sandbox.toml` declarative profile parser and serializer.
//!
//! Example `sandbox.toml`:
//! ```toml
//! [isolation]
//! namespaces = true
//! landlock = true
//! seccomp = true
//! allow_network = false
//! auto_system_runtime = true
//!
//! [limits]
//! memory_mb = 256
//! pids = 32
//! cpu_pct = 50
//! timeout_ms = 5000
//!
//! [filesystem]
//! ro = ["/etc/ssl"]
//! ro_data = ["/etc/hosts"]
//! rw = ["./work"]
//! ephemeral_cow = ["./work"]
//! ```

use crate::error::SandboxError;
use crate::policy::SandboxBuilder;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Declarative sandbox profile backed by `sandbox.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxProfile {
    pub namespaces: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub allow_network: bool,
    pub auto_system_runtime: bool,
    pub hostname: Option<String>,
    pub memory_mb: Option<u64>,
    pub pids: Option<u32>,
    pub cpu_pct: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub ro: Vec<PathBuf>,
    pub ro_data: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub ephemeral_cow: Vec<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub allow_domains: Vec<String>,
    pub allow_cidrs: Vec<String>,
    pub transparent_tap: bool,
    /// Optional strict Seccomp-BPF syscall allowlist (from `rsb learn --strict`).
    pub allow_syscalls: Option<Vec<u32>>,
}

impl Default for SandboxProfile {
    fn default() -> Self {
        Self {
            namespaces: true,
            landlock: true,
            seccomp: true,
            allow_network: false,
            auto_system_runtime: true,
            hostname: Some("rsb".to_string()),
            memory_mb: None,
            pids: None,
            cpu_pct: None,
            timeout_ms: None,
            ro: Vec::new(),
            ro_data: Vec::new(),
            rw: Vec::new(),
            ephemeral_cow: Vec::new(),
            rootfs: None,
            allow_domains: Vec::new(),
            allow_cidrs: Vec::new(),
            transparent_tap: false,
            allow_syscalls: None,
        }
    }
}

impl SandboxProfile {
    /// Load and parse a `sandbox.toml` profile from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SandboxError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_toml(&content)
    }

    /// Parse a `sandbox.toml` string without external dependencies.
    pub fn from_toml(input: &str) -> Result<Self, SandboxError> {
        let mut profile = Self::default();
        let mut section = String::new();
        let mut seen_sections = std::collections::BTreeSet::new();
        let mut seen_keys = std::collections::BTreeSet::new();
        let mut seccomp_mode: Option<String> = None;

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line_no = line_idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let sec = line[1..line.len() - 1].trim();
                if !matches!(sec, "isolation" | "limits" | "filesystem" | "network" | "seccomp") {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "sandbox.toml line {line_no}: unknown section `[{sec}]`"
                    )));
                }
                if !seen_sections.insert(sec.to_string()) {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "sandbox.toml line {line_no}: duplicate section `[{sec}]`"
                    )));
                }
                section = sec.to_string();
                continue;
            }

            let Some((k, v)) = line.split_once('=') else {
                return Err(SandboxError::InvalidPolicy(format!(
                    "sandbox.toml line {line_no}: expected `key = value`"
                )));
            };
            let key = k.trim();
            let val = v.trim();
            if !seen_keys.insert((section.clone(), key.to_string())) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "sandbox.toml line {line_no}: duplicate key `{section}.{key}`"
                )));
            }

            match (section.as_str(), key) {
                ("isolation", "namespaces") => profile.namespaces = parse_bool(val, line_no)?,
                ("isolation", "landlock") => profile.landlock = parse_bool(val, line_no)?,
                ("isolation", "seccomp") => profile.seccomp = parse_bool(val, line_no)?,
                ("isolation", "allow_network") => profile.allow_network = parse_bool(val, line_no)?,
                ("isolation", "auto_system_runtime") => {
                    profile.auto_system_runtime = parse_bool(val, line_no)?
                }
                ("isolation", "hostname") => profile.hostname = Some(parse_string(val, line_no)?),
                ("limits", "memory_mb") => profile.memory_mb = Some(parse_u64(val, line_no)?),
                ("limits", "pids") => profile.pids = Some(parse_u32(val, line_no)?),
                ("limits", "cpu_pct") => profile.cpu_pct = Some(parse_u32(val, line_no)?),
                ("limits", "timeout_ms") => profile.timeout_ms = Some(parse_u64(val, line_no)?),
                ("filesystem", "ro") => profile.ro = parse_path_array(val, line_no)?,
                ("filesystem", "ro_data") => profile.ro_data = parse_path_array(val, line_no)?,
                ("filesystem", "rw") => profile.rw = parse_path_array(val, line_no)?,
                ("filesystem", "ephemeral_cow") => {
                    profile.ephemeral_cow = parse_path_array(val, line_no)?
                }
                ("filesystem", "rootfs") => {
                    profile.rootfs = Some(PathBuf::from(parse_string(val, line_no)?))
                }
                ("network", "allow_domains") => {
                    profile.allow_domains = parse_path_array(val, line_no)?
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                }
                ("network", "allow_cidrs") => {
                    profile.allow_cidrs = parse_path_array(val, line_no)?
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                }
                ("network", "transparent_tap") => {
                    profile.transparent_tap = parse_bool(val, line_no)?;
                }
                ("seccomp", "mode") => {
                    let mode = parse_string(val, line_no)?;
                    if mode != "allowlist" && mode != "denylist" {
                        return Err(SandboxError::InvalidPolicy(format!(
                            "sandbox.toml line {line_no}: seccomp.mode must be `allowlist` or `denylist`"
                        )));
                    }
                    seccomp_mode = Some(mode);
                }
                ("seccomp", "allow_syscalls") => {
                    profile.allow_syscalls = Some(parse_u32_array(val, line_no)?);
                }
                (sec, unknown) => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "sandbox.toml line {line_no}: unknown key `{sec}.{unknown}`"
                    )));
                }
            }
        }

        if let Some(mode) = seccomp_mode {
            if mode == "allowlist" && profile.allow_syscalls.is_none() {
                return Err(SandboxError::InvalidPolicy(
                    "sandbox.toml: seccomp.mode = \"allowlist\" requires `allow_syscalls`".into(),
                ));
            }
            if mode == "denylist" && profile.allow_syscalls.is_some() {
                return Err(SandboxError::InvalidPolicy(
                    "sandbox.toml: seccomp.mode = \"denylist\" cannot be combined with `allow_syscalls`".into(),
                ));
            }
        }

        Ok(profile)
    }

    /// Serialize this profile to a clean, human-readable `sandbox.toml` string.
    pub fn to_toml(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str("# rust-sandbox security profile\n\n");
        out.push_str("[isolation]\n");
        out.push_str(&format!("namespaces = {}\n", self.namespaces));
        out.push_str(&format!("landlock = {}\n", self.landlock));
        out.push_str(&format!("seccomp = {}\n", self.seccomp));
        out.push_str(&format!("allow_network = {}\n", self.allow_network));
        out.push_str(&format!(
            "auto_system_runtime = {}\n",
            self.auto_system_runtime
        ));
        if let Some(ref h) = self.hostname {
            out.push_str(&format!("hostname = \"{}\"\n", escape_toml_str(h)));
        }

        if self.memory_mb.is_some()
            || self.pids.is_some()
            || self.cpu_pct.is_some()
            || self.timeout_ms.is_some()
        {
            out.push_str("\n[limits]\n");
            if let Some(m) = self.memory_mb {
                out.push_str(&format!("memory_mb = {m}\n"));
            }
            if let Some(p) = self.pids {
                out.push_str(&format!("pids = {p}\n"));
            }
            if let Some(c) = self.cpu_pct {
                out.push_str(&format!("cpu_pct = {c}\n"));
            }
            if let Some(t) = self.timeout_ms {
                out.push_str(&format!("timeout_ms = {t}\n"));
            }
        }

        out.push_str("\n[filesystem]\n");
        out.push_str(&format!("ro = {}\n", format_path_array(&self.ro)));
        out.push_str(&format!("ro_data = {}\n", format_path_array(&self.ro_data)));
        out.push_str(&format!("rw = {}\n", format_path_array(&self.rw)));
        if !self.ephemeral_cow.is_empty() {
            out.push_str(&format!(
                "ephemeral_cow = {}\n",
                format_path_array(&self.ephemeral_cow)
            ));
        }
        if let Some(ref root) = self.rootfs {
            out.push_str(&format!(
                "rootfs = \"{}\"\n",
                escape_toml_str(&root.to_string_lossy())
            ));
        }
        if !self.allow_domains.is_empty() || !self.allow_cidrs.is_empty() || self.transparent_tap {
            out.push_str("\n[network]\n");
            let dom_paths: Vec<PathBuf> = self.allow_domains.iter().map(PathBuf::from).collect();
            let cidr_paths: Vec<PathBuf> = self.allow_cidrs.iter().map(PathBuf::from).collect();
            out.push_str(&format!("allow_domains = {}\n", format_path_array(&dom_paths)));
            out.push_str(&format!("allow_cidrs = {}\n", format_path_array(&cidr_paths)));
            out.push_str(&format!("transparent_tap = {}\n", self.transparent_tap));
        }
        if let Some(ref allow) = self.allow_syscalls {
            out.push_str("\n[seccomp]\n");
            out.push_str("mode = \"allowlist\"\n");
            out.push_str(&format!("allow_syscalls = {}\n", format_u32_array(allow)));
        }
        out
    }

    /// Merge another `SandboxProfile` into `self` by taking the union of observed
    /// filesystem paths, network allowlists, and `allow_syscalls`.
    ///
    /// Useful with `rsb learn --merge` to combine multiple runs (e.g. happy path +
    /// failure path + test suite) into a single `sandbox.toml` profile.
    pub fn merge(&mut self, other: &SandboxProfile) {
        self.allow_network |= other.allow_network;
        self.transparent_tap |= other.transparent_tap;

        fn union_sorted<T: Ord + Clone>(dst: &mut Vec<T>, src: &[T]) {
            dst.extend(src.iter().cloned());
            dst.sort();
            dst.dedup();
        }

        union_sorted(&mut self.rw, &other.rw);
        union_sorted(&mut self.ro, &other.ro);
        union_sorted(&mut self.ro_data, &other.ro_data);
        union_sorted(&mut self.ephemeral_cow, &other.ephemeral_cow);
        union_sorted(&mut self.allow_domains, &other.allow_domains);
        union_sorted(&mut self.allow_cidrs, &other.allow_cidrs);

        // Paths promoted to `rw` do not need to be duplicated in `ro` / `ro_data`.
        self.ro.retain(|p| !self.rw.contains(p));
        self.ro_data.retain(|p| !self.rw.contains(p));

        match (&mut self.allow_syscalls, &other.allow_syscalls) {
            (Some(dst), Some(src)) => union_sorted(dst, src),
            (None, Some(src)) => {
                let mut v = src.clone();
                v.sort_unstable();
                v.dedup();
                self.allow_syscalls = Some(v);
            }
            _ => {}
        }
    }

    /// Apply this profile's settings onto a `SandboxBuilder`.
    pub fn apply_to(&self, mut builder: SandboxBuilder) -> SandboxBuilder {
        builder = builder
            .namespaces(self.namespaces)
            .landlock(self.landlock)
            .seccomp(self.seccomp)
            .allow_network(self.allow_network);

        if let Some(ref allow) = self.allow_syscalls
            && self.seccomp
        {
            builder = builder.allow_syscalls(allow.clone());
        }

        if self.auto_system_runtime && self.landlock {
            builder = builder.allow_system_runtime();
        }
        if let Some(ref h) = self.hostname {
            builder = builder.hostname(h.clone());
        }
        if let Some(m) = self.memory_mb {
            builder = builder.memory_limit_mb(m);
        }
        if let Some(p) = self.pids {
            builder = builder.pids_limit(p);
        }
        if let Some(c) = self.cpu_pct {
            builder = builder.cpu_quota_percent(c);
        }
        if let Some(t) = self.timeout_ms {
            builder = builder.timeout(Duration::from_millis(t));
        }
        for p in &self.ro {
            builder = builder.ro(p);
        }
        for p in &self.ro_data {
            builder = builder.ro_data(p);
        }
        for p in &self.rw {
            builder = builder.rw(p);
        }
        for p in &self.ephemeral_cow {
            builder = builder.ephemeral_cow(p);
        }
        if let Some(ref root) = self.rootfs {
            builder = builder.rootfs(root);
        }
        builder
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_bool(val: &str, line_no: usize) -> Result<bool, SandboxError> {
    match val {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: expected boolean (`true`/`false`), got `{val}`"
        ))),
    }
}

fn parse_u64(val: &str, line_no: usize) -> Result<u64, SandboxError> {
    val.replace('_', "").parse::<u64>().map_err(|_| {
        SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: expected integer, got `{val}`"
        ))
    })
}

fn parse_u32(val: &str, line_no: usize) -> Result<u32, SandboxError> {
    let n = parse_u64(val, line_no)?;
    u32::try_from(n).map_err(|_| {
        SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: integer `{val}` exceeds u32::MAX"
        ))
    })
}

fn parse_string(val: &str, line_no: usize) -> Result<String, SandboxError> {
    if !(val.starts_with('"') && val.ends_with('"') && val.len() >= 2) {
        return Err(SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: expected quoted string, got `{val}`"
        )));
    }
    let inner = &val[1..val.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            return Err(SandboxError::InvalidPolicy(format!(
                "sandbox.toml line {line_no}: unescaped `\"` inside string `{val}`"
            )));
        }
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{0008}'),
                Some('f') => out.push('\u{000C}'),
                Some(other) => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "sandbox.toml line {line_no}: unsupported escape `\\{other}`"
                    )));
                }
                None => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "sandbox.toml line {line_no}: unterminated escape sequence in `{val}`"
                    )));
                }
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn parse_path_array(val: &str, line_no: usize) -> Result<Vec<PathBuf>, SandboxError> {
    if !(val.starts_with('[') && val.ends_with(']')) {
        return Err(SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: expected array `[...]`, got `{val}`"
        )));
    }
    let inner = val[1..val.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            cur.push('\\');
            cur.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                let item = cur.trim();
                if !item.is_empty() {
                    items.push(PathBuf::from(parse_string(item, line_no)?));
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let last = cur.trim();
    if !last.is_empty() {
        items.push(PathBuf::from(parse_string(last, line_no)?));
    }

    Ok(items)
}

fn parse_u32_array(val: &str, line_no: usize) -> Result<Vec<u32>, SandboxError> {
    if !(val.starts_with('[') && val.ends_with(']')) {
        return Err(SandboxError::InvalidPolicy(format!(
            "sandbox.toml line {line_no}: expected integer array `[...]`, got `{val}`"
        )));
    }
    let inner = val[1..val.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    for part in inner.split(',') {
        let s = part.trim();
        if s.is_empty() {
            continue;
        }
        let n = parse_u32(s, line_no)?;
        items.push(n);
    }
    Ok(items)
}

fn format_u32_array(nums: &[u32]) -> String {
    let mut out = String::from("[");
    for (idx, n) in nums.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&n.to_string());
    }
    out.push(']');
    out
}

fn escape_toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {}
            c => out.push(c),
        }
    }
    out
}

fn format_path_array(paths: &[PathBuf]) -> String {
    let mut out = String::from("[");
    for (idx, p) in paths.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&escape_toml_str(&p.to_string_lossy()));
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_profile_roundtrip() {
        let p = SandboxProfile {
            allow_network: false,
            memory_mb: Some(128),
            pids: Some(32),
            cpu_pct: Some(25),
            timeout_ms: Some(3000),
            ro: vec![PathBuf::from("/etc/ssl")],
            rw: vec![PathBuf::from("/tmp/work")],
            ephemeral_cow: vec![PathBuf::from("/tmp/work")],
            ..Default::default()
        };

        let toml = p.to_toml();
        let parsed = SandboxProfile::from_toml(&toml).expect("parse generated toml");
        assert_eq!(parsed, p);
    }

    #[test]
    fn merge_profiles_unions_paths_and_syscalls() {
        let mut base = SandboxProfile {
            allow_network: false,
            ro: vec![PathBuf::from("/etc/a"), PathBuf::from("/var/log/app")],
            rw: vec![PathBuf::from("/tmp/out")],
            allow_syscalls: Some(vec![1, 60]),
            ..Default::default()
        };
        let extra = SandboxProfile {
            allow_network: true,
            ro: vec![PathBuf::from("/etc/b")],
            rw: vec![PathBuf::from("/var/log/app"), PathBuf::from("/tmp/err")],
            allow_syscalls: Some(vec![2, 60, 231]),
            ..Default::default()
        };

        base.merge(&extra);
        assert!(base.allow_network);
        assert_eq!(base.ro, vec![PathBuf::from("/etc/a"), PathBuf::from("/etc/b")]);
        assert_eq!(
            base.rw,
            vec![
                PathBuf::from("/tmp/err"),
                PathBuf::from("/tmp/out"),
                PathBuf::from("/var/log/app"),
            ]
        );
        assert_eq!(base.allow_syscalls, Some(vec![1, 2, 60, 231]));
    }

    #[test]
    fn fuzz_toml_profile_parser_never_panics() {
        let nasty_cases = [
            "",
            "=",
            "[",
            "]",
            "[[[]]]",
            "[isolation]\nnamespaces = \"",
            "[isolation]\nhostname = \"unterminated\\",
            "[filesystem]\nro = [\"a\", \"b\\\", \"c\"]",
            "[filesystem]\nro = [\"\"\"\"\"\"",
            "[seccomp]\nallow_syscalls = [9999999999999999999999999999]",
            "[limits]\nmemory_mb = -1",
            "[isolation]\n# comment with \"quotes\" and [brackets]\nnamespaces = true # trailing",
            "\0\0\0[isolation]\nnamespaces = false\0",
        ];
        for case in nasty_cases {
            let _ = SandboxProfile::from_toml(case);
        }

        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789[]=\"#,\\ \n\t_-.";
        let mut state: u64 = 0x517C_C1B7_2722_0A95;
        let mut next_usize = || -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as usize
        };

        for _ in 0..10_000u32 {
            let len = next_usize() % 180;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                s.push(alphabet[next_usize() % alphabet.len()] as char);
            }
            let _ = SandboxProfile::from_toml(&s);
        }
    }
}
