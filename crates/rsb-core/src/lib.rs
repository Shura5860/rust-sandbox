//! `rsb-core` — Zero-C-dependency, embeddable Linux isolation engine.
//!
//! Combines rootless Linux namespaces (`clone3`), Landlock LSM, pure-Rust
//! Seccomp-BPF syscall filtering, rootless Cgroups v2 quotas, ephemeral CoW
//! OverlayFS, declarative `sandbox.toml` profiles, and `ptrace`-based automatic
//! policy learning (`learn_policy`) into a single embeddable Rust crate.

#![cfg(target_os = "linux")]

pub mod cgroup;
mod child;
pub mod error;
#[cfg(target_arch = "x86_64")]
pub mod learn;
pub mod overlay;
pub mod policy;
pub mod prepared;
pub mod profile;
pub mod sandbox;
pub mod seccomp_bpf;
pub mod unotify;
pub mod zygote;

pub use cgroup::{ResourceLimits, find_writable_cgroup_v2_dir};
pub use error::{ChildStage, SandboxError};
#[cfg(target_arch = "x86_64")]
pub use learn::{LearnReport, learn_policy, learn_policy_with_options};
pub use overlay::{CowChange, CowChangeKind};
pub use policy::{AccessMode, FsRule, NamespaceConfig, Sandbox, SandboxBuilder, SandboxPolicy};
pub use prepared::PreparedSandbox;
pub use profile::SandboxProfile;
pub use sandbox::{CapturedExecutionReport, ExecutionReport, SpawnedSandbox};
pub use seccomp_bpf::{SeccompAction, SeccompPolicy};
pub use unotify::{SupervisedReport, UnotifyDecision, run_supervised};
pub use zygote::{NodeZygoteConfig, ZygoteConfig, ZygoteExecResult, ZygotePool};
pub use rsb_sys::landlock::abi_version as landlock_abi_version;
