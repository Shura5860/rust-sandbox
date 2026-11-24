//! Unified facade crate for `rust-sandbox` (`rsb`).
//!
//! Re-exports the core sandbox engine ([`rsb_core`]) at the crate root, the
//! low-level syscall layer under [`sys`], and (with the default `net` feature)
//! the L3/L4/L7 network egress filter and `smoltcp` TAP bridge under [`net`].
//!
//! # Quick Example
//!
//! ```no_run
//! use rsb_sandbox::Sandbox;
//! use std::time::Duration;
//!
//! let out = Sandbox::builder("/usr/bin/python3")
//!     .args(["-c", "print(6 * 7)"])
//!     .allow_system_runtime()
//!     .timeout(Duration::from_secs(5))
//!     .run_captured(64 * 1024)?;
//!
//! println!("{}", out.stdout_lossy());
//! # Ok::<(), rsb_sandbox::SandboxError>(())
//! ```

pub use rsb_core::*;

/// Low-level Linux syscall wrappers (`clone3`, Landlock, Seccomp, `ptrace`, `tap`, `unotify`).
pub use rsb_sys as sys;

/// Core sandbox engine module alias.
pub use rsb_core as core;

/// Network egress policy, TLS SNI verifier, DNS filter, `EgressProxy`, and `SlirpBridge`.
#[cfg(feature = "net")]
pub use rsb_net as net;
