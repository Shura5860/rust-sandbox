//! `rsb-net` — Zero-C-dependency L3/L4/L7 network egress filtering for `rust-sandbox`.
//!
//! Provides:
//! - [`EgressPolicy`]: Declarative domain wildcard + CIDR/port allowlist with default-on SSRF guard.
//! - [`extract_tls_sni`]: Pure-Rust TLS 1.2/1.3 `ClientHello` SNI extractor (no MITM decryption).
//! - [`dns`]: Pure-Rust RFC 1035 DNS wire parser, `REFUSED` and `A`-record response builders.
//! - [`EgressProxy`]: Filtering HTTP/HTTPS `CONNECT` proxy with post-DNS SSRF & SNI verification.
//! - [`tap`]: Rootless Linux `/dev/net/tun` TAP creation + pure-Rust IPv4 ioctl configuration.
//! - [`slirp`] (`feature = "smoltcp-bridge"`): Transparent L2/L3 `smoltcp` userspace gateway
//!   with `any_ip = true` for binaries that ignore `HTTP_PROXY`.

#![cfg(target_os = "linux")]

pub mod dns;
pub mod policy;
pub mod proxy;
#[cfg(feature = "smoltcp-bridge")]
pub mod slirp;
pub mod sni;
pub mod tap;

pub use policy::{CidrRule, DomainRule, EgressDecision, EgressPolicy, is_private_or_metadata};
pub use proxy::EgressProxy;
#[cfg(feature = "smoltcp-bridge")]
pub use slirp::{BridgeStats, GATEWAY_IP, GUEST_IP, SlirpBridge, SlirpHandle};
pub use sni::extract_tls_sni;
