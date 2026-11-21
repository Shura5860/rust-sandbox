//! Rootless Linux `/dev/net/tun` TAP device creation and pure-Rust IPv4 interface setup.
//!
//! Thin ergonomic wrapper around `rsb_sys::tap` (which is zero-allocation and
//! async-signal-safe for direct use inside `CLONE_NEWNET` child processes).

use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

/// Create a rootless TAP interface inside the current network namespace.
///
/// Returns `(tap_fd, assigned_ifname)`.
pub fn open_tap(name_hint: &str) -> Result<(OwnedFd, String), std::io::Error> {
    let (fd, name_buf) =
        rsb_sys::tap::open_tap_raw(name_hint.as_bytes()).map_err(|e| e.to_io_error())?;
    let end = name_buf.iter().position(|&b| b == 0).unwrap_or(16);
    let ifname = String::from_utf8_lossy(&name_buf[..end]).into_owned();
    Ok((fd, ifname))
}

/// Configure `ifname` with an IPv4 address, netmask, link UP, and default gateway
/// using pure Linux ioctls inside the sandbox's `CLONE_NEWNET` namespace.
pub fn configure_tap_ipv4(
    ifname: &str,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Result<(), std::io::Error> {
    let mut name_buf = [0u8; 16];
    let bytes = ifname.as_bytes();
    let n = bytes.len().min(15);
    name_buf[..n].copy_from_slice(&bytes[..n]);
    rsb_sys::tap::configure_tap_ipv4_raw(&name_buf, ip, netmask, gateway)
        .map_err(|e| e.to_io_error())
}
