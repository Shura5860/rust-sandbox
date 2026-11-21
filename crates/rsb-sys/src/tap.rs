//! Zero-allocation, async-signal-safe Linux `/dev/net/tun` TAP device creation
//! and IPv4 interface configuration (`SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`, `SIOCADDRT`).
//!
//! Designed to run inside a post-`clone3` `CLONE_NEWUSER | CLONE_NEWNET` child
//! before `drop_all_capabilities()` and `execve`, with zero heap allocations.

use crate::rustix::fs::{CWD, Mode, OFlags, openat};
use crate::{RawErrno, syscall3};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: usize = 16;
#[cfg(target_arch = "aarch64")]
const SYS_IOCTL: usize = 29;

#[cfg(target_arch = "x86_64")]
const SYS_SOCKET: usize = 41;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKET: usize = 198;

const AF_INET: usize = 2;
const SOCK_DGRAM: usize = 2;
const SOCK_CLOEXEC: usize = 0o2000000;

const TUNSETIFF: usize = 0x4004_54CA;
const SIOCSIFFLAGS: usize = 0x8914;
const SIOCSIFADDR: usize = 0x8916;
const SIOCSIFNETMASK: usize = 0x891C;
const SIOCADDRT: usize = 0x890B;

const IFF_UP: u16 = 0x0001;
const IFF_RUNNING: u16 = 0x0040;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;
const RTF_UP: u16 = 0x0001;
const RTF_GATEWAY: u16 = 0x0002;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

impl SockAddrIn {
    const fn from_ipv4(ip: Ipv4Addr) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: ip.octets(),
            sin_zero: [0u8; 8],
        }
    }
}

#[repr(C)]
struct IfReqFlags {
    ifr_name: [u8; 16],
    ifr_flags: u16,
    _pad: [u8; 22],
}

#[repr(C)]
struct IfReqAddr {
    ifr_name: [u8; 16],
    ifr_addr: SockAddrIn,
    _pad: [u8; 8],
}

#[repr(C)]
struct RtEntry {
    rt_pad1: usize,
    rt_dst: SockAddrIn,
    rt_gateway: SockAddrIn,
    rt_genmask: SockAddrIn,
    rt_flags: u16,
    rt_pad2: i16,
    rt_pad3: usize,
    rt_tos: u8,
    rt_class: u8,
    rt_pad4: [i16; 3],
    rt_metric: i16,
    rt_dev: *const u8,
    rt_mtu: usize,
    rt_window: usize,
    rt_irtt: u16,
}

/// Open `/dev/net/tun` with `O_RDWR | O_CLOEXEC` and attach a TAP device (`IFF_TAP | IFF_NO_PI`).
///
/// Zero heap allocation; returns `(tap_fd, fixed_16_byte_ifname)`.
pub fn open_tap_raw(name_hint: &[u8]) -> Result<(OwnedFd, [u8; 16]), RawErrno> {
    let fd = openat(
        CWD,
        c"/dev/net/tun",
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| RawErrno(e.raw_os_error()))?;

    let mut req = IfReqFlags {
        ifr_name: copy_ifname(name_hint),
        ifr_flags: IFF_TAP | IFF_NO_PI,
        _pad: [0u8; 22],
    };

    let ret = unsafe {
        syscall3(
            SYS_IOCTL,
            fd.as_raw_fd() as usize,
            TUNSETIFF,
            &mut req as *mut IfReqFlags as usize,
        )
    };
    RawErrno::from_raw_ret(ret)?;
    Ok((fd, req.ifr_name))
}

/// Configure a TAP interface (`ip`, `netmask`, link UP, default route via `gateway`)
/// and bring `lo` UP using pure Linux ioctls. Zero heap allocation.
pub fn configure_tap_ipv4_raw(
    ifname: &[u8; 16],
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Result<(), RawErrno> {
    let sock_ret = unsafe { syscall3(SYS_SOCKET, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    let sock_raw = RawErrno::from_raw_ret(sock_ret)? as RawFd;
    let sock = unsafe { OwnedFd::from_raw_fd(sock_raw) };

    // 0. Bring loopback `lo` UP (best-effort)
    let mut lo_req = IfReqFlags {
        ifr_name: copy_ifname(b"lo"),
        ifr_flags: IFF_UP | IFF_RUNNING,
        _pad: [0u8; 22],
    };
    let _ = ioctl_checked(sock.as_raw_fd(), SIOCSIFFLAGS, &mut lo_req);

    // 1. Assign IPv4 address
    let mut addr_req = IfReqAddr {
        ifr_name: *ifname,
        ifr_addr: SockAddrIn::from_ipv4(ip),
        _pad: [0u8; 8],
    };
    ioctl_checked(sock.as_raw_fd(), SIOCSIFADDR, &mut addr_req)?;

    // 2. Assign netmask
    let mut mask_req = IfReqAddr {
        ifr_name: *ifname,
        ifr_addr: SockAddrIn::from_ipv4(netmask),
        _pad: [0u8; 8],
    };
    ioctl_checked(sock.as_raw_fd(), SIOCSIFNETMASK, &mut mask_req)?;

    // 3. Bring interface UP
    let mut flags_req = IfReqFlags {
        ifr_name: *ifname,
        ifr_flags: IFF_UP | IFF_RUNNING,
        _pad: [0u8; 22],
    };
    ioctl_checked(sock.as_raw_fd(), SIOCSIFFLAGS, &mut flags_req)?;

    // 4. Add default route via `gateway`
    let mut rt: RtEntry = unsafe { core::mem::zeroed() };
    rt.rt_dst = SockAddrIn::from_ipv4(Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = SockAddrIn::from_ipv4(Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = SockAddrIn::from_ipv4(gateway);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    ioctl_checked(sock.as_raw_fd(), SIOCADDRT, &mut rt)?;

    Ok(())
}

fn copy_ifname(name: &[u8]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let n = name.len().min(15);
    buf[..n].copy_from_slice(&name[..n]);
    buf
}

fn ioctl_checked<T>(fd: RawFd, req: usize, arg: &mut T) -> Result<(), RawErrno> {
    let ret = unsafe { syscall3(SYS_IOCTL, fd as usize, req, arg as *mut T as usize) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}
