//! Raw Linux `seccomp_unotify` (`SECCOMP_RET_USER_NOTIF`) and `SCM_RIGHTS` FD-passing primitives.
//!
//! Enables real-time, zero-`ptrace` syscall supervision from the host process:
//! 1. Child installs a Seccomp-BPF filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
//! 2. Child sends the returned listener FD to the parent over an `AF_UNIX` `socketpair`
//!    using `send_fd` (`SCM_RIGHTS`) and proceeds to `execve`.
//! 3. Parent loops on `notif_recv` / `notif_id_valid` / `notif_send` to inspect,
//!    allow (`CONTINUE`), deny (`-errno`), or spoof return values for intercepted syscalls.

use crate::{RawErrno, syscall3, syscall4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: usize = 16;
#[cfg(target_arch = "aarch64")]
const SYS_IOCTL: usize = 29;

#[cfg(target_arch = "x86_64")]
const SYS_SENDMSG: usize = 46;
#[cfg(target_arch = "aarch64")]
const SYS_SENDMSG: usize = 211;

#[cfg(target_arch = "x86_64")]
const SYS_RECVMSG: usize = 47;
#[cfg(target_arch = "aarch64")]
const SYS_RECVMSG: usize = 212;

#[cfg(target_arch = "x86_64")]
const SYS_SOCKETPAIR: usize = 53;
#[cfg(target_arch = "aarch64")]
const SYS_SOCKETPAIR: usize = 199;

const AF_UNIX: usize = 1;
const SOCK_STREAM: usize = 1;
const SOCK_CLOEXEC: usize = 0o2000000;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

// Linux <linux/seccomp.h> ioctl request codes (64-bit)
const SECCOMP_IOCTL_NOTIF_RECV: usize = 0xC050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: usize = 0xC018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: usize = 0x4008_2102;

/// Tell the kernel to continue executing the intercepted syscall normally.
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

/// Kernel `struct seccomp_data` (64 bytes).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Kernel `struct seccomp_notif` (80 bytes = 0x50).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Kernel `struct seccomp_notif_resp` (24 bytes = 0x18).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Create an `AF_UNIX` `SOCK_STREAM | SOCK_CLOEXEC` socket pair for `SCM_RIGHTS` FD passing.
pub fn unix_socketpair() -> Result<(OwnedFd, OwnedFd), RawErrno> {
    let mut fds = [0i32; 2];
    let ret = unsafe {
        syscall4(
            SYS_SOCKETPAIR,
            AF_UNIX,
            SOCK_STREAM | SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr() as usize,
        )
    };
    RawErrno::from_raw_ret(ret)?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[repr(C)]
struct IoVec {
    iov_base: *mut u8,
    iov_len: usize,
}

#[repr(C)]
struct MsgHdr {
    msg_name: *mut u8,
    msg_namelen: u32,
    _pad0: u32,
    msg_iov: *mut IoVec,
    msg_iovlen: usize,
    msg_control: *mut u8,
    msg_controllen: usize,
    msg_flags: i32,
    _pad1: i32,
}

#[repr(C, align(8))]
struct CmsgFdBuf {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
    fd: RawFd,
    _pad: i32,
}

/// Send a single file descriptor (`fd_to_send`) over Unix socket `sock_fd` via `SCM_RIGHTS`.
/// Async-signal-safe (zero heap allocation).
pub fn send_fd(sock_fd: RawFd, fd_to_send: RawFd) -> Result<(), RawErrno> {
    let mut byte = *b"F";
    let mut iov = IoVec {
        iov_base: byte.as_mut_ptr(),
        iov_len: 1,
    };
    let mut cmsg = CmsgFdBuf {
        cmsg_len: core::mem::size_of::<usize>() + 2 * core::mem::size_of::<i32>() + core::mem::size_of::<RawFd>(),
        cmsg_level: SOL_SOCKET,
        cmsg_type: SCM_RIGHTS,
        fd: fd_to_send,
        _pad: 0,
    };
    let msg = MsgHdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        _pad0: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: (&mut cmsg as *mut CmsgFdBuf).cast::<u8>(),
        // Linux requires `msg_controllen` = CMSG_SPACE(sizeof(int)) (24 bytes),
        // while `cmsg_len` = CMSG_LEN(sizeof(int)) (20 bytes).
        msg_controllen: core::mem::size_of::<CmsgFdBuf>(),
        msg_flags: 0,
        _pad1: 0,
    };
    let ret = unsafe { syscall3(SYS_SENDMSG, sock_fd as usize, &msg as *const MsgHdr as usize, 0) };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Receive a single file descriptor over Unix socket `sock_fd` via `SCM_RIGHTS`.
///
/// If the sender wrote a 4-byte `i32` errno without ancillary data, returns `Err(RawErrno(errno))`.
pub fn recv_fd(sock_fd: RawFd) -> Result<OwnedFd, RawErrno> {
    let mut byte = [0u8; 4];
    let mut iov = IoVec {
        iov_base: byte.as_mut_ptr(),
        iov_len: 4,
    };
    let mut cmsg = CmsgFdBuf {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
        fd: -1,
        _pad: 0,
    };
    let mut msg = MsgHdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        _pad0: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: (&mut cmsg as *mut CmsgFdBuf).cast::<u8>(),
        msg_controllen: core::mem::size_of::<CmsgFdBuf>(),
        msg_flags: 0,
        _pad1: 0,
    };
    let ret = unsafe { syscall3(SYS_RECVMSG, sock_fd as usize, &mut msg as *mut MsgHdr as usize, 0) };
    let n = RawErrno::from_raw_ret(ret)?;
    if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS && cmsg.fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(cmsg.fd) });
    }
    if n == 4 {
        let child_errno = i32::from_ne_bytes(byte);
        if child_errno > 0 {
            return Err(RawErrno(child_errno));
        }
    }
    Err(RawErrno(22)) // EINVAL
}

/// Receive the next pending `seccomp_unotify` syscall notification from `listener_fd`.
pub fn notif_recv(listener_fd: &OwnedFd) -> Result<SeccompNotif, RawErrno> {
    let mut notif = SeccompNotif::default();
    let ret = unsafe {
        syscall3(
            SYS_IOCTL,
            listener_fd.as_raw_fd() as usize,
            SECCOMP_IOCTL_NOTIF_RECV,
            &mut notif as *mut SeccompNotif as usize,
        )
    };
    RawErrno::from_raw_ret(ret)?;
    Ok(notif)
}

/// Check whether notification `id` is still valid (prevents TOCTOU against PID reuse).
pub fn notif_id_valid(listener_fd: &OwnedFd, id: u64) -> Result<(), RawErrno> {
    let ret = unsafe {
        syscall3(
            SYS_IOCTL,
            listener_fd.as_raw_fd() as usize,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &id as *const u64 as usize,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

/// Send a supervisor decision back to the kernel for an intercepted syscall.
pub fn notif_send(listener_fd: &OwnedFd, resp: &SeccompNotifResp) -> Result<(), RawErrno> {
    let ret = unsafe {
        syscall3(
            SYS_IOCTL,
            listener_fd.as_raw_fd() as usize,
            SECCOMP_IOCTL_NOTIF_SEND,
            resp as *const SeccompNotifResp as usize,
        )
    };
    RawErrno::from_raw_ret(ret).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_struct_sizes_match_linux_abi() {
        assert_eq!(core::mem::size_of::<SeccompData>(), 64);
        assert_eq!(core::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(core::mem::size_of::<SeccompNotifResp>(), 24);
    }
}
