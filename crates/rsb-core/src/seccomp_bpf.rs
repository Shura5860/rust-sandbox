//! Pure-Rust classic BPF (cBPF) assembler and Seccomp-BPF policy compiler.
//!
//! Compiles a declarative `SeccompPolicy` into a kernel-verifiable `Vec<SockFilter>`
//! in the parent process (`PreparedSandbox`) with zero C dependencies (no `libseccomp`).
//!
//! Security properties:
//! - Verifies `seccomp_data.arch` on instruction 0 (`SECCOMP_RET_KILL_PROCESS` on mismatch)
//!   to prevent 32-bit `int 0x80` / compat syscall table bypasses.
//! - Rejects `x32` ABI syscalls (`nr >= 0x4000_0000`) on `x86_64` with `SECCOMP_RET_KILL_PROCESS`.
//! - Blocks `TIOCSTI` (`0x5412`) and `TIOCLINUX` (`0x541C`) `ioctl` calls to prevent
//!   terminal keystroke injection attacks.
//! - Terminates dangerous escape syscalls (`ptrace`, `bpf`, `io_uring_*`, `kexec_*`,
//!   `mount`, `userfaultfd`, etc.) immediately with `SECCOMP_RET_KILL_PROCESS`.
//! - Supports argument-aware `socket(domain, ...)` filtering (`EPERM`) so network
//!   isolation works even in `--no-ns` mode without breaking local `AF_UNIX`.
//! - Supports strict default-deny syscall allowlist mode (`rsb learn --strict`).

use rsb_sys::seccomp::SockFilter;

// Classic BPF instruction opcodes (from <linux/bpf_common.h> & <linux/filter.h>)
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

// Seccomp return actions (from <linux/seccomp.h>)
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// Offsets inside `struct seccomp_data`
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0_LO: u32 = 16; // Little-endian low 32 bits of args[0]
const OFFSET_ARG1_LO: u32 = 24; // Little-endian low 32 bits of args[1]

// Audit architecture constants
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_CURRENT: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_CURRENT: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Standard Linux errno values
pub const EPERM: u16 = 1;

// Socket address families
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_NETLINK: u32 = 16;
const AF_PACKET: u32 = 17;

// Dangerous terminal injection ioctl request codes
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;

/// Architecture-specific syscall numbers used by the default hardening profile.
#[cfg(target_arch = "x86_64")]
pub mod nr {
    pub const IOCTL: u32 = 16;
    pub const SOCKET: u32 = 41;
    pub const EXECVE: u32 = 59;
    pub const EXIT: u32 = 60;
    pub const PTRACE: u32 = 101;
    pub const PERSONALITY: u32 = 135;
    pub const PIVOT_ROOT: u32 = 155;
    pub const CHROOT: u32 = 161;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const SWAPON: u32 = 167;
    pub const SWAPOFF: u32 = 168;
    pub const REBOOT: u32 = 169;
    pub const INIT_MODULE: u32 = 175;
    pub const DELETE_MODULE: u32 = 176;
    pub const EXIT_GROUP: u32 = 231;
    pub const KEXEC_LOAD: u32 = 246;
    pub const ADD_KEY: u32 = 248;
    pub const REQUEST_KEY: u32 = 249;
    pub const KEYCTL: u32 = 250;
    pub const UNSHARE: u32 = 272;
    pub const PERF_EVENT_OPEN: u32 = 298;
    pub const OPEN_BY_HANDLE_AT: u32 = 304;
    pub const SETNS: u32 = 308;
    pub const PROCESS_VM_READV: u32 = 310;
    pub const PROCESS_VM_WRITEV: u32 = 311;
    pub const FINIT_MODULE: u32 = 313;
    pub const KEXEC_FILE_LOAD: u32 = 320;
    pub const BPF: u32 = 321;
    pub const USERFAULTFD: u32 = 323;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
}

#[cfg(target_arch = "aarch64")]
pub mod nr {
    pub const IOCTL: u32 = 29;
    pub const SOCKET: u32 = 198;
    pub const EXECVE: u32 = 221;
    pub const EXIT: u32 = 93;
    pub const EXIT_GROUP: u32 = 94;
    pub const PTRACE: u32 = 117;
    pub const PERSONALITY: u32 = 92;
    pub const CHROOT: u32 = 51;
    pub const MOUNT: u32 = 40;
    pub const UMOUNT2: u32 = 39;
    pub const SWAPON: u32 = 224;
    pub const SWAPOFF: u32 = 225;
    pub const REBOOT: u32 = 142;
    pub const INIT_MODULE: u32 = 105;
    pub const DELETE_MODULE: u32 = 106;
    pub const PIVOT_ROOT: u32 = 41;
    pub const KEXEC_LOAD: u32 = 104;
    pub const ADD_KEY: u32 = 217;
    pub const REQUEST_KEY: u32 = 218;
    pub const KEYCTL: u32 = 219;
    pub const UNSHARE: u32 = 97;
    pub const PERF_EVENT_OPEN: u32 = 241;
    pub const OPEN_BY_HANDLE_AT: u32 = 265;
    pub const SETNS: u32 = 268;
    pub const PROCESS_VM_READV: u32 = 270;
    pub const PROCESS_VM_WRITEV: u32 = 271;
    pub const FINIT_MODULE: u32 = 273;
    pub const KEXEC_FILE_LOAD: u32 = 294;
    pub const BPF: u32 = 280;
    pub const USERFAULTFD: u32 = 282;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
}

/// Action taken when a Seccomp rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Reject syscall immediately with the given Linux errno (e.g., `EPERM = 1`).
    Errno(u16),
    /// Immediately terminate the entire process with `SIGSYS`.
    KillProcess,
    /// Defer decision to a live userspace supervisor via `seccomp_unotify`.
    UserNotif,
}

impl SeccompAction {
    #[inline]
    const fn to_bpf_ret(self) -> u32 {
        match self {
            Self::Errno(e) => SECCOMP_RET_ERRNO | ((e as u32) & SECCOMP_RET_DATA),
            Self::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Self::UserNotif => SECCOMP_RET_USER_NOTIF,
        }
    }
}

/// High-level Seccomp-BPF policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompPolicy {
    /// Enable Seccomp-BPF filtering.
    pub enabled: bool,
    /// Terminate dangerous kernel-attack / escape syscalls with `SECCOMP_RET_KILL_PROCESS`.
    pub block_dangerous_syscalls: bool,
    /// Block `socket(AF_INET | AF_INET6 | AF_NETLINK | AF_PACKET, ...)` with `EPERM`.
    pub block_network_sockets: bool,
    /// Block `ioctl(..., TIOCSTI | TIOCLINUX, ...)` with `EPERM` to prevent terminal injection.
    pub block_tiocsti: bool,
    /// Additional custom `(syscall_nr, action)` deny rules (denylist mode).
    pub extra_denied: Vec<(u32, SeccompAction)>,
    /// Strict allowlist mode: when `Some`, ONLY these syscall numbers (plus `execve`,
    /// `exit`, `exit_group`) are permitted; all other syscalls return `default_deny_action`.
    pub allowlist: Option<Vec<u32>>,
    /// Action returned when an unlisted syscall is invoked in strict allowlist mode.
    pub default_deny_action: SeccompAction,
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            block_dangerous_syscalls: true,
            block_network_sockets: true,
            block_tiocsti: true,
            extra_denied: Vec::new(),
            allowlist: None,
            default_deny_action: SeccompAction::Errno(EPERM),
        }
    }
}

impl SeccompPolicy {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            block_dangerous_syscalls: false,
            block_network_sockets: false,
            block_tiocsti: false,
            extra_denied: Vec::new(),
            allowlist: None,
            default_deny_action: SeccompAction::Errno(EPERM),
        }
    }

    /// Compile this policy into a ready-to-install cBPF bytecode vector.
    /// Returns an empty `Vec` if `enabled == false`.
    pub fn compile(&self) -> Vec<SockFilter> {
        if !self.enabled {
            return Vec::new();
        }

        let mut asm = BpfAssembler::new();

        // 1. Strict architecture validation: kill on any non-native ABI (blocks int 0x80).
        asm.ld_abs_w(OFFSET_ARCH);
        asm.jeq_k(AUDIT_ARCH_CURRENT, 1, 0);
        asm.ret_k(SECCOMP_RET_KILL_PROCESS);

        // 2. Load syscall number into accumulator A.
        asm.ld_abs_w(OFFSET_NR);

        // 2b. On x86_64, reject x32 ABI syscalls (nr & 0x4000_0000 != 0) immediately.
        #[cfg(target_arch = "x86_64")]
        {
            asm.jge_k(X32_SYSCALL_BIT, 0, 1);
            asm.ret_k(SECCOMP_RET_KILL_PROCESS);
        }

        // 3. Block terminal keystroke injection ioctls (TIOCSTI / TIOCLINUX).
        if self.block_tiocsti {
            const BLOCKED_IOCTLS: &[u32] = &[TIOCSTI, TIOCLINUX];
            let skip = (2 + 2 * BLOCKED_IOCTLS.len()) as u8;
            asm.jeq_k(nr::IOCTL, 0, skip);
            asm.ld_abs_w(OFFSET_ARG1_LO);
            for &req in BLOCKED_IOCTLS {
                asm.jeq_k(req, 0, 1);
                asm.ret_k(SeccompAction::Errno(EPERM).to_bpf_ret());
            }
            asm.ld_abs_w(OFFSET_NR);
        }

        // 4. Network socket domain filter (blocks IPv4, IPv6, Netlink, Packet sockets;
        //    preserves AF_UNIX so local IPC/runtimes still work).
        if self.block_network_sockets {
            const BLOCKED_DOMAINS: &[u32] = &[AF_INET, AF_INET6, AF_NETLINK, AF_PACKET];
            let skip = (2 + 2 * BLOCKED_DOMAINS.len()) as u8;
            asm.jeq_k(nr::SOCKET, 0, skip);
            asm.ld_abs_w(OFFSET_ARG0_LO);
            for &dom in BLOCKED_DOMAINS {
                asm.jeq_k(dom, 0, 1);
                asm.ret_k(SeccompAction::Errno(EPERM).to_bpf_ret());
            }
            asm.ld_abs_w(OFFSET_NR);
        }

        // 5a. Strict Allowlist Mode (default-deny everything not explicitly allowed).
        if let Some(ref raw_allow) = self.allowlist {
            let mut allowed: Vec<u32> = raw_allow.clone();
            allowed.push(nr::EXECVE);
            allowed.push(nr::EXIT);
            allowed.push(nr::EXIT_GROUP);
            allowed.sort_unstable();
            allowed.dedup();

            for sys_nr in allowed {
                asm.jeq_k(sys_nr, 0, 1);
                asm.ret_k(SECCOMP_RET_ALLOW);
            }
            asm.ret_k(self.default_deny_action.to_bpf_ret());
            return asm.finish();
        }

        // 5b. Default hardened syscall denylist: terminate escape attempts immediately
        //     with `SECCOMP_RET_KILL_PROCESS` so no sibling threads survive.
        if self.block_dangerous_syscalls {
            const KILL_ON_CALL: &[u32] = &[
                nr::PTRACE,
                nr::PERSONALITY,
                nr::CHROOT,
                nr::MOUNT,
                nr::UMOUNT2,
                nr::SWAPON,
                nr::SWAPOFF,
                nr::REBOOT,
                nr::INIT_MODULE,
                nr::DELETE_MODULE,
                nr::PIVOT_ROOT,
                nr::KEXEC_LOAD,
                nr::ADD_KEY,
                nr::REQUEST_KEY,
                nr::KEYCTL,
                nr::UNSHARE,
                nr::PERF_EVENT_OPEN,
                nr::OPEN_BY_HANDLE_AT,
                nr::SETNS,
                nr::PROCESS_VM_READV,
                nr::PROCESS_VM_WRITEV,
                nr::FINIT_MODULE,
                nr::KEXEC_FILE_LOAD,
                nr::BPF,
                nr::USERFAULTFD,
            ];
            for &sys_nr in KILL_ON_CALL {
                asm.jeq_k(sys_nr, 0, 1);
                asm.ret_k(SECCOMP_RET_KILL_PROCESS);
            }

            // Block `io_uring_*` with EPERM (instead of SIGSYS) so modern runtimes like
            // Node.js / libuv cleanly fall back to `epoll` instead of crashing at startup.
            const DENY_EPERM: &[u32] = &[
                nr::IO_URING_SETUP,
                nr::IO_URING_ENTER,
                nr::IO_URING_REGISTER,
            ];
            let eperm_ret = SeccompAction::Errno(EPERM).to_bpf_ret();
            for &sys_nr in DENY_EPERM {
                asm.jeq_k(sys_nr, 0, 1);
                asm.ret_k(eperm_ret);
            }
        }

        // 6. Custom caller-specified deny rules.
        for &(sys_nr, action) in &self.extra_denied {
            asm.jeq_k(sys_nr, 0, 1);
            asm.ret_k(action.to_bpf_ret());
        }

        // 7. Default allow.
        asm.ret_k(SECCOMP_RET_ALLOW);

        asm.finish()
    }
}

/// Minimal, zero-dependency classic BPF instruction emitter.
struct BpfAssembler {
    insns: Vec<SockFilter>,
}

impl BpfAssembler {
    fn new() -> Self {
        Self {
            insns: Vec::with_capacity(112),
        }
    }

    #[inline]
    fn ld_abs_w(&mut self, offset: u32) {
        self.insns.push(SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        });
    }

    #[inline]
    fn jeq_k(&mut self, k: u32, jt: u8, jf: u8) {
        self.insns.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k,
        });
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn jge_k(&mut self, k: u32, jt: u8, jf: u8) {
        self.insns.push(SockFilter {
            code: BPF_JMP | BPF_JGE | BPF_K,
            jt,
            jf,
            k,
        });
    }

    #[inline]
    fn ret_k(&mut self, k: u32) {
        self.insns.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        });
    }

    fn finish(self) -> Vec<SockFilter> {
        self.insns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_compiles_valid_bpf() {
        let insns = SeccompPolicy::default().compile();
        assert!(insns.len() > 30, "expected hardened BPF program");
        assert!(insns.len() < 4096, "BPF program must stay under kernel BPF_MAXINSNS");
        assert_eq!(insns[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(insns[0].k, OFFSET_ARCH);
        assert_eq!(insns.last().unwrap().code, BPF_RET | BPF_K);
        assert_eq!(insns.last().unwrap().k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn disabled_policy_produces_empty_program() {
        assert!(SeccompPolicy::disabled().compile().is_empty());
    }

    #[test]
    fn allowlist_policy_ends_with_default_deny() {
        let p = SeccompPolicy {
            allowlist: Some(vec![0, 1, 3]),
            ..Default::default()
        };
        let insns = p.compile();
        assert_eq!(insns.last().unwrap().code, BPF_RET | BPF_K);
        assert_eq!(
            insns.last().unwrap().k,
            SECCOMP_RET_ERRNO | (EPERM as u32)
        );
    }
}
