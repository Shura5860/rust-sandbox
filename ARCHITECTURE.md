# Architecture & Design Notes

This document summarizes the internal architecture, Linux kernel design decisions, and known boundaries of `rust-sandbox` (`rsb`).

## 1. Layered Workspace Design

```text
+-------------------------------------------------------------------+
|  CLI (`rsb`)  |  Rust SDK (`rsb-core`)  |  C / Python (`rsb-ffi`) |
+-------------------------------------------------------------------+
|  Policy & Profile Layer (`SandboxBuilder`, `sandbox.toml`)        |
+---------------+---------------+-----------------+-----------------+
|  Namespaces   |  Landlock LSM |   Seccomp-BPF   |   Cgroups v2    |
+---------------+---------------+-----------------+-----------------+
|  OverlayFS CoW (`--cow`)      |  Userspace Egress (`rsb-net`)     |
+-------------------------------+-----------------------------------+
|  Syscall Layer (`rsb-sys`: rustix linux_raw + raw Linux syscalls) |
+-------------------------------------------------------------------+
```

- **`rsb-sys`**: Thin Linux syscall layer built on `rustix` (`linux_raw` backend) plus direct syscall wrappers (`clone3`, Landlock, `seccomp`, `ptrace`, `/dev/net/tun` ioctls, `SCM_RIGHTS`, `seccomp_unotify`) with zero C dependencies.
- **`rsb-core`**: Core sandbox lifecycle (`PreparedSandbox`, `child_main`, `Sandbox`), pure-Rust classic BPF compiler, Cgroups v2 guard, OverlayFS CoW sessions, `sandbox.toml` parser/serializer, `ptrace` policy learner, `seccomp-unotify` supervisor, and pre-warmed `ZygotePool` runtimes.
- **`rsb-net`**: Declarative egress policy (domain wildcards, IPv4/IPv6 CIDR + port rules, fail-closed SSRF guard), TLS `ClientHello` SNI/ECH parser, RFC 1035 DNS parser/builder, HTTP/HTTPS `CONNECT` proxy, and `smoltcp`-based L2/L3 `SlirpBridge`.
- **`rsb-ffi`**: `cdylib` (`librsb_ffi.so`) exposing a panic-safe (`catch_unwind`) C ABI alongside `bindings/c/rsb.h` and `bindings/python/rsb.py`.
- **`rsb-cli`**: Standalone `rsb` CLI (`info`, `run`, `ai-exec`, `learn`, `zygote-bench`).

## 2. Async-Signal-Safe Child Lifecycle (`PreparedSandbox` -> `child_main`)

After `clone3(2)` in a multithreaded host process, heap allocation (`malloc`/Rust allocator locks) is unsafe. `rust-sandbox` splits execution into two phases:

1. **Parent preparation (`PreparedSandbox::from_policy`)**: Resolves the executable path (including `rootfs`-relative paths), builds NUL-terminated `argv`/`envp` C strings, probes the kernel's Landlock ABI version, validates and compiles per-path Landlock access masks, and compiles the Seccomp-BPF bytecode (enforcing `BPF_MAXINSNS <= 4096`).
2. **Child setup (`child_main`)**: Runs strictly with pre-allocated slices and raw syscalls before `execve`:
   - Synchronizes with the parent over an `O_CLOEXEC` pipe so `uid_map`/`gid_map` and fallback `cgroup.procs` writes complete before mount/network setup.
   - Marks `/` as `MS_REC | MS_PRIVATE`, mounts optional OverlayFS CoW layers, sets up optional rootless `tap0` + `SCM_RIGHTS` handoff **before** `pivot_root`, mounts fresh `/proc` inside `CLONE_NEWPID`, and masks sensitive `/proc` subpaths (`/proc/sys`, `/proc/irq`, `/proc/bus`, `/proc/fs`, `/proc/acpi`, `/proc/scsi`, `/proc/asound`, `/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/sched_debug`, `/proc/sysrq-trigger`, `/proc/kallsyms`, `/proc/latency_stats`).
   - Drops ambient, bounding, and effective/permitted/inheritable capabilities (`PR_CAP_AMBIENT_CLEAR_ALL`, `PR_CAPBSET_DROP`, `capset`) unconditionally, applies `RLIMIT_CORE=0` and `RLIMIT_NOFILE`, sets `PR_SET_NO_NEW_PRIVS`, enforces Landlock, forks a PID 2 worker inside `CLONE_NEWPID` (with PID 1 acting as a zero-allocation subreaper that exits immediately when PID 2 terminates), installs Seccomp-BPF last, marks remaining host FDs `O_CLOEXEC` via `close_range`, and calls `execve`.
   - Any setup failure writes an 8-byte `(ChildStage, errno)` packet to an `O_CLOEXEC` error pipe and terminates via `exit_group(127)`.

## 3. Kernel Compatibility & Fallback Decisions

- **`clone3` -> `clone(2)` fallback**: When an outer container seccomp filter returns `ENOSYS` for `clone3`, `rsb_sys::clone3` transparently falls back to legacy `clone(2)` whenever only low-32-bit flags and standard `exit_signal` are used.
- **`CLONE_INTO_CGROUP` fallback**: Atomic cgroup placement via `CLONE_INTO_CGROUP` falls back to `cgroup.procs` on `ENOSYS`, `EINVAL`, `EACCES`, or `EOPNOTSUPP`. Under Cgroups v2's *no internal processes* rule, `CgroupGuard::create` verifies that at least one requested quota file (`memory.max`, `pids.max`, `cpu.max`) was actually written before reporting `cgroup_v2 = true`.
- **Landlock ABI masking**: Queries `LANDLOCK_CREATE_RULESET_VERSION` at runtime and masks `handled_access_fs` and per-rule flags to the host kernel's supported ABI (v1–v11+), stripping directory-only access bits from non-directory FDs to avoid `EINVAL`.
- **Seccomp-BPF choices**:
  - Verifies `AUDIT_ARCH` and rejects `x32` ABI syscalls on `x86_64`.
  - Blocks `TIOCSTI` / `TIOCLINUX` with `EPERM`.
  - When network sockets are disabled, allowlists `AF_UNIX` only on both `socket` and `socketpair` (blocking `AF_INET`, `AF_INET6`, `AF_NETLINK`, `AF_PACKET`, `AF_VSOCK`, `AF_ALG`, etc.).
  - Returns `ENOSYS` for `clone3` (so glibc/musl fall back to `clone(2)`) and returns `EPERM` for `clone(2)` with any `CLONE_NEW*` bit set, preventing nested user-namespace capability re-acquisition.
  - Returns `EPERM` (rather than `SIGSYS`) for `io_uring_*` so runtimes such as Node.js/libuv cleanly fall back to `epoll`.
  - Terminates dangerous syscalls (`ptrace`, `mount`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `unshare`, `setns`, `bpf`, `userfaultfd`, `pidfd_getfd`, `process_vm_readv/writev`, `kcmp`, `vmsplice`, etc.) via `SECCOMP_RET_KILL_PROCESS`.

## 4. Userspace Egress Filtering (`rsb-net`)

- **Transparent Rootless TAP (`--transparent-tap`)**: Inside `CLONE_NEWNET`, the child opens `/dev/net/tun` (`tap0`), configures `10.0.2.15/24` with default gateway `10.0.2.2`, bind-mounts a private temporary `/etc/resolv.conf` (`nameserver 10.0.2.2`), sends `tap_fd` to the host via `SCM_RIGHTS` (`CMSG_SPACE(4)` / `MSG_CMSG_CLOEXEC`), and drops `tap_fd` before `execve`.
- **`smoltcp` `SlirpBridge`**: Runs with `any_ip = true` and a default IPv4 route to `GATEWAY_IP` so arbitrary public IPv4 destinations are routed into the userspace stack.
  - UDP/53 DNS queries are validated against `EgressPolicy` (returning `REFUSED` for disallowed domains and `NOERROR`/NODATA for non-`A` queries such as `AAAA`/`HTTPS`).
  - TCP connections enforce both `DomainRule` port restrictions and fail-closed SSRF checks (blocking loopback, RFC1918, CGNAT, cloud metadata `169.254.0.0/16`, reserved/benchmark ranges, and IPv6 transition encodings including `::ffff:0:0/96`, `::/96`, NAT64 `64:ff9b::/96` & `64:ff9b:1::/48`, 6to4 `2002::/16`, and Teredo `2001::/32`).
  - TLS `ClientHello` records (buffered up to RFC 8446's 16,389-byte single-record maximum for post-quantum key shares) are inspected for SNI on port 443 and any TLS-carrying port; duplicate `server_name` extensions/entries and Encrypted Client Hello (`0xfe0d`) are rejected.
  - Host-to-guest writes are capped to `smoltcp`'s available TX buffer capacity, and guest-to-host `tx_pending` is capped at 64 KiB to preserve TCP backpressure.

## 5. Pre-Warmed Worker Pools (`ZygotePool`)

- **Python Zygote**: Duplicates control-channel FDs off `0`/`1` and redirects FD `0` and `1` to `/dev/null` before preloading modules. Each request uses Linux CoW `fork()`; the worker closes `proto_in`/`proto_out`, inherits Landlock + Seccomp-BPF from the kernel, and runs in its own process group (`setpgid` from both parent and child). Timeouts send `SIGKILL` to both the process group and direct PID and enforce a host-side `poll` deadline.
- **Node.js Zygote**: Does not rely on `node:vm` for isolation. Each request spawns a separate OS `node` child process (`stdio: ['ignore', 'pipe', 'pipe']`) that inherits Landlock + Seccomp-BPF and cannot access Zygote memory or control FDs.

## 6. Known Boundaries & Limitations

- **Shared kernel**: Like all Linux container/namespace sandboxes, `rsb` shares the host Linux kernel rather than using hardware virtualization (KVM).
- **Proxy mode (`--no-ns --allow-domain`)**: When namespaces are disabled, `EgressProxy` operates via `HTTP_PROXY`/`HTTPS_PROXY` environment variables and cannot prevent a process from opening direct sockets. Kernel-enforced egress filtering requires `--transparent-tap` (enabled automatically with `--allow-domain`/`--allow-cidr` when namespaces are active).
- **`seccomp_unotify` `Continue`**: Returning `UnotifyDecision::Continue` after inspecting pointer arguments in child memory is subject to TOCTOU races if the target process is multithreaded. Use `Errno` or `ReturnValue` for security-critical pointer checks.
- **Platform support**: Linux `x86_64` is primary; `aarch64` syscall and compilation layers are maintained in CI, while `rsb learn` is currently `x86_64`-only.
