# Changelog

All notable changes to `rust-sandbox` (`rsb`) are documented in this file.

## [0.2.0] - 2026-11-24

### Added
- **Kernel & Isolation Depth:** Landlock ABI v4+ TCP network (`BIND_TCP`/`CONNECT_TCP`) and ABI v6+ IPC scope (`ABSTRACT_UNIX_SOCKET`/`SIGNAL`), Cgroups v2 sibling-leaf delegation + `io.max` (block I/O quota), minimal `tmpfs` `/dev` in `rootfs` mode, `/sys/firmware` & `/sys/kernel` masking, `CLONE_NEWTIME`, OverlayFS `user.overlay.opaque` deletion detection, full `aarch64` `ptrace` (`PTRACE_GETREGSET`) & `rsb learn` parity, and `fuzz/` libFuzzer targets.
- **Production `rsb-net`:** Bounded async DNS/TCP worker concurrency, multi-domain TTL/LRU CDN `dns_cache`, RFC 8446 multi-record TLS `ClientHello` reassembly, `UpstreamState::Closed`, deferred TCP `RST` flushing, idle connection eviction, TAP per-tick frame cap + `EAGAIN` retry queue, and optional `max_egress_bps` rate limiting.
- **Policy Learning & TOML:** Exit-verified (`ret >= 0`) `rsb learn` syscall recording, `(deleted)` FD filtering, root/`$HOME` over-coalescing protection, multiline TOML arrays & single-quoted literal strings, and built-in `--preset` profiles (`python-ai`, `node-build`, `strict-offline`).
- **AI Agent DX & Rich FFI:** Stateful `rsb session <start|exec|ls|stop>`, `rsb_exec_profile_toml_json` FFI API (+ Python `exec_with_profile_toml`), `ResourceLimits` on `ZygoteConfig`/`NodeZygoteConfig`, `--flag=value` CLI support, `--no-net` / `--no-transparent-tap` overrides, `--audit-log` JSONL output, `rsb completions <bash|zsh|fish>`, and Ubuntu AppArmor `apparmor_userns` reporting in `rsb info`.
- **Portable Distribution:** Static `x86_64-unknown-linux-musl` CLI + `ubuntu-22.04` `librsb_ffi.so` (`SONAME`) release pipeline with GitHub Artifact Attestations, `SECURITY.md`, `flake.nix`, `bindings/python/pyproject.toml`, and `benchmarks/bench.sh`.

## [0.1.3] - 2026-11-23

### Added
- `SandboxProfile::merge` and `rsb learn --merge --out <PATH>` to union filesystem paths, network allowlists, and `allow_syscalls` across multiple traced runs (e.g. happy path + failure path) into a single `sandbox.toml`.
- Added `ARCHITECTURE.md` and `CHANGELOG.md`.

## [0.1.2] - 2026-11-21

### Fixed
- Added system CA certificate paths (`/etc/ssl/certs`, `/etc/ca-certificates`, `/etc/pki`, `/etc/hosts`) to `allow_system_runtime()` so HTTPS clients (`curl`, OpenSSL) verify TLS certificates cleanly under Landlock.
- Returned RFC 1035 `NOERROR`/NODATA responses for non-`A` DNS queries (`AAAA`, `HTTPS`, etc.) in `SlirpBridge` instead of returning `A` records for mismatched query types.

## [0.1.1] - 2026-11-21

### Security & Hardening
- Blocked nested user/mount namespace creation in Seccomp-BPF (`clone3` -> `ENOSYS`, `clone(CLONE_NEW*)` -> `EPERM`) and added Linux 5.2+ mount API and cross-process syscalls (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `pidfd_getfd`, `process_madvise`, `process_mrelease`, `kcmp`, `vmsplice`) to `KILL_PROCESS`.
- Switched `block_network_sockets` to an `AF_UNIX`-only allowlist across both `socket` and `socketpair`.
- Enforced `DomainRule` port restrictions on DNS-validated IPs in `EgressPolicy::check_ip`.
- Defaulted CLI `--allow-domain`/`--allow-cidr` to kernel-enforced `--transparent-tap` when namespaces are enabled; failed closed on incompatible `--no-ns` + `--cow`/`--rootfs`/`--transparent-tap` combinations.
- Expanded IPv4/IPv6 SSRF blocking to cover NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001::/32`), IPv4-compatible (`::/96`), site-local (`fec0::/10`), and reserved IPv4 ranges (`192.0.0.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `240.0.0.0/4`).
- Rejected Encrypted Client Hello (`0xfe0d`) and duplicate `server_name` extensions/entries in `sni.rs`; raised `ClientHello` buffer cap to 16,389 bytes for post-quantum TLS 1.3 and enforced SNI checks across all TLS-carrying ports.
- Added absolute Slowloris handshake deadlines and 5-minute tunnel idle timeouts in `EgressProxy`; fixed server-speaks-first protocol deadlocks.
- Fixed partial-write data loss in `SlirpBridge` host-to-guest `send_slice`, bounded `tx_pending` (64 KiB) and `MAX_TCP_CONNS` (128), and bounded `dns_cache`.
- Moved TAP and `resolv.conf` setup before `pivot_root`, added OCI-style `/proc` masking in both default and `rootfs` modes, unconditionally dropped capabilities (including ambient caps), and fixed `CgroupGuard` false-positive reporting under Cgroups v2's no-internal-processes rule.
- Hardened Python and Node.js `ZygotePool` against `killpg` races, grandchild pipe deadlocks, `preload_modules` stdout corruption, `stderr` pipe stalls, and host-side hangs.
- Fixed `learn_policy` multi-threaded / `fork` `SIGSTOP` deadlocks and `PTRACE_O_TRACEEXEC` tracking; aligned `PTRACE_PEEKDATA` reads in `rsb-sys`.
- Hardened `sandbox.toml` parser against duplicate keys/sections, `u32` truncation, unescaped quotes, and `[seccomp] mode` mismatches.
- Wrapped all `rsb-ffi` `extern "C"` entry points in `catch_unwind`, validated `argv`/`argc` bounds, and added `__del__`, `threading.Lock`, NUL/negative-timeout checks, and release-archive library discovery to `bindings/python/rsb.py`.
- Set workspace MSRV to `1.88` across all crates and expanded CI (`aarch64 --all-targets`, `rsb-net --no-default-features`, Ubuntu 24.04 AppArmor userns handling).

## [0.1.0] - 2026-11-21

### Added
- Initial release of `rust-sandbox` (`rsb`): 5-crate zero-C-dependency Rust workspace (`rsb-sys`, `rsb-core`, `rsb-net`, `rsb-ffi`, `rsb-cli`).
- Rootless Linux namespaces (`clone3`), Landlock LSM (ABI v1–v11+), pure-Rust Seccomp-BPF + `seccomp-unotify`, delegated Cgroups v2, ephemeral `userxattr` OverlayFS CoW (`--cow`), `pivot_root`, `rsb learn`, `sandbox.toml` profiles, `EgressProxy`, `smoltcp` `SlirpBridge` (`--transparent-tap`), Python & Node.js `ZygotePool`, and C/Python FFI bindings.
