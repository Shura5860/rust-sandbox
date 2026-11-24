# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `0.2.x` | Yes |
| `< 0.2.0` | Security fixes only in latest minor |

## Threat Model & Scope

`rust-sandbox` (`rsb`) is a **shared-kernel** Linux process isolation engine combining unprivileged namespaces, Landlock LSM, classic Seccomp-BPF, Cgroups v2, OverlayFS CoW, and userspace network filtering.

- **In scope:** Sandbox escapes from Landlock/Seccomp/namespace boundaries, SSRF/SNI/DNS filter bypasses in `rsb-net`, Zygote control-channel/FD leaks, FFI memory-safety/UB issues, and host filesystem/temp-file races.
- **Out of scope:** Linux kernel vulnerabilities (which require hardware virtualization / KVM such as Firecracker rather than namespace isolation), or bypasses when `--no-ns` is explicitly combined with advisory `HTTP_PROXY` mode.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report vulnerabilities privately via GitHub Security Advisories:
- https://github.com/Shura5860/rust-sandbox/security/advisories/new

Include reproduction steps, host kernel version (`uname -a`), `rsb info` output, and expected vs. observed behavior. You can expect an initial acknowledgement within 72 hours.
