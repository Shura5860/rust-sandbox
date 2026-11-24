<div align="center">

# `rust-sandbox` (`rsb`)

**Rootless Linux process sandbox in pure Rust**

*Namespaces · Landlock LSM · Seccomp-BPF · Cgroups v2 · OverlayFS CoW · `smoltcp` TAP*

<p>
  <a href="https://github.com/Shura5860/rust-sandbox/actions/workflows/ci.yml">
    <img src="https://github.com/Shura5860/rust-sandbox/actions/workflows/ci.yml/badge.svg" alt="CI Status" />
  </a>
  <a href="https://github.com/Shura5860/rust-sandbox/releases">
    <img src="https://img.shields.io/github/v/release/Shura5860/rust-sandbox?style=flat-square&color=d97706" alt="Latest Release" />
  </a>
  <img src="https://img.shields.io/badge/Rust-1.88%2B-dea584?style=flat-square&logo=rust" alt="Rust 1.88+" />
  <img src="https://img.shields.io/badge/Platform-Linux-222222?style=flat-square&logo=linux" alt="Linux" />
  <a href="LICENSE-MIT">
    <img src="https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-2563eb?style=flat-square" alt="License" />
  </a>
</p>

<p>
  <a href="#english">English</a> ·
  <a href="#türkçe">Türkçe</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="ARCHITECTURE.md">Architecture</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

</div>

---

## English

`rsb` runs untrusted binaries, scripts, and AI-agent code inside a rootless Linux sandbox. It talks directly to Linux kernel primitives (namespaces, Landlock, Seccomp-BPF, Cgroups v2, OverlayFS) without shelling out to Docker, `bwrap`, or `libseccomp`, and ships as a CLI, a Rust library, and a C/Python FFI shared object (`librsb_ffi.so`).

### Quick Start

```bash
# Build the CLI (`rsb`) and shared FFI library (`librsb_ffi.so`)
cargo build --workspace --release

# Inspect what the running kernel supports (Landlock ABI, userns, AppArmor, Cgroups v2)
./target/release/rsb info

# Run a command with read-only system libs and one writable directory
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo hello > ./work/out.txt'

# Run in JSON mode with a built-in preset and audit log
./target/release/rsb ai-exec --preset strict-offline --audit-log ./audit.jsonl -- \
  /usr/bin/python3 -c 'print(6 * 7)'
```

Nix flake users can build directly with `nix build`.

### What's Inside (v0.2.0)

- **Namespaces & Rootfs:** `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`) with automatic `clone(2)` fallback if an outer seccomp filter returns `ENOSYS`. Runs a small PID 1 subreaper inside `CLONE_NEWPID`, masks sensitive `/proc` and `/sys` paths, and supports `--rootfs` (`pivot_root` + minimal tmpfs `/dev`).
- **Landlock LSM (ABI v1–v6+):** Detects the kernel ABI at runtime. Enforces filesystem path rules (v1+), blocks TCP bind/connect when network is disabled (v4+), and scopes abstract UNIX sockets and signals to the sandbox domain (v6+).
- **Seccomp-BPF & `unotify`:** Pure-Rust classic BPF compiler with `AUDIT_ARCH` validation, `x32` ABI rejection on `x86_64`, `TIOCSTI`/`TIOCLINUX` blocking, socket domain filtering, strict allowlist mode, and live userspace supervision via `SECCOMP_RET_USER_NOTIF`.
- **Cgroups v2 & Limits:** Discovers delegated Cgroups v2 subtrees (including sibling leaf creation under systemd user slices) and applies `memory.max` + `memory.swap.max=0`, `pids.max`, `cpu.max`, and `io.max`, alongside `RLIMIT_CORE=0`, configurable `RLIMIT_NOFILE`, `close_range`, capability dropping, and a sanitized default environment.
- **Ephemeral CoW (`--cow`):** Mounts rootless `userxattr` OverlayFS over target directories so the host copy stays untouched, reports `added` / `modified` / `deleted` paths (including recursive opaque directory deletions), and wipes staging directories on exit.
- **Network Egress Filtering (`rsb-net`):** Domain/wildcard and IPv4/IPv6 CIDR allowlists with default SSRF blocking (loopback, `169.254.0.0/16` metadata, RFC1918, NAT64/6to4/Teredo). Works either as an HTTP/HTTPS `CONNECT` proxy or as a transparent rootless `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 bridge (`--transparent-tap`) with UDP/53 DNS filtering and multi-record TLS `ClientHello` SNI verification (ECH rejected, no MITM).
- **Policy Learning (`rsb learn`):** Traces a command with `ptrace` on `x86_64` and `aarch64`, records succeeded syscalls/paths, and writes a `sandbox.toml` profile. Supports `--strict` (syscall allowlist) and `--merge` (union across multiple runs).
- **Persistent Sessions & Presets:** `rsb session <start|exec|ls|stop>` keeps a scoped working directory across multiple `ai-exec` calls; built-in presets (`python-ai`, `node-build`, `strict-offline`) and shell completions (`rsb completions bash|zsh|fish`) cut down CLI boilerplate.
- **Zygote Pools & C/Python FFI:** Pre-warmed Python (CoW `fork()`) and Node.js (detached child process per request) pools that inherit Landlock + Seccomp without cold-start overhead. `librsb_ffi.so` exposes `rsb_exec_json`, `rsb_exec_profile_toml_json`, and the Python Zygote API (`bindings/c/rsb.h`, `bindings/python/rsb.py`).

### Common Workflows

```bash
# Learn a strict profile across two runs and replay it
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo run1'
./target/release/rsb learn --merge  --out sandbox.toml -- /bin/sh -c 'echo run2'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo run2'

# Run mutations against a real directory without touching the host copy
./target/release/rsb ai-exec --cow ./work -- /bin/sh -c 'rm -rf ./work/*; echo temp > ./work/x'

# Transparent L2/L3 network filter (works even for binaries that ignore HTTP_PROXY)
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- \
  /usr/bin/curl -sI https://example.com

# Stateful agent session
SID=$(./target/release/rsb session start --preset python-ai)
./target/release/rsb session exec "$SID" -- /usr/bin/python3 -c 'open("data.txt","w").write("42")'
./target/release/rsb session exec "$SID" -- /usr/bin/python3 -c 'print(open("data.txt").read())'
./target/release/rsb session stop "$SID"

# Local startup & Zygote latency benchmark
bash benchmarks/bench.sh 20
```

### Workspace Layout

| Path | Description |
|---|---|
| `crates/rsb-sys` | Raw Linux syscall wrappers (`rustix` `linux_raw`, `clone3`, Landlock, `seccomp`, `ptrace`, `tap`, `unotify`). |
| `crates/rsb-core` | Sandbox engine, `PreparedSandbox`, cBPF compiler, Cgroups v2, OverlayFS CoW, `sandbox.toml`, `learn`, `ZygotePool`. |
| `crates/rsb-net` | Egress policy, SSRF guard, TLS SNI & DNS parsers, `EgressProxy`, and `smoltcp` `SlirpBridge`. |
| `crates/rsb-ffi` | C ABI shared library (`librsb_ffi.so`). |
| `crates/rsb-cli` | `rsb` CLI (`info`, `run`, `ai-exec`, `learn`, `session`, `completions`, `zygote-bench`). |
| `bindings/` | C header (`bindings/c/rsb.h`) and Python `ctypes` wrapper (`bindings/python/rsb.py`). |
| `fuzz/` | `cargo-fuzz` (`libFuzzer`) targets for TOML profile, TLS SNI, and DNS parsers. |
| `benchmarks/` | Reproducible startup & Zygote latency script (`benchmarks/bench.sh`). |

### Verification & Notes

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- **Tests:** 37 automated tests (unit, integration, 8 adversarial escape checks in `crates/rsb-core/tests/escape_suite.rs`, plus deterministic parser fuzzing).
- **Platform:** Linux `x86_64` and `aarch64`. Needs unprivileged user namespaces for namespace/OverlayFS/TAP modes, Landlock (Linux 5.13+) for path rules, and delegated Cgroups v2 for memory/CPU/PID/IO quotas (skipped cleanly when unavailable).
- **Security boundary:** `rsb` isolates processes using Linux kernel primitives, not a separate VM kernel. See [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the threat model and known limits.
- **License:** MIT or Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

---

## Türkçe

`rsb`, güvenilmeyen ikili dosyaları, betikleri ve yapay zeka ajanı kodlarını root yetkisi gerektirmeden izole eden saf Rust tabanlı bir Linux sandbox motorudur. Docker, `bwrap` veya `libseccomp` çağırmadan doğrudan Linux çekirdek arayüzleriyle (namespaces, Landlock, Seccomp-BPF, Cgroups v2, OverlayFS) çalışır; CLI, Rust kütüphanesi ve C/Python FFI paylaşımlı kütüphanesi (`librsb_ffi.so`) olarak kullanılabilir.

### Hızlı Başlangıç

```bash
# CLI (`rsb`) ve paylaşımlı FFI kütüphanesini (`librsb_ffi.so`) derleyin
cargo build --workspace --release

# Çekirdeğin desteklediği özellikleri görün (Landlock ABI, userns, AppArmor, Cgroups v2)
./target/release/rsb info

# Salt-okunur sistem kütüphaneleri ve tek yazılabilir dizinle komut çalıştırın
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo merhaba > ./work/out.txt'

# Hazır profil (preset) ve JSONL denetim kaydıyla JSON modunda kod yürütün
./target/release/rsb ai-exec --preset strict-offline --audit-log ./audit.jsonl -- \
  /usr/bin/python3 -c 'print(6 * 7)'
```

Nix flake ile doğrudan `nix build` kullanarak da derleyebilirsiniz.

### Neler Var? (v0.2.0)

- **Namespace & Rootfs:** `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`); dış ortam seccomp'u `ENOSYS` döndürürse otomatik `clone(2)` yedeğine geçer. `CLONE_NEWPID` içinde hafif PID 1 subreaper çalıştırır, hassas `/proc` ve `/sys` yollarını maskeler ve `--rootfs` (`pivot_root` + minimal tmpfs `/dev`) destekler.
- **Landlock LSM (ABI v1–v6+):** Çalışan çekirdeğin ABI sürümünü otomatik algılar. Dosya yolu kurallarına (v1+) ek olarak ağ kapalıyken TCP bind/connect engellemesi (v4+) ve abstract UNIX soket / sinyal kapsam izolasyonu (v6+) uygular.
- **Seccomp-BPF & `unotify`:** Saf Rust cBPF derleyicisi; `AUDIT_ARCH` denetimi, `x86_64`'te `x32` ABI reddi, `TIOCSTI`/`TIOCLINUX` engellemesi, soket domain filtresi, katı allowlist modu ve `SECCOMP_RET_USER_NOTIF` ile canlı denetim içerir.
- **Cgroups v2 & Sınırlar:** Delege edilmiş Cgroups v2 dizinlerini (systemd user slice altındaki kardeş yapraklar dahil) bulur; `memory.max` + `memory.swap.max=0`, `pids.max`, `cpu.max` ve `io.max` kotalarını `RLIMIT_CORE=0`, `RLIMIT_NOFILE`, `close_range`, yetki düşürme ve temizlenmiş ortam değişkenleriyle birlikte uygular.
- **Geçici CoW (`--cow`):** Hedef dizinlere rootless `userxattr` OverlayFS bağlar; host kopyasına dokunmadan tüm `added` / `modified` / `deleted` (özyinelemeli opaque dizin silmeleri dahil) değişikliklerini raporlar ve çıkışta geçici katmanı siler.
- **Ağ Çıkış Filtresi (`rsb-net`):** Domain/wildcard ve IPv4/IPv6 CIDR izin listeleri, varsayılan SSRF engellemesi (loopback, `169.254.0.0/16` metadata, RFC1918, NAT64/6to4/Teredo). İster HTTP/HTTPS `CONNECT` proxy, ister `HTTP_PROXY`'yi yoksayabilen uygulamalar için şeffaf `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 köprüsü (`--transparent-tap`, UDP/53 DNS filtresi + çoklu kayıt TLS `ClientHello` SNI doğrulaması, ECH reddi, MITM yok).
- **Politika Öğrenme (`rsb learn`):** `x86_64` ve `aarch64` üzerinde komutu `ptrace` ile izleyip başarılı syscall/dosya erişimlerinden `sandbox.toml` üretir; `--strict` (syscall allowlist) ve `--merge` (birden fazla koşuyu birleştirme) destekler.
- **Kalıcı Oturumlar & Hazır Profiller:** `rsb session <start|exec|ls|stop>` birden fazla `ai-exec` çağrısında izole çalışma dizinini korur; yerleşik profiller (`python-ai`, `node-build`, `strict-offline`) ve kabuk tamamlama (`rsb completions bash|zsh|fish`) ile hızlı kullanım sağlar.
- **Zygote Havuzları & C/Python FFI:** Landlock + Seccomp sınırını devralan sıcak Python (CoW `fork()`) ve Node.js (istek başına ayrık süreç) havuzları. `librsb_ffi.so` üzerinden `rsb_exec_json`, `rsb_exec_profile_toml_json` ve Python Zygote API'si sunulur (`bindings/c/rsb.h`, `bindings/python/rsb.py`).

### Sık Kullanılan Örnekler

```bash
# İki farklı koşudan katı profil öğrenip tekrar çalıştırma
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo run1'
./target/release/rsb learn --merge  --out sandbox.toml -- /bin/sh -c 'echo run2'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo run2'

# Host dizinine dokunmadan geçici CoW testi
./target/release/rsb ai-exec --cow ./work -- /bin/sh -c 'rm -rf ./work/*; echo temp > ./work/x'

# Şeffaf L2/L3 ağ filtresi
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- \
  /usr/bin/curl -sI https://example.com

# Durum koruyan ajan oturumu
SID=$(./target/release/rsb session start --preset python-ai)
./target/release/rsb session exec "$SID" -- /usr/bin/python3 -c 'open("data.txt","w").write("42")'
./target/release/rsb session exec "$SID" -- /usr/bin/python3 -c 'print(open("data.txt").read())'
./target/release/rsb session stop "$SID"

# Yerel gecikme ve Zygote ölçümü
bash benchmarks/bench.sh 20
```

### Doğrulama ve Sınırlar

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- **Testler:** 37 otomatik test (birim, entegrasyon, `crates/rsb-core/tests/escape_suite.rs` içinde 8 kaçış denemesi ve deterministik ayrıştırıcı fuzz testleri).
- **Platform:** Linux `x86_64` ve `aarch64`. Namespace/OverlayFS/TAP için rootless user namespaces, dosya yolu kuralları için Landlock (Linux 5.13+), kaynak kotaları için delege edilmiş Cgroups v2 gerekir (yoksa güvenli biçimde atlanır).
- **Güvenlik sınırı:** `rsb` ayrı bir VM çekirdeği değil, Linux çekirdek izolasyon primitiflerini kullanır. Tehdit modeli ve bilinen sınırlar için [SECURITY.md](SECURITY.md) ve [ARCHITECTURE.md](ARCHITECTURE.md) dosyalarına bakın.
- **Lisans:** MIT veya Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
