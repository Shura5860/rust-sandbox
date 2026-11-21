# `rust-sandbox` (`rsb`)

[English](#english) | [Türkçe](#türkçe)

---

## English

`rust-sandbox` (`rsb`) is a Linux process isolation engine and CLI written in Rust. It combines Linux kernel isolation primitives—unprivileged namespaces, Landlock LSM, classic Seccomp-BPF, Cgroups v2, ephemeral OverlayFS, and userspace network filtering—behind both a standalone binary (`rsb`) and an embeddable Rust library (`rsb-core`), with C and Python FFI bindings.

### Architecture Overview

```text
+-------------------------------------------------------------------+
|  CLI (`rsb`)  |  Rust SDK (`rsb-core`)  |  C / Python (`rsb-ffi`) |
+-------------------------------------------------------------------+
|  Policy & Profile Layer (`SandboxBuilder`, `sandbox.toml`)        |
+---------------+---------------+-----------------+-----------------+
|  Namespaces   |  Landlock LSM |   Seccomp-BPF   |   Cgroups v2    |
|  (clone3,     |  (ABI v1-v11+ |   (pure-Rust    |  (memory, cpu,  |
|   PID 1 init, |   path rules) |   cBPF, unotify)|   pids, rlimit) |
|   pivot_root) |               |                 |                 |
+---------------+---------------+-----------------+-----------------+
|  Ephemeral CoW OverlayFS (`--cow`)  |  Egress Filter (`rsb-net`)  |
|  (userxattr + Added/Mod/Del diff)   |  (Proxy & smoltcp TAP)      |
+-------------------------------------+-----------------------------+
|  Syscall Layer (`rsb-sys`: rustix linux_raw + raw Linux syscalls) |
+-------------------------------------------------------------------+
```

### Capabilities

- **Standalone Binary & Embeddable Crate:** Use `rsb` directly from the terminal or embed `rsb-core` in Rust applications. `PreparedSandbox` pre-compiles paths, `argv`/`envp`, Landlock masks, and BPF bytecode in the parent process so the post-`clone3` child avoids heap allocations before `execve`.
- **Linux Namespaces & Rootfs:** Rootless `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`) with automatic `clone(2)` fallback when an outer seccomp filter returns `ENOSYS`. Includes a lightweight PID 1 subreaper loop inside `CLONE_NEWPID` and optional `pivot_root` with masked `/proc` subpaths.
- **Landlock LSM:** Queries the running kernel's supported Landlock ABI version and masks access flags accordingly for compatibility across kernel versions.
- **Pure-Rust Seccomp-BPF & `seccomp-unotify`:** Assembles classic BPF bytecode directly in Rust (`AUDIT_ARCH` check, `x32` ABI rejection on `x86_64`, `TIOCSTI`/`TIOCLINUX` blocking, socket domain filtering, strict allowlist mode, and live userspace supervision via `SECCOMP_RET_USER_NOTIF`).
- **Resource Quotas & Process Hygiene:** Supports delegated Cgroups v2 (`CLONE_INTO_CGROUP` with `cgroup.procs` fallback), `setrlimit` (`RLIMIT_CORE=0`, configurable `RLIMIT_NOFILE`), `close_range` FD cleanup, capability dropping (`PR_CAPBSET_DROP` + `capset`), `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG`, and sanitized default environment variables.
- **Ephemeral Copy-on-Write (`--cow`):** Mounts rootless `userxattr` OverlayFS inside the mount namespace, reports `added` / `modified` / `deleted` paths on exit, and removes staging files automatically.
- **Selective Network Egress (`rsb-net`):**
  - Domain wildcard and IPv4/IPv6 CIDR + port allowlists with default SSRF protection (blocking loopback, link-local / cloud metadata `169.254.0.0/16`, and RFC1918 ranges).
  - Pure-Rust TLS `ClientHello` SNI inspection without TLS decryption.
  - Both an HTTP/HTTPS `CONNECT` proxy mode (`--allow-domain`) and a transparent rootless `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 bridge (`--transparent-tap`) with built-in UDP/53 DNS filtering.
- **Policy Learning (`rsb learn`):** Traces a command via `ptrace` to observe accessed paths, syscalls, and network usage, then writes a declarative `sandbox.toml` profile (with optional `--strict` syscall allowlist).
- **Pre-warmed Worker Pools (`ZygotePool`):** Keeps a confined Python interpreter warm and forks per request via Linux CoW `fork()` (closing control-channel FDs and redirecting `stdin` to `/dev/null` in each worker), plus an OS-process-isolated Node.js worker pool.
- **C & Python Bindings (`rsb-ffi`):** Exports a C ABI (`librsb_ffi.so`, `bindings/c/rsb.h`) and a `ctypes` Python wrapper (`bindings/python/rsb.py`) covering both one-shot execution and `ZygotePool`.

### Workspace Structure

| Crate / Path | Purpose |
|---|---|
| `crates/rsb-sys` | Low-level Linux syscall wrappers (`rustix` `linux_raw` + raw `clone3`, Landlock, `seccomp`, `ptrace`, `tap`, `unotify`). |
| `crates/rsb-core` | Core sandbox engine, `PreparedSandbox`, cBPF compiler, Cgroups v2, OverlayFS CoW, `sandbox.toml`, `learn_policy`, `unotify`, `ZygotePool`. |
| `crates/rsb-net` | L3/L4/L7 egress policy, SSRF guard, TLS SNI parser, DNS wire parser, `EgressProxy`, and `smoltcp` L2/L3 `SlirpBridge`. |
| `crates/rsb-ffi` | C ABI shared library (`librsb_ffi.so`). |
| `crates/rsb-cli` | `rsb` command-line interface (`info`, `run`, `ai-exec`, `learn`, `zygote-bench`). |
| `bindings/` | C header (`bindings/c/rsb.h`) and Python `ctypes` wrapper (`bindings/python/rsb.py`). |
| `DEVLOG.md` | Engineering decision log, kernel findings, and audit history. |

### Quick Start

#### Build & Test

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

#### CLI Examples

```bash
# Inspect host kernel capabilities (Landlock ABI, userns, Cgroups v2)
./target/release/rsb info

# Run a command with read-only system runtime and a writable workspace
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo hello > ./work/out.txt'

# JSON execution mode with timeout and bounded stdout/stderr capture
./target/release/rsb ai-exec --timeout-ms 2000 -- /usr/bin/python3 -c 'print(6 * 7)'

# Learn a sandbox.toml profile (add --strict for a syscall allowlist)
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo hello'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo hello'

# Ephemeral CoW OverlayFS (host directory remains unchanged; JSON reports cow_diffs)
./target/release/rsb ai-exec --cow ./work -- /bin/sh -c 'rm -rf ./work/*; echo temp > ./work/x'

# Filtered network egress via transparent rootless TAP + smoltcp bridge
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- /usr/bin/curl -sI https://example.com

# Benchmark cold Python execution and warm Zygote execution on your machine
./target/release/rsb zygote-bench --iters 20
```

#### Rust SDK Example

See [crates/rsb-core/examples/ai_sandbox.rs](crates/rsb-core/examples/ai_sandbox.rs):

```bash
cargo run --release -p rsb-core --example ai_sandbox
```

#### Python FFI Example

```bash
cargo build --release -p rsb-ffi
python3 bindings/python/rsb.py
```

### Local Measurements & Test Coverage

The following measurements were observed on an `x86_64` Linux 7.3 host (results vary by hardware and kernel):

- Sandbox setup latency (`rsb run` / `rsb ai-exec` with Landlock + 72-instruction Seccomp-BPF): ~`0.6 – 1.0 ms`
- Python `ZygotePool` round-trip (20 warm runs, Landlock + Seccomp-BPF): ~`1.2 – 1.4 ms` average
- Automated test suite: 36 tests covering unit behavior, integration flows, 8 adversarial escape checks (`crates/rsb-core/tests/escape_suite.rs`), and 50,000 deterministic fuzz inputs across the TLS SNI, DNS, and TOML parsers.

### Scope & Requirements

- **OS:** Linux (`x86_64`; `aarch64` syscall layers included, `rsb learn` is currently `x86_64`-only).
- **Kernel features:** Unprivileged user namespaces (`CLONE_NEWUSER`) for namespace/OverlayFS/TAP features; Landlock LSM (Linux 5.13+) for path rules; delegated Cgroups v2 for memory/CPU/PID quotas (gracefully falls back when unavailable).
- **License:** Dual-licensed under MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).

---

## Türkçe

`rust-sandbox` (`rsb`), Rust ile yazılmış bir Linux süreç izolasyon motoru ve komut satırı aracıdır. Linux çekirdeğinin sunduğu root yetkisi gerektirmeyen izolasyon mekanizmalarını — user/PID/mount/network namespace'leri, Landlock LSM, klasik Seccomp-BPF, Cgroups v2, geçici OverlayFS ve userspace ağ filtrelemesini — hem tek bir CLI aracı (`rsb`) hem de Rust projelerine gömülebilen bir kütüphane (`rsb-core`) olarak sunar; ayrıca C ve Python FFI bağlayıcıları içerir.

### Mimari Genel Bakış

- **Çekirdek Syscall Katmanı (`rsb-sys`):** Standart Linux çağrıları için `rustix` (`linux_raw` backend) ve doğrudan ABI kontrolü gereken çağrılar (`clone3`, Landlock, `seccomp`, `ptrace`, `tap`, `unotify`) için minimal ham syscall sarmalayıcıları.
- **İzolasyon Motoru (`rsb-core`):** `PreparedSandbox`, yol çözümleme, `argv`/`envp`, Landlock maskeleri ve BPF bytecode derlemesini ana süreçte önceden tamamlar; böylece `clone3` sonrası çocuk süreç `execve` öncesinde heap bellek tahsisinden kaçınır.
- **Namespace ve Rootfs:** Rootless `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`) ve dış ortam seccomp'u `ENOSYS` döndürdüğünde otomatik `clone(2)` geçişi. `CLONE_NEWPID` içinde hafif bir PID 1 subreaper döngüsü ve isteğe bağlı `pivot_root` + maskelenmiş `/proc` desteği.
- **Landlock LSM:** Çalışan çekirdeğin desteklediği Landlock ABI sürümünü sorgular ve erişim bayraklarını ilgili sürüme göre maskeler.
- **Saf Rust Seccomp-BPF ve `seccomp-unotify`:** Klasik BPF komutlarını çalışma zamanında doğrudan Rust ile derler (`AUDIT_ARCH` doğrulaması, `x86_64` üzerinde `x32` ABI reddi, `TIOCSTI`/`TIOCLINUX` engellemesi, soket domain filtresi, katı allowlist modu ve `SECCOMP_RET_USER_NOTIF` ile canlı denetim).
- **Kaynak Kotaları ve Süreç Hijyeni:** Delege edilmiş Cgroups v2 (`CLONE_INTO_CGROUP` + `cgroup.procs` yedeği), `setrlimit` (`RLIMIT_CORE=0`, yapılandırılabilir `RLIMIT_NOFILE`), `close_range` ile açık FD temizliği, yetki (capability) düşürme, `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG` ve temizlenmiş varsayılan ortam değişkenleri.
- **Geçici Copy-on-Write (`--cow`):** Mount namespace içinde rootless `userxattr` OverlayFS bağlar; çıkışta `added` / `modified` / `deleted` değişikliklerini raporlar ve geçici dizinleri otomatik temizler.
- **Seçici Ağ Çıkış Filtresi (`rsb-net`):**
  - Wildcard destekli domain ve IPv4/IPv6 CIDR + port izin listeleri ile varsayılan SSRF koruması (loopback, `169.254.0.0/16` metadata ve RFC1918 özel ağların engellenmesi).
  - TLS şifresini çözmeden `ClientHello` üzerinden SNI doğrulaması.
  - Hem HTTP/HTTPS `CONNECT` proxy modu (`--allow-domain`) hem de dahili UDP/53 DNS filtreli, şeffaf `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 köprüsü (`--transparent-tap`).
- **Otomatik Politika Üretimi (`rsb learn`):** Hedef komutu `ptrace` altında gözlemleyerek erişilen dosya yollarını, syscall'ları ve ağ kullanımını kaydedip `sandbox.toml` profili üretir (`--strict` ile syscall allowlist'i dahil).
- **Önceden Isıtılmış İşçi Havuzları (`ZygotePool`):** İzole edilmiş sıcak bir Python yorumlayıcısını Linux CoW `fork()` ile istek başına dallandırır (çocuk süreçte kontrol kanalı FD'lerini kapatır ve `stdin`'i `/dev/null`'a yönlendirir); ayrıca her istekte ayrı OS süreci açan bir Node.js işçi havuzu sunar.
- **C ve Python Bağlayıcıları (`rsb-ffi`):** `librsb_ffi.so`, `bindings/c/rsb.h` ve `ctypes` tabanlı `bindings/python/rsb.py` üzerinden hem tek seferlik çalıştırma hem de `ZygotePool` erişimi.

### Hızlı Başlangıç

```bash
# Derleme, statik analiz ve testler
cargo build --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Host çekirdek yeteneklerini görüntüleme
./target/release/rsb info

# Salt-okunur sistem ortamı ve yazılabilir çalışma dizini ile çalıştırma
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo merhaba > ./work/out.txt'

# Zaman aşımı ve sınırlı stdout/stderr yakalamalı JSON yürütme modu
./target/release/rsb ai-exec --timeout-ms 2000 -- /usr/bin/python3 -c 'print(6 * 7)'

# Otomatik sandbox.toml profili üretme ve yeniden çalıştırma
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo merhaba'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo merhaba'

# Şeffaf rootless TAP + smoltcp L2/L3 filtresi
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- /usr/bin/curl -sI https://example.com

# Rust SDK ve Python FFI örnekleri
cargo run --release -p rsb-core --example ai_sandbox
python3 bindings/python/rsb.py
```

### Yerel Gözlemler ve Test Kapsamı

`x86_64` Linux 7.3 üzerinde gözlemlenen değerler (donanım ve çekirdek sürümüne göre değişiklik gösterir):

- Sandbox kurulum süresi (Landlock + 72 komutluk Seccomp-BPF ile): ~`0.6 – 1.0 ms`
- Python `ZygotePool` gidiş-dönüş süresi (20 sıcak çalıştırma ortalaması): ~`1.2 – 1.4 ms`
- Otomatik test paketi: Birim ve entegrasyon testleri, 8 kaçış testi (`crates/rsb-core/tests/escape_suite.rs`) ve TLS SNI, DNS, TOML ayrıştırıcıları üzerinde 50.000 deterministik fuzz girdisi dahil toplam 36 test.

### Kapsam ve Gereksinimler

- **İşletim Sistemi:** Linux (`x86_64`; `aarch64` syscall katmanı dahildir, `rsb learn` şu an yalnızca `x86_64` destekler).
- **Çekirdek Özellikleri:** Namespace, OverlayFS ve TAP özellikleri için rootless user namespaces (`CLONE_NEWUSER`); dosya yolu kuralları için Landlock LSM (Linux 5.13+); bellek/CPU/PID kotaları için delege edilmiş Cgroups v2 (erişilemediğinde güvenli biçimde atlanır).
- **Geliştirme Günlüğü:** Mimari kararlar ve çekirdek bulguları [DEVLOG.md](file:///home/shura/Projects/Rust%20Sandbox/DEVLOG.md) dosyasında yer alır.
- **Lisans:** MIT veya Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
