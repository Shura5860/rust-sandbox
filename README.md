# `rust-sandbox` (`rsb`)

[English](#english) | [Türkçe](#türkçe)

---

## English

`rust-sandbox` (`rsb`) is a Linux process isolation engine, CLI, and embeddable Rust library designed for running untrusted code, scripts, and AI-agent tools with minimal overhead. It combines rootless Linux kernel primitives (namespaces, Landlock LSM, Seccomp-BPF, Cgroups v2, OverlayFS) with userspace network filtering in a single workspace with C and Python FFI bindings.

### Quick Start

```bash
# 1. Build the CLI (`rsb`) and shared FFI library (`librsb_ffi.so`)
cargo build --workspace --release

# 2. Check supported kernel features on your machine (Landlock ABI, userns, Cgroups v2)
./target/release/rsb info

# 3. Run a command with read-only system runtime and a single writable directory
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo hello > ./work/out.txt'

# 4. Execute untrusted code in JSON mode with a timeout and bounded output capture
./target/release/rsb ai-exec --timeout-ms 2000 -- /usr/bin/python3 -c 'print(6 * 7)'
```

### Architecture & Capabilities

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

#### Process & Filesystem Isolation
- **Rootless Namespaces & Rootfs:** `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`) with automatic `clone(2)` fallback when an outer seccomp filter returns `ENOSYS`. Includes a lightweight PID 1 subreaper inside `CLONE_NEWPID` and optional `pivot_root` with masked `/proc` subpaths.
- **Landlock LSM:** Queries the host kernel's Landlock ABI version at runtime and masks access rights accordingly across kernel versions.
- **Ephemeral Copy-on-Write (`--cow`):** Mounts rootless `userxattr` OverlayFS inside the mount namespace, reports `added` / `modified` / `deleted` paths on exit, and cleans up staging directories automatically.
- **Pre-compiled Child Setup:** `PreparedSandbox` resolves paths, `argv`/`envp`, Landlock masks, and BPF bytecode in the parent so the post-`clone3` child avoids heap allocations before `execve`.

#### Syscall & Resource Controls
- **Pure-Rust Seccomp-BPF & `seccomp-unotify`:** Compiles classic BPF directly in Rust (`AUDIT_ARCH` check, `x32` ABI rejection on `x86_64`, `TIOCSTI`/`TIOCLINUX` blocking, socket domain filtering, strict allowlist mode, and live userspace syscall supervision via `SECCOMP_RET_USER_NOTIF`).
- **Quotas & Process Hygiene:** Delegated Cgroups v2 (`CLONE_INTO_CGROUP` with `cgroup.procs` fallback), `setrlimit` (`RLIMIT_CORE=0`, configurable `RLIMIT_NOFILE`), `close_range` FD cleanup, capability dropping (`PR_CAPBSET_DROP` + `capset`), `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG`, and sanitized default environment variables.

#### Network Egress Filtering (`rsb-net`)
- **Allowlists & SSRF Protection:** Domain wildcard and IPv4/IPv6 CIDR + port allowlists with default blocking of loopback, link-local / cloud metadata (`169.254.0.0/16`), and RFC1918 ranges.
- **Proxy & Transparent TAP Modes:** Pure-Rust TLS `ClientHello` SNI inspection without decryption, available via both an HTTP/HTTPS `CONNECT` proxy (`--allow-domain`) and a transparent rootless `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 bridge (`--transparent-tap`) with built-in UDP/53 DNS filtering.

#### Tooling, Runtimes & Embeddings
- **Policy Learning (`rsb learn`):** Traces a target command via `ptrace` and writes a reusable `sandbox.toml` profile (optionally with `--strict` syscall allowlist).
- **Pre-warmed Worker Pools (`ZygotePool`):** Keeps a confined Python interpreter warm and forks per request via Linux CoW `fork()` (closing control-channel FDs and redirecting `stdin` to `/dev/null` in each worker), plus an OS-process-isolated Node.js worker pool.
- **C & Python Bindings (`rsb-ffi`):** Exports a C ABI (`librsb_ffi.so`, `bindings/c/rsb.h`) and a `ctypes` Python wrapper (`bindings/python/rsb.py`) covering both one-shot execution and `ZygotePool`.

### More Examples

```bash
# Learn a sandbox.toml profile and replay it
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo hello'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo hello'

# Ephemeral CoW OverlayFS (host directory stays untouched; JSON reports cow_diffs)
./target/release/rsb ai-exec --cow ./work -- /bin/sh -c 'rm -rf ./work/*; echo temp > ./work/x'

# Transparent rootless TAP + smoltcp L2/L3 egress filter
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- /usr/bin/curl -sI https://example.com

# Benchmark cold Python vs. warm Zygote execution on your machine
./target/release/rsb zygote-bench --iters 20

# Run the Rust SDK example and Python ctypes FFI example
cargo run --release -p rsb-core --example ai_sandbox
python3 bindings/python/rsb.py
```

### Workspace Structure

| Crate / Path | Purpose |
|---|---|
| `crates/rsb-sys` | Low-level Linux syscall wrappers (`rustix` `linux_raw` + raw `clone3`, Landlock, `seccomp`, `ptrace`, `tap`, `unotify`). |
| `crates/rsb-core` | Core sandbox engine, `PreparedSandbox`, cBPF compiler, Cgroups v2, OverlayFS CoW, `sandbox.toml`, `learn_policy`, `unotify`, `ZygotePool`. |
| `crates/rsb-net` | L3/L4/L7 egress policy, SSRF guard, TLS SNI parser, DNS wire parser, `EgressProxy`, and `smoltcp` L2/L3 `SlirpBridge`. |
| `crates/rsb-ffi` | C ABI shared library (`librsb_ffi.so`). |
| `crates/rsb-cli` | `rsb` command-line interface (`info`, `run`, `ai-exec`, `learn`, `zygote-bench`). |
| `bindings/` | C header (`bindings/c/rsb.h`) and Python `ctypes` wrapper (`bindings/python/rsb.py`). |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Internal design decisions, kernel fallbacks, and known security boundaries. |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes. |

### Tests & Local Measurements

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Observed on an `x86_64` Linux 7.3 host (results vary by hardware and kernel):
- Sandbox setup latency (`rsb run` / `rsb ai-exec` with Landlock + 72-instruction Seccomp-BPF): ~`0.6 – 1.0 ms`
- Python `ZygotePool` round-trip (20 warm runs, Landlock + Seccomp-BPF): ~`1.2 – 1.4 ms` average
- Test suite: 36 automated tests including 8 adversarial escape checks (`crates/rsb-core/tests/escape_suite.rs`) and 50,000 deterministic fuzz inputs across the TLS SNI, DNS, and TOML parsers.

### Scope & Requirements

- **OS:** Linux (`x86_64`; `aarch64` syscall layers included, `rsb learn` is currently `x86_64`-only).
- **Kernel features:** Unprivileged user namespaces (`CLONE_NEWUSER`) for namespace/OverlayFS/TAP features; Landlock LSM (Linux 5.13+) for path rules; delegated Cgroups v2 for memory/CPU/PID quotas (gracefully skipped when unavailable).
- **License:** Dual-licensed under MIT or Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

---

## Türkçe

`rust-sandbox` (`rsb`), güvenilmeyen kodları, betikleri ve yapay zeka ajanı araçlarını düşük ek yükle izole ederek çalıştırmak için Rust ile yazılmış bir Linux süreç izolasyon motoru, CLI aracı ve gömülebilir kütüphanedir. Root yetkisi gerektirmeyen Linux çekirdek mekanizmalarını (namespace'ler, Landlock LSM, Seccomp-BPF, Cgroups v2, OverlayFS) userspace ağ filtrelemesi ve C/Python FFI bağlayıcılarıyla tek bir workspace içinde birleştirir.

### Hızlı Başlangıç

```bash
# 1. CLI (`rsb`) ve paylaşımlı FFI kütüphanesini (`librsb_ffi.so`) derleyin
cargo build --workspace --release

# 2. Sistemdeki çekirdek yeteneklerini kontrol edin (Landlock ABI, userns, Cgroups v2)
./target/release/rsb info

# 3. Salt-okunur sistem ortamı ve tek bir yazılabilir dizinle komut çalıştırın
./target/release/rsb run --rw ./work --stats -- /bin/sh -c 'echo merhaba > ./work/out.txt'

# 4. Zaman aşımı ve sınırlı çıktı yakalamayla JSON modunda kod yürütün
./target/release/rsb ai-exec --timeout-ms 2000 -- /usr/bin/python3 -c 'print(6 * 7)'
```

### Mimari ve Özellikler

#### Süreç ve Dosya Sistemi İzolasyonu
- **Rootless Namespace ve Rootfs:** `clone3` (`USER`, `PID`, `MOUNT`, `IPC`, `UTS`, `NET`) ve dış ortam seccomp'u `ENOSYS` döndürdüğünde otomatik `clone(2)` geçişi. `CLONE_NEWPID` içinde hafif PID 1 subreaper döngüsü ve isteğe bağlı `pivot_root` + maskelenmiş `/proc` desteği.
- **Landlock LSM:** Çalışan çekirdeğin desteklediği Landlock ABI sürümünü çalışma zamanında sorgular ve erişim bayraklarını ilgili sürüme göre maskeler.
- **Geçici Copy-on-Write (`--cow`):** Mount namespace içinde rootless `userxattr` OverlayFS bağlar; çıkışta `added` / `modified` / `deleted` değişikliklerini raporlar ve geçici dizinleri otomatik temizler.
- **Önceden Derlenmiş Çocuk Kurulumu:** `PreparedSandbox`, yol çözümleme, `argv`/`envp`, Landlock maskeleri ve BPF bytecode'unu ana süreçte hazırlar; böylece `clone3` sonrası çocuk süreç `execve` öncesinde heap tahsisinden kaçınır.

#### Syscall ve Kaynak Kontrolleri
- **Saf Rust Seccomp-BPF ve `seccomp-unotify`:** Klasik BPF komutlarını doğrudan Rust ile derler (`AUDIT_ARCH` doğrulaması, `x86_64` üzerinde `x32` ABI reddi, `TIOCSTI`/`TIOCLINUX` engellemesi, soket domain filtresi, katı allowlist modu ve `SECCOMP_RET_USER_NOTIF` ile canlı denetim).
- **Kotalar ve Süreç Hijyeni:** Delege edilmiş Cgroups v2 (`CLONE_INTO_CGROUP` + `cgroup.procs` yedeği), `setrlimit` (`RLIMIT_CORE=0`, yapılandırılabilir `RLIMIT_NOFILE`), `close_range` ile açık FD temizliği, yetki (capability) düşürme, `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG` ve temizlenmiş varsayılan ortam değişkenleri.

#### Ağ Çıkış Filtrelemesi (`rsb-net`)
- **İzin Listeleri ve SSRF Koruması:** Wildcard destekli domain ve IPv4/IPv6 CIDR + port kuralları ile loopback, link-local / bulut metadata (`169.254.0.0/16`) ve RFC1918 özel ağlarının varsayılan olarak engellenmesi.
- **Proxy ve Şeffaf TAP Modları:** TLS şifresini çözmeden `ClientHello` üzerinden SNI doğrulaması; hem HTTP/HTTPS `CONNECT` proxy (`--allow-domain`) hem de dahili UDP/53 DNS filtreli şeffaf `CLONE_NEWNET` + `tap0` + `smoltcp` L2/L3 köprüsü (`--transparent-tap`).

#### Araçlar, Çalışma Zamanları ve Entegrasyon
- **Otomatik Politika Üretimi (`rsb learn`):** Hedef komutu `ptrace` altında gözlemleyerek yeniden kullanılabilir bir `sandbox.toml` profili üretir (`--strict` ile syscall allowlist'i dahil).
- **Önceden Isıtılmış İşçi Havuzları (`ZygotePool`):** İzole edilmiş sıcak Python yorumlayıcısını Linux CoW `fork()` ile istek başına dallandırır (çocuk süreçte kontrol kanalı FD'lerini kapatır ve `stdin`'i `/dev/null`'a yönlendirir); ayrıca her istekte ayrı OS süreci açan Node.js işçi havuzu sunar.
- **C ve Python Bağlayıcıları (`rsb-ffi`):** `librsb_ffi.so`, `bindings/c/rsb.h` ve `ctypes` tabanlı `bindings/python/rsb.py` üzerinden hem tek seferlik çalıştırma hem de `ZygotePool` erişimi.

### Diğer Örnekler

```bash
# Otomatik sandbox.toml profili üretme ve yeniden çalıştırma
./target/release/rsb learn --strict --out sandbox.toml -- /bin/sh -c 'echo merhaba'
./target/release/rsb run --profile sandbox.toml -- /bin/sh -c 'echo merhaba'

# Geçici CoW OverlayFS (host dizini değişmez; JSON çıktısında cow_diffs raporlanır)
./target/release/rsb ai-exec --cow ./work -- /bin/sh -c 'rm -rf ./work/*; echo temp > ./work/x'

# Şeffaf rootless TAP + smoltcp L2/L3 çıkış filtresi
./target/release/rsb run --transparent-tap --allow-domain example.com:443 -- /usr/bin/curl -sI https://example.com

# Rust SDK ve Python FFI örnekleri
cargo run --release -p rsb-core --example ai_sandbox
python3 bindings/python/rsb.py
```

### Testler ve Yerel Gözlemler

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`x86_64` Linux 7.3 üzerinde gözlemlenen değerler (donanım ve çekirdek sürümüne göre değişiklik gösterir):
- Sandbox kurulum süresi (Landlock + 72 komutluk Seccomp-BPF ile): ~`0.6 – 1.0 ms`
- Python `ZygotePool` gidiş-dönüş süresi (20 sıcak çalıştırma ortalaması): ~`1.2 – 1.4 ms`
- Otomatik test paketi: 8 kaçış testi (`crates/rsb-core/tests/escape_suite.rs`) ve TLS SNI, DNS, TOML ayrıştırıcıları üzerinde 50.000 deterministik fuzz girdisi dahil toplam 36 test.

### Kapsam ve Gereksinimler

- **İşletim Sistemi:** Linux (`x86_64`; `aarch64` syscall katmanı dahildir, `rsb learn` şu an yalnızca `x86_64` destekler).
- **Çekirdek Özellikleri:** Namespace, OverlayFS ve TAP özellikleri için rootless user namespaces (`CLONE_NEWUSER`); dosya yolu kuralları için Landlock LSM (Linux 5.13+); bellek/CPU/PID kotaları için delege edilmiş Cgroups v2 (erişilemediğinde güvenli biçimde atlanır).
- **Mimari ve Sürüm Geçmişi:** Tasarım kararları ve bilinen sınırlar [ARCHITECTURE.md](ARCHITECTURE.md), sürüm notları [CHANGELOG.md](CHANGELOG.md) dosyasında yer alır.
- **Lisans:** MIT veya Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
