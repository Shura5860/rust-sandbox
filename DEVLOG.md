# rust-sandbox (`rsb`) — Mühendislik Devlog

Bu dosya, sıfır C bağımlılıklı evrensel Linux izolasyon motoru **`rust-sandbox`**'ın mimari kararlarını, karşılaşılan çekirdek (kernel) detaylarını, performans ölçümlerini ve faz bazlı ilerleyişini kaydeder.

---

## Giriş 001 — Mimari Temeller & Faz 1 İskeleti
**Tarih:** 2026-11-21  
**Ortam:** Linux `7.3.5-arch1-1` (`x86_64`), `rustc 1.98.0`, `unprivileged_userns_clone = 1`

### 1. Temel Mimari Karar: Hibrit `rustix` + Ham Syscall
Başlangıçta iki yaklaşım değerlendirildi:
- **Seçenek A (Purist):** Tüm syscall'ları elle yazmak.
- **Seçenek B (Hibrit):** Standart POSIX/Linux çağrıları için `rustix` (`linux_raw` backend, sıfır `libc`) + özel çekirdek ABI'leri (`clone3`, Landlock LSM, `seccomp`) için minimal ham syscall modülleri.

**Karar:** **Seçenek B** seçildi. `rustix` Linux üzerinde `default-features = false` ile zaten `libc` linklemeden doğrudan inline assembly syscall üretiyor. Böylece "Zero C Dependencies" vaadi %100 korunurken, mühendislik odağı BPF/Landlock/Learn katmanlarına ayrıldı.

### 2. Workspace Yapısı
Proje baştan hem gömülebilir crate hem tek static binary CLI olacak şekilde 3 crate'e bölündü:
- `crates/rsb-sys`: `rustix` re-export'ları + `x86_64`/`aarch64` inline `syscall` yardımcıları + `clone3`, `landlock` (ABI v1–v5), `seccomp` (`PR_SET_NO_NEW_PRIVS`, `sock_filter`, `sock_fprog`).
- `crates/rsb-core`: Bildirimsel `Sandbox::builder()` API'si, `PreparedSandbox` ön-derleme katmanı, async-signal-safe `child_main` ve parent koordinasyonu (`clone3` + UID/GID map + `waitpid` + cold-start ölçümü).
- `crates/rsb-cli`: Harici bağımlılıksız `rsb` CLI (`rsb info`, `rsb run`).

### 3. Kritik Çekirdek & Güvenlik Tasarım Notları
1. **Multithreaded Host Güvenliği (Zero-Alloc Child):**  
   `rsb-core` bir kütüphane olarak Tokio gibi çok iş parçacıklı süreçlere gömüleceği için, `clone3` ile `execve` arasında çocuk süreçte **hiçbir heap allocation veya mutex kilidi** kullanılamaz. Bu yüzden tüm `CString` dönüşümleri, `argv`/`envp` pointer dizileri, executable `PATH` çözümlemesi ve Landlock erişim maskeleri parent süreçte `PreparedSandbox` içine önceden derlenir.
2. **Landlock + `CLONE_NEWNS` Sıralaması:**  
   Landlock kuralları çekirdekte `(vfsmount, dentry)` çiftine bağlanır. Eğer kurallar `clone3(CLONE_NEWNS)` öncesinde parent'ta oluşturulursa, çocuk sürecin klonlanmış mount namespace'indeki yeni `vfsmount` nesneleriyle eşleşmez. Bu yüzden Landlock FD'leri çocuk süreçte `CLONE_NEWNS` **sonrasında** (önceden hazırlanmış `CString` slice'ları üzerinden, sıfır allocation ile) açılıp uygulanır.
3. **Dosya vs Dizin Landlock Maskesi:**  
   Linux Landlock, düzenli dosyalara (regular file) `READ_DIR`, `MAKE_DIR` gibi dizin bitleri eklenirse `EINVAL` döner. `PreparedSandbox` parent aşamasında `metadata.is_dir()` kontrolü yaparak dosya kurallarına `file_only_mask(abi)` uygular.
4. **Sıfır Allocation Hata Raporlama Kanalı:**  
   `O_CLOEXEC` ile açılan 2 boru (`sync_pipe`, `err_pipe`) kullanılır. `execve` başarılı olduğunda çekirdek `err_tx` ucunu otomatik kapatır (parent EOF alır → tam o an `setup_time` ölçülür). Çocukta bir adım hata verirse `[stage_id: u32, errno: i32]` (8 byte) yazılır ve `_exit`/`exit_group(127)` çağrılır.

### 4. Sıradaki Adım
- `cargo test` ile `rsb-sys`, `rsb-core` ve `rsb-cli` derlemesi ve entegrasyon testlerinin doğrulanması.
- Gerçek ortamda `rsb info` ve `rsb run --stats` ile cold-start gecikmesinin ölçülmesi.

---

## Giriş 002 — İlk Derleme, `clone3` → `clone(2)` Fallback Keşfi & Sub-ms Ölçüm
**Tarih:** 2026-11-21  

### 1. Bağımlılık Ağacı & Derleme
- `Cargo.lock` toplamda yalnızca **7 crate** içeriyor (`rustix 1.1.6`, `linux-raw-sys`, `bitflags`, `errno` vb.); `libc` veya herhangi bir C kütüphanesi yok.
- `release` profili sıfırdan **3.19 saniyede** derlendi.

### 2. Gerçek Dünya Çekirdek Bulgusu: `clone3` → `ENOSYS` (errno=38)
İlk test koşusunda, kısıtlı (outer sandbox / container) ortamların seccomp politikalarının `clone3(2)` çağrısına `ENOSYS` (38) döndüğü görüldü (bu, Docker ve benzeri konteyner ortamlarında `glibc`'nin eski `clone(2)` çağrısına düşmesini sağlamak için yaygın kullanılan bir seccomp kuralıdır).
- **Çözüm:** `crates/rsb-sys/src/clone3.rs` içine otomatik fallback eklendi: `SYS_clone3` `ENOSYS` döndüğünde ve 64-bit üst flag'ler kullanılmadığında şeffaf biçimde `SYS_clone` (`x86_64=56`, `aarch64=220`) ile devam ediyor.
- `CLONE_NEWUSER` dış ortam seccomp'u tarafından engellendiğinde (`EPERM=1`, `EACCES=13`, `ENOSYS=38`) entegrasyon testi bunu tespit edip Landlock-only testlerini doğrulamaya devam ediyor.

### 3. Doğrulama & İlk Performans Ölçümleri
- `rsb info`:
  - `kernel: 7.3.5-arch1-1`, `arch: x86_64`
  - `landlock_abi: v11 (supported)`
  - `unpriv_userns: enabled`
- **Landlock İzolasyon Testi (`landlock_blocks_unlisted_secret_and_allows_rw_dir`):**
  - Politika dışı gizli dosyayı (`secret/token.txt`) okumaya çalışan `/bin/cat` çekirdek tarafından anında `Permission denied` ile durduruldu.
  - `--rw` ile izin verilen dizine yazan `/bin/sh` komutu başarıyla çalıştı.
- **Cold-Start Ölçümü (`rsb run --no-ns --stats`):**
  - `setup = 0.920ms` (**1 ms altı soğuk başlangıç** — `clone` + `PR_SET_NO_NEW_PRIVS` + Landlock ruleset kurulumu + `execve`).
  - `total = 3.346ms` (tüm `/bin/sh` süreci dahil).

### 4. Faz 2 İçin Sıradaki Hedefler
1. **Saf Rust Seccomp-BPF Assembler (`rsb-core/src/seccomp_bpf.rs`):** `sock_filter` bytecode üreticisi, mimari doğrulama (`AUDIT_ARCH_*`), `--no-net` / tehlikeli syscall engelleme (`ptrace`, `bpf`, `kexec_load`, `mount`, `io_uring_setup` vb.).
2. **Cgroups v2 Kaynak Kotaları (`rsb-core/src/cgroup.rs`):** `memory.max`, `cpu.max`, `pids.max` + rootless systemd user-slice delegasyon desteği.
3. **Ephemeral CoW (`tmpfs` + `OverlayFS`)** ve tam rootless `pivot_root` + yeni `/proc` mount.
4. **JSON Raporlu `rsb ai-exec` Modu:** `stdout`/`stderr` yakalama, zaman aşımı (timeout) ile süreç grubunu öldürme, yapılandırılmış JSON çıktısı.

---

## Giriş 003 — Faz 2: Saf Rust Seccomp-BPF Assembler, Cgroups v2 & `rsb ai-exec`
**Tarih:** 2026-11-21  

### 1. Saf Rust Classic BPF (cBPF) Assembler (`crates/rsb-core/src/seccomp_bpf.rs`)
`libseccomp` veya herhangi bir C kütüphanesi kullanmadan doğrudan `struct sock_filter` bytecode'u üreten derleyici eklendi:
- **Mimari Doğrulama (Komut 0):** `seccomp_data.arch` alanı `AUDIT_ARCH_X86_64` / `AUDIT_ARCH_AARCH64` ile doğrulanır; uyuşmazlıkta `SECCOMP_RET_KILL_PROCESS` dönerek 32-bit/compat syscall tablosu bypass'ını engeller.
- **Argüman Farkındalıklı Ağ Engelleme:** `allow_network(false)` durumunda yalnızca `CLONE_NEWNET` değil, aynı zamanda BPF düzeyinde `socket(AF_INET | AF_INET6 | AF_NETLINK | AF_PACKET, ...)` çağrıları `EPERM` ile reddedilir (`AF_UNIX` korunarak yerel runtime IPC'lerinin kırılması önlenir). Böylece `--no-ns` (Landlock + Seccomp) modunda bile ağ erişimi çekirdek seviyesinde kesilir.
- **Varsayılan Sertleştirme Listesi:** `ptrace`, `bpf`, `io_uring_setup/enter/register`, `mount`, `umount2`, `pivot_root`, `chroot`, `setns`, `unshare`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `perf_event_open`, `userfaultfd`, `keyctl`, `process_vm_readv/writev`, `open_by_handle_at`, `personality` vb. çağrılar `EPERM` ile engellenir.
- **Sıfır Allocation Kurulum:** Bytecode `PreparedSandbox` içinde derlenir (varsayılan sertleştirilmiş profil = **72 BPF komutu**); çocuk süreç `execve` öncesi yalnızca tek bir `seccomp(SECCOMP_SET_MODE_FILTER)` syscall'ı atar.

### 2. Rootless Cgroups v2 Kota Yöneticisi (`crates/rsb-core/src/cgroup.rs`)
- `/proc/self/cgroup` üzerinden birleşik v2 hiyerarşisini (`0::<path>`) keşfeder ve yazılabilir (systemd user-slice delege edilmiş) dizin varsa geçici `rsb-<pid>-<seq>` alt cgroup'u oluşturur.
- `memory.max`, `pids.max` (fork-bomb koruması) ve `cpu.max` kotalarını uygular; `child_pid`'yi `sync_tx` sinyali gönderilmeden **önce** `cgroup.procs`'a taşır (güvenilmeyen kod tek bir komut bile kota dışında çalışmaz).
- Çıkışta Linux 5.19+ `memory.peak` değerini okuyup `ExecutionReport`'a ekler ve `Drop` ile geçici cgroup dizinini temizler.
- Delege edilmiş cgroup olmayan ortamlarda (ör. kısıtlı container'lar) `strict_cgroup = false` varsayılanıyla zarif biçimde atlayıp `cgroup_active = false` raporlar.

### 3. `rsb ai-exec` & Milisaniye Hassasiyetinde Timeout + Çıktı Yakalama
- `PreparedSandbox::run_captured(max_output_bytes)`: `stdout` ve `stderr` borularını `O_NONBLOCK` + `rustix::event::poll` döngüsüyle paralel okur, stream başına bellek tavanı (`max_output_bytes`) uygulayarak sonsuz çıktı üreten kodların host belleğini tüketmesini engeller.
- **Process Group Timeout:** `--no-ns` modunda çocuk süreç `setpgid(0, 0)` ile kendi süreç grubuna alınır; `--timeout-ms` aşıldığında `kill_process_group(..., SIGKILL)` ile tüm alt süreç ağacı anında temizlenir.
- `rsb ai-exec`: Harici `serde` bağımlılığı olmadan sıfır-bağımlılıklı JSON raporu üretir (`ok`, `exit_code`, `signal`, `timed_out`, `setup_ms`, `total_ms`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `isolation`).

### 4. Doğrulama & Ölçümler
- **Testler:** `cargo test --offline` → **8/8 geçti** (3 unit + 5 integration):
  - `seccomp_blocks_inet_socket_with_eperm`: Python `socket(AF_INET, SOCK_STREAM)` çağrısının 72 komutluk BPF filtresiyle çekirdekten `EPERM` yediği doğrulandı.
  - `timeout_kills_infinite_loop_and_captures_output`: `sleep 10` komutu `120ms` zaman aşımında kesilip `timed_out = true` ve `"starting"` çıktısı yakalandı.
  - `captured_output_truncates_at_limit`: 8 byte tavanında `stdout_truncated = true` doğrulandı.
  - `landlock_blocks_unlisted_secret_and_allows_rw_dir`: Landlock + Seccomp birlikte doğrulandı.
- **Cold-Start (`rsb ai-exec --no-ns`, release):**
  - `setup_ms = 0.889ms` (Landlock v11 + 72 BPF komutu + stdout/stderr pipe yakalama dahil **1 ms altı**).
  - Bağımlılık ağacı hâlâ yalnızca **7 crate**, sıfır C bağımlılığı.

### 5. Faz 3 İçin Sıradaki Hedefler
1. **Ephemeral CoW Dosya Sistemi (`tmpfs` + `OverlayFS`) & `pivot_root`** (rootless mount namespace içinde iz bırakmayan değişiklikler + isteğe bağlı diff raporu).
2. **`rsb learn` (Otomatik Politika Üretici):** `seccomp-unotify` / `ptrace` ile bir uygulamanın açtığı dosyaları ve kullandığı syscall'ları izleyip otomatik `sandbox.toml` profili çıkarma.
3. **TOML Profil Desteği:** `rsb run --profile sandbox.toml -- <cmd>`.

---

## Giriş 004 — Faz 3: `rsb learn` (Saf Rust `ptrace`), `sandbox.toml` Profil Motoru & Ephemeral CoW OverlayFS
**Tarih:** 2026-11-21  

### 1. Saf Rust `ptrace` Politika Öğrenicisi (`crates/rsb-sys/src/ptrace.rs`, `crates/rsb-core/src/learn.rs`)
Harici `strace` veya C bağımlılığı olmadan doğrudan `SYS_ptrace` (`PTRACE_TRACEME`, `PTRACE_SETOPTIONS`, `PTRACE_SYSCALL`, `PTRACE_GETREGS`, `PTRACE_PEEKDATA`) üzerinden çalışan otomatik profil üreteci eklendi:
- `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL` ile tüm alt süreç ve thread ağaçlarını izler (`waitpid(None, __WALL)`).
- `openat`, `open`, `execve`, `mkdirat`, `unlinkat`, `renameat`, `renameat2` çağrılarının path argümanlarını `PTRACE_PEEKDATA` ile bellekten okur, `dirfd` (`AT_FDCWD` veya `/proc/<tid>/fd/<fd>`) üzerinden tam yola çözer ve açılış bayraklarına (`O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND`) göre `ro` / `rw` olarak sınıflandırır.
- `socket(AF_INET | AF_INET6)` çağrısını yakalayarak `allow_network` değerini otomatik belirler.
- Sistem runtime dizinlerini (`/usr`, `/lib`, `/proc`, `/dev/null` vb.) otomatik ayıklayıp en sıkı `SandboxProfile`'ı (`sandbox.toml`) sentezler.

### 2. Sıfır Bağımlılıklı `sandbox.toml` Motoru (`crates/rsb-core/src/profile.rs`)
- `serde` veya `toml` crate'i eklemeden `[isolation]`, `[limits]` ve `[filesystem]` (`ro`, `ro_data`, `rw`, `ephemeral_cow`) bölümlerini ayrıştıran ve serileştiren tam round-trip profil motoru.
- CLI entegrasyonu:
  - `rsb learn --out sandbox.toml -- <CMD>`
  - `rsb run --profile sandbox.toml -- <CMD>`
  - `rsb ai-exec --profile sandbox.toml -- <CMD>`

### 3. Ephemeral Copy-on-Write OverlayFS & Diff Raporu (`crates/rsb-core/src/overlay.rs`)
- Rootless Linux 5.11+ uyumlu `userxattr` seçeneğiyle `CLONE_NEWNS` içinde, Landlock'tan **hemen önce** `mount("overlay", target, "overlay", 0, "lowerdir=...,upperdir=...,workdir=...,userxattr")` bağlanır.
- Süreç bittikten sonra `CowSession::collect_diffs()` `upperdir` ağacını tarayıp `Added`, `Modified` ve `Deleted` (OverlayFS `0/0` char device whiteout) kayıtlarını `CapturedExecutionReport.cow_diffs` içine ve `rsb ai-exec` JSON çıktısına yazar; `Drop` anında tüm geçici `upper`/`work` dizinleri iz bırakmadan silinir.
- CLI bayrağı: `--cow <PATH>` (veya `sandbox.toml` içinde `ephemeral_cow = [...]`).

### 4. Doğrulama Sonuçları
- **Testler:** `cargo test --offline` → **11/11 geçti** (5 unit + 6 integration):
  - `learn_policy_discovers_read_and_write_paths_and_replays_with_profile`: Gerçek bir `cat <in> > <out>` komutunu `ptrace` ile izleyip `ro`/`rw` dizinlerini otomatik çıkardı, `sandbox.toml` round-trip yaptı ve aynı komutu üretilen profille **Landlock + Seccomp-BPF** altında yeniden başarıyla çalıştırdı.
  - `profile::tests::toml_profile_roundtrip`: TOML serileştirme/ayrıştırma doğrulandı.
  - `overlay::tests::collect_upper_diff_detects_added_and_modified_files`: OverlayFS `upperdir` diff motoru doğrulandı.
- **Canlı `rsb learn` Çıktısı (`rsb learn -- /bin/sh -c 'cat /etc/hostname > /dev/null'`):**
  - `[rsb learn] observed 38 unique syscalls, 44 read paths, 2 write paths, network=false`
  - Otomatik üretilen profil: `ro = ["/etc"]`, `rw = []`, `allow_network = false`.
- **Bağımlılık Durumu:** Hâlâ yalnızca **7 crate**, sıfır C bağımlılığı, release derleme süresi **1.21s**.

---

## Giriş 005 — Faz 4: Zygote / Pre-warmed Fork Server (`19.2x` Hızlanma)
**Tarih:** 2026-11-21  

### 1. İki Katmanlı Güvenli Zygote Mimarisi (`crates/rsb-core/src/zygote.rs`, `SpawnedSandbox`)
- `PreparedSandbox::spawn_piped()` ile `stdin`/`stdout`/`stderr` boruları açık uzun ömürlü sandbox süreçleri (`SpawnedSandbox`) eklendi (`Drop` anında süreç grubu temizlenir).
- `ZygotePool::start_python(ZygoteConfig)`:
  - Tek bir sıcak Python 3 yorumlayıcısını **doğrudan `rsb-core` sandbox'ı içinde** (Landlock v11 + 72 komutluk Seccomp-BPF + opsiyonel namespace/cgroup) başlatır ve istenen modülleri (`json`, `math`, `re`, `collections` vb.) bir kez yükler.
  - Protokol FD'lerini `dup` + `set_inheritable(False)` ile `0`/`1`'den ayırır; 4-byte big-endian length-prefixed ikili çerçevelerle Rust host ile konuşur.
  - Her `exec(code, timeout)` çağrısında sıcak Zygote bir **Linux Copy-on-Write `os.fork()`** yapar:
    - Çekirdek, Landlock + Seccomp-BPF sınırlarını çocuk sürece **sıfır ek syscall maliyetiyle** miras bırakır.
    - Her istek tamamen izole bir CoW bellek alanına sahiptir (istek #1'de değiştirilen global değişken istek #2'ye sızmaz).
    - İstek bazlı timeout (`SIGKILL`) sıcak Zygote havuzunu bozmadan yalnızca kaçak işçiyi sonlandırır.

### 2. Benchmark & Doğrulama (`rsb zygote-bench --no-ns --iters 20`)
- **Cold Python (`rsb ai-exec`):** `26.969 ms`
- **Zygote tek seferlik ısınma:** `40.436 ms`
- **Warm Zygote ortalama roundtrip:** **`1.403 ms`** (`min 1.248 ms`, saf `fork+exec` `min 1.191 ms`) → **`19.2x` hızlanma**.
- `zygote_pool_isolates_memory_inherits_seccomp_and_survives_timeout` testiyle bellek izolasyonu, miras alınan Seccomp-BPF `AF_INET` engeli ve timeout sonrası havuz sağlığı doğrulandı.

---

## Giriş 006 — Faz 5: Strict Syscall Allowlist Modu & Çok Thread'li `ptrace` Düzeltmesi
**Tarih:** 2026-11-21  

### 1. Varsayılan-Red (Allowlist) Seccomp-BPF Derleyicisi (`crates/rsb-core/src/seccomp_bpf.rs`)
- `SeccompPolicy.allowlist: Option<Vec<u32>>` ve `SandboxBuilder::allow_syscalls(...)` eklendi.
- Allowlist modunda BPF derleyicisi:
  1. `AUDIT_ARCH_CURRENT` kontrolü (`SECCOMP_RET_KILL_PROCESS`),
  2. `block_network_sockets` aktifse `socket(AF_INET|AF_INET6|AF_NETLINK|AF_PACKET) -> EPERM`,
  3. Yalnızca izin verilen syscall numaraları (+ `execve`, `exit`, `exit_group`) için `SECCOMP_RET_ALLOW`,
  4. Geri kalan **tüm 400+ Linux syscall'ı** için varsayılan `EPERM` (veya `KillProcess`) üretir.
- `sandbox.toml` `[seccomp]` bölümü (`mode = "allowlist"`, `allow_syscalls = [...]`) ve `rsb learn --strict` komutu eklendi.

### 2. Çok İş Parçacıklı Host Keşfi: `waitpid(None, __WALL)` Yarış Durumu
Aynı test binary'si içinde iki `learn_policy` testi paralel çalıştırıldığında, her iki thread'in de `waitpid(None, __WALL)` çağırması nedeniyle thread'lerin birbirlerinin tracee event'lerini çaldığı ve kilitlendiği tespit edildi.
- **Çözüm:** `crates/rsb-core/src/learn.rs` içinde izlenen kök çocuk `setpgid(None, None)` ile kendi süreç grubuna alındı ve ana döngü `waitpgid(root_pid_t, __WALL)` ile yalnızca kendi tracee ağacını dinleyecek şekilde düzeltildi. Paralel test koşusu anında **0.18s** içinde sorunsuz tamamlandı.

### 3. Doğrulama Sonuçları
- `cargo test --offline` → **14/14 test geçti** (6 unit + 8 integration, paralel).
- `strict_syscall_allowlist_replays_target_and_blocks_unobserved_syscalls`:
  - `rsb learn --strict` ile öğrenilen 29 syscall'lık allowlist `sandbox.toml` üzerinden tekrar oynatıldığında hedef komut başarıyla çalıştı.
  - Landlock `--rw` izni olsa bile allowlist'te olmayan `mkdir` çağrısı çekirdek Seccomp-BPF tarafından `EPERM` ile durduruldu.
- **Bağımlılık Durumu:** 5 faz sonunda hâlâ toplam **7 crate**, **0 C bağımlılığı**, release derleme süresi **1.19s**.

---

## Giriş 007 — Güvenlik Denetimi, Savunma Sertleştirmesi & Kaçış Test Paketi (`escape_suite`)
**Tarih:** 2026-11-21  

Kapsamlı Linux izolasyon güvenlik kontrol listesi üzerinden tüm katmanlar denetlendi ve tespit edilen boşluklar kapatıldı:

### 1. Kapatılan Güvenlik Boşlukları
1. **Kör FD Kapatma (`close_range`):** `crates/rsb-sys/src/seccomp.rs` içine `close_range_cloexec(3, u32::MAX)` (`SYS_close_range = 436`, `CLOSE_RANGE_CLOEXEC`) eklendi ve `child_main` içinde `execve` öncesi zorunlu hale getirildi. Host süreçteki üçüncü parti kütüphanelerin `O_CLOEXEC` olmadan açtığı sızmış FD'ler `execve` anında atomik olarak kapatılır.
2. **Capabilities Temizliği (`PR_CAPBSET_DROP` + `capset` v3):** User namespace içindeki `uid=0` sürecinin devraldığı tüm yetkiler (`CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE` vb.) bounding + effective/permitted/inheritable setlerinden tamamen düşürülüyor.
3. **Seccomp-BPF Sertleştirmesi (`crates/rsb-core/src/seccomp_bpf.rs`):**
   - `x32` ABI baypası (`nr >= 0x4000_0000` on `x86_64`) `SECCOMP_RET_KILL_PROCESS` ile kapatıldı (`AUDIT_ARCH` kontrolüne ek olarak).
   - `TIOCSTI` (`0x5412`) ve `TIOCLINUX` (`0x541C`) `ioctl` çağrıları BPF argüman filtresiyle `EPERM` ile engellendi (terminal tuş enjeksiyonu koruması).
   - 28 tehlikeli kaçış syscall'ı (`ptrace`, `bpf`, `io_uring_*`, `kexec_*`, `mount`, `userfaultfd`, `perf_event_open`, `process_vm_readv/writev` vb.) `EPERM` yerine doğrudan **`SECCOMP_RET_KILL_PROCESS` (`SIGSYS`)** olarak yükseltildi.
4. **Parent Death Signal (`PR_SET_PDEATHSIG` + `getppid()` yarışı):** `child_main` başlangıcında `prctl(PR_SET_PDEATHSIG, SIGKILL)` + `getppid() != expected_parent_pid` kontrolü eklendi; host süreç `SIGKILL` yese bile yetim sandbox süreçleri yaşamaz.
5. **Ortam Değişkeni Temizliği:** `SandboxBuilder` varsayılanı `inherit_env: false` olarak değiştirildi (`PATH`, `HOME`, `TERM`, `LANG` beyaz listesi); `AWS_SECRET_ACCESS_KEY`, `SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS` gibi host sırları artık varsayılan olarak sızmıyor.
6. **`setrlimit` + `PR_SET_DUMPABLE=0` Yedek Güvenlik Ağı:** Cgroups v2 delege olmayan ortamlarda bile `RLIMIT_CORE = 0` (core dump kapalı), `RLIMIT_NOFILE = 256` ve `prctl(PR_SET_DUMPABLE, 0)` (pre-`execve` aynı-UID `ptrace` koruması) doğrudan çekirdeğe uygulanıyor. (Not: Linux çekirdeği normal okunabilir binary'lerde `execve` sırasında `dumpable`'ı sıfırladığı için `SIGSYS` testinde `systemd-coredump` pipe'ı bildirim düşürebilir, ancak `RLIMIT_CORE = 0` diske core dosyası yazılmasını kesin olarak engeller.)

### 2. Kaçış Test Paketi (`crates/rsb-core/tests/escape_suite.rs`)
6 saldırgan kaçış testi eklendi ve tamamı geçti (**toplam 20/20 test yeşil**, release build **1.25s**):
- `escape_leaked_host_fd_closed_by_close_range`: `O_CLOEXEC` olmadan açılmış host FD'sini okuma denemesi → `EBADF (9)`.
- `escape_host_env_secrets_sanitized_by_default`: Host gizli env değişkeni sızıntı testi → temizlendi.
- `escape_symlink_to_secret_blocked_by_landlock`: `--rw` içinden dışarıdaki gizli dosyaya symlink → `Permission denied`.
- `escape_tiocsti_terminal_injection_blocked`: `fcntl.ioctl(0, 0x5412, b'x')` → `EPERM`.
- `escape_dangerous_syscall_killed_with_sigsys`: `ctypes` ile ham `SYS_ptrace (101)` çağrısı → anında **`SIGSYS (31)`**.
- `escape_core_dumps_disabled_and_nofile_capped_by_rlimit`: `RLIMIT_CORE == (0, 0)` ve `RLIMIT_NOFILE == (256, 256)` doğrulandı.

### 3. İleri Faz Notları (Tam Rootfs / Container Modu İçin)
- `pivot_root(".", ".")` + `/proc/sys`, `/proc/irq`, `/proc/kcore` maskelemesi ve PID 1 mini-init (subreaper/sinyal yönlendirme) katmanı, özel bir rootfs imajıyla çalışan container modu eklendiğinde devreye alınacak şekilde mimariye uyumlu bırakıldı.
- `CLONE_INTO_CGROUP` atomik cgroup yerleştirme bayrağı `rsb-sys/src/clone3.rs` içinde zaten tanımlı; delegated cgroup'lu hostlarda bir sonraki iterasyonda `clone3` çağrısına doğrudan bağlanabilir.

---

## Giriş 008 — Faz 6: `pivot_root`, PID 1 Mini-Init, `CLONE_INTO_CGROUP`, `README.md` & SDK Örneği
**Tarih:** 2026-11-21  

### 1. İleri Çekirdek & Container İzolasyonu
- **`CLONE_INTO_CGROUP` (`crates/rsb-core/src/cgroup.rs`, `sandbox.rs`):** Cgroups v2 aktifken cgroup dizini `O_PATH | O_DIRECTORY | O_CLOEXEC` ile açılıp `clone3` çağrısına doğrudan `CLONE_INTO_CGROUP` ile verilir (fork-bomb yarış penceresi sıfırlanır). Dış seccomp `ENOSYS` dönerse şeffaf biçimde `cgroup.procs` fallback'ine geçer.
- **Rootfs `pivot_root` + Maskelenmiş `/proc` (`crates/rsb-core/src/child.rs`, `--rootfs`):** Özel rootfs verildiğinde `mount_recursive_bind` → `chdir` → taze `/proc` mount + `/proc/sys`, `/proc/irq`, `/proc/bus` (read-only `tmpfs`) ve `/proc/kcore` (`/dev/null` bind) maskelemesi → `pivot_root(".", ".")` → `umount2(".", MNT_DETACH)` → `chdir("/")` uygulanır.
- **PID 1 Mini-Init Subreaper (`crates/rsb-core/src/child.rs`):** `CLONE_NEWPID` içinde çocuk süreç PID 1 olarak kalır, kullanıcı programını PID 2 olarak `clone3` ile başlatır, yetim kalan tüm zombi torun süreçleri `waitpid` döngüsüyle toplar ve PID 2'nin çıkış kodunu host'a iletir.

### 2. Dokümantasyon & SDK Örneği
- `README.md`: Mimari özet, gerçek benchmark tablosu, CLI komutları (`info`, `run`, `ai-exec`, `learn --strict`, `zygote-bench`) ve Rust SDK kullanımı eklendi.
- `crates/rsb-core/examples/ai_sandbox.rs`: Hem tek seferlik `Sandbox::builder()` hem de sıcak `ZygotePool` kullanımını gösteren çalıştırılabilir Rust SDK örneği eklendi.

---

## Giriş 009 — Faz 7: `crates/rsb-net` (Saf Rust L3/L4/L7 Egress Filtresi, TLS SNI, DNS, SSRF Koruması & TAP)
**Tarih:** 2026-11-21  

Çekirdek `rsb-core` bağımlılıklarını hiç artırmadan (hâlâ toplam **7 harici crate, 0 C bağımlılığı**) yeni **`crates/rsb-net`** modülü kuruldu:

### 1. Bileşenler
- **L3/L4/L7 Politika & SSRF Kalkanı (`crates/rsb-net/src/policy.rs`):**
  - Tam ve wildcard domain eşleştirme (`api.openai.com:443`, `*.pypi.org`).
  - IPv4/IPv6 CIDR + port kuralları (`203.0.113.10/32:443`, `[2001:db8::/32]:443`).
  - Varsayılan SSRF bloğu: DNS çözümlemesi sonrasında bile `127.0.0.0/8`, `169.254.0.0/16` (cloud metadata), RFC1918 özel ağlar, CGNAT `100.64.0.0/10`, IPv6 `::1`/`fc00::/7`/`fe80::/10` ve IPv4-mapped IPv6 (`::ffff:169.254.169.254`) hedeflerini reddeder.
- **Saf Rust TLS `ClientHello` SNI Ayrıştırıcısı (`crates/rsb-net/src/sni.rs`):**
  - MITM veya sertifika kurmadan ilk TCP paketinden TLS 1.2/1.3 SNI (extension `0x0000`) alanını çıkarır; paylaşımlı CDN IP'si üzerinden başka domain'e sızmayı önler.
- **Saf Rust RFC 1035 DNS Ayrıştırıcı (`crates/rsb-net/src/dns.rs`):**
  - UDP/53 sorgularını ayrıştırır ve izinli olmayan domain'ler için anında `RCODE=5 (REFUSED)` yanıtı sentezler.
- **Filtreleyici Egress Proxy (`crates/rsb-net/src/proxy.rs`) & CLI (`--allow-domain`, `--allow-cidr`):**
  - Host tarafında çalışan HTTP/HTTPS `CONNECT` köprüsü: domain/CIDR kontrolü + post-DNS SSRF doğrulaması + port 443'te TLS SNI eşleştirme.
  - `rsb run --allow-domain api.openai.com:443 -- ...` ve `rsb ai-exec --allow-domain ...` ile entegre.
- **Rootless TAP Altyapısı (`crates/rsb-net/src/tap.rs`):**
  - Linux `/dev/net/tun` (`TUNSETIFF`, `IFF_TAP | IFF_NO_PI`) raw ioctl sarmalayıcısı (Faz 7B'de opsiyonel `smoltcp` L2/L3 köprüsünün doğrudan bağlanacağı taban).

---

## Giriş 010 — Faz 7B: Saf Rust `smoltcp` Şeffaf L2/L3 Userspace Köprüsü (`SlirpBridge`)
**Tarih:** 2026-11-21  

### 1. Şeffaf L2/L3 Köprü Mimarisi (`crates/rsb-net/src/slirp.rs`, `feature = "smoltcp-bridge"`)
`HTTP_PROXY` ortam değişkenini görmezden gelen ham TCP/UDP binary'lerini bile root yetkisi olmadan filtrelemek için saf Rust `smoltcp 0.12` tabanlı userspace ağ geçidi (`10.0.2.2/24`) geliştirildi:
- **`any_ip = true` + Yerel Default Route Keşfi:** `smoltcp 0.12` çekirdeği (`ipv4.rs`), `any_ip = true` açıkken bile uzak IPv4 paketlerini kabul etmek için `routes.lookup(dst)` sonucunda kendi yerel IP'sine (`10.0.2.2`) dönen bir default route (`0.0.0.0/0 -> 10.0.2.2`) şart koşuyor. Bu rota eklendiği an `SlirpBridge` herhangi bir uzak IPv4 (`203.0.113.10:443` vb.) için gelen Ethernet/ARP/IPv4/TCP paketlerini şeffaf biçimde userspace'te sonlandırabiliyor.
- **SYN Öncesi L3/L4 Politika Denetimi (`inspect_tcp_syn`):** Ham Ethernet çerçevesindeki TCP `SYN` hedefi (`dst_ip`, `dst_port`) daha `smoltcp` soketine ulaşmadan `EgressPolicy::check_ip` ile denetlenir; yasaklı hedefler (ör. `169.254.169.254:80`) host üzerinde tek bir soket bile açılmadan düşürülür.
- **Dahili UDP/53 DNS Filtresi:** Yasaklı domain'lere anında `REFUSED (RCODE=5)` döner; izinli domain'leri host'ta çözüp SSRF filtresinden geçirdikten sonra `dns_cache`'e yazar ve RFC 1035 `A` yanıtı (`build_dns_a_response`) üretir.
- **Port 443 TLS SNI Doğrulaması:** İzinli TCP bağlantısı kurulduktan sonra ilk `ClientHello` paketinden `extract_tls_sni` ile SNI doğrulanır; uyuşmazlıkta bağlantı `sock.abort()` ile kesilir.
- **Rootless TAP IPv4 Yapılandırması (`crates/rsb-net/src/tap.rs`):** `ip`/`ifconfig` binary'sine ihtiyaç duymadan doğrudan `SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`, `SIOCADDRT` ioctl'larıyla `tap0` arayüzünü ayağa kaldıran `configure_tap_ipv4()` eklendi.

### 2. Doğrulama Sonuçları
- `cargo test --offline` → **28/28 test geçti** (0 uyarı, release derleme **2.74s**, **0 C bağımlılığı**):
  - `slirp_bridge_refuses_disallowed_dns_and_blocks_ssrf_metadata_syn`: Sanal L2 Ethernet üzerinden `evil.com` DNS sorgusuna `REFUSED (RCODE=5)` dönüldü ve `169.254.169.254:80` SSRF TCP `SYN` paketi host soketi açılmadan engellendi.
  - `slirp_bridge_relays_allowed_tcp_over_l2_ethernet_to_host`: Sanal guest `10.0.2.15` → `203.0.113.10:<port>` üzerinden ARP + TCP 3-way handshake + host `TcpListener` echo verisi tüm L2/L3 yığınından uçtan uca taşındı.

---

## Giriş 011 — Faz 8: `seccomp-unotify` Canlı Denetim, Node.js Zygote & C/Python FFI (`librsb_ffi.so`)
**Tarih:** 2026-11-21  

### 1. `seccomp-unotify` Canlı Syscall Denetimi (`crates/rsb-sys/src/unotify.rs`, `crates/rsb-core/src/unotify.rs`)
- `SECCOMP_RET_USER_NOTIF` (`SeccompAction::UserNotif`) + `SECCOMP_FILTER_FLAG_NEW_LISTENER` + saf Rust `AF_UNIX` `SCM_RIGHTS` FD aktarımı (`send_fd` / `recv_fd`, `msg_controllen = CMSG_SPACE(4) = 24`) eklendi.
- Host supervisor `SECCOMP_IOCTL_NOTIF_RECV` → kullanıcı callback'i (`UnotifyDecision::Continue | Errno(e) | ReturnValue(v)`) → TOCTOU doğrulaması (`SECCOMP_IOCTL_NOTIF_ID_VALID`) → `SECCOMP_IOCTL_NOTIF_SEND` döngüsüyle `ptrace` maliyeti olmadan canlı syscall denetimi yapar.
- **Not:** Linux çekirdeği bir süreç zincirinde tek bir `SECCOMP_FILTER_FLAG_NEW_LISTENER` dinleyicisine izin verir (`EBUSY=16`); dış sandbox'ın kendisi unotify tuttuğu için entegrasyon testi `errno=16` durumunda zarifçe atlar, normal host terminalinde `$$ == 4242` canlı olarak doğrulanır.

### 2. Node.js Zygote (`ZygotePool::start_node`) & Gerçek Dünya Keşifleri
- Python Zygote ile birebir aynı 4-byte length-prefixed ikili protokolü kullanan izole `vm.createContext` tabanlı Node.js Zygote (`NodeZygoteConfig`, `ZygotePool::start_node`) eklendi.
- **Keşif 1 (`io_uring` + libuv):** Node.js v26 (libuv) başlangıçta `io_uring_setup` yoklar; `SECCOMP_RET_KILL_PROCESS` yerine `EPERM` döndürülerek `epoll` fallback'i güvenle sağlandı (`ptrace`/`bpf`/`kexec_*`/`mount` hâlâ `KILL_PROCESS`).
- **Keşif 2 (OpenSSL + Landlock):** Node.js v26 başlangıçta `/etc/ssl/openssl.cnf` okuduğu için bu dosya `allow_system_runtime()` read-only listesine eklendi.
- `node_zygote_executes_isolated_js_if_node_installed` testi **Node.js v26.13.1** üzerinde Landlock v11 + Seccomp-BPF altında geçti.

### 3. C ABI (`crates/rsb-ffi` → `librsb_ffi.so`) & Python `ctypes` Bağlayıcısı
- `crates/rsb-ffi` (`crate-type = ["cdylib", "rlib"]`): `rsb_version`, `rsb_landlock_abi`, `rsb_exec_json`, `rsb_string_free`.
- C başlık dosyası: `bindings/c/rsb.h`.
- Sıfır bağımlılıklı Python bağlayıcısı: `bindings/python/rsb.py` (`ctypes` üzerinden doğrudan `target/release/librsb_ffi.so` çağırır).
- Canlı test (`python3 bindings/python/rsb.py`): `rsb-ffi v0.1.0 (landlock_abi=v11)`, `ok: true`, `setup_ms: 1.068ms`.

### 4. Genel Durum
- Workspace: **5 crate** (`rsb-sys`, `rsb-core`, `rsb-net`, `rsb-ffi`, `rsb-cli`), **31/31 test yeşil**, **0 uyarı**, **0 C bağımlılığı**, release derleme **1.61s**.

---

## Giriş 012 — Eleştirel Kod İncelemesi Sertleştirmesi: Zygote İzolasyonu, `clippy -D warnings`, 50K Fuzz & Canlı TAP Pompası
**Tarih:** 2026-11-21  

Mimari kod incelemesinde tespit edilen gerçek güvenlik ve olgunluk riskleri doğrudan kapatıldı:

### 1. Zygote Protokol FD Sızıntısı & Node.js `node:vm` Kaçışı Düzeltildi (`crates/rsb-core/src/zygote.rs`)
- **Python Zygote:** `os.set_inheritable(..., False)` yalnızca `execve` için `O_CLOEXEC` koyar, `os.fork()` sonrası çocukta FD'yi kapatmaz. Artık `if pid == 0:` dalında ilk iş olarak `os.close(proto_in)` ve `os.close(proto_out)` çağrılıyor.
- **Node.js Zygote:** `node:vm` (`vm.createContext`) güvenlik sınırı olmadığı için (`this.constructor.constructor('return process')()` ile tek satırda kaçılabiliyor), Node.js Zygote her istekte ayrı bir OS çocuk süreci (`child_process.spawnSync(..., { stdio: ['ignore', 'pipe', 'pipe'], killSignal: 'SIGKILL' })`) açacak şekilde yeniden yazıldı. Çocuk süreç Landlock + Seccomp-BPF sınırını çekirdekten devralır ve Zygote belleğine / protokol FD'lerine erişemez.
- **Yeni Kaçış Testleri (`crates/rsb-core/tests/escape_suite.rs`):**
  - `escape_python_zygote_worker_cannot_access_protocol_fds`: FDs `3..32` taranarak `LEAKED_FDS: []` doğrulandı.
  - `escape_node_zygote_worker_cannot_kill_or_corrupt_zygote_pool`: `this.constructor.constructor('return process')().kill(process.pid, 9)` saldırısının yalnızca çocuk işçiyi öldürdüğü, Zygote havuzunun hayatta kalıp sonraki isteğe `"zygote-survived"` döndüğü doğrulandı.

### 2. Dış Byte Ayrıştırıcıları Üzerinde 50.000 İterasyonlu Fuzz / İşkence Testi & `clippy -D warnings`
- `cargo clippy --workspace --all-targets -- -D warnings` → tüm 5 crate, test ve örneklerde **0 uyarı / 0 hata**; tüm `pub unsafe fn` fonksiyonlarına `# Safety` dokümantasyonu eklendi.
- **50.000 deterministik fuzz girdisi (0 panic):**
  - `sni::tests::fuzz_tls_sni_parser_never_panics`: 20.000 bozuk/kesik/mutasyonlu TLS `ClientHello` paketi.
  - `dns::tests::fuzz_dns_parser_never_panics`: 20.000 rastgele/bozuk UDP DNS paketi + `REFUSED`/`A` yanıt sentezi.
  - `profile::tests::fuzz_toml_profile_parser_never_panics`: 10.000 bozuk/kaçış karakterli/NUL byte'lı `sandbox.toml` girdisi.

### 3. Canlı TAP Pompa Döngüsü (`SlirpBridge::spawn_on_tap`)
- `crates/rsb-net/src/slirp.rs` içine `O_NONBLOCK` + `rustix::event::poll` ile gerçek bir Linux TAP FD'si üzerinden Ethernet çerçevelerini canlı pompalayan `SlirpBridge::spawn_on_tap(tap_fd) -> SlirpHandle` eklendi.

### 4. Güncel Doğrulama
- `cargo clippy --offline --workspace --all-targets -- -D warnings` → **temiz (0 uyarı)**
- `cargo test --offline` → **36/36 test geçti** (8 escape suite + 10 integration + 7 `rsb-core` unit + 10 `rsb-net` unit + 1 `rsb-sys` unit), release build **1.84s**.

---

## Giriş 013 — Canlı `CLONE_NEWNET` + `tap0` (`SCM_RIGHTS`) + `SlirpBridge` Uçtan Uca Entegrasyonu
**Tarih:** 2026-11-21  

- Sıfır allocation `open_tap_raw` ve `configure_tap_ipv4_raw` (`lo` UP + `tap0` `10.0.2.15/24`, gw `10.0.2.2`) `crates/rsb-sys/src/tap.rs` içine taşındı (`rsb-core` ile `rsb-net` arasında döngüsel bağımlılık oluşmadan).
- `child_main` (`CLONE_NEWUSER | CLONE_NEWNET` içinde, `drop_all_capabilities()` öncesinde): `/dev/net/tun` üzerinden `tap0` açar, IP/route yapılandırır, geçici `/etc/resolv.conf` (`nameserver 10.0.2.2`) bind-mount eder, `tap_fd`'yi `SCM_RIGHTS` ile host'a gönderir ve çocuk kopyasını hemen kapatır.
- `PreparedSandbox::run_with_tap` / `run_captured_with_tap` ve CLI `--transparent-tap` bayrağı eklendi:
  ```bash
  rsb run --transparent-tap --allow-domain api.openai.com:443 -- curl -I https://api.openai.com
  ```

---

## Giriş 014 — Kapsamlı Hata Temizliği (Dalga 1 Kritik + Dalga 2 Yüksek + Dalga 3 Orta — 22/22 Madde)
**Tarih:** 2026-11-21  

Satır satır taramada bulunan **22 somut bug, güvenlik açığı ve eksik entegrasyonun tamamı** 3 fazda kapatıldı:

### Dalga 1 — Kritik (1–9)
1. **Python Zygote `stdin` (FD 0) Sızıntısı:** `os.dup(0)` sonrası FD 0 `/dev/null`'a yönlendirildi; kaçış testi `STDIN_LEN: 0` ile doğrulandı.
2. **`--transparent-tap` + Landlock:** `/etc/resolv.conf` `allow_system_runtime()` read-only listesine eklendi.
3. **`--rootfs` + Landlock / `resolve_executable`:** `PreparedSandbox`, `rootfs` verildiğinde hem binary'yi hem Landlock `metadata` kontrollerini `rootfs` dizinine göre çözer ve rootfs'te olmayan host yollarını zarifçe atlar.
4. **PID 1 Mini-Init FD Kapatma:** PID 1, PID 2'yi başlattıktan sonra `0/1/2` ve `close_range(3, MAX, 0)` ile tüm pipe/FD kopyalarını kapatır (erken EOF kilidi çözüldü).
5. **Non-blocking `SlirpBridge` TX Tamponu:** `ActiveTcpConn.tx_pending: VecDeque<u8>` eklendi; büyük upload'larda `WouldBlock` bağlantıyı koparmaz.
6. **Non-blocking DNS & Upstream Connect (`SlirpBridge`):** `to_socket_addrs()` ve `TcpStream::connect_timeout` arka plan thread + `mpsc` kanalına alındı; yavaş hedefler artık `SlirpBridge` döngüsünü bloklamıyor.
7. **Parçalı TLS `ClientHello` SNI Tamponlama:** Hem `EgressProxy` hem `SlirpBridge` `tls_record_expected_len` ile tam TLS kaydı gelene kadar biriktiriyor.
8. **`EgressProxy` DoS Koruması:** Header satırları `4 KiB` / `64` adet ile sınırlandı (`431`), eşzamanlı bağlantı sayısı `128` ile sınırlandı (`503`).
9. **`rsb-resolv` Yarış & Sızıntı:** Atomik sayaç + `TempFileGuard` (`Drop`) ile erken hata yollarında bile `/tmp` temizliği garantilendi.

### Dalga 2 — Yüksek (10–16)
10. **`ZygotePool::read_frame` Anti-OOM:** `MAX_ZYGOTE_FRAME_BYTES = 16 MiB` üst sınırı eklendi.
11. **Python Zygote Süreç Grubu Timeout:** `os.setpgrp()` + `os.killpg(pid, SIGKILL)` ile kaçak torun süreçlerin `select()` kilitlemesi engellendi.
12. **`rsb ai-exec --profile` Öncelik Hatası:** AI varsayılanları (`256 MiB`, `32 pids`, `5000ms`) artık yalnızca `--profile` ve CLI ikisi de belirtmediyse (`get_or_insert`) uygulanır.
13. **`rsb learn` Syscall Kapsamı & Zombi Koruması:** `mkdir`, `creat`, `unlink`, `rename`, `linkat`, `symlinkat`, `openat2` eklendi; `ptrace` kurulum hatasında `root_pid` öldürülüp reap edilir.
14. **`unotify::run_supervised` Temizlik:** Çocukta `listener_fd` `send_fd` sonrası kapatılır; `recv_fd` hatasında `child_pid` öldürülüp reap edilir.
15. **`spawn_piped()` + `CLONE_INTO_CGROUP`:** `run_internal()` ile tam tutarlılık sağlandı.
16. **Node.js Zygote:** Her istekte ayrı OS çocuk süreci izolasyonu korundu.

### Dalga 3 — Orta (17–22)
17. **`sandbox.toml` `[network]` & `rootfs`:** `rootfs`, `allow_domains`, `allow_cidrs`, `transparent_tap` desteği eklendi ve `rsb-cli` ile birleştirildi.
18. **`cgroup.rs` Paralel Probe:** `.rsb-probe-{pid}-{seq}` atomik sayacı eklendi.
19. **`resolve_executable` `X_OK` Kontrolü:** `+x` izni olmayan dosyalar `PATH` taramasında atlanır.
20. **`aarch64` `syscall2..5` `# Safety` Dokümanı:** ARM64 `clippy -D warnings` uyumluluğu tamamlandı.
21. **Yapılandırılabilir `RLIMIT_NOFILE`:** `ResourceLimits.rlimit_nofile` + `SandboxBuilder::rlimit_nofile(u64)` eklendi.
22. **C/Python FFI `ZygotePool`:** `rsb_zygote_start_python`, `rsb_zygote_exec_json`, `rsb_zygote_free` (`librsb_ffi.so`, `rsb.h`, `rsb.py`) eklendi ve canlı doğrulandı.
