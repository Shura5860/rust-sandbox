//! Pre-warmed Zygote Fork Server for sub-millisecond Python sandbox cloning.
//!
//! Instead of paying ~35–50 ms to cold-start Python and import libraries on every
//! AI agent code execution, `ZygotePool` starts a single warm Python interpreter
//! *already confined* inside `rsb-core` (Landlock + Seccomp-BPF + optional
//! Namespaces/Cgroups).
//!
//! Every `exec(code, timeout)` request triggers a Linux Copy-on-Write `fork()`
//! inside the warm Zygote:
//! - Inherits Landlock + Seccomp-BPF from the kernel at **zero extra syscall cost**.
//! - Gets a completely isolated Copy-on-Write address space (globals/modules
//!   mutated in request #1 never leak to request #2).
//! - Enforces per-request `timeout` (`SIGKILL`) without tearing down the warm pool.

use crate::error::SandboxError;
use crate::policy::Sandbox;
use crate::sandbox::SpawnedSandbox;
use rsb_sys::RawErrno;
use rsb_sys::rustix::io::{Errno, read, write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Configuration for a pre-warmed Python Zygote pool.
#[derive(Debug, Clone)]
pub struct ZygoteConfig {
    pub python_bin: PathBuf,
    pub preload_modules: Vec<String>,
    pub namespaces: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub allow_network: bool,
    pub ro_paths: Vec<PathBuf>,
    pub rw_paths: Vec<PathBuf>,
    pub limits: crate::cgroup::ResourceLimits,
}

impl Default for ZygoteConfig {
    fn default() -> Self {
        Self {
            python_bin: PathBuf::from("/usr/bin/python3"),
            preload_modules: vec![
                "json".into(),
                "math".into(),
                "re".into(),
                "collections".into(),
            ],
            namespaces: true,
            landlock: true,
            seccomp: true,
            allow_network: false,
            ro_paths: Vec::new(),
            rw_paths: Vec::new(),
            limits: crate::cgroup::ResourceLimits::default(),
        }
    }
}

/// Result of a single forked execution inside a `ZygotePool`.
#[derive(Debug, Clone)]
pub struct ZygoteExecResult {
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    /// End-to-end wall-clock round-trip time from Rust host (IPC + CoW fork + exec + IPC).
    pub roundtrip_time: Duration,
    /// Pure fork + execution time measured inside the warm Zygote.
    pub fork_exec_us: u64,
}

impl ZygoteExecResult {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == 0
    }
}

/// A live, pre-warmed, sandboxed Python Zygote fork server.
pub struct ZygotePool {
    child: SpawnedSandbox,
    req_tx: OwnedFd,
    resp_rx: OwnedFd,
    pub warmup_time: Duration,
}

/// Minimal, zero-dependency Python 3 Zygote bootstrap script.
///
/// Protocol over stdin/stdout (binary 4-byte big-endian length-prefixed frames):
/// - Ready frame: `b"READY"`
/// - Request frame: `u32 timeout_ms` (BE) + UTF-8 Python source code
/// - Response frame:
///   `i32 exit_code` (BE) + `u8 timed_out` + `u64 fork_exec_us` (BE)
///   + `u32 stdout_len` (BE) + stdout bytes
///   + `u32 stderr_len` (BE) + stderr bytes
const PYTHON_ZYGOTE_BOOTSTRAP: &str = r#"
import os, sys, struct, time, select, signal, traceback

def read_exact(fd, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def write_all(fd, data):
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        sent += os.write(fd, view[sent:])

def send_frame(fd, payload):
    write_all(fd, struct.pack(">I", len(payload)) + payload)

# Duplicate protocol FDs away from 0/1 and redirect FD 0 & FD 1 to /dev/null BEFORE
# preloading modules so preload stdout cannot corrupt the binary protocol and forked
# workers cannot read host request bytes from stdin (FD 0)!
proto_in = os.dup(0)
proto_out = os.dup(1)
os.set_inheritable(proto_in, False)
os.set_inheritable(proto_out, False)
_devnull_r = os.open("/dev/null", os.O_RDONLY)
os.dup2(_devnull_r, 0)
os.close(_devnull_r)
_devnull_w = os.open("/dev/null", os.O_WRONLY)
os.dup2(_devnull_w, 1)
os.close(_devnull_w)

# Preload requested modules once into warm address space
for mod in sys.argv[1:]:
    if mod:
        try:
            __import__(mod)
        except Exception:
            pass

send_frame(proto_out, b"READY")

while True:
    hdr = read_exact(proto_in, 4)
    if hdr is None:
        break
    (frame_len,) = struct.unpack(">I", hdr)
    body = read_exact(proto_in, frame_len)
    if body is None or len(body) < 4:
        break

    (timeout_ms,) = struct.unpack(">I", body[:4])
    code = body[4:].decode("utf-8", errors="replace")

    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    t0 = time.perf_counter_ns()
    pid = os.fork()

    if pid == 0:
        # Worker child: inherits Landlock + Seccomp-BPF automatically via kernel!
        # Put worker in its own process group so timeout SIGKILL terminates all
        # spawned subprocesses/grandchildren and prevents select() pipe deadlock.
        try:
            os.setpgrp()
        except OSError:
            pass
        # CRITICAL: Close host control-channel FDs immediately after fork() so
        # untrusted Python code CANNOT read/write/spoof the Zygote protocol!
        os.close(proto_in)
        os.close(proto_out)
        os.close(out_r)
        os.close(err_r)
        os.dup2(out_w, 1)
        os.dup2(err_w, 2)
        os.close(out_w)
        os.close(err_w)
        # Re-open Python sys.stdout/stderr on the new pipes
        sys.stdout = os.fdopen(1, "w", buffering=1)
        sys.stderr = os.fdopen(2, "w", buffering=1)
        exit_code = 0
        try:
            exec(compile(code, "<rsb-zygote>", "exec"), {"__name__": "__main__"})
        except SystemExit as e:
            exit_code = 0 if e.code is None else (e.code if isinstance(e.code, int) else 1)
        except BaseException:
            traceback.print_exc()
            exit_code = 1
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(exit_code & 0xFF)
    else:
        # Set worker's process group from parent as well to eliminate the pre-setpgrp race.
        try:
            os.setpgid(pid, pid)
        except OSError:
            pass
        os.close(out_w)
        os.close(err_w)
        os.set_blocking(out_r, False)
        os.set_blocking(err_r, False)
        out_buf = bytearray()
        err_buf = bytearray()
        open_fds = [out_r, err_r]
        deadline = time.monotonic() + (timeout_ms / 1000.0) if timeout_ms > 0 else None
        timed_out = False
        exit_code = -1
        waited = False

        while True:
            if not waited:
                wpid, st = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    waited = True
                    if os.WIFEXITED(st):
                        exit_code = os.WEXITSTATUS(st)
                    elif os.WIFSIGNALED(st):
                        exit_code = 128 + os.WTERMSIG(st)

            if not waited and deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                # Kill both the process group AND the direct worker PID independently
                # so a pre-setpgrp race can never leave the worker alive.
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                _, st = os.waitpid(pid, 0)
                waited = True
                exit_code = 128 + os.WTERMSIG(st) if os.WIFSIGNALED(st) else 124
                # Bounded non-blocking drain of any buffered output, then close open FDs
                # immediately so an escaped grandchild holding pipes cannot deadlock us.
                for fd in list(open_fds):
                    try:
                        while True:
                            chunk = os.read(fd, 8192)
                            if not chunk:
                                break
                            if fd == out_r and len(out_buf) < 1048576:
                                out_buf.extend(chunk)
                            elif fd == err_r and len(err_buf) < 1048576:
                                err_buf.extend(chunk)
                    except OSError:
                        pass
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                open_fds.clear()
                break

            if open_fds:
                rem = 0.005
                if deadline is not None:
                    rem = max(0.001, min(0.005, deadline - time.monotonic()))
                rlist, _, _ = select.select(open_fds, [], [], rem)
                for fd in rlist:
                    try:
                        chunk = os.read(fd, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        open_fds.remove(fd)
                        os.close(fd)
                    elif fd == out_r:
                        if len(out_buf) < 1048576:
                            out_buf.extend(chunk)
                    else:
                        if len(err_buf) < 1048576:
                            err_buf.extend(chunk)
                # If worker already exited and deadline expired (e.g., grandchild holds pipes),
                # close remaining FDs and break instead of hanging forever.
                if waited and deadline is not None and time.monotonic() >= deadline:
                    for fd in list(open_fds):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    open_fds.clear()
                    break
            elif waited:
                break
            else:
                time.sleep(0.001)

        fork_exec_us = (time.perf_counter_ns() - t0) // 1000
        resp = (
            struct.pack(">iBQI", exit_code, 1 if timed_out else 0, fork_exec_us, len(out_buf))
            + bytes(out_buf)
            + struct.pack(">I", len(err_buf))
            + bytes(err_buf)
        )
        send_frame(proto_out, resp)
"#;

/// Configuration for a pre-warmed Node.js Zygote pool.
#[derive(Debug, Clone)]
pub struct NodeZygoteConfig {
    pub node_bin: PathBuf,
    pub namespaces: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub allow_network: bool,
    pub ro_paths: Vec<PathBuf>,
    pub rw_paths: Vec<PathBuf>,
    pub limits: crate::cgroup::ResourceLimits,
}

impl Default for NodeZygoteConfig {
    fn default() -> Self {
        Self {
            node_bin: PathBuf::from("/usr/bin/node"),
            namespaces: true,
            landlock: true,
            seccomp: true,
            allow_network: false,
            ro_paths: Vec::new(),
            rw_paths: Vec::new(),
            limits: crate::cgroup::ResourceLimits::default(),
        }
    }
}

/// Minimal, zero-dependency Node.js Zygote bootstrap script using the exact same
/// 4-byte big-endian length-prefixed binary protocol as the Python Zygote.
///
/// SECURITY: Does NOT rely on `node:vm` for isolation (since `node:vm` is trivially
/// escapable via `this.constructor.constructor('return process')()`). Instead, each
/// request spawns a separate OS child process via `child_process.spawnSync` with
/// isolated stdio pipes and `SIGKILL` timeout; the child automatically inherits the
/// kernel Landlock + Seccomp-BPF boundary and cannot access the Zygote's memory or
/// protocol FDs (`stdio: ['ignore', 'pipe', 'pipe']`).
const NODE_ZYGOTE_BOOTSTRAP: &str = r#"
const fs = require('fs');
const { spawn } = require('child_process');

function writeAll(fd, buf) {
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(fd, buf, off, buf.length - off);
    } catch (e) {
      if (e.code === 'EINTR' || e.code === 'EAGAIN') continue;
      throw e;
    }
  }
}

function sendFrame(buf) {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(buf.length, 0);
  writeAll(1, hdr);
  writeAll(1, buf);
}

const MAX_FRAME = 16 * 1024 * 1024;
const MAX_OUT = 1024 * 1024;

function readExact(n) {
  if (n > MAX_FRAME) return null;
  const out = Buffer.alloc(n);
  let off = 0;
  while (off < n) {
    try {
      const r = fs.readSync(0, out, off, n - off, null);
      if (r === 0) return null;
      off += r;
    } catch (e) {
      if (e.code === 'EINTR' || e.code === 'EAGAIN') continue;
      return null;
    }
  }
  return out;
}

function runWorker(code, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    if (code.indexOf('\0') !== -1) {
      return resolve({
        exitCode: 1,
        timedOut: 0,
        elapsedUs: Number((process.hrtime.bigint() - t0) / 1000n),
        outBuf: Buffer.alloc(0),
        errBuf: Buffer.from('code contains NUL byte\n'),
      });
    }
    let child;
    try {
      // Spawn in its own process group (`detached: true`) with isolated stdio so
      // untrusted code cannot access protocol FDs and timeout SIGKILL terminates
      // all spawned grandchildren (`process.kill(-child.pid, 'SIGKILL')`).
      child = spawn(process.execPath, ['-e', code], {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true,
      });
    } catch (e) {
      return resolve({
        exitCode: 1,
        timedOut: 0,
        elapsedUs: Number((process.hrtime.bigint() - t0) / 1000n),
        outBuf: Buffer.alloc(0),
        errBuf: Buffer.from(String(e) + '\n'),
      });
    }

    const outChunks = [];
    const errChunks = [];
    let outLen = 0;
    let errLen = 0;
    let timedOut = 0;
    let finished = false;
    let timer = null;

    const finish = (exitCode) => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      resolve({
        exitCode,
        timedOut,
        elapsedUs: Number((process.hrtime.bigint() - t0) / 1000n),
        outBuf: Buffer.concat(outChunks),
        errBuf: Buffer.concat(errChunks),
      });
    };

    child.stdout.on('data', (chunk) => {
      if (outLen < MAX_OUT) {
        const take = chunk.slice(0, MAX_OUT - outLen);
        outChunks.push(take);
        outLen += take.length;
      }
    });
    child.stderr.on('data', (chunk) => {
      if (errLen < MAX_OUT) {
        const take = chunk.slice(0, MAX_OUT - errLen);
        errChunks.push(take);
        errLen += take.length;
      }
    });

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = 1;
        if (child.pid) {
          try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
          try { process.kill(child.pid, 'SIGKILL'); } catch (_) {}
        }
        try { child.stdout.destroy(); } catch (_) {}
        try { child.stderr.destroy(); } catch (_) {}
        finish(124);
      }, timeoutMs);
    }

    child.on('error', (e) => {
      errChunks.push(Buffer.from(String(e) + '\n'));
      finish(1);
    });
    child.on('close', (code, sig) => {
      const ec = timedOut ? 124 : (typeof code === 'number' ? code : (sig ? 128 : 1));
      finish(ec);
    });
  });
}

(async () => {
  sendFrame(Buffer.from('READY'));
  while (true) {
    const hdr = readExact(4);
    if (!hdr) break;
    const len = hdr.readUInt32BE(0);
    if (len > MAX_FRAME) break;
    const body = readExact(len);
    if (!body || body.length < 4) break;

    const timeoutMs = body.readUInt32BE(0);
    const code = body.slice(4).toString('utf8');
    const r = await runWorker(code, timeoutMs);

    const resp = Buffer.alloc(17 + r.outBuf.length + 4 + r.errBuf.length);
    resp.writeInt32BE(r.exitCode, 0);
    resp.writeUInt8(r.timedOut, 4);
    resp.writeBigUInt64BE(BigInt(r.elapsedUs), 5);
    resp.writeUInt32BE(r.outBuf.length, 13);
    r.outBuf.copy(resp, 17);
    resp.writeUInt32BE(r.errBuf.length, 17 + r.outBuf.length);
    r.errBuf.copy(resp, 21 + r.outBuf.length);
    sendFrame(resp);
  }
})();
"#;

impl ZygotePool {
    /// Start a pre-warmed, sandboxed Node.js Zygote pool and wait until `READY`.
    pub fn start_node(cfg: NodeZygoteConfig) -> Result<Self, SandboxError> {
        let t0 = Instant::now();

        let mut builder = Sandbox::builder(&cfg.node_bin)
            .args(["-e", NODE_ZYGOTE_BOOTSTRAP])
            .namespaces(cfg.namespaces)
            .landlock(cfg.landlock)
            .seccomp(cfg.seccomp)
            .allow_network(cfg.allow_network);

        if cfg.landlock {
            builder = builder.allow_system_runtime();
        }
        for p in &cfg.ro_paths {
            builder = builder.ro(p);
        }
        for p in &cfg.rw_paths {
            builder = builder.rw(p);
        }
        if let Some(mem) = cfg.limits.memory_max_bytes {
            builder = builder.memory_limit_bytes(mem);
        }
        if let Some(pids) = cfg.limits.pids_max {
            builder = builder.pids_limit(pids);
        }
        if let Some(cpu) = cfg.limits.cpu_quota_percent {
            builder = builder.cpu_quota_percent(cpu);
        }
        if let Some((maj, min, rbps, wbps)) = cfg.limits.io_max_bps {
            builder = builder.io_max_bps(maj, min, rbps, wbps);
        }
        if let Some(nofile) = cfg.limits.rlimit_nofile {
            builder = builder.rlimit_nofile(nofile);
        }
        if cfg.limits.strict_cgroup {
            builder = builder.strict_cgroup(true);
        }

        let mut child = builder.prepare()?.spawn_piped()?;
        let req_tx = child.stdin.take().expect("piped stdin");
        let resp_rx = child.stdout.take().expect("piped stdout");
        if let Some(stderr_rx) = child.stderr.take() {
            spawn_stderr_drainer(stderr_rx);
        }

        let ready = read_frame_deadline(&resp_rx, Some(Instant::now() + Duration::from_secs(10)))?;
        if ready != b"READY" {
            return Err(SandboxError::InvalidPolicy(format!(
                "node zygote failed to initialize: expected READY, got {:?}",
                String::from_utf8_lossy(&ready)
            )));
        }

        Ok(Self {
            child,
            req_tx,
            resp_rx,
            warmup_time: t0.elapsed(),
        })
    }

    /// Start a pre-warmed, sandboxed Python 3 Zygote pool and wait until `READY`.
    pub fn start_python(cfg: ZygoteConfig) -> Result<Self, SandboxError> {
        let t0 = Instant::now();

        let mut builder = Sandbox::builder(&cfg.python_bin)
            .args(["-u", "-c", PYTHON_ZYGOTE_BOOTSTRAP])
            .args(&cfg.preload_modules)
            .namespaces(cfg.namespaces)
            .landlock(cfg.landlock)
            .seccomp(cfg.seccomp)
            .allow_network(cfg.allow_network);

        if cfg.landlock {
            builder = builder.allow_system_runtime();
        }
        for p in &cfg.ro_paths {
            builder = builder.ro(p);
        }
        for p in &cfg.rw_paths {
            builder = builder.rw(p);
        }
        if let Some(mem) = cfg.limits.memory_max_bytes {
            builder = builder.memory_limit_bytes(mem);
        }
        if let Some(pids) = cfg.limits.pids_max {
            builder = builder.pids_limit(pids);
        }
        if let Some(cpu) = cfg.limits.cpu_quota_percent {
            builder = builder.cpu_quota_percent(cpu);
        }
        if let Some((maj, min, rbps, wbps)) = cfg.limits.io_max_bps {
            builder = builder.io_max_bps(maj, min, rbps, wbps);
        }
        if let Some(nofile) = cfg.limits.rlimit_nofile {
            builder = builder.rlimit_nofile(nofile);
        }
        if cfg.limits.strict_cgroup {
            builder = builder.strict_cgroup(true);
        }

        let mut child = builder.prepare()?.spawn_piped()?;
        let req_tx = child.stdin.take().expect("piped stdin");
        let resp_rx = child.stdout.take().expect("piped stdout");
        if let Some(stderr_rx) = child.stderr.take() {
            spawn_stderr_drainer(stderr_rx);
        }

        let ready = read_frame_deadline(&resp_rx, Some(Instant::now() + Duration::from_secs(10)))?;
        if ready != b"READY" {
            return Err(SandboxError::InvalidPolicy(format!(
                "zygote failed to initialize: expected READY, got {:?}",
                String::from_utf8_lossy(&ready)
            )));
        }

        Ok(Self {
            child,
            req_tx,
            resp_rx,
            warmup_time: t0.elapsed(),
        })
    }

    /// Execute code inside a fresh isolated worker of this Zygote.
    pub fn exec(&mut self, code: &str, timeout: Duration) -> Result<ZygoteExecResult, SandboxError> {
        let t0 = Instant::now();
        let timeout_ms: u32 = if timeout.is_zero() {
            0
        } else {
            timeout.as_millis().clamp(1, u32::MAX as u128) as u32
        };

        let mut payload = Vec::with_capacity(4 + code.len());
        payload.extend_from_slice(&timeout_ms.to_be_bytes());
        payload.extend_from_slice(code.as_bytes());
        if payload.len() > MAX_ZYGOTE_FRAME_BYTES {
            return Err(SandboxError::InvalidPolicy(
                "zygote request exceeds 16 MiB frame limit".into(),
            ));
        }
        if let Err(e) = write_frame(&self.req_tx, &payload) {
            self.child.kill_and_wait();
            return Err(e);
        }

        // Enforce a host-side deadline (worker timeout + 2s grace) so a hung Zygote
        // cannot block the caller indefinitely.
        let host_deadline = if timeout.is_zero() {
            None
        } else {
            Some(Instant::now() + timeout + Duration::from_secs(2))
        };
        let resp = match read_frame_deadline(&self.resp_rx, host_deadline) {
            Ok(r) => r,
            Err(e) => {
                self.child.kill_and_wait();
                return Err(e);
            }
        };
        if resp.len() < 17 {
            self.child.kill_and_wait();
            return Err(SandboxError::InvalidPolicy(
                "truncated response frame from zygote".into(),
            ));
        }

        let exit_code = i32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]);
        let timed_out = resp[4] != 0;
        let fork_exec_us = u64::from_be_bytes([
            resp[5], resp[6], resp[7], resp[8], resp[9], resp[10], resp[11], resp[12],
        ]);
        let out_len = u32::from_be_bytes([resp[13], resp[14], resp[15], resp[16]]) as usize;
        let Some(out_end) = 17usize.checked_add(out_len) else {
            self.child.kill_and_wait();
            return Err(SandboxError::InvalidPolicy("invalid stdout length in zygote response".into()));
        };
        if resp.len() < out_end.saturating_add(4) {
            self.child.kill_and_wait();
            return Err(SandboxError::InvalidPolicy(
                "truncated stdout in zygote response".into(),
            ));
        }
        let stdout = String::from_utf8_lossy(&resp[17..out_end]).into_owned();
        let err_len = u32::from_be_bytes([
            resp[out_end],
            resp[out_end + 1],
            resp[out_end + 2],
            resp[out_end + 3],
        ]) as usize;
        let err_start = out_end + 4;
        let Some(err_end) = err_start.checked_add(err_len) else {
            self.child.kill_and_wait();
            return Err(SandboxError::InvalidPolicy("invalid stderr length in zygote response".into()));
        };
        if err_end != resp.len() {
            self.child.kill_and_wait();
            return Err(SandboxError::InvalidPolicy(
                "truncated or malformed stderr in zygote response".into(),
            ));
        }
        let stderr = String::from_utf8_lossy(&resp[err_start..err_end]).into_owned();

        Ok(ZygoteExecResult {
            exit_code,
            timed_out,
            stdout,
            stderr,
            roundtrip_time: t0.elapsed(),
            fork_exec_us,
        })
    }

    /// Gracefully terminate the warm Zygote process.
    pub fn shutdown(mut self) {
        self.child.kill_and_wait();
    }
}

fn write_all_fd(fd: &OwnedFd, mut buf: &[u8]) -> Result<(), SandboxError> {
    while !buf.is_empty() {
        match write(fd, buf) {
            Ok(0) => {
                return Err(SandboxError::Syscall {
                    stage: "write(zygote pipe closed)",
                    errno: RawErrno(32), // EPIPE
                });
            }
            Ok(n) => buf = &buf[n..],
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "write(zygote)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    }
    Ok(())
}

fn spawn_stderr_drainer(stderr_rx: OwnedFd) {
    let _ = std::thread::Builder::new()
        .name("rsb-zygote-stderr".into())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match read(&stderr_rx, &mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(Errno::INTR) => continue,
                    Err(_) => break,
                }
            }
        });
}

fn read_exact_fd_deadline(
    fd: &OwnedFd,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> Result<(), SandboxError> {
    use rsb_sys::rustix::event::{PollFd, PollFlags, Timespec, poll};
    let mut filled = 0usize;
    while filled < buf.len() {
        if let Some(dl) = deadline {
            let now = Instant::now();
            if now >= dl {
                return Err(SandboxError::Syscall {
                    stage: "read(zygote host timeout)",
                    errno: RawErrno(110), // ETIMEDOUT
                });
            }
            let rem = dl.saturating_duration_since(now);
            let ts = Timespec {
                tv_sec: rem.as_secs() as i64,
                tv_nsec: rem.subsec_nanos() as i64,
            };
            let mut pfd = [PollFd::new(fd, PollFlags::IN)];
            match poll(&mut pfd, Some(&ts)) {
                Ok(0) => {
                    return Err(SandboxError::Syscall {
                        stage: "read(zygote host timeout)",
                        errno: RawErrno(110), // ETIMEDOUT
                    });
                }
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(e) => {
                    return Err(SandboxError::Syscall {
                        stage: "poll(zygote)",
                        errno: RawErrno(e.raw_os_error()),
                    });
                }
            }
        }
        match read(fd, &mut buf[filled..]) {
            Ok(0) => {
                return Err(SandboxError::Syscall {
                    stage: "read(zygote EOF)",
                    errno: RawErrno(104), // ECONNRESET
                });
            }
            Ok(n) => filled += n,
            Err(Errno::INTR) => continue,
            Err(e) => {
                return Err(SandboxError::Syscall {
                    stage: "read(zygote)",
                    errno: RawErrno(e.raw_os_error()),
                });
            }
        }
    }
    Ok(())
}

fn write_frame(fd: &OwnedFd, payload: &[u8]) -> Result<(), SandboxError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| SandboxError::InvalidPolicy("zygote frame exceeds u32::MAX".into()))?
        .to_be_bytes();
    write_all_fd(fd, &len)?;
    write_all_fd(fd, payload)
}

const MAX_ZYGOTE_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB anti-OOM cap

fn read_frame_deadline(fd: &OwnedFd, deadline: Option<Instant>) -> Result<Vec<u8>, SandboxError> {
    let mut hdr = [0u8; 4];
    read_exact_fd_deadline(fd, &mut hdr, deadline)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_ZYGOTE_FRAME_BYTES {
        return Err(SandboxError::InvalidPolicy(format!(
            "zygote frame length {len} exceeds maximum allowed ({MAX_ZYGOTE_FRAME_BYTES} bytes)"
        )));
    }
    let mut buf = vec![0u8; len];
    read_exact_fd_deadline(fd, &mut buf, deadline)?;
    Ok(buf)
}
