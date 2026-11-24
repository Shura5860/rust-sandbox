//! Pure-Rust filtering HTTP/HTTPS `CONNECT` egress proxy with:
//! - Domain allowlist enforcement (`EgressPolicy::check_domain`)
//! - Post-DNS SSRF protection (`EgressPolicy::check_ip` blocks `127.0.0.0/8`,
//!   `169.254.169.254`, RFC1918 LANs even if an allowed domain rebinds to them!)
//! - Optional TLS `ClientHello` SNI verification (`extract_tls_sni`) on port 443
//!   to prevent shared-CDN host spoofing without MITM decryption.

use crate::policy::EgressPolicy;
use crate::sni::{MAX_CLIENT_HELLO_BYTES, extract_tls_sni, tls_record_expected_len};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_CONCURRENT_CONNS: usize = 128;
const MAX_HEADER_LINE_BYTES: usize = 4096;
const MAX_HEADER_COUNT: usize = 64;

struct ConnSlot(Arc<AtomicUsize>);
impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Running background filtering egress proxy bound on `127.0.0.1:<ephemeral_port>`.
pub struct EgressProxy {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EgressProxy {
    /// Start the filtering egress proxy on an ephemeral loopback port.
    pub fn start(policy: EgressPolicy) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_bg = Arc::clone(&shutdown);
        let policy = Arc::new(policy);

        let active_conns = Arc::new(AtomicUsize::new(0));

        let handle = thread::spawn(move || {
            while !shutdown_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let prev = active_conns.fetch_add(1, Ordering::Relaxed);
                        if prev >= MAX_CONCURRENT_CONNS {
                            active_conns.fetch_sub(1, Ordering::Relaxed);
                            let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
                            continue;
                        }
                        let slot = ConnSlot(Arc::clone(&active_conns));
                        let pol = Arc::clone(&policy);
                        let spawned = thread::Builder::new()
                            .name("rsb-proxy-conn".into())
                            .spawn(move || {
                                let _slot = slot;
                                let _ = handle_client(stream, &pol);
                            });
                        if spawned.is_err() {
                            // `slot` drops automatically here, freeing the connection slot.
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Local `SocketAddr` (`127.0.0.1:<port>`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// URL suitable for `HTTP_PROXY` / `HTTPS_PROXY` environment variables.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop accepting new connections and join the accept loop.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_client(mut client: TcpStream, policy: &EgressPolicy) -> io::Result<()> {
    let _ = client.set_nonblocking(false);
    // Enforce an absolute wall-clock deadline across the entire HTTP header read phase
    // so a slowloris client trickling 1 byte every 9s cannot hold connection slots for days.
    let header_deadline = Instant::now() + Duration::from_secs(10);
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));

    let mut reader = BufReader::new(client.try_clone()?);
    let mut request_line = String::new();
    match read_bounded_line(&mut reader, &mut request_line, MAX_HEADER_LINE_BYTES, header_deadline)? {
        BoundedLine::Eof => return Ok(()),
        BoundedLine::Timeout => {
            let _ = client.write_all(b"HTTP/1.1 408 Request Timeout\r\n\r\n");
            return Ok(());
        }
        BoundedLine::TooLong => {
            client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")?;
            return Ok(());
        }
        BoundedLine::Ok => {}
    }

    // Drain remaining HTTP headers with strict line-length, header-count, and total-time bounds
    let mut hdr = String::new();
    let mut hdr_count = 0usize;
    let mut saw_end_of_headers = false;
    loop {
        hdr.clear();
        match read_bounded_line(&mut reader, &mut hdr, MAX_HEADER_LINE_BYTES, header_deadline)? {
            BoundedLine::Eof => break,
            BoundedLine::Timeout => {
                let _ = client.write_all(b"HTTP/1.1 408 Request Timeout\r\n\r\n");
                return Ok(());
            }
            BoundedLine::TooLong => {
                client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")?;
                return Ok(());
            }
            BoundedLine::Ok => {
                if hdr == "\r\n" || hdr == "\n" {
                    saw_end_of_headers = true;
                    break;
                }
                hdr_count += 1;
                if hdr_count > MAX_HEADER_COUNT {
                    client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")?;
                    return Ok(());
                }
            }
        }
    }
    if !saw_end_of_headers {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
        return Ok(());
    }

    if parts[0].eq_ignore_ascii_case("CONNECT") {
        let target = parts[1];
        let Some((host, port_str)) = target.rsplit_once(':') else {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
            return Ok(());
        };
        let Ok(port) = port_str.parse::<u16>() else {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
            return Ok(());
        };
        let host = host.trim_matches(|c| c == '[' || c == ']');

        // 1. Check domain or direct IP against EgressPolicy
        let (validated_domain, direct_ip) = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                if !policy.check_ip(ip, port, None).is_allowed() {
                    client.write_all(b"HTTP/1.1 403 Forbidden\r\nX-RSB-Reason: ip-denied\r\n\r\n")?;
                    return Ok(());
                }
                (None, Some(ip))
            }
            Err(_) => {
                if !policy.check_domain(host, Some(port)).is_allowed() {
                    client.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nX-RSB-Reason: domain-denied\r\n\r\n",
                    )?;
                    return Ok(());
                }
                (Some(host), None)
            }
        };

        // 2. Resolve DNS on host and enforce post-resolution SSRF protection!
        let resolved_addrs: Vec<SocketAddr> = if let Some(ip) = direct_ip {
            vec![SocketAddr::new(ip, port)]
        } else {
            let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
                Ok(it) => it.collect(),
                Err(_) => {
                    client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")?;
                    return Ok(());
                }
            };
            let allowed: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| policy.check_ip(a.ip(), port, validated_domain).is_allowed())
                .collect();
            if allowed.is_empty() {
                client.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nX-RSB-Reason: ssrf-blocked\r\n\r\n",
                )?;
                return Ok(());
            }
            allowed
        };

        // Acknowledge tunnel establishment
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        client.flush()?;

        // 3. Only buffer initial client bytes BEFORE connecting upstream on port 443
        //    when TLS SNI verification is active; on non-443 ports connect upstream
        //    immediately so server-speaks-first protocols (SSH, SMTP, IMAP, MySQL)
        //    do not deadlock, while still inspecting first client->upstream bytes for
        //    TLS SNI inside the client->upstream relay thread.
        let check_sni_before_connect =
            port == 443 && policy.verify_tls_sni && validated_domain.is_some();
        let mut first_buf = Vec::new();
        if check_sni_before_connect {
            let sni_deadline = Instant::now() + Duration::from_secs(10);
            first_buf.reserve(512);
            let mut chunk = [0u8; 4096];
            loop {
                let now = Instant::now();
                if now >= sni_deadline {
                    return Ok(());
                }
                let _ = reader
                    .get_ref()
                    .set_read_timeout(Some(sni_deadline.saturating_duration_since(now)));
                let n = reader.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                first_buf.extend_from_slice(&chunk[..n]);
                if first_buf.len() >= MAX_CLIENT_HELLO_BYTES {
                    break;
                }
                // If initial bytes are not TLS Handshake (0x16 0x03), stop buffering immediately
                if first_buf[0] != 0x16 || (first_buf.len() >= 2 && first_buf[1] != 0x03) {
                    break;
                }
                if let Some(expected_len) = tls_record_expected_len(&first_buf)
                    && first_buf.len() >= expected_len.min(MAX_CLIENT_HELLO_BYTES)
                {
                    break;
                }
            }
            if first_buf.is_empty() {
                return Ok(());
            }

            if let Some(expected_host) = validated_domain {
                let expected_norm = expected_host.trim_end_matches('.');
                match extract_tls_sni(&first_buf) {
                    Some(ref sni)
                        if sni.eq_ignore_ascii_case(expected_norm)
                            && policy.check_domain(sni, Some(port)).is_allowed() => {}
                    _ => {
                        // SNI mismatch, ECH, or missing SNI on HTTPS tunnel -> drop immediately!
                        return Ok(());
                    }
                }
            }
        }

        // 4. Connect upstream (trying all allowed dual-stack addresses) and relay bidirectionally
        let mut upstream_opt = None;
        for addr in &resolved_addrs {
            if let Ok(s) = TcpStream::connect_timeout(addr, Duration::from_secs(5)) {
                upstream_opt = Some(s);
                break;
            }
        }
        let Some(mut upstream) = upstream_opt else {
            return Ok(());
        };
        if !first_buf.is_empty() {
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(10)));
            upstream.write_all(&first_buf)?;
        }

        // Handshake and SNI validation are complete; switch from the 10s handshake
        // timeout to a 5-minute tunnel idle timeout so long downloads/streams do not
        // prematurely half-close while idle connections still time out cleanly.
        let tunnel_idle = Some(Duration::from_secs(300));
        let _ = client.set_read_timeout(tunnel_idle);
        let _ = client.set_write_timeout(tunnel_idle);
        let _ = upstream.set_read_timeout(tunnel_idle);
        let _ = upstream.set_write_timeout(tunnel_idle);

        let mut c_read = reader;
        let mut c_write = client;
        let mut u_read = upstream.try_clone()?;
        let mut u_write = upstream;

        let defer_sni_check = !check_sni_before_connect && policy.verify_tls_sni;
        let expected_domain_owned = if defer_sni_check {
            validated_domain.map(|h| h.trim_end_matches('.').to_string())
        } else {
            None
        };
        let policy_clone = if expected_domain_owned.is_some() {
            Some(policy.clone())
        } else {
            None
        };

        let t1 = thread::Builder::new()
            .name("rsb-proxy-c2u".into())
            .spawn(move || {
                if let (Some(expected_norm), Some(pol)) = (expected_domain_owned, policy_clone) {
                    let mut buf = Vec::with_capacity(512);
                    let mut chunk = [0u8; 4096];
                    loop {
                        match c_read.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.len() >= MAX_CLIENT_HELLO_BYTES {
                                    break;
                                }
                                if buf[0] != 0x16 || (buf.len() >= 2 && buf[1] != 0x03) {
                                    break;
                                }
                                if let Some(expected_len) = tls_record_expected_len(&buf)
                                    && buf.len() >= expected_len.min(MAX_CLIENT_HELLO_BYTES)
                                {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = u_write.shutdown(std::net::Shutdown::Both);
                                return;
                            }
                        }
                    }
                    if buf.is_empty() {
                        let _ = u_write.shutdown(std::net::Shutdown::Write);
                        return;
                    }
                    let is_tls_handshake = buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0x03;
                    if is_tls_handshake {
                        let valid = match extract_tls_sni(&buf) {
                            Some(ref sni) => {
                                sni.eq_ignore_ascii_case(&expected_norm)
                                    && pol.check_domain(sni, Some(port)).is_allowed()
                            }
                            None => false,
                        };
                        if !valid {
                            let _ = u_write.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                    }
                    if u_write.write_all(&buf).is_err() {
                        let _ = u_write.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
                let _ = io::copy(&mut c_read, &mut u_write);
                let _ = u_write.shutdown(std::net::Shutdown::Write);
            });
        let _ = io::copy(&mut u_read, &mut c_write);
        let _ = c_write.shutdown(std::net::Shutdown::Write);
        if let Ok(h) = t1 {
            let _ = h.join();
        }
    } else {
        client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")?;
    }

    Ok(())
}

enum BoundedLine {
    Ok,
    Eof,
    TooLong,
    Timeout,
}

fn read_bounded_line(
    reader: &mut BufReader<TcpStream>,
    out: &mut String,
    max_bytes: usize,
    deadline: Instant,
) -> io::Result<BoundedLine> {
    let mut total = 0usize;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(BoundedLine::Timeout);
        }
        let _ = reader
            .get_ref()
            .set_read_timeout(Some(deadline.saturating_duration_since(now)));
        let avail = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(BoundedLine::Timeout);
            }
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(if total == 0 {
                BoundedLine::Eof
            } else {
                BoundedLine::Ok
            });
        }
        if let Some(nl) = avail.iter().position(|&b| b == b'\n') {
            let take = nl + 1;
            if total + take > max_bytes {
                reader.consume(take);
                return Ok(BoundedLine::TooLong);
            }
            out.push_str(&String::from_utf8_lossy(&avail[..take]));
            reader.consume(take);
            return Ok(BoundedLine::Ok);
        }
        let len = avail.len();
        if total + len > max_bytes {
            reader.consume(len);
            return Ok(BoundedLine::TooLong);
        }
        out.push_str(&String::from_utf8_lossy(avail));
        total += len;
        reader.consume(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sni::tests::build_test_client_hello;

    #[test]
    fn proxy_blocks_disallowed_domain_and_ssrf_loopback() {
        let pol = EgressPolicy::default()
            .allow_domain("api.openai.com:443")
            .unwrap();
        let proxy = EgressProxy::start(pol).expect("start proxy");

        // 1. Disallowed domain -> 403 Forbidden (domain-denied)
        let mut c1 = TcpStream::connect(proxy.addr()).unwrap();
        c1.write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
            .unwrap();
        let mut resp1 = String::new();
        c1.read_to_string(&mut resp1).unwrap();
        assert!(resp1.contains("403 Forbidden"), "got: {resp1}");
        assert!(resp1.contains("domain-denied"), "got: {resp1}");

        // 2. Direct metadata IP -> 403 Forbidden (ip-denied)
        let mut c2 = TcpStream::connect(proxy.addr()).unwrap();
        c2.write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n")
            .unwrap();
        let mut resp2 = String::new();
        c2.read_to_string(&mut resp2).unwrap();
        assert!(resp2.contains("403 Forbidden"), "got: {resp2}");
        assert!(resp2.contains("ip-denied"), "got: {resp2}");

        proxy.stop();
    }

    #[test]
    fn proxy_enforces_tls_sni_match_on_allowed_tunnel() {
        // Start a dummy local echo server on 127.0.0.1:<port> and allow loopback ONLY for this test
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_handle = thread::spawn(move || {
            if let Ok((mut s, _)) = echo_listener.accept() {
                let mut buf = [0u8; 512];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            }
        });

        let pol = EgressPolicy::default()
            .block_private_ips(false)
            .allow_domain(&format!("localhost:{echo_port}"))
            .unwrap();
        let proxy = EgressProxy::start(pol).unwrap();

        let mut client = TcpStream::connect(proxy.addr()).unwrap();
        client
            .write_all(
                format!(
                    "CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

        let mut hdr_buf = [0u8; 64];
        let n = client.read(&mut hdr_buf).unwrap();
        assert!(
            String::from_utf8_lossy(&hdr_buf[..n]).contains("200 Connection Established")
        );

        let hello = build_test_client_hello("localhost");
        client.write_all(&hello).unwrap();
        let mut echoed = vec![0u8; hello.len()];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, hello);

        proxy.stop();
        let _ = echo_handle.join();
    }
}
