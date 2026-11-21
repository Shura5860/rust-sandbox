//! Pure-Rust TLS 1.2 / 1.3 `ClientHello` SNI (Server Name Indication) parser.
//!
//! Extracts the target hostname from the first TCP payload of a TLS connection
//! without performing TLS termination or MITM decryption. Prevents DNS rebinding
//! and shared-CDN host spoofing when enforcing `--allow-domain`.

/// If `buf` begins with a TLS Handshake record (`0x16`), return its full expected
/// record length (`5 + record_len`) once at least 5 header bytes have been buffered.
pub fn tls_record_expected_len(buf: &[u8]) -> Option<usize> {
    if buf.len() >= 5 && buf[0] == 0x16 {
        Some(5 + u16::from_be_bytes([buf[3], buf[4]]) as usize)
    } else {
        None
    }
}

/// Extract the TLS SNI hostname (extension type `0x0000`, `host_name` type `0x00`)
/// from a raw TLS record beginning with a `ClientHello` handshake message.
///
/// Returns `Some(hostname)` if a valid SNI extension is found, or `None` if the
/// payload is not a TLS `ClientHello`, is truncated, or has no SNI extension.
pub fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: [content_type: 1][version: 2][length: 2]
    if buf.len() < 5 || buf[0] != 0x16 {
        // 0x16 = Handshake
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let payload = buf.get(5..5 + record_len).or_else(|| buf.get(5..))?;

    // Handshake header: [msg_type: 1][length: 3]
    if payload.len() < 4 || payload[0] != 0x01 {
        // 0x01 = ClientHello
        return None;
    }
    let hs_len = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | (payload[3] as usize);
    let body = payload.get(4..4 + hs_len).or_else(|| payload.get(4..))?;

    // ClientHello body:
    // - legacy_version (2 bytes)
    // - random (32 bytes)
    let mut pos = 2 + 32;
    if pos >= body.len() {
        return None;
    }

    // - legacy_session_id (1-byte length + bytes)
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;

    // - cipher_suites (2-byte length + bytes)
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;

    // - legacy_compression_methods (1-byte length + bytes)
    let comp_len = *body.get(pos)? as usize;
    pos += 1 + comp_len;

    // - extensions (2-byte total length + extension entries)
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());

    let mut found_sni: Option<String> = None;
    let mut saw_sni_ext = false;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return None;
        }
        // Reject Encrypted Client Hello (ECH, 0xfe0d) so an outer cover domain
        // cannot smuggle a blocked inner target domain on shared CDNs.
        if ext_type == 0xfe0d {
            return None;
        }
        if ext_type == 0x0000 {
            if saw_sni_ext {
                // RFC 8446 §4.2 forbids duplicate extensions (prevents SNI smuggling)
                return None;
            }
            saw_sni_ext = true;
            // server_name extension:
            // [list_len: 2][name_type: 1][name_len: 2][name_bytes...]
            let ext_data = &body[pos..pos + ext_len];
            if ext_data.len() < 5 {
                return None;
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + list_len != ext_data.len() {
                return None;
            }
            let list_end = 2 + list_len;
            let mut lpos = 2;
            while lpos + 3 <= list_end {
                let name_type = ext_data[lpos];
                let name_len = u16::from_be_bytes([ext_data[lpos + 1], ext_data[lpos + 2]]) as usize;
                lpos += 3;
                if lpos + name_len > list_end {
                    return None;
                }
                if name_type == 0x00 {
                    if found_sni.is_some() || name_len == 0 {
                        // Duplicate host_name entry or empty SNI -> reject
                        return None;
                    }
                    let s = core::str::from_utf8(&ext_data[lpos..lpos + name_len]).ok()?;
                    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
                        return None;
                    }
                    found_sni = Some(s.to_ascii_lowercase());
                }
                lpos += name_len;
            }
        }
        pos += ext_len;
    }

    found_sni
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Helper to build a minimal valid TLS 1.2/1.3 ClientHello with a given SNI.
    pub(crate) fn build_test_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        // ServerNameList: [list_len: 2][type=0: 1][name_len: 2][name]
        let list_len = (3 + sni_bytes.len()) as u16;
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        sni_ext.extend_from_slice(&(2 + list_len).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[0xAA; 32]);   // random
        body.push(0);                          // session_id len = 0
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1);
        body.push(0);                          // null compression
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xFF) as u8);
        hs.push(((hs_len >> 8) & 0xFF) as u8);
        hs.push((hs_len & 0xFF) as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let pkt = build_test_client_hello("API.OpenAI.com");
        assert_eq!(extract_tls_sni(&pkt).as_deref(), Some("api.openai.com"));
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn fuzz_tls_sni_parser_never_panics() {
        // Deterministic xorshift64 fuzzing: 20,000 truncated, mutated, and random TLS records
        let valid = build_test_client_hello("api.openai.com");
        for cut in 0..=valid.len() {
            let _ = extract_tls_sni(&valid[..cut]);
        }

        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_u8 = || -> u8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        };

        for iter in 0..20_000u32 {
            let mut buf = if iter % 2 == 0 {
                // Mutate a valid ClientHello
                let mut b = valid.clone();
                let idx = (next_u8() as usize) % b.len();
                b[idx] ^= next_u8();
                b
            } else {
                // Pure random bytes starting with TLS Handshake byte 0x16
                let len = (next_u8() as usize) % 160;
                let mut b = Vec::with_capacity(len);
                if len > 0 {
                    b.push(0x16);
                    for _ in 1..len {
                        b.push(next_u8());
                    }
                }
                b
            };
            if iter % 5 == 0 && !buf.is_empty() {
                buf.truncate((next_u8() as usize) % buf.len());
            }
            let _ = extract_tls_sni(&buf);
        }
    }
}
