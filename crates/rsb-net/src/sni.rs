//! Pure-Rust TLS 1.2 / 1.3 `ClientHello` SNI (Server Name Indication) parser.
//!
//! Extracts the target hostname from the first TCP payload of a TLS connection
//! without performing TLS termination or MITM decryption. Prevents DNS rebinding
//! and shared-CDN host spoofing when enforcing `--allow-domain`.

/// Maximum TLS ClientHello wire bytes we buffer across contiguous Handshake records.
pub const MAX_CLIENT_HELLO_BYTES: usize = 16_384 + 64;

/// If `buf` begins with a TLS Handshake record (`0x16`), return the total wire byte
/// length needed to cover the full `ClientHello` handshake message across one or more
/// contiguous `0x16` records (RFC 8446 multi-record `ClientHello`), once enough header
/// bytes have been buffered.
pub fn tls_record_expected_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let mut off = 0usize;
    let mut payload_len = 0usize;
    let mut hs_need: Option<usize> = None;
    let mut hs_hdr = [0u8; 4];
    let mut hs_hdr_len = 0usize;

    while off + 5 <= buf.len() && buf[off] == 0x16 {
        let rec_len = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if rec_len == 0 {
            // Invalid zero-length Handshake record; stop buffering so extract_tls_sni rejects it.
            return Some(off + 5);
        }
        let rec_start = off + 5;
        let rec_end = rec_start.saturating_add(rec_len);

        if hs_hdr_len < 4 && rec_start < buf.len() {
            let avail = (buf.len().min(rec_end)) - rec_start;
            let take = avail.min(4 - hs_hdr_len);
            hs_hdr[hs_hdr_len..hs_hdr_len + take]
                .copy_from_slice(&buf[rec_start..rec_start + take]);
            hs_hdr_len += take;
            if hs_hdr_len == 4 && hs_need.is_none() {
                if hs_hdr[0] != 0x01 {
                    return Some(rec_end.min(MAX_CLIENT_HELLO_BYTES));
                }
                let hs_len = ((hs_hdr[1] as usize) << 16)
                    | ((hs_hdr[2] as usize) << 8)
                    | (hs_hdr[3] as usize);
                hs_need = Some(4 + hs_len);
            }
        }

        if rec_end > buf.len() {
            return Some(rec_end.min(MAX_CLIENT_HELLO_BYTES));
        }

        payload_len = payload_len.saturating_add(rec_len);
        off = rec_end;

        if let Some(need) = hs_need
            && payload_len >= need
        {
            return Some(off);
        }
        if payload_len >= 16_384 || off >= MAX_CLIENT_HELLO_BYTES {
            return Some(off);
        }
    }

    if off < buf.len() && buf[off] != 0x16 {
        return Some(buf.len());
    }
    // Need at least the 5-byte header of the next contiguous Handshake record.
    Some(off.saturating_add(5).min(MAX_CLIENT_HELLO_BYTES))
}

/// Extract the TLS SNI hostname (extension type `0x0000`, `host_name` type `0x00`)
/// from one or more contiguous TLS Handshake (`0x16`) records beginning with a
/// `ClientHello` handshake message (supports RFC 8446 multi-record `ClientHello`).
///
/// Returns `Some(hostname)` if a valid SNI extension is found, or `None` if the
/// payload is not a TLS `ClientHello`, is truncated, contains duplicate SNI entries,
/// uses Encrypted Client Hello (`0xfe0d`), or has no SNI extension.
pub fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    // Reassemble contiguous TLS Handshake (0x16) records up to 16 KiB.
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let mut reassembled: Vec<u8> = Vec::new();
    let mut off = 0usize;
    while off + 5 <= buf.len() && buf[off] == 0x16 && reassembled.len() < 16_384 {
        let rec_len = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if rec_len == 0 {
            return None;
        }
        off += 5;
        let take = rec_len.min(buf.len() - off).min(16_384 - reassembled.len());
        reassembled.extend_from_slice(&buf[off..off + take]);
        off += take;
        if take < rec_len {
            break;
        }
    }
    let payload: &[u8] = &reassembled;

    // Handshake header: [msg_type: 1][length: 3]
    if payload.len() < 4 || payload[0] != 0x01 {
        // 0x01 = ClientHello
        return None;
    }
    let hs_len = ((payload[1] as usize) << 16)
        | ((payload[2] as usize) << 8)
        | (payload[3] as usize);
    // Reject truncated ClientHello messages so a trailing ECH (0xfe0d) or duplicate
    // SNI extension cannot be hidden past a record boundary.
    let body = payload.get(4..4 + hs_len)?;

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
    if pos + ext_total > body.len() {
        return None;
    }
    let ext_end = pos + ext_total;

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

    if pos != ext_end {
        return None;
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

        // Truncated ClientHello MUST be rejected (prevents hiding ECH / duplicate SNI in tail)
        assert_eq!(extract_tls_sni(&pkt[..pkt.len() - 1]), None);

        // Multi-record ClientHello split across 2 TLS Handshake (0x16) records
        let hs = &pkt[5..];
        let mid = hs.len() / 2;
        let mut multi = Vec::new();
        multi.push(0x16);
        multi.extend_from_slice(&[0x03, 0x01]);
        multi.extend_from_slice(&(mid as u16).to_be_bytes());
        multi.extend_from_slice(&hs[..mid]);
        let rec1_len = multi.len();
        multi.push(0x16);
        multi.extend_from_slice(&[0x03, 0x01]);
        multi.extend_from_slice(&((hs.len() - mid) as u16).to_be_bytes());
        multi.extend_from_slice(&hs[mid..]);

        // After only record 1, tls_record_expected_len demands more bytes
        assert!(tls_record_expected_len(&multi[..rec1_len]).unwrap() > rec1_len);
        // Once both records are present, expected length matches and SNI extracts cleanly
        assert_eq!(tls_record_expected_len(&multi), Some(multi.len()));
        assert_eq!(extract_tls_sni(&multi).as_deref(), Some("api.openai.com"));

        // Zero-length Handshake record MUST be rejected
        let mut zero_rec = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        zero_rec.extend_from_slice(&pkt);
        assert_eq!(extract_tls_sni(&zero_rec), None);
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
