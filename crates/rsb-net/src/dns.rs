//! Minimal pure-Rust RFC 1035 DNS wire-format parser and `REFUSED` response builder.
//!
//! Used by the rootless egress filter to inspect UDP/53 queries inside the sandbox,
//! block disallowed domains before any upstream lookup happens, and track allowed
//! domain lookups.

/// Parsed DNS query header and first question (`QNAME`, `QTYPE`, `QCLASS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub tx_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
}

/// Parse a standard RFC 1035 DNS query packet (UDP/53).
pub fn parse_dns_query(pkt: &[u8]) -> Option<DnsQuery> {
    if pkt.len() < 12 {
        return None;
    }
    let tx_id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    // Must be a standard query (QR == 0, OPCODE == 0) with exactly 1 question
    if (flags & 0xF800) != 0 || qdcount != 1 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    while pos < pkt.len() {
        let len = pkt[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // Reject pointer compression in queries (malformed/ambiguous) and RFC 1035 >255B QNAME
        if (len & 0xC0) != 0 || pos + len > pkt.len() || (pos + len - 12) > 255 {
            return None;
        }
        let label = core::str::from_utf8(&pkt[pos..pos + len]).ok()?;
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }

    if pos + 4 > pkt.len() || labels.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    let question_end = pos + 4;

    Some(DnsQuery {
        tx_id,
        qname: labels.join("."),
        qtype,
        qclass,
        question_end,
    })
}

/// Build a valid RFC 1035 `REFUSED` (`RCODE = 5`) DNS response echoing the original question.
pub fn build_dns_refused(original_query: &[u8], parsed: &DnsQuery) -> Vec<u8> {
    let qslice = original_query
        .get(12..parsed.question_end)
        .unwrap_or(&[]);
    let mut resp = Vec::with_capacity(12 + qslice.len());
    resp.extend_from_slice(&parsed.tx_id.to_be_bytes());
    // QR=1 (response), RD=copied, RA=1, RCODE=5 (REFUSED)
    let rd = original_query.get(2).copied().unwrap_or(0) & 0x01;
    resp.push(0x80 | rd);
    resp.push(0x85);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(qslice);
    resp
}

/// Build a valid RFC 1035 `NOERROR` DNS `A` record response for the given IPv4 addresses,
/// staying within the 512-byte classic UDP DNS packet limit (setting `TC` if truncated).
pub fn build_dns_a_response(
    original_query: &[u8],
    parsed: &DnsQuery,
    ips: &[std::net::Ipv4Addr],
) -> Vec<u8> {
    let qslice = original_query
        .get(12..parsed.question_end)
        .unwrap_or(&[]);
    let base_len = 12 + qslice.len();
    let max_answers = 512usize.saturating_sub(base_len) / 16;
    let take = ips.len().min(max_answers);
    let tc_bit = if take < ips.len() { 0x02 } else { 0x00 };

    let mut resp = Vec::with_capacity(base_len + take * 16);
    resp.extend_from_slice(&parsed.tx_id.to_be_bytes());
    let rd = original_query.get(2).copied().unwrap_or(0) & 0x01;
    resp.push(0x80 | tc_bit | rd); // QR=1, optional TC, RD copied
    resp.push(0x80);               // RA=1, RCODE=0 (NOERROR)
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&(take as u16).to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(qslice);

    for ip in &ips[..take] {
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12 (QNAME)
        resp.extend_from_slice(&1u16.to_be_bytes());  // TYPE = A
        resp.extend_from_slice(&1u16.to_be_bytes());  // CLASS = IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
        resp.extend_from_slice(&4u16.to_be_bytes());  // RDLENGTH = 4
        resp.extend_from_slice(&ip.octets());
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_query_and_builds_refused_response() {
        // Query for "api.openai.com" type A (1), class IN (1)
        let mut pkt = vec![
            0x12, 0x34, // tx_id
            0x01, 0x00, // standard query, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.push(3);
        pkt.extend_from_slice(b"api");
        pkt.push(6);
        pkt.extend_from_slice(b"openai");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

        let q = parse_dns_query(&pkt).expect("parse dns query");
        assert_eq!(q.tx_id, 0x1234);
        assert_eq!(q.qname, "api.openai.com");
        assert_eq!(q.qtype, 1);

        let refused = build_dns_refused(&pkt, &q);
        assert_eq!(&refused[0..2], &[0x12, 0x34]);
        assert_eq!(refused[2] & 0x80, 0x80); // QR=1
        assert_eq!(refused[3] & 0x0F, 5);    // RCODE=REFUSED
    }

    #[test]
    fn fuzz_dns_parser_never_panics() {
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next_u8 = || -> u8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        };

        for _ in 0..20_000u32 {
            let len = (next_u8() as usize) % 128;
            let mut pkt = Vec::with_capacity(len);
            for _ in 0..len {
                pkt.push(next_u8());
            }
            if let Some(q) = parse_dns_query(&pkt) {
                let _ = build_dns_refused(&pkt, &q);
                let _ = build_dns_a_response(&pkt, &q, &[std::net::Ipv4Addr::new(1, 2, 3, 4)]);
            }
        }
    }
}
