//! Declarative L3/L4/L7 network egress policy with built-in SSRF protection.
//!
//! Supports:
//! - Domain allowlisting with exact (`api.openai.com`) and wildcard (`*.openai.com`) rules
//! - IPv4/IPv6 CIDR + optional port allowlisting (`203.0.113.10/32:443`)
//! - Default-on SSRF hard block (`127.0.0.0/8`, `169.254.0.0/16` cloud metadata,
//!   RFC1918 private LANs, CGNAT `100.64.0.0/10`, IPv6 `::1`, `fc00::/7`, `fe80::/10`,
//!   and IPv4-mapped IPv6 `::ffff:127.0.0.1`)

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An L3/L4 CIDR + optional port rule (e.g. `203.0.113.10/32:443` or `198.51.100.0/24`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRule {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub port: Option<u16>,
}

impl CidrRule {
    /// Parse `IP[/PREFIX][:PORT]` (supports IPv4 and bracketed `[IPv6]/PREFIX:PORT`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let s = spec.trim();
        if s.is_empty() {
            return Err("empty CIDR rule".into());
        }

        // Handle bracketed IPv6: `[2001:db8::/32]:443` or `[2001:db8::]:443`
        if let Some(rest) = s.strip_prefix('[') {
            let Some((inside, after)) = rest.split_once(']') else {
                return Err(format!("unclosed `[` in CIDR rule '{s}'"));
            };
            let port = if let Some(p) = after.strip_prefix(':') {
                Some(p.parse::<u16>().map_err(|_| format!("invalid port '{p}'"))?)
            } else if after.is_empty() {
                None
            } else {
                return Err(format!("unexpected trailing characters in '{s}'"));
            };
            let (ip_str, prefix) = match inside.split_once('/') {
                Some((ip, pre)) => (
                    ip,
                    pre.parse::<u8>()
                        .map_err(|_| format!("invalid prefix '{pre}'"))?,
                ),
                None => (inside, 128),
            };
            let v6: Ipv6Addr = ip_str
                .parse()
                .map_err(|_| format!("invalid IPv6 address '{ip_str}'"))?;
            if prefix > 128 {
                return Err(format!("IPv6 prefix length {prefix} > 128"));
            }
            return Ok(Self {
                network: IpAddr::V6(v6),
                prefix_len: prefix,
                port,
            });
        }

        // IPv4: `a.b.c.d`, `a.b.c.d/24`, `a.b.c.d:443`, `a.b.c.d/32:443`
        let (addr_part, port) = match s.rsplit_once(':') {
            Some((left, right)) if !left.contains(':') => {
                let p = right
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port '{right}' in '{s}'"))?;
                (left, Some(p))
            }
            _ => (s, None),
        };

        let (ip_str, prefix_opt) = match addr_part.split_once('/') {
            Some((ip, pre)) => (
                ip,
                Some(
                    pre.parse::<u8>()
                        .map_err(|_| format!("invalid prefix '{pre}' in '{s}'"))?,
                ),
            ),
            None => (addr_part, None),
        };

        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("invalid IP address '{ip_str}' in '{s}'"))?;
        let max_bits = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = prefix_opt.unwrap_or(max_bits);
        if prefix_len > max_bits {
            return Err(format!("prefix length {prefix_len} > {max_bits} in '{s}'"));
        }

        Ok(Self {
            network: ip,
            prefix_len,
            port,
        })
    }

    /// Returns `true` if `(ip, port)` matches this CIDR + port rule.
    pub fn matches(&self, ip: IpAddr, port: u16) -> bool {
        if let Some(req_port) = self.port
            && req_port != port
        {
            return false;
        }
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix_len);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

/// Domain allowlist pattern (`api.openai.com` or `*.openai.com`), optionally with `:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRule {
    pub pattern: String,
    pub port: Option<u16>,
}

impl DomainRule {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let s = spec.trim().to_ascii_lowercase();
        if s.is_empty() {
            return Err("empty domain rule".into());
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => {
                let port_num = p
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port '{p}' in domain rule '{s}'"))?;
                (h, Some(port_num))
            }
            None => (s.as_str(), None),
        };
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return Err(format!("invalid empty hostname in '{s}'"));
        }
        Ok(Self {
            pattern: host.to_string(),
            port,
        })
    }

    pub fn matches_domain(&self, host: &str, port: Option<u16>) -> bool {
        if let (Some(req), Some(actual)) = (self.port, port)
            && req != actual
        {
            return false;
        }
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = self.pattern.strip_prefix("*.") {
            // `*.openai.com` matches `api.openai.com` and `a.b.openai.com`, not `evilopenai.com`
            h.len() > suffix.len() + 1
                && h.ends_with(suffix)
                && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
        } else {
            h == self.pattern
        }
    }
}

/// Policy decision returned by `EgressPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny(&'static str),
}

impl EgressDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for EgressDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny(reason) => write!(f, "deny ({reason})"),
        }
    }
}

/// Declarative L3/L4/L7 network egress policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    pub allow_domains: Vec<DomainRule>,
    pub allow_cidrs: Vec<CidrRule>,
    /// Block loopback, link-local / cloud metadata (`169.254.169.254`), and RFC1918 LANs.
    pub block_private_ips: bool,
    /// Require TLS SNI to match the requested domain on port 443.
    pub verify_tls_sni: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            allow_cidrs: Vec::new(),
            block_private_ips: true,
            verify_tls_sni: true,
        }
    }
}

impl EgressPolicy {
    pub fn allow_domain(mut self, spec: &str) -> Result<Self, String> {
        self.allow_domains.push(DomainRule::parse(spec)?);
        Ok(self)
    }

    pub fn allow_cidr(mut self, spec: &str) -> Result<Self, String> {
        self.allow_cidrs.push(CidrRule::parse(spec)?);
        Ok(self)
    }

    pub fn block_private_ips(mut self, block: bool) -> Self {
        self.block_private_ips = block;
        self
    }

    /// Check if a DNS query or CONNECT request for `domain` (with optional `port`) is permitted.
    pub fn check_domain(&self, domain: &str, port: Option<u16>) -> EgressDecision {
        if self
            .allow_domains
            .iter()
            .any(|r| r.matches_domain(domain, port))
        {
            EgressDecision::Allow
        } else {
            EgressDecision::Deny("domain not in allowlist")
        }
    }

    /// Check if connecting to a resolved `(ip, port)` is permitted.
    ///
    /// When `validated_domain` is `Some`, the domain was already approved by `check_domain`,
    /// so we still enforce SSRF protection (`block_private_ips`) to prevent DNS rebinding!
    pub fn check_ip(
        &self,
        ip: IpAddr,
        port: u16,
        validated_domain: Option<&str>,
    ) -> EgressDecision {
        if self.block_private_ips && is_private_or_metadata(ip) {
            return EgressDecision::Deny("private/loopback/metadata IP blocked (SSRF guard)");
        }
        if validated_domain.is_some() {
            return EgressDecision::Allow;
        }
        if self.allow_cidrs.iter().any(|r| r.matches(ip, port)) {
            EgressDecision::Allow
        } else {
            EgressDecision::Deny("IP/port not in CIDR allowlist")
        }
    }
}

/// Returns `true` for loopback, cloud metadata (`169.254.0.0/16`), RFC1918 private LANs,
/// CGNAT (`100.64.0.0/10`), unspecified (`0.0.0.0/8`), IPv6 ULA/link-local, and
/// IPv4-mapped IPv6 addresses pointing to any of the above.
pub fn is_private_or_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_v4(mapped);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique Local Address (fc00::/7)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    v4.is_loopback()          // 127.0.0.0/8
        || v4.is_private()    // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254.0.0/16 (AWS/GCP/Azure metadata!)
        || v4.is_broadcast()
        || v4.is_multicast()
        || a == 0             // 0.0.0.0/8
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 (CGNAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_exact_and_wildcard_matching() {
        let pol = EgressPolicy::default()
            .allow_domain("api.openai.com:443")
            .unwrap()
            .allow_domain("*.pypi.org")
            .unwrap();

        assert!(pol.check_domain("api.openai.com", Some(443)).is_allowed());
        assert!(!pol.check_domain("api.openai.com", Some(80)).is_allowed());
        assert!(pol.check_domain("files.pypi.org", Some(443)).is_allowed());
        assert!(!pol.check_domain("evilpypi.org", Some(443)).is_allowed());
        assert!(!pol.check_domain("evil.com", Some(443)).is_allowed());
    }

    #[test]
    fn ssrf_blocks_metadata_loopback_and_ipv4_mapped_v6() {
        let pol = EgressPolicy::default()
            .allow_cidr("203.0.113.10/32:443")
            .unwrap();

        assert!(pol.check_ip("203.0.113.10".parse().unwrap(), 443, None).is_allowed());
        assert!(!pol.check_ip("203.0.113.10".parse().unwrap(), 80, None).is_allowed());

        // Even with a validated domain (DNS rebinding attack!), private/metadata IPs are blocked!
        assert!(!pol.check_ip("169.254.169.254".parse().unwrap(), 80, Some("api.openai.com")).is_allowed());
        assert!(!pol.check_ip("127.0.0.1".parse().unwrap(), 443, Some("api.openai.com")).is_allowed());
        assert!(!pol.check_ip("10.0.0.5".parse().unwrap(), 443, Some("api.openai.com")).is_allowed());
        assert!(!pol.check_ip("::ffff:169.254.169.254".parse().unwrap(), 80, Some("api.openai.com")).is_allowed());
    }
}
