#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(q) = rsb_net::dns::parse_dns_query(data) {
        let _ = rsb_net::dns::build_dns_refused(data, &q);
        let _ = rsb_net::dns::build_dns_a_response(data, &q, &[std::net::Ipv4Addr::new(1, 1, 1, 1)]);
    }
});
