#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rsb_net::sni::tls_record_expected_len(data);
    let _ = rsb_net::sni::extract_tls_sni(data);
});
