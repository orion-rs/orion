#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::stream::chacha20;

fuzz_target!(|data: &[u8]| {
    let (key, nonce) = chacha_key_nonce_setup(16, data);
    chacha20::hchacha20(&key, &nonce).unwrap();
});
