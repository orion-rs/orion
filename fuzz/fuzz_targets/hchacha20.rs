#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::stream::chacha20;

fuzz_target!(|data: &[u8]| {
	let (key, nonce) = chacha_key_nonce_setup(16, data);
	let orion_key = chacha20::SecretKey::from_slice(&key).unwrap();
	chacha20::hchacha20(&orion_key, &nonce).unwrap();
});
