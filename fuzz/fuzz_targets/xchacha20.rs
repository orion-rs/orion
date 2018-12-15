#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::stream::xchacha20;

fuzz_target!(|data: &[u8]| {
	let (key, nonce) = chacha_key_nonce_setup(24, data);
	let mut pt = Vec::new();
	apply_from_input_heap(&mut pt, data, key.len() + nonce.len());

	let orion_key = xchacha20::SecretKey::from_slice(&key).unwrap();
	let orion_nonce = xchacha20::Nonce::from_slice(&nonce).unwrap();

	let icount = data.len() as u32;
	let mut dst_pt = vec![0u8; pt.len()];
	let mut dst_ct = vec![0u8; pt.len()];
	// Encrypt data
	xchacha20::encrypt(&orion_key, &orion_nonce, icount, &pt, &mut dst_ct).unwrap();
	// Decrypt the ciphertext and verify it matches data
	xchacha20::decrypt(&orion_key, &orion_nonce, icount, &dst_ct, &mut dst_pt).unwrap();
	assert_eq!(&dst_pt, &pt);
});
