#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate chacha;
extern crate orion;
pub mod util;

use self::util::*;
use chacha::{ChaCha, KeyStream};
use orion::hazardous::stream::chacha20;

fuzz_target!(|data: &[u8]| {
	let (key, nonce) = chacha_key_nonce_setup(12, data);
	// chacha crate does not allow slices of unkown length to be passed
	let mut fixed_nonce = [0u8; 12];
	fixed_nonce.copy_from_slice(&nonce[..]);

	let mut pt = Vec::new();
	apply_from_input_heap(&mut pt, data, key.len() + nonce.len());

	let mut chacha_ct = pt.clone();
	// Different structs because they don't reset counter
	let mut stream_enc = ChaCha::new_ietf(&key, &fixed_nonce);
	let mut stream_dec = ChaCha::new_ietf(&key, &fixed_nonce);

	stream_enc
		.xor_read(&mut chacha_ct)
		.expect("hit end of stream far too soon");
	let mut chacha_pt = chacha_ct.clone();
	stream_dec
		.xor_read(&mut chacha_pt)
		.expect("hit end of stream far too soon");

	// chacha crates uses 0 as inital counter
	let mut orion_pt = vec![0u8; pt.len()];
	let mut orion_ct = vec![0u8; pt.len()];

	let orion_key = chacha20::SecretKey::from_slice(&key).unwrap();
	let orion_nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

	chacha20::encrypt(&orion_key, &orion_nonce, 0, &pt, &mut orion_ct).unwrap();
	chacha20::decrypt(&orion_key, &orion_nonce, 0, &orion_ct, &mut orion_pt).unwrap();

	assert_eq!(pt, chacha_pt);
	assert_eq!(orion_ct, chacha_ct);
	assert_eq!(orion_pt, chacha_pt);
});
