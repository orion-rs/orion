pub mod other_chacha20;
pub mod other_hchacha20;
pub mod rfc_chacha20;
pub mod rfc_xchacha20;

extern crate hex;
extern crate orion;

use self::{
	chacha20::SecretKey,
	hex::decode,
	orion::hazardous::stream::{
		chacha20::{self, IETF_CHACHA_NONCESIZE},
		xchacha20::{self, XCHACHA_NONCESIZE},
	},
};

pub fn chacha_test_runner(
	key: &[u8],
	nonce: &[u8],
	init_block_count: u32,
	pt: &mut [u8],
	ct: &mut [u8],
) {
	let original_pt = pt.to_vec();
	let original_ct = ct.to_vec();

	// Selecting variant based on nonce size
	if nonce.len() == IETF_CHACHA_NONCESIZE {
		chacha20::encrypt(
			&SecretKey::from_slice(&key).unwrap(),
			&chacha20::Nonce::from_slice(&nonce).unwrap(),
			init_block_count,
			&original_pt,
			ct,
		)
		.unwrap();
		chacha20::decrypt(
			&SecretKey::from_slice(&key).unwrap(),
			&chacha20::Nonce::from_slice(&nonce).unwrap(),
			init_block_count,
			&original_ct,
			pt,
		)
		.unwrap();
	}
	if nonce.len() == XCHACHA_NONCESIZE {
		xchacha20::encrypt(
			&SecretKey::from_slice(&key).unwrap(),
			&xchacha20::Nonce::from_slice(&nonce).unwrap(),
			init_block_count,
			&original_pt,
			ct,
		)
		.unwrap();
		xchacha20::decrypt(
			&SecretKey::from_slice(&key).unwrap(),
			&xchacha20::Nonce::from_slice(&nonce).unwrap(),
			init_block_count,
			&original_ct,
			pt,
		)
		.unwrap();
	}

	assert!(&original_pt == &pt);
	assert!(&original_ct == &ct);
}

pub fn hchacha_test_runner(key: &str, nonce: &str, output_expected: &str) {
	let actual: [u8; 32] = chacha20::hchacha20(
		&SecretKey::from_slice(&decode(key).unwrap()).unwrap(),
		&decode(nonce).unwrap(),
	)
	.unwrap();

	assert_eq!(&actual, &decode(output_expected).unwrap()[..]);
}
