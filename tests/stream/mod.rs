pub mod other_chacha20;
pub mod rfc_chacha20;
pub mod rfc_xchacha20;

extern crate orion;

use self::{
	chacha20::SecretKey,
	orion::hazardous::stream::{
		chacha20::{self, IETF_CHACHA_NONCESIZE},
		xchacha20::{self, XCHACHA_NONCESIZE},
	},
};
use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::test_framework::streamcipher_interface::StreamCipherTestRunner;

pub fn chacha_test_runner(
	key: &[u8],
	nonce: &[u8],
	init_block_count: u32,
	input: &[u8],
	output: &[u8],
) {
	if key.len() != CHACHA_KEYSIZE {
		assert!(SecretKey::from_slice(&key).is_err());
		return;
	}
	if input.is_empty() || output.is_empty() {
		return;
	}

	// Selecting variant based on nonce size
	if nonce.len() == IETF_CHACHA_NONCESIZE {
		let sk = SecretKey::from_slice(&key).unwrap();
		let n = chacha20::Nonce::from_slice(&nonce).unwrap();
		StreamCipherTestRunner(
			chacha20::encrypt,
			chacha20::decrypt,
			sk,
			n,
			init_block_count,
			input,
			Some(output),
		);
	} else if nonce.len() == XCHACHA_NONCESIZE {
		let sk = SecretKey::from_slice(&key).unwrap();
		let n = xchacha20::Nonce::from_slice(&nonce).unwrap();
		StreamCipherTestRunner(
			xchacha20::encrypt,
			xchacha20::decrypt,
			sk,
			n,
			init_block_count,
			input,
			Some(output),
		);
	} else {
		assert!(chacha20::Nonce::from_slice(&nonce).is_err());
		assert!(xchacha20::Nonce::from_slice(&nonce).is_err());
	}
}
