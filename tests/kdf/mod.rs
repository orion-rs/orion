pub mod custom_hkdf;
pub mod custom_pbkdf2;
pub mod other_hkdf;
pub mod wycheproof_hkdf;

extern crate orion;
use self::orion::hazardous::{kdf::hkdf::*, mac::hmac};

pub fn hkdf_test_runner(
	expected_prk: Option<&[u8]>,
	expected_okm: &[u8],
	salt: &[u8],
	ikm: &[u8],
	info: &[u8],
	okm_len: usize,
	valid_result: bool,
) {
	if expected_prk.is_some() {
		let actual_prk = extract(salt, &ikm).unwrap();
		assert!(actual_prk == hmac::Tag::from_slice(expected_prk.unwrap()).unwrap());
	}

	let mut okm_out = vec![0u8; okm_len];

	// verify() also runs derive_key()
	if valid_result {
		assert!(verify(expected_okm, salt, ikm, Some(&info), &mut okm_out).is_ok());
	} else {
		assert!(verify(expected_okm, salt, ikm, Some(&info), &mut okm_out).is_err());
	}
}