pub mod custom_hkdf;
pub mod custom_pbkdf2;
pub mod other_hkdf;

extern crate orion;
use self::orion::hazardous::{kdf::hkdf::*, mac::hmac};

pub fn hkdf_test_runner(
	excp_prk: Option<&[u8]>,
	excp_okm: &[u8],
	salt: &[u8],
	ikm: &[u8],
	info: &[u8],
	okm_out: &mut [u8],
) -> bool {
	let actual_prk = extract(salt, &ikm).unwrap();

	if excp_prk.is_some() {
		assert!(actual_prk == hmac::Tag::from_slice(excp_prk.unwrap()).unwrap());
	}

	expand(&actual_prk, Some(&info), okm_out).unwrap();

	let mut okm_one_shot_dst = okm_out.to_vec();
	derive_key(salt, ikm, Some(&info), &mut okm_one_shot_dst).unwrap();

	((okm_out == excp_okm) == (okm_one_shot_dst == excp_okm))
}
