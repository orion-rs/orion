pub mod nist_cavp_hmac;
pub mod other_poly1305;
pub mod rfc_hmac;
pub mod rfc_poly1305;

extern crate orion;

use self::{
	orion::{
		errors::UnknownCryptoError,
		hazardous::mac::{hmac, poly1305},
	},
	poly1305::{OneTimeKey, Tag},
};

fn hmac_test_runner(
	secret_key: &[u8],
	data: &[u8],
	expected: &[u8],
	trunc: Option<usize>,
) -> Result<(), UnknownCryptoError> {
	let key = hmac::SecretKey::from_slice(secret_key).unwrap();
	let mut mac = hmac::init(&key);
	mac.update(data).unwrap();

	let res = mac.finalize().unwrap();
	let len = match trunc {
		Some(ref length) => *length,
		None => 64,
	};

	let one_shot = hmac::hmac(&key, data).unwrap();

	assert_eq!(
		res.unprotected_as_bytes()[..len].as_ref(),
		expected[..len].as_ref()
	);
	assert_eq!(
		one_shot.unprotected_as_bytes()[..len].as_ref(),
		expected[..len].as_ref()
	);
	// If the MACs are modified, then they should not be equal to the expected
	let mut bad_res = res.unprotected_as_bytes()[..len].to_vec();
	bad_res[0] ^= 1;
	assert_ne!(&bad_res[..len], expected);

	Ok(())
}

fn poly1305_test_runner(key: &[u8], input: &[u8], output: &[u8]) -> Result<(), UnknownCryptoError> {
	let mut state = poly1305::init(&OneTimeKey::from_slice(key).unwrap());
	state.update(input).unwrap();

	let tag_stream = state.finalize().unwrap();
	let tag_one_shot = poly1305::poly1305(&OneTimeKey::from_slice(key).unwrap(), input).unwrap();

	assert!(tag_stream == Tag::from_slice(&output).unwrap());
	assert!(tag_one_shot == Tag::from_slice(&output).unwrap());
	assert!(poly1305::verify(
		&Tag::from_slice(&output).unwrap(),
		&OneTimeKey::from_slice(key).unwrap(),
		input
	)
	.is_ok());

	// If the MACs are modified, then they should not be equal to the expected
	let mut bad_tag = tag_stream.unprotected_as_bytes().to_vec();
	bad_tag[0] ^= 1;
	assert!(Tag::from_slice(&bad_tag).unwrap() != Tag::from_slice(&output).unwrap());
	assert!(poly1305::verify(
		&Tag::from_slice(&bad_tag).unwrap(),
		&OneTimeKey::from_slice(key).unwrap(),
		input
	)
	.is_err());

	Ok(())
}
