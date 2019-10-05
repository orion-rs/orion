pub mod nist_cavp_hmac;
pub mod other_poly1305;
pub mod rfc_hmac;
pub mod rfc_poly1305;

extern crate orion;

use self::{
	orion::hazardous::mac::{hmac, poly1305},
	poly1305::{OneTimeKey, Tag},
};

fn hmac_test_runner(secret_key: &[u8], data: &[u8], expected: &[u8], trunc: Option<usize>) {
	let key = hmac::SecretKey::from_slice(secret_key).unwrap();
	let mut mac = hmac::Hmac::new(&key);
	mac.update(data).unwrap();

	let res = mac.finalize().unwrap();
	let len = match trunc {
		Some(length) => length,
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
}

fn poly1305_test_runner(key: &[u8], input: &[u8], output: &[u8]) {
	let sk = OneTimeKey::from_slice(key).unwrap();

	let mut state = poly1305::Poly1305::new(&sk);
	state.update(input).unwrap();
	let tag_stream = state.finalize().unwrap();

	let tag_one_shot = poly1305::poly1305(&sk, input).unwrap();

	assert!(tag_stream == output);
	assert!(tag_one_shot == output);
	assert!(poly1305::verify(&Tag::from_slice(&output).unwrap(), &sk, input).unwrap());
}
