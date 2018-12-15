#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
pub mod util;

use self::util::*;
use orion::hazardous::{
	kdf::{hkdf, pbkdf2},
	mac::hmac,
};
use ring::{
	digest,
	hkdf::extract_and_expand as ring_hkdf,
	hmac as ring_hmac,
	pbkdf2 as ring_pbkdf2,
};

fn ro_hmac(data: &[u8]) {
	let (secret_key, message) = hmac_setup(data);
	let orion_key = hmac::SecretKey::from_slice(&secret_key);
	let mut orion_hmac = hmac::init(&orion_key);
	orion_hmac.update(&message).unwrap();
	let orion_signature = orion_hmac.finalize().unwrap();

	let s_key = ring_hmac::SigningKey::new(&digest::SHA512, &secret_key);
	let ring_signature = ring_hmac::sign(&s_key, &message);
	let v_key = ring_hmac::VerificationKey::new(&digest::SHA512, &secret_key);

	assert!(hmac::verify(
		&hmac::Tag::from_slice(&ring_signature.as_ref()).unwrap(),
		&orion_key,
		&message
	)
	.unwrap());
	assert!(ring_hmac::verify(&v_key, &message, orion_signature.unprotected_as_bytes()).is_ok());
}

fn ro_hkdf(data: &[u8]) {
	let (ikm, salt, info, mut okm_out_orion) = hkdf_setup(data);
	let mut okm_out_ring = okm_out_orion.clone();
	hkdf::derive_key(&salt, &ikm, Some(&info), &mut okm_out_orion).unwrap();

	let s_key = ring_hmac::SigningKey::new(&digest::SHA512, &salt);
	ring_hkdf(&s_key, &ikm, &info, &mut okm_out_ring);

	assert_eq!(okm_out_orion, okm_out_ring);
}

fn ro_pbkdf2(data: &[u8]) {
	let (password, salt, mut dk_out_orion, iter) = pbkdf2_setup(data);
	let mut dk_out_ring = dk_out_orion.clone();
	let orion_password = pbkdf2::Password::from_slice(&password);

	pbkdf2::derive_key(&orion_password, &salt, iter, &mut dk_out_orion).unwrap();
	ring_pbkdf2::derive(
		&digest::SHA512,
		iter as u32,
		&salt,
		&password,
		&mut dk_out_ring,
	);

	assert_eq!(&dk_out_ring, &dk_out_orion);
	assert!(ring_pbkdf2::verify(
		&digest::SHA512,
		iter as u32,
		&salt,
		&password,
		&dk_out_orion
	)
	.is_ok());
	assert!(pbkdf2::verify(
		&dk_out_ring,
		&orion_password,
		&salt,
		iter,
		&mut dk_out_orion
	)
	.unwrap());
}

fuzz_target!(|data: &[u8]| {
	ro_hmac(data);
	ro_hkdf(data);
	ro_pbkdf2(data);
});
