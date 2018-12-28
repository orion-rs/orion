#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;

fuzz_target!(|data: &[u8]| {
	let mut key = [0u8; 32];
	let mut salt = vec![0u8; 1];
	apply_from_input_fixed(&mut key, data, 32);
	apply_from_input_heap(&mut salt, data, key.len());

	// orion::aead
	let aead_key = orion::aead::SecretKey::from_slice(&key).unwrap();
	// Plaintext for `seal` cannot be empty
	let mut plaintext = data.to_vec();
	if data.is_empty() {
		plaintext.push(0u8);
	}
	let aead_ciphertext = orion::aead::seal(&aead_key, &plaintext).unwrap();
	let aead_decrypted = orion::aead::open(&aead_key, &aead_ciphertext).unwrap();
	assert_eq!(&plaintext, &aead_decrypted);

	// orion::auth
	let auth_key = orion::auth::SecretKey::from_slice(&key).unwrap();
	let tag = orion::auth::authenticate(&auth_key, &data).unwrap();
	let res = orion::auth::authenticate_verify(&tag, &auth_key, &data).unwrap();
	assert!(res);

	// orion::pwhash
	// TODO: Don't test pwhash_password with the same value as salt
	let pwhash_password = orion::pwhash::Password::from_slice(&salt).unwrap();
	let c = if data.is_empty() {
		10000
	} else {
		((data[0] as usize) * 100) + 1 // +1 to avoid 0 if [0] is zero
	};

	let password_hash = orion::pwhash::hash_password(&pwhash_password, c).unwrap();
	assert!(orion::pwhash::hash_password_verify(&password_hash, &pwhash_password, c).unwrap());

	// orion::kdf
	let kdf_salt = orion::kdf::Salt::from_slice(&salt).unwrap();
	// TODO: Only fuzzed against a derived key length of 256
	let derived_key = orion::kdf::derive_key(&pwhash_password, &kdf_salt, c, 256).unwrap();
	assert!(orion::kdf::derive_key_verify(&derived_key, &pwhash_password, &kdf_salt, c).unwrap());

	// orion::hash
	let _hash = orion::hash::digest(&data).unwrap();
});
