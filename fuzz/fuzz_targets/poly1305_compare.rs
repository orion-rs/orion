#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate sodiumoxide;
pub mod util;

use self::util::*;
use orion::hazardous::mac::poly1305::*;
use sodiumoxide::crypto::onetimeauth::poly1305;

fuzz_target!(|data: &[u8]| {
	sodiumoxide::init().unwrap();

	let orion_key = OneTimeKey::from_slice(&[0u8; 32]).unwrap();

	let mut poly1305_state = init(&orion_key);
	poly1305_state.update(&data).unwrap();

	let mut other_data: Vec<u8> = Vec::new();
	other_data.extend_from_slice(data);

	if data.len() > 32 {
		poly1305_state.update(b"").unwrap();
		other_data.extend_from_slice(b"");
	}
	if data.len() > 48 {
		poly1305_state.update(b"Extra").unwrap();
		other_data.extend_from_slice(b"Extra");
	}
	if data.len() > 64 {
		poly1305_state.update(&[0u8; 256]).unwrap();
		other_data.extend_from_slice(&[0u8; 256]);
	}

	let orion_one_shot = poly1305(&orion_key, &other_data).unwrap();
	let orion_stream_tag = poly1305_state.finalize().unwrap();
	let sodium_poly1305_key = sodiumoxide::crypto::onetimeauth::Key::from_slice(&[0u8; 32]).unwrap();
	let sodium_tag = poly1305::authenticate(&other_data, &sodium_poly1305_key);

	assert_eq!(orion_stream_tag.unprotected_as_bytes(), orion_one_shot.unprotected_as_bytes());
	assert_eq!(orion_stream_tag.unprotected_as_bytes(), sodium_tag.as_ref());
	// Let orion verify sodiumoxide tag
	assert!(verify(
		&Tag::from_slice(sodium_tag.as_ref()).unwrap(),
		&orion_key,
		&other_data
	)
	.unwrap());
	// Let sodiumoxide verify orion tag
	assert!(poly1305::verify(
		&sodium_tag,
		&other_data,
		&sodium_poly1305_key
	));
});
