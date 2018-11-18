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

    let (key, message) = poly1305_setup(data);
    let orion_key = OneTimeKey::from_slice(&key).unwrap();

    let mut poly1305_state = init(&orion_key).unwrap();
    poly1305_state.update(&message).unwrap();
    let orion_stream_tag = poly1305_state.finalize().unwrap();

    let sodium_poly1305_key = sodiumoxide::crypto::onetimeauth::Key::from_slice(&key).unwrap();
    let sodium_tag = poly1305::authenticate(&message, &sodium_poly1305_key);

    assert_eq!(orion_stream_tag.unprotected_as_bytes(), sodium_tag.as_ref());
    // Let orion verify sodiumoxide tag
    assert!(verify(
        &Tag::from_slice(sodium_tag.as_ref()).unwrap(),
        &orion_key,
        &message
    )
    .unwrap());
    // Let sodiumoxide verify orion tag
    assert!(poly1305::verify(
        &sodium_tag,
        &message,
        &sodium_poly1305_key
    ));
});
