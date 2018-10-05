#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate crypto;
extern crate orion;
extern crate ring;
pub mod util;

use self::util::*;
use crypto::mac::Mac;
use orion::hazardous::poly1305::*;

fuzz_target!(|data: &[u8]| {
    let mut key = [0u8; 32];
    apply_from_input_fixed(&mut key, &data, 0);

    let mut message = Vec::new();
    apply_from_input_heap(&mut message, data, key.len());

    // Test both stream and one-shot
    let mut poly1305_state = init(&key).unwrap();
    poly1305_state.update(&message).unwrap();
    let orion_stream_tag = poly1305_state.finalize().unwrap();

    let mut crypto_poly1305_state = crypto::poly1305::Poly1305::new(&key);
    crypto_poly1305_state.input(&message);
    let mut crypto_stream_tag = [0u8; 16];
    crypto_poly1305_state.raw_result(&mut crypto_stream_tag);

    assert_eq!(orion_stream_tag, crypto_stream_tag);
    assert!(verify(&crypto_stream_tag, &key, &message).unwrap());
});
