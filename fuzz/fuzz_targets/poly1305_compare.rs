#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate crypto;
extern crate orion;
extern crate ring;
pub mod util;

use self::util::*;
use crypto::mac::Mac;
use orion::hazardous::mac::poly1305::*;

fuzz_target!(|data: &[u8]| {
    let (key, message) = poly1305_setup(data);
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
