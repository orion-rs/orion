#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate crypto;
pub mod util;

use orion::hazardous::poly1305::*;
use orion::hazardous::constants::POLY1305_BLOCKSIZE;
use self::util::*;
use crypto::mac::Mac;

fuzz_target!(|data: &[u8]| {
    let mut key = [0u8; 32];
    apply_from_input_fixed(&mut key, &data, 0);

    let mut message = Vec::new();
    apply_from_input_heap(&mut message, data, key.len());

    // Test both stream and one-shot
    let mut poly1305_state = init(&key).unwrap();
    let mut orion_stream_tag = [0u8; 16];

    let mut crypto_poly1305_state = crypto::poly1305::Poly1305::new(&key);
    let mut crypto_stream_tag = [0u8; 16];

    for message_chunk in message.chunks(POLY1305_BLOCKSIZE) {
        if message_chunk.len() < POLY1305_BLOCKSIZE {
            orion_stream_tag.copy_from_slice(&poly1305_state.finalize(message_chunk).unwrap());
            crypto_poly1305_state.input(message_chunk);
            crypto_poly1305_state.raw_result(&mut crypto_stream_tag);
        } else {
            poly1305_state.update(message_chunk).unwrap();
            crypto_poly1305_state.input(message_chunk);
        }
    }

    let orion_oneshot_tag = poly1305(&key, &message).unwrap();

    assert_eq!(orion_stream_tag, orion_oneshot_tag);
    assert_eq!(orion_stream_tag, crypto_stream_tag);
});
