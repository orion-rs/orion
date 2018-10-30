#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate chacha;
extern crate orion;
pub mod util;

use self::util::*;
use chacha::{ChaCha, KeyStream};
use orion::hazardous::chacha20;

fuzz_target!(|data: &[u8]| {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    apply_from_input_fixed(&mut key, &data, 0);
    apply_from_input_fixed(&mut nonce, &data, 32);

    let mut pt = Vec::new();
    apply_from_input_heap(&mut pt, data, key.len() + nonce.len());

    // For orion
    let mut dst_pt = vec![0u8; pt.len()];
    let mut dst_ct = vec![0u8; pt.len()];

    // For chacha
    let mut buffer = pt.clone();
    // Different structs because they don't reset counter
    let mut stream_enc = ChaCha::new_ietf(&key, &nonce);
    let mut stream_dec = ChaCha::new_ietf(&key, &nonce);
    // Encrypt pt
    stream_enc
        .xor_read(&mut buffer)
        .expect("hit end of stream far too soon");
    let mut buffer_2 = buffer.clone();
    // Decrypt ct
    stream_dec
        .xor_read(&mut buffer_2)
        .expect("hit end of stream far too soon");
    assert_eq!(pt, buffer_2);

    // chacha crates uses 0 as inital counter
    chacha20::encrypt(&key, &nonce, 0, &pt, &mut dst_ct).unwrap();
    assert_eq!(dst_ct, buffer);
    chacha20::decrypt(&key, &nonce, 0, &dst_ct, &mut dst_pt).unwrap();
    assert_eq!(&dst_pt, &pt);
});
