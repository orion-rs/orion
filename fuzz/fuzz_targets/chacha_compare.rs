#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate chacha;
use orion::hazardous::chacha20;
use orion::utilities::util;
use chacha::{ChaCha, KeyStream};

fuzz_target!(|data: &[u8]| {
    // Random nonce and key
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    util::gen_rand_key(&mut key).unwrap();
    util::gen_rand_key(&mut nonce).unwrap();

    let mut pt = Vec::from(data);
    if data.is_empty() {
        pt.push(1u8);
    }

    // For orion
    let mut dst_pt = vec![0u8; pt.len()];
    let mut dst_ct = vec![0u8; pt.len()];

    // For chacha
    let mut buffer = pt.clone();

    // chacha crates uses 0 as inital counter
    // different structs because they don't reset counter
    let mut stream_enc = ChaCha::new_ietf(&key, &nonce);
    let mut stream_dec = ChaCha::new_ietf(&key, &nonce);
    // Encrypt pt
    stream_enc.xor_read(&mut buffer).expect("hit end of stream far too soon");
    let mut buffer_2 = buffer.clone();
    // Decrypt ct
    stream_dec.xor_read(&mut buffer_2).expect("hit end of stream far too soon");
    assert_eq!(pt, buffer_2);
    // chacha crates uses 0 as inital counter
    chacha20::encrypt(&key, &nonce, 0, &pt, &mut dst_ct).unwrap();
    assert_eq!(dst_ct, buffer);
    chacha20::decrypt(&key, &nonce, 0, &dst_ct, &mut dst_pt).unwrap();
    assert_eq!(&dst_pt, &pt);
    assert_eq!(dst_pt, buffer_2);
});
