#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;
use orion::hazardous::chacha20;
use orion::utilities::util;
use rand::prelude::*;

fuzz_target!(|data: &[u8]| {

    // Random nonce and key
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    util::gen_rand_key(&mut key).unwrap();
    util::gen_rand_key(&mut nonce).unwrap();

    let mut rng = rand::thread_rng();
    if rng.gen() {
        // Random inital counter value
        let icount: u32 = rng.gen_range(0, 4097);

        let mut pt = Vec::from(data);
        if data.is_empty() {
            pt.push(1u8);
        }

        let mut dst_pt = vec![0u8; pt.len()];
        let mut dst_ct = vec![0u8; pt.len()];

        // Encrypt data
        chacha20::encrypt(&key, &nonce, icount, &pt, &mut dst_ct).unwrap();
        // Decrypt the ciphertext and verify it matches data
        chacha20::decrypt(&key, &nonce, icount, &dst_ct, &mut dst_pt).unwrap();
        assert_eq!(&dst_pt, &pt);
        // Obvios not equal on plaintext to decrypt input
        chacha20::decrypt(&key, &nonce, icount, &pt, &mut dst_pt).unwrap();
        assert_ne!(&dst_pt, &pt);
    }
});
