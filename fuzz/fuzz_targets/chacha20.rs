#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::chacha20;

fuzz_target!(|data: &[u8]| {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    apply_from_input_fixed(&mut key, &data, 0);
    apply_from_input_fixed(&mut nonce, &data, 32);

    let mut pt = Vec::new();
    apply_from_input_heap(&mut pt, data, key.len() + nonce.len());

    let icount = data.len() as u32;
    let mut dst_pt = vec![0u8; pt.len()];
    let mut dst_ct = vec![0u8; pt.len()];
    // Encrypt data
    chacha20::encrypt(&key, &nonce, icount, &pt, &mut dst_ct).unwrap();
    // Decrypt the ciphertext and verify it matches data
    chacha20::decrypt(&key, &nonce, icount, &dst_ct, &mut dst_pt).unwrap();
    assert_eq!(&dst_pt, &pt);
});
