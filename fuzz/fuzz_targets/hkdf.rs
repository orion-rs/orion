#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use orion::hazardous::hkdf;
use self::util::*;

fuzz_target!(|data: &[u8]| {

    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut ikm = vec![0u8; input[0] as usize];
    let mut salt = Vec::new();
    let mut info = Vec::new();
    apply_from_input_fixed(&mut ikm, &input, 0);
    apply_from_input_heap(&mut salt, &input, ikm.len());
    apply_from_input_heap(&mut info, &input, ikm.len() + salt.len());

    // Max iteration count will be (255*63) + 1 = 16066
    let out_len = (input[0] as usize * 63) + 1;
    let mut okm_out = vec![0u8; out_len];

    hkdf::derive_key(&salt, &ikm, &info, &mut okm_out).unwrap();
    let exp_okm = okm_out.clone();
    assert!(hkdf::verify(&exp_okm, &salt, &ikm, &info, &mut okm_out).unwrap());
});
