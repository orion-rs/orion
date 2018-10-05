#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::pbkdf2;

fuzz_target!(|data: &[u8]| {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut password = vec![0u8; input[0] as usize];
    let mut salt = Vec::new();
    apply_from_input_fixed(&mut password, &input, 0);
    apply_from_input_heap(&mut salt, &input, password.len());

    let mut dk_out = vec![0u8; input.len()];
    // Max iteration count will be (255*40) + 1 = 10201
    let iter = (input[0] as usize * 40) + 1;

    pbkdf2::derive_key(&password, &salt, iter, &mut dk_out).unwrap();
    let exp_dk = dk_out.clone();
    assert!(pbkdf2::verify(&exp_dk, &password, &salt, iter, &mut dk_out).unwrap());
});
