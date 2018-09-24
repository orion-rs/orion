#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;
pub mod util;

use orion::hazardous::pbkdf2;
use rand::prelude::*;
use self::util::*;

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

    let mut rng = rand::thread_rng();
    if rng.gen() {
        let iter: usize = rng.gen_range(1, 10001);

        pbkdf2::derive_key(&password, &salt, iter, &mut dk_out).unwrap();
        let exp_dk = dk_out.clone();
        assert!(pbkdf2::verify(&exp_dk, &password, &salt, iter, &mut dk_out).unwrap());
    }
});
