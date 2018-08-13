#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::pbkdf2;
use rand::prelude::*;

fn fuzz_pbkdf2(password: &[u8], salt: &[u8]) {
    let mut rng = rand::thread_rng();

    if rng.gen() {
        let iter: usize = rng.gen_range(1, 10001);
        let len: usize = rng.gen_range(1, 1025);

        let mut dk_out = vec![0u8; len];

        pbkdf2::derive_key(password, salt, iter, &mut dk_out).unwrap();

        let exp_dk = dk_out.clone();

        assert!(pbkdf2::verify(&exp_dk, password, salt, iter, &mut dk_out).unwrap());
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_pbkdf2(data, data);
});
