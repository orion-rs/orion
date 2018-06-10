#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::pbkdf2::Pbkdf2;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;


// Testing PBKDF2's function_f with focus on random index value
fn make_pbkdf2(ipad: &[u8],
                opad: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {

    let mut rng = rand::thread_rng();

    let len = rng.gen_range(1, 137438953440);

    let dk = Pbkdf2 {
        password: password.to_vec(),
        salt: salt.to_vec(),
        iterations: 0,
        length: len,
        hmac: ShaVariantOption::SHA256
    };

    let index = rand::random::<u32>();

    dk.function_f(index, ipad, opad)
}

fuzz_target!(|data: &[u8]| {
    make_pbkdf2(data, data, data, data);
});
