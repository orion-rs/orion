#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::pbkdf2::Pbkdf2;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;


// Testing PBKDF2's function_f with focus on random index value
fn make_pbkdf2(ipad: &[u8],
                opad: &[u8], password: &[u8], salt: &[u8]) -> () {

    let mut rng = rand::thread_rng();

    let choices = [ShaVariantOption::SHA256, ShaVariantOption::SHA384, ShaVariantOption::SHA512];

    if rng.gen() {

        let len = rng.gen_range(1, 137438953441);
        let iter = rng.gen_range(1, 10001);

        let hmac_choice = rng.choose(&choices).unwrap();

        let dk = Pbkdf2 {
            password: password.to_vec(),
            salt: salt.to_vec(),
            iterations: iter,
            length: len,
            hmac: *hmac_choice
        };

        let index = rand::random::<u32>();

        dk.function_f(index, ipad, opad);
        let dk_def = dk.pbkdf2_compute().unwrap();
        assert_eq!(dk.pbkdf2_compare(&dk_def).unwrap(), true);
    }

}

fuzz_target!(|data: &[u8]| {
    make_pbkdf2(data, data, data, data);
});
