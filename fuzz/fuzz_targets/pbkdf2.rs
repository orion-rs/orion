#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::pbkdf2::Pbkdf2;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;


// Testing PBKDF2's function_f with focus on random index value
fn make_pbkdf2(password: &[u8], salt: &[u8]) -> () {

    let mut rng = rand::thread_rng();

    let choices = [ShaVariantOption::SHA256, ShaVariantOption::SHA384, ShaVariantOption::SHA512];

    if rng.gen() {

        let iter: usize = rng.gen_range(1, 10001);
        let hmac_choice = rng.choose(&choices).unwrap();
        let len: usize = rng.gen_range(1, 128);

        let dk = Pbkdf2 {
            password: password.to_vec(),
            salt: salt.to_vec(),
            iterations: iter,
            dklen: len,
            hmac: *hmac_choice
        };

        assert_eq!(dk.verify(&dk.derive_key().unwrap()).unwrap(), true);
    } else { () }

}

fuzz_target!(|data: &[u8]| {
    make_pbkdf2(data, data);
});
