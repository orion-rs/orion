#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::pbkdf2::Pbkdf2;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;

fn fuzz_pbkdf2(password: &[u8], salt: &[u8], hmac: ShaVariantOption) {

    let mut rng = rand::thread_rng();

    if rng.gen() {

        let iter: usize = rng.gen_range(1, 10001);
        let len: usize = rng.gen_range(1, 1025);

        let dk = Pbkdf2 {
            password: password.to_vec(),
            salt: salt.to_vec(),
            iterations: iter,
            dklen: len,
            hmac
        };

        assert_eq!(dk.verify(&dk.derive_key().unwrap()).unwrap(), true);

    }
}

fuzz_target!(|data: &[u8]| {

    fuzz_pbkdf2(data, data, ShaVariantOption::SHA256);

    fuzz_pbkdf2(data, data, ShaVariantOption::SHA384);

    fuzz_pbkdf2(data, data, ShaVariantOption::SHA512);

    fuzz_pbkdf2(data, data, ShaVariantOption::SHA512Trunc256);

});
