#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::core::util;
use orion::default;
use rand::Rng;

fn test_def(data: &[u8]) -> () {

    let rand_salt = util::gen_rand_key(64).unwrap();
    let mut rng = rand::thread_rng();

    if rng.gen() {

        let len_hkdf: usize = rng.gen_range(1, 16321);
        let len_pbkdf2: usize = rng.gen_range(14, 128);

        default::hkdf_verify(&
            default::hkdf(&rand_salt, data, data, len_hkdf).unwrap(),
            &rand_salt, &data, data, len_hkdf)
            .unwrap();

        default::hmac_verify(&default::hmac(&rand_salt, data).unwrap(),
            &rand_salt, data)
            .unwrap();

        default::pbkdf2_verify(&default::pbkdf2(data, &rand_salt, len_pbkdf2).unwrap(),
            data, &rand_salt, len_pbkdf2)
            .unwrap();
    }
}


fuzz_target!(|data: &[u8]| {
    test_def(data);
});
