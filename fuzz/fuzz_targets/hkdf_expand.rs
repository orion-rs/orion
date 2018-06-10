#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hkdf::Hkdf;
use orion::core::options::ShaVariantOption;
use rand::prelude::*;


fn make_hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> Vec<u8> {

    let mut rng = thread_rng();

    let len = rng.gen_range(0, 8160);

    let mut prk = Vec::new();

    if rng.gen() {

        let len = rng.gen_range(0, 8160);
        let dk = Hkdf {
            salt: salt.to_vec(),
            ikm: ikm.to_vec(),
            info: info.to_vec(),
            hmac: ShaVariantOption::SHA256,
            length: len,
        };

        let prk = dk.hkdf_extract(ikm, salt);

        dk.hkdf_expand(&prk).unwrap()
    } else  { prk }

}

fuzz_target!(|data: &[u8]| {
    make_hkdf(&data, &data, &data);
});
