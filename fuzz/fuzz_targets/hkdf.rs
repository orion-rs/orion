#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::core::options::ShaVariantOption;
use orion::hazardous::hkdf::Hkdf;
use rand::prelude::*;

fn fuzz_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len_max: usize, hmac: ShaVariantOption) {
    let mut rng = rand::thread_rng();
    let okm_len_rand = rng.gen_range(1, len_max + 1);

    let dk = Hkdf {
        salt: salt.to_vec(),
        ikm: ikm.to_vec(),
        info: info.to_vec(),
        length: okm_len_rand,
        hmac,
    };

    let prk = dk.extract(ikm, salt);
    let dk_fin = dk.expand(&prk).unwrap();

    assert_eq!(dk_fin, dk.derive_key().unwrap());
    assert_eq!(dk.verify(&dk_fin).unwrap(), true);
}

fuzz_target!(|data: &[u8]| {
    fuzz_hkdf(data, data, data, 8160, ShaVariantOption::SHA256);

    fuzz_hkdf(data, data, data, 12240, ShaVariantOption::SHA384);

    fuzz_hkdf(data, data, data, 16320, ShaVariantOption::SHA512);

    fuzz_hkdf(data, data, data, 8160, ShaVariantOption::SHA512Trunc256);
});
