#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::hkdf;
use rand::prelude::*;

fn fuzz_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len_max: usize) {
    let mut rng = rand::thread_rng();
    let okm_len_rand = rng.gen_range(1, len_max + 1);

    let prk = hkdf::extract(ikm, salt);
    let mut dk_out = vec![0u8; okm_len_rand];
    hkdf::expand(&prk, info, &mut dk_out).unwrap();

    let exp_okm = dk_out.clone();
    assert!(hkdf::verify(&exp_okm, salt, ikm, info, &mut dk_out).unwrap());
}

fuzz_target!(|data: &[u8]| {
    fuzz_hkdf(data, data, data, 8160);

    fuzz_hkdf(data, data, data, 12240);

    fuzz_hkdf(data, data, data, 16320);

    fuzz_hkdf(data, data, data, 8160);
});
