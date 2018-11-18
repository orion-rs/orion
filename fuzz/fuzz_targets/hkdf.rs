#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::kdf::hkdf;

fuzz_target!(|data: &[u8]| {
    let (ikm, salt, info, mut okm_out) = hkdf_setup(data);
    hkdf::derive_key(&salt, &ikm, Some(&info), &mut okm_out).unwrap();
    let exp_okm = okm_out.clone();

    assert!(hkdf::verify(&exp_okm, &salt, &ikm, Some(&info), &mut okm_out).unwrap());
});
