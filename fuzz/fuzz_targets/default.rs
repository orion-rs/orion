#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::default;
use orion::utilities::util;
use rand::Rng;

fn fuzz_default(data: &[u8]) -> () {
    let mut rand_salt = [0u8; 64];
    util::gen_rand_key(&mut rand_salt).unwrap();
    let mut rng = rand::thread_rng();

    // cSHAKE `custom` can't be empty
    let mut mod_custom = data.to_vec();
    mod_custom.push(0u8);

    if rng.gen() {
        default::hkdf_verify(
            &default::hkdf(&rand_salt, data, data).unwrap(),
            &rand_salt,
            &data,
            data,
        ).unwrap();

        default::hmac_verify(&default::hmac(&rand_salt, data).unwrap(), &rand_salt, data).unwrap();

        let mut password = data.to_vec();
        password.extend_from_slice(&[0u8; 14]);

        default::pbkdf2_verify(&default::pbkdf2(&password).unwrap(), &password).unwrap();

        default::cshake_verify(
            &default::cshake(&data, &mod_custom).unwrap(),
            &data,
            &mod_custom,
        ).unwrap();
        default::cshake_verify(
            &default::cshake("".as_bytes(), &mod_custom).unwrap(),
            "".as_bytes(),
            &mod_custom,
        ).unwrap();
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_default(data);
});
