#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::default;

fuzz_target!(|data: &[u8]| {
    let mut rand_salt = [0u8; 64];
    let mut rand_key = [0u8; 32];
    apply_from_input_fixed(&mut rand_key, data, 32);
    apply_from_input_fixed(&mut rand_salt, data, rand_key.len());

    // cSHAKE `custom` can't be empty
    let mut mod_custom = data.to_vec();
    // Plaintext for `encrypt` cannot be empty
    let mut plaintext = data.to_vec();
    // PBKDF2 `password` must be at least 14 bytes long
    let mut password = data.to_vec();
    if data.len() < 14 {
        if data.is_empty() {
            mod_custom.push(0u8);
            plaintext.push(0u8);
        }
        let len = password.len();
        password.extend_from_slice(&vec![0u8; 14 - len]);
    }

    default::hkdf_verify(
        &default::hkdf(&rand_salt, data, data).unwrap(),
        &rand_salt,
        &data,
        data,
    ).unwrap();

    default::hmac_verify(&default::hmac(&rand_salt, data).unwrap(), &rand_salt, data).unwrap();
    default::pbkdf2_verify(&default::pbkdf2(&password).unwrap(), &password).unwrap();
    default::cshake(&data, &mod_custom).unwrap();
    default::cshake(b"", &mod_custom).unwrap();
    assert_eq!(
        default::decrypt(&rand_key, &default::encrypt(&rand_key, &plaintext).unwrap()).unwrap(),
        plaintext
    );
});
