#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;

fuzz_target!(|data: &[u8]| {
    let mut rand_key = [0u8; 32];
    apply_from_input_fixed(&mut rand_key, data, 32);


    // orion::aead
    let aead_key = orion::aead::SecretKey::from_slice(&rand_key).unwrap();
    // Plaintext for `seal` cannot be empty
    let mut plaintext = data.to_vec();
    if data.is_empty() {
        plaintext.push(0u8);
    }
    let aead_ciphertext = orion::aead::seal(&aead_key, &plaintext).unwrap();
    let aead_decrypted = orion::aead::open(&aead_key, &aead_ciphertext).unwrap();
    assert_eq!(&plaintext, &aead_decrypted);

    // orion::auth
    let auth_key = orion::auth::SecretKey::from_slice(data);
    let tag = orion::auth::authenticate(&auth_key, &data);
    let res = orion::auth::authenticate_verify(&tag, &auth_key, &data).unwrap();
    assert!(res);

    // orion::pwhash
    let pwhash_password = orion::pwhash::Password::from_slice(data);
    let c = if data.is_empty() {
        10000
    } else {
        ((data[0] as usize) * 100) + 1 // +1 to avoid 0 if [0] is zero
    };

    let password_hash = orion::pwhash::hash_password(&pwhash_password, c).unwrap();
    assert!(orion::pwhash::hash_password_verify(&password_hash, &pwhash_password, c).unwrap();)
});
