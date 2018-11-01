#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use util::*;

fuzz_target!(|data: &[u8]| {
    let (key, nonce, aad, plaintext) = aead_setup_with_nonce_len(24, data);
    let mut ciphertext_with_tag_orion: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let mut plaintext_out_orion = vec![0u8; plaintext.len()];

    orion::hazardous::aead::xchacha20_poly1305_encrypt(
        &key,
        &nonce,
        &plaintext,
        &aad,
        &mut ciphertext_with_tag_orion,
    ).unwrap();
    orion::hazardous::aead::xchacha20_poly1305_decrypt(
        &key,
        &nonce,
        &ciphertext_with_tag_orion,
        &aad,
        &mut plaintext_out_orion,
    ).unwrap();

    assert_eq!(&plaintext, &plaintext_out_orion);
});
