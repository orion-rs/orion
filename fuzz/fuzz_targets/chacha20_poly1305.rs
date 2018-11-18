#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use orion::hazardous::aead::chacha20poly1305;
use util::*;

fuzz_target!(|data: &[u8]| {
    let (key, nonce, aad, plaintext) = aead_setup_with_nonce_len(12, data);
    let mut ciphertext_with_tag_orion: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let mut plaintext_out_orion = vec![0u8; plaintext.len()];

    let orion_key = chacha20poly1305::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = chacha20poly1305::Nonce::from_slice(&nonce).unwrap();

    chacha20poly1305::seal(
        &orion_key,
        &orion_nonce,
        &plaintext,
        Some(&aad),
        &mut ciphertext_with_tag_orion,
    )
    .unwrap();
    chacha20poly1305::open(
        &orion_key,
        &orion_nonce,
        &ciphertext_with_tag_orion,
        Some(&aad),
        &mut plaintext_out_orion,
    )
    .unwrap();

    assert_eq!(&plaintext, &plaintext_out_orion);
});
