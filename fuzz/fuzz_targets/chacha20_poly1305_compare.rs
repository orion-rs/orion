#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
pub mod util;

use util::*;

fuzz_target!(|data: &[u8]| {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    apply_from_input_fixed(&mut key, &data, 0);
    apply_from_input_fixed(&mut nonce, &data, 32);
    let mut aad = Vec::new();
    apply_from_input_heap(&mut aad, data, key.len() + nonce.len());
    let mut plaintext = Vec::new();
    apply_from_input_heap(&mut plaintext, data, key.len() + nonce.len() + aad.len());

    let mut ciphertext_with_tag_orion: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let mut plaintext_out_orion = vec![0u8; plaintext.len()];

    orion::hazardous::aead::ietf_chacha20_poly1305_encrypt(
        &key,
        &nonce,
        &plaintext,
        &aad,
        &mut ciphertext_with_tag_orion,
    ).unwrap();
    orion::hazardous::aead::ietf_chacha20_poly1305_decrypt(
        &key,
        &nonce,
        &ciphertext_with_tag_orion,
        &aad,
        &mut plaintext_out_orion,
    ).unwrap();

    let enc_key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
    let dec_key = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();

    let mut ciphertext_with_tag_ring: Vec<u8> = vec![0u8; plaintext.len() + 16];
    // Insert plaintext
    ciphertext_with_tag_ring[..plaintext.len()].copy_from_slice(&plaintext);

    let index =
        ring::aead::seal_in_place(&enc_key, &nonce, &aad, &mut ciphertext_with_tag_ring, 16)
            .unwrap();
    assert_eq!(
        &ciphertext_with_tag_ring[..index].as_ref(),
        &ciphertext_with_tag_orion[..].as_ref()
    );
    // Check the same Poly1305 tags are generated
    assert_eq!(
        &ciphertext_with_tag_ring[index - 16..index].as_ref(),
        &ciphertext_with_tag_orion[plaintext.len()..].as_ref()
    );
    ring::aead::open_in_place(&dec_key, &nonce, &aad, 0, &mut ciphertext_with_tag_ring).unwrap();
    let mut plaintext_out_ring = Vec::new();
    plaintext_out_ring.extend_from_slice(&ciphertext_with_tag_ring);
    assert_eq!(
        &ciphertext_with_tag_ring[..plaintext.len()].as_ref(),
        &plaintext_out_orion[..].as_ref()
    );
});
