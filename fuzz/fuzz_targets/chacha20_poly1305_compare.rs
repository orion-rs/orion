#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
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

	let enc_key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
	let dec_key = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
	
	let ring_nonce_enc = ring::aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();
	let ring_aad_enc = ring::aead::Aad::from(&aad);
	
	let ring_nonce_dec = ring::aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();
	let ring_aad_dec = ring::aead::Aad::from(&aad);

	let mut ciphertext_with_tag_ring: Vec<u8> = vec![0u8; plaintext.len() + 16];
	let mut plaintext_out_ring = Vec::new();
	// Insert plaintext
	ciphertext_with_tag_ring[..plaintext.len()].copy_from_slice(&plaintext);

	let index =
		ring::aead::seal_in_place(&enc_key, ring_nonce_enc, ring_aad_enc, &mut ciphertext_with_tag_ring, 16)
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
	ring::aead::open_in_place(&dec_key, ring_nonce_dec, ring_aad_dec, 0, &mut ciphertext_with_tag_ring).unwrap();
	plaintext_out_ring.extend_from_slice(&ciphertext_with_tag_ring);
	assert_eq!(
		&ciphertext_with_tag_ring[..plaintext.len()].as_ref(),
		&plaintext_out_orion[..].as_ref()
	);
});
