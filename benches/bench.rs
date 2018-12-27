#![feature(test)]
extern crate orion;
extern crate test;

use orion::hazardous::{
	aead::{chacha20poly1305, xchacha20poly1305},
	hash::*,
	kdf::{hkdf, pbkdf2},
	mac::{hmac, poly1305},
	stream::*,
	xof::cshake,
};
use test::Bencher;

fn cshake(data: &[u8], hash_out: &mut [u8]) {
	let mut cshake = cshake::init(&[0x01; 64], None).unwrap();
	cshake.update(data).unwrap();
	cshake.finalize(hash_out).unwrap();
}

fn chacha_encrypt(pt: &[u8], ct: &mut [u8], key: &chacha20::SecretKey, nonce: &chacha20::Nonce) {
	chacha20::encrypt(&key, &nonce, 0, &pt, ct).unwrap();
}

fn xchacha_encrypt(pt: &[u8], ct: &mut [u8], key: &xchacha20::SecretKey, nonce: &xchacha20::Nonce) {
	xchacha20::encrypt(&key, &nonce, 0, &pt, ct).unwrap();
}

fn chacha20poly1305(
	pt: &mut [u8],
	ct: &mut [u8],
	key: &chacha20::SecretKey,
	nonce: &chacha20::Nonce,
) {
	chacha20poly1305::seal(&key, &nonce, &pt, None, ct).unwrap();
	chacha20poly1305::open(&key, &nonce, &ct, None, pt).unwrap();
}

fn xchacha20poly1305(
	pt: &mut [u8],
	ct: &mut [u8],
	key: &xchacha20::SecretKey,
	nonce: &xchacha20::Nonce,
) {
	xchacha20poly1305::seal(&key, &nonce, &pt, None, ct).unwrap();
	xchacha20poly1305::open(&key, &nonce, &ct, None, pt).unwrap();
}

fn poly1305(data: &[u8], key: &poly1305::OneTimeKey) {
	let mut mac = poly1305::init(&key);
	mac.update(data).unwrap();
	let _tag = mac.finalize().unwrap();
}

fn hmac(data: &[u8], key: &hmac::SecretKey) {
	let mut mac = hmac::init(&key);
	mac.update(data).unwrap();
	let _tag = mac.finalize().unwrap();
}

#[bench]
fn bench_hmac_512(b: &mut Bencher) {
	let key = hmac::SecretKey::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		hmac(&[0u8; 512], &key);
	});
}

#[bench]
fn bench_hmac_1024(b: &mut Bencher) {
	let key = hmac::SecretKey::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		hmac(&[0u8; 1024], &key);
	});
}

#[bench]
fn bench_hmac_2048(b: &mut Bencher) {
	let key = hmac::SecretKey::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		hmac(&[0u8; 2048], &key);
	});
}

#[bench]
fn bench_hmac_4096(b: &mut Bencher) {
	let key = hmac::SecretKey::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		hmac(&[0u8; 4096], &key);
	});
}

#[bench]
fn bench_hkdf_512(b: &mut Bencher) {
	let mut okm_out = [0u8; 512];
	b.iter(|| {
		hkdf::derive_key(&[0x01; 64], &[0x01; 64], Some(&[0x01; 64]), &mut okm_out).unwrap();
	});
}

#[bench]
fn bench_hkdf_1024(b: &mut Bencher) {
	let mut okm_out = [0u8; 1024];
	b.iter(|| {
		hkdf::derive_key(&[0x01; 64], &[0x01; 64], Some(&[0x01; 64]), &mut okm_out).unwrap();
	});
}

#[bench]
fn bench_hkdf_2048(b: &mut Bencher) {
	let mut okm_out = [0u8; 2048];
	b.iter(|| {
		hkdf::derive_key(&[0x01; 64], &[0x01; 64], Some(&[0x01; 64]), &mut okm_out).unwrap();
	});
}

#[bench]
fn bench_hkdf_4096(b: &mut Bencher) {
	let mut okm_out = [0u8; 4096];
	b.iter(|| {
		hkdf::derive_key(&[0x01; 64], &[0x01; 64], Some(&[0x01; 64]), &mut okm_out).unwrap();
	});
}

#[bench]
fn bench_pbkdf2_iter_1000(b: &mut Bencher) {
	let mut dk_out = [0u8; 64];
	let password = pbkdf2::Password::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		pbkdf2::derive_key(&password, &[0x01; 64], 1000, &mut dk_out).unwrap();
	});
}

#[bench]
fn bench_pbkdf2_iter_10000(b: &mut Bencher) {
	let mut dk_out = [0u8; 64];
	let password = pbkdf2::Password::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		pbkdf2::derive_key(&password, &[0x01; 64], 10000, &mut dk_out).unwrap();
	});
}

#[bench]
fn bench_pbkdf2_iter_100000(b: &mut Bencher) {
	let mut dk_out = [0u8; 64];
	let password = pbkdf2::Password::from_slice(&[0x01; 64]).unwrap();

	b.iter(|| {
		pbkdf2::derive_key(&password, &[0x01; 64], 100000, &mut dk_out).unwrap();
	});
}

#[bench]
fn bench_cshake_512(b: &mut Bencher) {
	let mut hash_out = [0u8; 512];
	b.iter(|| {
		cshake(&[0u8; 512], &mut hash_out);
	});
}

#[bench]
fn bench_cshake_1024(b: &mut Bencher) {
	let mut hash_out = [0u8; 1024];
	b.iter(|| {
		cshake(&[0u8; 1024], &mut hash_out);
	});
}

#[bench]
fn bench_cshake_2048(b: &mut Bencher) {
	let mut hash_out = [0u8; 2048];
	b.iter(|| {
		cshake(&[0u8; 2048], &mut hash_out);
	});
}

#[bench]
fn bench_cshake_4096(b: &mut Bencher) {
	let mut hash_out = [0u8; 4096];
	b.iter(|| {
		cshake(&[0u8; 4096], &mut hash_out);
	});
}

#[bench]
fn bench_chacha20_encrypt_512(b: &mut Bencher) {
	let plaintext = [0u8; 512];
	let mut ciphertext = [0u8; 512];
	let key = chacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| {
		chacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_chacha20_encrypt_1024(b: &mut Bencher) {
	let plaintext = [0u8; 1024];
	let mut ciphertext = [0u8; 1024];
	let key = chacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| {
		chacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_chacha20_encrypt_2048(b: &mut Bencher) {
	let plaintext = [0u8; 2048];
	let mut ciphertext = [0u8; 2048];
	let key = chacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| {
		chacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_chacha20_encrypt_4096(b: &mut Bencher) {
	let plaintext = [0u8; 4096];
	let mut ciphertext = [0u8; 4096];
	let key = chacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| {
		chacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_xchacha20_encrypt_512(b: &mut Bencher) {
	let plaintext = [0u8; 512];
	let mut ciphertext = [0u8; 512];
	let key = xchacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| {
		xchacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_xchacha20_encrypt_1024(b: &mut Bencher) {
	let plaintext = [0u8; 1024];
	let mut ciphertext = [0u8; 1024];
	let key = xchacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| {
		xchacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_xchacha20_encrypt_2048(b: &mut Bencher) {
	let plaintext = [0u8; 2048];
	let mut ciphertext = [0u8; 2048];
	let key = xchacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| {
		xchacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_xchacha20_encrypt_4096(b: &mut Bencher) {
	let plaintext = [0u8; 4096];
	let mut ciphertext = [0u8; 4096];
	let key = xchacha20::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| {
		xchacha_encrypt(&plaintext, &mut ciphertext, &key, &nonce);
	});
}

#[bench]
fn bench_poly1305_512(b: &mut Bencher) {
	let key = poly1305::OneTimeKey::from_slice(&[0x01; 32]).unwrap();

	b.iter(|| {
		poly1305(&[0u8; 512], &key);
	});
}

#[bench]
fn bench_poly1305_1024(b: &mut Bencher) {
	let key = poly1305::OneTimeKey::from_slice(&[0u8; 32]).unwrap();

	b.iter(|| {
		poly1305(&[0u8; 1024], &key);
	});
}

#[bench]
fn bench_poly1305_2048(b: &mut Bencher) {
	let key = poly1305::OneTimeKey::from_slice(&[0u8; 32]).unwrap();

	b.iter(|| {
		poly1305(&[0u8; 2048], &key);
	});
}

#[bench]
fn bench_poly1305_4096(b: &mut Bencher) {
	let key = poly1305::OneTimeKey::from_slice(&[0u8; 32]).unwrap();

	b.iter(|| {
		poly1305(&[0u8; 4096], &key);
	});
}

#[bench]
fn bench_chacha20poly1305_encrypt_decrypt_512(b: &mut Bencher) {
	let mut plaintext = [0u8; 512];
	let mut ciphertext_with_tag = [0u8; 512 + 16];
	let key = chacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| chacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_chacha20poly1305_encrypt_decrypt_1024(b: &mut Bencher) {
	let mut plaintext = [0u8; 1024];
	let mut ciphertext_with_tag = [0u8; 1024 + 16];
	let key = chacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| chacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_chacha20poly1305_encrypt_decrypt_2048(b: &mut Bencher) {
	let mut plaintext = [0u8; 2048];
	let mut ciphertext_with_tag = [0u8; 2048 + 16];
	let key = chacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| chacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_chacha20poly1305_encrypt_decrypt_4096(b: &mut Bencher) {
	let mut plaintext = [0u8; 4096];
	let mut ciphertext_with_tag = [0u8; 4096 + 16];
	let key = chacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

	b.iter(|| chacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_xchacha20poly1305_encrypt_decrypt_512(b: &mut Bencher) {
	let mut plaintext = [0u8; 512];
	let mut ciphertext_with_tag = [0u8; 512 + 16];
	let key = xchacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20poly1305::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| xchacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_xchacha20poly1305_encrypt_decrypt_1024(b: &mut Bencher) {
	let mut plaintext = [0u8; 1024];
	let mut ciphertext_with_tag = [0u8; 1024 + 16];
	let key = xchacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20poly1305::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| xchacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_xchacha20poly1305_encrypt_decrypt_2048(b: &mut Bencher) {
	let mut plaintext = [0u8; 2048];
	let mut ciphertext_with_tag = [0u8; 2048 + 16];
	let key = xchacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20poly1305::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| xchacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_xchacha20poly1305_encrypt_decrypt_4096(b: &mut Bencher) {
	let mut plaintext = [0u8; 4096];
	let mut ciphertext_with_tag = [0u8; 4096 + 16];
	let key = xchacha20poly1305::SecretKey::from_slice(&[0u8; 32]).unwrap();
	let nonce = xchacha20poly1305::Nonce::from_slice(&[0u8; 24]).unwrap();

	b.iter(|| xchacha20poly1305(&mut plaintext, &mut ciphertext_with_tag, &key, &nonce));
}

#[bench]
fn bench_blake2b256_512(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b256.digest(&[0u8; 512]).unwrap();
	});
}

#[bench]
fn bench_blake2b256_1024(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b256.digest(&[0u8; 1024]).unwrap();
	});
}

#[bench]
fn bench_blake2b256_2048(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b256.digest(&[0u8; 2048]).unwrap();
	});
}

#[bench]
fn bench_blake2b256_4096(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b256.digest(&[0u8; 4096]).unwrap();
	});
}

#[bench]
fn bench_blake2b384_512(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b384.digest(&[0u8; 512]).unwrap();
	});
}

#[bench]
fn bench_blake2b384_1024(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b384.digest(&[0u8; 1024]).unwrap();
	});
}

#[bench]
fn bench_blake2b384_2048(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b384.digest(&[0u8; 2048]).unwrap();
	});
}

#[bench]
fn bench_blake2b384_4096(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b384.digest(&[0u8; 4096]).unwrap();
	});
}

#[bench]
fn bench_blake2b512_512(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b512.digest(&[0u8; 512]).unwrap();
	});
}

#[bench]
fn bench_blake2b512_1024(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b512.digest(&[0u8; 1024]).unwrap();
	});
}

#[bench]
fn bench_blake2b512_2048(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b512.digest(&[0u8; 2048]).unwrap();
	});
}

#[bench]
fn bench_blake2b512_4096(b: &mut Bencher) {
	b.iter(|| {
		let _digest = blake2b::Hasher::Blake2b512.digest(&[0u8; 4096]).unwrap();
	});
}

#[bench]
fn bench_sha512_512(b: &mut Bencher) {
	b.iter(|| {
		let _digest = sha512::digest(&[0u8; 512]).unwrap();
	});
}

#[bench]
fn bench_sha512_1024(b: &mut Bencher) {
	b.iter(|| {
		let _digest = sha512::digest(&[0u8; 1024]).unwrap();
	});
}

#[bench]
fn bench_sha512_2048(b: &mut Bencher) {
	b.iter(|| {
		let _digest = sha512::digest(&[0u8; 2048]).unwrap();
	});
}

#[bench]
fn bench_sha512_4096(b: &mut Bencher) {
	b.iter(|| {
		let _digest = sha512::digest(&[0u8; 4096]).unwrap();
	});
}
