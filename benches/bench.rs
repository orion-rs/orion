#![feature(test)]
extern crate orion;
extern crate test;

use orion::hazardous::{
	aead::{chacha20poly1305, xchacha20poly1305},
	hash::*,
	kdf::{hkdf, pbkdf2},
	mac::{hmac, poly1305},
	stream::*,
};
use test::Bencher;

mod mac {
	use super::*;

	macro_rules! bench_poly1305 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;
				let key = poly1305::OneTimeKey::from_slice(&[0u8; 32]).unwrap();

				b.iter(|| {
					let _ = poly1305::poly1305(&key, &[0u8; $input_len]).unwrap();
				});
			}
		};
	}

	macro_rules! bench_hmac {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;

				b.iter(|| {
					// SecretKey processes the input for use with HMAC.
					let key = hmac::SecretKey::from_slice(&[0x01; 64]).unwrap();
					let _ = hmac::hmac(&key, &[0u8; $input_len]).unwrap();
				});
			}
		};
	}

	bench_hmac!(bench_hmac_512, 512);
	bench_hmac!(bench_hmac_1024, 1024);
	bench_hmac!(bench_hmac_2048, 2048);
	bench_hmac!(bench_hmac_4096, 4096);

	bench_poly1305!(bench_poly1305_512, 512);
	bench_poly1305!(bench_poly1305_1024, 1024);
	bench_poly1305!(bench_poly1305_2048, 2048);
	bench_poly1305!(bench_poly1305_4096, 4096);
}

mod aead {
	use super::*;

	macro_rules! bench_chacha20poly1305 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;
				let key = chacha20poly1305::SecretKey::generate();
				let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

				let mut out = [0u8; $input_len + 16];

				b.iter(|| {
					chacha20poly1305::seal(&key, &nonce, &[0u8; $input_len], None, &mut out)
						.unwrap();
				});
			}
		};
	}

	macro_rules! bench_xchacha20poly1305 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;
				let key = xchacha20poly1305::SecretKey::generate();
				let nonce = xchacha20poly1305::Nonce::generate();

				let mut out = [0u8; $input_len + 16];

				b.iter(|| {
					xchacha20poly1305::seal(&key, &nonce, &[0u8; $input_len], None, &mut out)
						.unwrap();
				});
			}
		};
	}

	bench_chacha20poly1305!(bench_chacha20poly1305_512, 512);
	bench_chacha20poly1305!(bench_chacha20poly1305_1024, 1024);
	bench_chacha20poly1305!(bench_chacha20poly1305_2048, 2048);
	bench_chacha20poly1305!(bench_chacha20poly1305_4096, 4096);

	bench_xchacha20poly1305!(bench_xchacha20poly1305_512, 512);
	bench_xchacha20poly1305!(bench_xchacha20poly1305_1024, 1024);
	bench_xchacha20poly1305!(bench_xchacha20poly1305_2048, 2048);
	bench_xchacha20poly1305!(bench_xchacha20poly1305_4096, 4096);
}

mod hash {
	use super::*;

	macro_rules! bench_sha512 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;

				b.iter(|| {
					let _ = sha512::digest(&[0u8; $input_len]).unwrap();
				});
			}
		};
	}

	macro_rules! bench_blake2b {
		($bench_name:ident, $input_len:expr, $worker_function:path) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;

				b.iter(|| {
					let _ = $worker_function.digest(&[0u8; $input_len]).unwrap();
				});
			}
		};
	}

	bench_sha512!(bench_sha512_512, 512);
	bench_sha512!(bench_sha512_1024, 1024);
	bench_sha512!(bench_sha512_2048, 2048);
	bench_sha512!(bench_sha512_4096, 4096);

	bench_blake2b!(bench_blake2b256_512, 512, blake2b::Hasher::Blake2b256);
	bench_blake2b!(bench_blake2b256_1024, 1024, blake2b::Hasher::Blake2b256);
	bench_blake2b!(bench_blake2b256_2048, 2048, blake2b::Hasher::Blake2b256);
	bench_blake2b!(bench_blake2b256_4096, 4096, blake2b::Hasher::Blake2b256);

	bench_blake2b!(bench_blake2b384_512, 512, blake2b::Hasher::Blake2b384);
	bench_blake2b!(bench_blake2b384_1024, 1024, blake2b::Hasher::Blake2b384);
	bench_blake2b!(bench_blake2b384_2048, 2048, blake2b::Hasher::Blake2b384);
	bench_blake2b!(bench_blake2b384_4096, 4096, blake2b::Hasher::Blake2b384);

	bench_blake2b!(bench_blake2b512_512, 512, blake2b::Hasher::Blake2b512);
	bench_blake2b!(bench_blake2b512_1024, 1024, blake2b::Hasher::Blake2b512);
	bench_blake2b!(bench_blake2b512_2048, 2048, blake2b::Hasher::Blake2b512);
	bench_blake2b!(bench_blake2b512_4096, 4096, blake2b::Hasher::Blake2b512);
}

mod stream {
	use super::*;

	macro_rules! bench_chacha20 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;
				let key = chacha20::SecretKey::generate();
				let nonce = chacha20::Nonce::from_slice(&[0u8; 12]).unwrap();

				let mut out = [0u8; $input_len];

				b.iter(|| {
					chacha20::encrypt(&key, &nonce, 0, &[0u8; $input_len], &mut out).unwrap();
				});
			}
		};
	}

	macro_rules! bench_xchacha20 {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;
				let key = xchacha20::SecretKey::generate();
				let nonce = xchacha20::Nonce::generate();

				let mut out = [0u8; $input_len];

				b.iter(|| {
					xchacha20::encrypt(&key, &nonce, 0, &[0u8; $input_len], &mut out).unwrap();
				});
			}
		};
	}

	bench_chacha20!(bench_chacha20_512, 512);
	bench_chacha20!(bench_chacha20_1024, 1024);
	bench_chacha20!(bench_chacha20_2048, 2048);
	bench_chacha20!(bench_chacha20_4096, 4096);

	bench_xchacha20!(bench_xchacha20_512, 512);
	bench_xchacha20!(bench_xchacha20_1024, 1024);
	bench_xchacha20!(bench_xchacha20_2048, 2048);
	bench_xchacha20!(bench_xchacha20_4096, 4096);
}

mod kdf {
	use super::*;

	macro_rules! bench_hkdf {
		($bench_name:ident, $input_len:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				b.bytes = $input_len;

				let mut out = [0u8; $input_len];

				b.iter(|| {
					hkdf::derive_key(&[0x01; 64], &[0x01; 64], Some(&[0x01; 64]), &mut out)
						.unwrap();
				});
			}
		};
	}

	macro_rules! bench_pbkdf2 {
		($bench_name:ident, $cost_param:expr) => {
			#[bench]
			pub fn $bench_name(b: &mut Bencher) {
				let mut dk_out = [0u8; 64];

				b.iter(|| {
					let password = pbkdf2::Password::from_slice(&[0x01; 64]).unwrap();
					pbkdf2::derive_key(&password, &[0x01; 64], $cost_param, &mut dk_out).unwrap();
				});
			}
		};
	}

	bench_hkdf!(bench_hkdf_512, 512);
	bench_hkdf!(bench_hkdf_1024, 1024);
	bench_hkdf!(bench_hkdf_2048, 2048);
	bench_hkdf!(bench_hkdf_4096, 4096);

	bench_pbkdf2!(bench_pbkdf2_1000, 1000);
	bench_pbkdf2!(bench_pbkdf2_10000, 10000);
	bench_pbkdf2!(bench_pbkdf2_100000, 100000);
}
