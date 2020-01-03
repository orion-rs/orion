// MIT License

// Copyright (c) 2018-2020 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

extern crate criterion;
extern crate orion;

use criterion::*;

use orion::hazardous::{
	aead::{chacha20poly1305, xchacha20poly1305},
	hash::*,
	kdf::{hkdf, pbkdf2},
	mac::{hmac, poly1305},
	stream::*,
};

mod mac {
	use super::*;

	static INPUT_SIZES: [usize; 4] = [512, 1024, 2048, 4098];

	pub fn bench_poly1305(c: &mut Criterion) {
		let mut group = c.benchmark_group("Poly1305");
		let key = poly1305::OneTimeKey::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute mac", *size),
				&input,
				|b, input_message| {
					b.iter(|| poly1305::Poly1305::poly1305(&key, &input_message).unwrap())
				},
			);
		}
	}

	pub fn bench_hmac(c: &mut Criterion) {
		let mut group = c.benchmark_group("HMAC-SHA512");
		// NOTE: Setting the key like this will pad it for HMAC.
		// Padding is therefor not included in benchmarks.
		let key = hmac::SecretKey::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute mac", *size),
				&input,
				|b, input_message| b.iter(|| hmac::Hmac::hmac(&key, &input_message).unwrap()),
			);
		}
	}

	criterion_group! {
		name = mac_benches;
		config = Criterion::default();
		targets =
		bench_poly1305,
		bench_hmac,
	}
}

mod aead {
	use super::*;

	static INPUT_SIZES: [usize; 4] = [512, 1024, 2048, 4098];

	pub fn bench_chacha20poly1305(c: &mut Criterion) {
		let mut group = c.benchmark_group("ChaCha20-Poly1305");
		let key = chacha20poly1305::SecretKey::generate();
		let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];
			let mut out = vec![0u8; input.len() + 16];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("encrypt", *size),
				&input,
				|b, input_message| {
					b.iter(|| {
						chacha20poly1305::seal(&key, &nonce, &input_message, None, &mut out)
							.unwrap()
					})
				},
			);
		}
	}

	pub fn bench_xchacha20poly1305(c: &mut Criterion) {
		let mut group = c.benchmark_group("XChaCha20-Poly1305");
		let key = xchacha20poly1305::SecretKey::generate();
		let nonce = xchacha20poly1305::Nonce::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];
			let mut out = vec![0u8; input.len() + 16];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("encrypt", *size),
				&input,
				|b, input_message| {
					b.iter(|| {
						xchacha20poly1305::seal(&key, &nonce, &input_message, None, &mut out)
							.unwrap()
					})
				},
			);
		}
	}

	criterion_group! {
		name = aead_benches;
		config = Criterion::default();
		targets =
		bench_chacha20poly1305,
		bench_xchacha20poly1305,
	}
}

mod hash {
	use super::*;

	static INPUT_SIZES: [usize; 4] = [512, 1024, 2048, 4098];

	pub fn bench_sha512(c: &mut Criterion) {
		let mut group = c.benchmark_group("SHA512");

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute hash", *size),
				&input,
				|b, input_message| b.iter(|| sha512::Sha512::digest(&input_message).unwrap()),
			);
		}
	}

	pub fn bench_blake2b_256(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-256");

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute hash", *size),
				&input,
				|b, input_message| {
					b.iter(|| blake2b::Hasher::Blake2b256.digest(&input_message).unwrap())
				},
			);
		}
	}

	pub fn bench_blake2b_384(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-384");

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute hash", *size),
				&input,
				|b, input_message| {
					b.iter(|| blake2b::Hasher::Blake2b384.digest(&input_message).unwrap())
				},
			);
		}
	}

	pub fn bench_blake2b_512(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-512");

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute hash", *size),
				&input,
				|b, input_message| {
					b.iter(|| blake2b::Hasher::Blake2b512.digest(&input_message).unwrap())
				},
			);
		}
	}

	// Convenience function for testing Blake2b with a secret key.
	fn blake2b_keyed(
		sk: Option<&blake2b::SecretKey>,
		size: usize,
		input: &[u8],
	) -> Result<blake2b::Digest, orion::errors::UnknownCryptoError> {
		let mut state = blake2b::Blake2b::new(sk, size).unwrap();
		state.update(input).unwrap();
		state.finalize()
	}

	pub fn bench_blake2b_256_keyed(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-256_keyed");
		let sk = &blake2b::SecretKey::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute mac", *size),
				&input,
				|b, input_message| b.iter(|| blake2b_keyed(Some(sk), 32, input_message).unwrap()),
			);
		}
	}

	pub fn bench_blake2b_384_keyed(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-384_keyed");
		let sk = &blake2b::SecretKey::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute mac", *size),
				&input,
				|b, input_message| b.iter(|| blake2b_keyed(Some(sk), 48, input_message).unwrap()),
			);
		}
	}

	pub fn bench_blake2b_512_keyed(c: &mut Criterion) {
		let mut group = c.benchmark_group("BLAKE2b-512_keyed");
		let sk = &blake2b::SecretKey::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("compute mac", *size),
				&input,
				|b, input_message| b.iter(|| blake2b_keyed(Some(sk), 64, input_message).unwrap()),
			);
		}
	}

	criterion_group! {
		name = hash_benches;
		config = Criterion::default();
		targets =
		bench_sha512,
		bench_blake2b_256,
		bench_blake2b_384,
		bench_blake2b_512,
		bench_blake2b_256_keyed,
		bench_blake2b_384_keyed,
		bench_blake2b_512_keyed,
	}
}

mod stream {
	use super::*;

	static INPUT_SIZES: [usize; 4] = [512, 1024, 2048, 4098];

	pub fn bench_chacha20(c: &mut Criterion) {
		let mut group = c.benchmark_group("ChaCha20");
		let key = chacha20poly1305::SecretKey::generate();
		let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]).unwrap();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];
			let mut out = vec![0u8; input.len()];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("xor-stream", *size),
				&input,
				|b, input_message| {
					b.iter(|| chacha20::encrypt(&key, &nonce, 0, &input_message, &mut out).unwrap())
				},
			);
		}
	}

	pub fn bench_xchacha20(c: &mut Criterion) {
		let mut group = c.benchmark_group("XChaCha20");
		let key = xchacha20::SecretKey::generate();
		let nonce = xchacha20::Nonce::generate();

		for size in INPUT_SIZES.iter() {
			let input = vec![0u8; *size];
			let mut out = vec![0u8; input.len()];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("xor-stream", *size),
				&input,
				|b, input_message| {
					b.iter(|| {
						xchacha20::encrypt(&key, &nonce, 0, &input_message, &mut out).unwrap()
					})
				},
			);
		}
	}

	criterion_group! {
		name = stream_benches;
		config = Criterion::default();
		targets =
		bench_chacha20,
		bench_xchacha20,
	}
}

mod kdf {
	use super::*;

	static OKM_SIZES: [usize; 4] = [512, 1024, 2048, 4098];
	static PBKDF2_ITERATIONS: [usize; 3] = [1000, 10000, 100000];

	pub fn bench_hkdf(c: &mut Criterion) {
		let mut group = c.benchmark_group("HKDF-HMAC-SHA512");

		for size in OKM_SIZES.iter() {
			let ikm = vec![0u8; 64];
			let salt = ikm.clone();
			let mut okm_out = vec![0u8; *size];

			group.throughput(Throughput::Bytes(*size as u64));
			group.bench_with_input(
				BenchmarkId::new("derive bytes", *size),
				&ikm,
				|b, input_ikm| {
					b.iter(|| hkdf::derive_key(&salt, input_ikm, None, &mut okm_out).unwrap())
				},
			);
		}
	}

	pub fn bench_pbkdf2(c: &mut Criterion) {
		let mut group = c.benchmark_group("PBKDF2-HMAC-SHA512");
		// 10 is the lowest acceptable same size.
		group.sample_size(10);
		group.measurement_time(core::time::Duration::new(30, 0));

		for iterations in PBKDF2_ITERATIONS.iter() {
			let ikm = vec![0u8; 64];
			let salt = ikm.clone();
			let mut dk_out = vec![0u8; 64];

			// NOTE: The password newtype creation is included
			// as this pads the salt for HMAC internally.
			group.bench_with_input(
				BenchmarkId::new("derive 64 bytes", *iterations),
				&iterations,
				|b, iter_count| {
					b.iter(|| {
						pbkdf2::derive_key(
							&pbkdf2::Password::from_slice(&salt).unwrap(),
							&ikm,
							**iter_count,
							&mut dk_out,
						)
						.unwrap()
					})
				},
			);
		}
	}

	criterion_group! {
		name = kdf_benches;
		config = Criterion::default();
		targets =
		bench_hkdf,
		bench_pbkdf2,
	}
}

criterion_main!(
	mac::mac_benches,
	aead::aead_benches,
	hash::hash_benches,
	stream::stream_benches,
	kdf::kdf_benches,
);
