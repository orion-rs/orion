// MIT License

// Copyright (c) 2018-2019 The orion Developers

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

//! # Parameters:
//! - `secret_key`: An optional secret key.
//! - `size`: The desired output length for the digest.
//! - `data`: The data to be hashed.
//! - `expected`: The expected digest when verifying.
//!
//! # Errors:
//! An error will be returned if:
//! - `size` is 0.
//! - `size` is greater than 64.
//! - `finalize()` is called twice without a `reset()` in between.
//! - `update()` is called after `finalize()` without a `reset()` in between.
//! - `reset()` is called with `Some(secret_key)` but the struct was initialized
//!   with `None`.
//! - `reset()` is called with `None` as `secret_key` but the struct was
//!   initialized with `Some(secret_key)`.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   `SecretKey::generate()` can be used
//! for this. It generates a secret key of 64 bytes.
//! - The minimum recommended size for a secret key is 32 bytes.
//! - When using `Blake2b` with a secret key, then the output can be used as a
//!   MAC. If this is the
//! intention, __**avoid using**__ `as_bytes()` to compare such MACs and use
//! instead `verify()`, which will compare the MAC in constant time.
//! - The recommended minimum output size is 32.
//!
//! # Example:
//! ```
//! use orion::hazardous::hash::blake2b;
//!
//! // Using the streaming interface without a key.
//! let mut state = blake2b::init(None, 64).unwrap();
//! state.update(b"Some data").unwrap();
//! let digest = state.finalize().unwrap();
//!
//! // Using the streaming interface with a key.
//! let secret_key = blake2b::SecretKey::generate().unwrap();
//! let mut state_keyed = blake2b::init(Some(&secret_key), 64).unwrap();
//! state_keyed.update(b"Some data").unwrap();
//! let mac = state_keyed.finalize().unwrap();
//! assert!(blake2b::verify(&mac, &secret_key, 64, b"Some data").unwrap());
//!
//! // Using the `Hasher` for convenience functions.
//! let digest = blake2b::Hasher::Blake2b512.digest(b"Some data").unwrap();
//! ```

use crate::{
	endianness::{load_u64_into_le, store_u64_into_le},
	errors::{FinalizationCryptoError, UnknownCryptoError, ValidationCryptoError},
	hazardous::constants::{BLAKE2B_BLOCKSIZE, BLAKE2B_KEYSIZE, BLAKE2B_OUTSIZE},
};

construct_secret_key! {
	/// A type to represent the `SecretKey` that BLAKE2b uses for keyed mode.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `slice` is empty.
	/// - `slice` is greater than 64 bytes.
	/// - The `OsRng` fails to initialize or read from its source.
	(SecretKey, test_secret_key, 1, BLAKE2B_KEYSIZE, BLAKE2B_KEYSIZE)
}

construct_digest! {
	/// A type to represent the `Digest` that BLAKE2b returns.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `slice` is empty.
	/// - `slice` is greater than 64 bytes.
	(Digest, 64)
}

#[allow(clippy::unreadable_literal)]
/// The BLAKE2b initialization vector (IV) as defined in the [RFC 7693](https://tools.ietf.org/html/rfc7693).
const IV: [u64; 8] = [
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
];

/// BLAKE2b SGIMA as defined in the [RFC 7693](https://tools.ietf.org/html/rfc7693).
const SIGMA: [[usize; 16]; 12] = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
	[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
	[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
	[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
	[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
	[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
	[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
	[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
	[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Convenience functions for common BLAKE2b operations.
pub enum Hasher {
	/// Blake2b with `32` as `size`.
	Blake2b256,
	/// Blake2b with `48` as `size`.
	Blake2b384,
	/// Blake2b with `64` as `size`.
	Blake2b512,
}

impl Hasher {
	#[must_use]
	/// Return a digest selected by the given Blake2b variant.
	pub fn digest(&self, data: &[u8]) -> Result<Digest, UnknownCryptoError> {
		let size: usize = match *self {
			Hasher::Blake2b256 => 32,
			Hasher::Blake2b384 => 48,
			Hasher::Blake2b512 => 64,
		};

		let mut state = init(None, size)?;
		state.update(data)?;

		Ok(state.finalize()?)
	}

	#[must_use]
	/// Return a `Blake2b` state selected by the given Blake2b variant.
	pub fn init(&self) -> Result<Blake2b, UnknownCryptoError> {
		match *self {
			Hasher::Blake2b256 => Ok(init(None, 32)?),
			Hasher::Blake2b384 => Ok(init(None, 48)?),
			Hasher::Blake2b512 => Ok(init(None, 64)?),
		}
	}
}

#[must_use]
#[derive(Clone)]
/// BLAKE2b as specified in the [RFC 7693](https://tools.ietf.org/html/rfc7693).
pub struct Blake2b {
	init_state: [u64; 8],
	internal_state: [u64; 8],
	buffer: [u8; BLAKE2B_BLOCKSIZE],
	leftover: usize,
	t: [u64; 2],
	f: [u64; 2],
	is_finalized: bool,
	is_keyed: bool,
	size: usize,
}

impl Drop for Blake2b {
	fn drop(&mut self) {
		use zeroize::Zeroize;
		self.init_state.zeroize();
		self.internal_state.zeroize();
		self.buffer.zeroize();
	}
}

impl core::fmt::Debug for Blake2b {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"Blake2b {{ init_state: [***OMITTED***], internal_state: [***OMITTED***], buffer: \
			 [***OMITTED***], leftover: {:?}, t: {:?}, f: {:?}, is_finalized: {:?}, is_keyed: \
			 {:?}, size: {:?} }}",
			self.leftover, self.t, self.f, self.is_finalized, self.is_keyed, self.size
		)
	}
}

impl Blake2b {
	#[inline(always)]
	/// Increment the internal states offset value `t`.
	fn increment_offset(&mut self, value: u64) {
		let (res, was_overflow) = self.t[0].overflowing_add(value);
		self.t[0] = res;
		if was_overflow {
			// If this panics size limit is reached.
			self.t[1] = self.t[1].checked_add(1).unwrap();
		}
	}

	#[inline(always)]
	#[allow(clippy::many_single_char_names)]
	#[allow(clippy::too_many_arguments)]
	/// The primitive mixing function G as defined in the RFC.
	fn prim_mix_g(
		&mut self,
		x: u64,
		y: u64,
		a: usize,
		b: usize,
		c: usize,
		d: usize,
		w: &mut [u64],
	) {
		w[a] = w[a].wrapping_add(w[b]).wrapping_add(x);
		w[d] ^= w[a];
		w[d] = (w[d]).rotate_right(32u32);
		w[c] = w[c].wrapping_add(w[d]);
		w[b] ^= w[c];
		w[b] = (w[b]).rotate_right(24u32);
		w[a] = w[a].wrapping_add(w[b]).wrapping_add(y);
		w[d] ^= w[a];
		w[d] = (w[d]).rotate_right(16u32);
		w[c] = w[c].wrapping_add(w[d]);
		w[b] ^= w[c];
		w[b] = (w[b]).rotate_right(63u32);
	}

	#[inline(always)]
	/// Perform a single round based on a message schedule selection.
	fn round(&mut self, ri: usize, m: &mut [u64], w: &mut [u64]) {
		self.prim_mix_g(m[SIGMA[ri][0]], m[SIGMA[ri][1]], 0, 4, 8, 12, w);
		self.prim_mix_g(m[SIGMA[ri][2]], m[SIGMA[ri][3]], 1, 5, 9, 13, w);
		self.prim_mix_g(m[SIGMA[ri][4]], m[SIGMA[ri][5]], 2, 6, 10, 14, w);
		self.prim_mix_g(m[SIGMA[ri][6]], m[SIGMA[ri][7]], 3, 7, 11, 15, w);
		self.prim_mix_g(m[SIGMA[ri][8]], m[SIGMA[ri][9]], 0, 5, 10, 15, w);
		self.prim_mix_g(m[SIGMA[ri][10]], m[SIGMA[ri][11]], 1, 6, 11, 12, w);
		self.prim_mix_g(m[SIGMA[ri][12]], m[SIGMA[ri][13]], 2, 7, 8, 13, w);
		self.prim_mix_g(m[SIGMA[ri][14]], m[SIGMA[ri][15]], 3, 4, 9, 14, w);
	}

	#[allow(clippy::needless_range_loop)]
	/// The compression function f as defined in the RFC.
	fn compress_f(&mut self) {
		let mut m_vec = [0u64; 16];
		load_u64_into_le(&self.buffer, &mut m_vec);
		let mut w_vec = [
			self.internal_state[0],
			self.internal_state[1],
			self.internal_state[2],
			self.internal_state[3],
			self.internal_state[4],
			self.internal_state[5],
			self.internal_state[6],
			self.internal_state[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			self.t[0] ^ IV[4],
			self.t[1] ^ IV[5],
			self.f[0] ^ IV[6],
			self.f[1] ^ IV[7],
		];

		self.round(0, &mut m_vec, &mut w_vec);
		self.round(1, &mut m_vec, &mut w_vec);
		self.round(2, &mut m_vec, &mut w_vec);
		self.round(3, &mut m_vec, &mut w_vec);
		self.round(4, &mut m_vec, &mut w_vec);
		self.round(5, &mut m_vec, &mut w_vec);
		self.round(6, &mut m_vec, &mut w_vec);
		self.round(7, &mut m_vec, &mut w_vec);
		self.round(8, &mut m_vec, &mut w_vec);
		self.round(9, &mut m_vec, &mut w_vec);
		self.round(10, &mut m_vec, &mut w_vec);
		self.round(11, &mut m_vec, &mut w_vec);

		// XOR the two halves together and into the state
		self.internal_state[0] ^= w_vec[0] ^ w_vec[8];
		self.internal_state[1] ^= w_vec[1] ^ w_vec[9];
		self.internal_state[2] ^= w_vec[2] ^ w_vec[10];
		self.internal_state[3] ^= w_vec[3] ^ w_vec[11];
		self.internal_state[4] ^= w_vec[4] ^ w_vec[12];
		self.internal_state[5] ^= w_vec[5] ^ w_vec[13];
		self.internal_state[6] ^= w_vec[6] ^ w_vec[14];
		self.internal_state[7] ^= w_vec[7] ^ w_vec[15];
	}

	#[must_use]
	/// Reset to `init()` state.
	pub fn reset(&mut self, secret_key: Option<&SecretKey>) -> Result<(), UnknownCryptoError> {
		if secret_key.is_some() && (!self.is_keyed) {
			return Err(UnknownCryptoError);
		}

		if secret_key.is_none() && self.is_keyed {
			return Err(UnknownCryptoError);
		}

		self.internal_state.copy_from_slice(&self.init_state);
		self.buffer = [0u8; BLAKE2B_BLOCKSIZE];
		self.leftover = 0;
		self.t = [0u64; 2];
		self.f = [0u64; 2];
		self.is_finalized = false;

		if secret_key.is_some() && self.is_keyed {
			// .unwrap() cannot panic since secret_key.is_some() == true
			let sk = secret_key.unwrap();
			self.update(sk.unprotected_as_bytes())?;
			// The state needs updating with the secret key padded to blocksize length
			let pad = [0u8; BLAKE2B_BLOCKSIZE];
			let rem = BLAKE2B_BLOCKSIZE - sk.get_length();
			self.update(pad[..rem].as_ref())?;
		}

		Ok(())
	}

	#[must_use]
	/// Update state with a `data`. This can be called multiple times.
	pub fn update(&mut self, data: &[u8]) -> Result<(), FinalizationCryptoError> {
		if self.is_finalized {
			return Err(FinalizationCryptoError);
		}
		if data.is_empty() {
			return Ok(());
		}

		let mut bytes = data;

		if self.leftover > 0 {
			// Using .unwrap() since overflow should not happen in practice
			let fill = BLAKE2B_BLOCKSIZE.checked_sub(self.leftover).unwrap();

			if bytes.len() <= fill {
				self.buffer[self.leftover..(self.leftover + bytes.len())].copy_from_slice(&bytes);
				// Using .unwrap() since overflow should not happen in practice
				self.leftover = self.leftover.checked_add(bytes.len()).unwrap();
				return Ok(());
			}

			self.buffer[self.leftover..(self.leftover + fill)].copy_from_slice(&bytes[..fill]);
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64);
			self.compress_f();
			self.leftover = 0;
			// Reduce by slice
			bytes = &bytes[fill..];
		}

		while bytes.len() > BLAKE2B_BLOCKSIZE {
			self.buffer.copy_from_slice(&bytes[..BLAKE2B_BLOCKSIZE]);
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64);
			self.compress_f();
			// Reduce by slice
			bytes = &bytes[BLAKE2B_BLOCKSIZE..];
		}

		if !bytes.is_empty() {
			self.buffer[self.leftover..(self.leftover + bytes.len())].copy_from_slice(&bytes);
			// Using .unwrap() since overflow should not happen in practice
			self.leftover = self.leftover.checked_add(bytes.len()).unwrap();
		}

		Ok(())
	}

	#[must_use]
	/// Return a BLAKE2b digest.
	pub fn finalize(&mut self) -> Result<Digest, FinalizationCryptoError> {
		if self.is_finalized {
			return Err(FinalizationCryptoError);
		}

		self.is_finalized = true;

		let mut digest = [0u8; 64];

		let in_buffer_len = self.leftover;
		self.increment_offset(in_buffer_len as u64);
		// Mark that it is the last block of data to be processed
		self.f[0] = !0;

		for leftover_block in self.buffer.iter_mut().skip(in_buffer_len) {
			*leftover_block = 0;
		}
		self.compress_f();

		store_u64_into_le(&self.internal_state, &mut digest);

		Ok(Digest::from_slice(&digest[..self.size])?)
	}
}

#[must_use]
#[allow(clippy::unreadable_literal)]
/// Initialize a `Blake2b` struct with a given size and an optional key.
pub fn init(secret_key: Option<&SecretKey>, size: usize) -> Result<Blake2b, UnknownCryptoError> {
	if size < 1 || size > BLAKE2B_OUTSIZE {
		return Err(UnknownCryptoError);
	}

	let mut context = Blake2b {
		init_state: [0u64; 8],
		internal_state: IV,
		buffer: [0u8; BLAKE2B_BLOCKSIZE],
		leftover: 0,
		t: [0u64; 2],
		f: [0u64; 2],
		is_finalized: false,
		is_keyed: false,
		size,
	};

	if secret_key.is_some() {
		context.is_keyed = true;
		// .unwrap() cannot panic since secret_key.is_some() == true
		let key = secret_key.unwrap();
		let klen = key.get_length();
		context.internal_state[0] ^= 0x01010000 ^ ((klen as u64) << 8) ^ (size as u64);
		context.init_state.copy_from_slice(&context.internal_state);
		context.update(key.unprotected_as_bytes())?;
		// The state needs updating with the secret key padded to blocksize length
		let pad = [0u8; BLAKE2B_BLOCKSIZE];
		let rem = BLAKE2B_BLOCKSIZE - key.get_length();
		context.update(pad[..rem].as_ref())?;
	} else {
		context.internal_state[0] ^= 0x01010000 ^ (size as u64);
		context.init_state.copy_from_slice(&context.internal_state);
	}

	Ok(context)
}

#[must_use]
/// Verify a Blake2b Digest in constant time.
pub fn verify(
	expected: &Digest,
	secret_key: &SecretKey,
	size: usize,
	data: &[u8],
) -> Result<bool, ValidationCryptoError> {
	let mut state = init(Some(secret_key), size)?;
	state.update(data)?;

	if expected == &state.finalize()? {
		Ok(true)
	} else {
		Err(ValidationCryptoError)
	}
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	// One function tested per submodule.

	/// Compare two Blake2b state objects to check if their fields
	/// are the same.
	fn compare_blake2b_states(state_1: &Blake2b, state_2: &Blake2b) {
		assert_eq!(state_1.init_state, state_2.init_state);
		assert_eq!(state_1.internal_state, state_2.internal_state);
		assert_eq!(state_1.buffer[..], state_2.buffer[..]);
		assert_eq!(state_1.leftover, state_2.leftover);
		assert_eq!(state_1.t, state_2.t);
		assert_eq!(state_1.f, state_2.f);
		assert_eq!(state_1.is_finalized, state_2.is_finalized);
		assert_eq!(state_1.is_keyed, state_2.is_keyed);
		assert_eq!(state_1.size, state_2.size);
	}

	mod test_init {
		use super::*;

		/// Convenience testing function to avoid repetition when testing
		/// init sizes with and without a secret key. Returns false if
		/// incorrect Result is returned.
		fn init_tester(sk: Option<&SecretKey>, size: usize) -> bool {
			if size >= 1 && size <= BLAKE2B_OUTSIZE {
				let res = if init(sk, size).is_ok() { true } else { false };

				return res;
			} else {
				let res = if init(sk, size).is_err() { true } else { false };

				return res;
			}
		}

		#[test]
		fn test_init_size() {
			assert!(init_tester(None, 0));
			assert!(init_tester(None, 65));
			assert!(init_tester(None, 64));
			assert!(init_tester(None, 1));

			let sk = SecretKey::from_slice(&[0u8; 64]).unwrap();
			assert!(init_tester(Some(&sk), 0));
			assert!(init_tester(Some(&sk), 65));
			assert!(init_tester(Some(&sk), 64));
			assert!(init_tester(Some(&sk), 1));
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Given a valid size parameter, init should always pass. If size
				/// is invalid, then init should always fail.
				fn prop_init_size_no_key(size: usize) -> bool {
					init_tester(None, size)
				}
			}

			quickcheck! {
				/// Given a valid size parameter, init should always pass. If size
				/// is invalid, then init should always fail.
				fn prop_init_size_key(size: usize) -> bool {
					let sk = SecretKey::generate().unwrap();
					init_tester(Some(&sk), size)
				}
			}
		}
	}

	mod test_verify {
		use super::*;

		#[test]
		fn finalize_and_verify_true() {
			let secret_key = SecretKey::from_slice("Jefe".as_bytes()).unwrap();
			let data = "what do ya want for nothing?".as_bytes();

			let mut tag = init(Some(&secret_key), 64).unwrap();
			tag.update(data).unwrap();

			assert_eq!(
				verify(
					&tag.finalize().unwrap(),
					&SecretKey::from_slice("Jefe".as_bytes()).unwrap(),
					64,
					data
				)
				.unwrap(),
				true
			);
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// When using the same parameters verify() should always yeild true.
				fn prop_verify_same_params_true(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();

					let mut state = init(Some(&sk), 64).unwrap();
					state.update(&data[..]).unwrap();
					let tag = state.finalize().unwrap();
					// Failed verification on Err so res is not needed.
					let _res = verify(&tag, &sk, 64, &data[..]).unwrap();

					true
				}
			}

			quickcheck! {
				/// When using the same parameters verify() should always yeild true.
				fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
					let sk = SecretKey::generate().unwrap();
					let mut state = init(Some(&sk), 64).unwrap();
					state.update(&data[..]).unwrap();
					let tag = state.finalize().unwrap();

					let bad_sk = SecretKey::generate().unwrap();

					let res = if verify(&tag, &bad_sk, 64, &data[..]).is_err() {
						true
					} else {
						false
					};

					res
				}
			}
		}
	}

	mod test_hasher {
		use super::*;

		#[test]
		fn test_hasher_interface_no_panic_and_same_result() {
			let digest_256 = Hasher::Blake2b256.digest(b"Test").unwrap();
			let digest_384 = Hasher::Blake2b384.digest(b"Test").unwrap();
			let digest_512 = Hasher::Blake2b512.digest(b"Test").unwrap();

			assert_eq!(digest_256, Hasher::Blake2b256.digest(b"Test").unwrap());
			assert_eq!(digest_384, Hasher::Blake2b384.digest(b"Test").unwrap());
			assert_eq!(digest_512, Hasher::Blake2b512.digest(b"Test").unwrap());

			assert_ne!(digest_256, Hasher::Blake2b256.digest(b"Wrong").unwrap());
			assert_ne!(digest_384, Hasher::Blake2b384.digest(b"Wrong").unwrap());
			assert_ne!(digest_512, Hasher::Blake2b512.digest(b"Wrong").unwrap());

			let _state_256 = Hasher::Blake2b256.init().unwrap();
			let _state_384 = Hasher::Blake2b384.init().unwrap();
			let _state_512 = Hasher::Blake2b512.init().unwrap();
		}

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Given some data, .digest() should never fail in practice and should
				/// produce the same output on a second call.
				/// Only if data is unreasonably large.
				fn prop_hasher_digest_no_panic_and_same_result(data: Vec<u8>) -> bool {
					let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();
					let d384 = Hasher::Blake2b384.digest(&data[..]).unwrap();
					let d512 = Hasher::Blake2b512.digest(&data[..]).unwrap();

					let d256_re = Hasher::Blake2b256.digest(&data[..]).unwrap();
					let d384_re = Hasher::Blake2b384.digest(&data[..]).unwrap();
					let d512_re = Hasher::Blake2b512.digest(&data[..]).unwrap();

					(d256 == d256_re) && (d384 == d384_re) && (d512 == d512_re)
				}
			}

			quickcheck! {
				/// Given some data, .digest() should produce the same output as when
				/// calling with streaming state.
				fn prop_hasher_digest_256_same_as_streaming(data: Vec<u8>) -> bool {
					let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();;

					let mut state = init(None, 32).unwrap();
					state.update(&data[..]).unwrap();

					(d256 == state.finalize().unwrap())
				}
			}

			quickcheck! {
				/// Given some data, .digest() should produce the same output as when
				/// calling with streaming state.
				fn prop_hasher_digest_384_same_as_streaming(data: Vec<u8>) -> bool {
					let d256 = Hasher::Blake2b384.digest(&data[..]).unwrap();;

					let mut state = init(None, 48).unwrap();
					state.update(&data[..]).unwrap();

					(d256 == state.finalize().unwrap())
				}
			}

			quickcheck! {
				/// Given some data, .digest() should produce the same output as when
				/// calling with streaming state.
				fn prop_hasher_digest_512_same_as_streaming(data: Vec<u8>) -> bool {
					let d256 = Hasher::Blake2b512.digest(&data[..]).unwrap();;

					let mut state = init(None, 64).unwrap();
					state.update(&data[..]).unwrap();

					(d256 == state.finalize().unwrap())
				}
			}

			quickcheck! {
				/// Given two different data, .digest() should never produce the
				/// same output.ValidationCryptoError
				fn prop_hasher_digest_diff_input_diff_result(data: Vec<u8>) -> bool {
					let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();
					let d384 = Hasher::Blake2b384.digest(&data[..]).unwrap();
					let d512 = Hasher::Blake2b512.digest(&data[..]).unwrap();

					let d256_re = Hasher::Blake2b256.digest(b"Wrong data").unwrap();
					let d384_re = Hasher::Blake2b384.digest(b"Wrong data").unwrap();
					let d512_re = Hasher::Blake2b512.digest(b"Wrong data").unwrap();

					(d256 != d256_re) && (d384 != d384_re) && (d512 != d512_re)
				}
			}

			quickcheck! {
				/// .init() should never fail.
				fn prop_hasher_init_no_panic() -> bool {
					let _d256 = Hasher::Blake2b256.init().unwrap();
					let _d384 = Hasher::Blake2b384.init().unwrap();
					let _d512 = Hasher::Blake2b512.init().unwrap();

					true
				}
			}
		}
	}

	mod test_reset {
		use super::*;

		#[test]
		fn test_double_reset_ok() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Tests").unwrap();
			let _ = state.finalize().unwrap();
			state.reset(None).unwrap();
			state.reset(None).unwrap();
		}

		#[test]
		fn test_switching_keyed_modes_fails() {
			let secret_key = SecretKey::from_slice(b"Testing").unwrap();

			let mut state = init(Some(&secret_key), 64).unwrap();
			state.update(b"Tests").unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.reset(None).is_err());
			assert!(state.reset(Some(&secret_key)).is_ok());

			let mut state_second = init(None, 64).unwrap();
			state_second.update(b"Tests").unwrap();
			let _ = state_second.finalize().unwrap();
			assert!(state_second.reset(Some(&secret_key)).is_err());
			assert!(state_second.reset(None).is_ok());
		}
	}

	mod test_update {
		use super::*;

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/28
		fn test_update_after_finalize_fail() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Test").unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.update(b"Test").is_err());
		}

		#[test]
		fn test_update_after_finalize_with_reset() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Test").unwrap();
			let _ = state.finalize().unwrap();
			state.reset(None).unwrap();
			assert!(state.update(b"Test").is_ok());
		}
	}

	mod test_finalize {
		use super::*;

		#[test]
		fn test_double_finalize_fail() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Test").unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.finalize().is_err());
		}

		#[test]
		fn test_finalize_after_reset() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Test").unwrap();
			let _ = state.finalize().unwrap();
			state.reset(None).unwrap();
			assert!(state.finalize().is_ok());
		}

		#[test]
		fn test_double_finalize_with_reset_no_update() {
			let mut state = init(None, 64).unwrap();
			state.update(b"Test").unwrap();
			let _ = state.finalize().unwrap();
			state.reset(None).unwrap();
			let _ = state.finalize().unwrap();
		}
	}

	mod test_streaming_interface {
		use super::*;

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest/Tag.
		fn produces_same_hash(sk: Option<&SecretKey>, size: usize, data: &[u8]) {
			// init(), update(), finalize()
			let mut state_1 = init(sk, size).unwrap();
			state_1.update(data).unwrap();
			let res_1 = state_1.finalize().unwrap();

			// init(), reset(), update(), finalize()
			let mut state_2 = init(sk, size).unwrap();
			state_2.reset(sk).unwrap();
			state_2.update(data).unwrap();
			let res_2 = state_2.finalize().unwrap();

			// init(), update(), reset(), update(), finalize()
			let mut state_3 = init(sk, size).unwrap();
			state_3.update(data).unwrap();
			state_3.reset(sk).unwrap();
			state_3.update(data).unwrap();
			let res_3 = state_3.finalize().unwrap();

			// init(), update(), finalize(), reset(), update(), finalize()
			let mut state_4 = init(sk, size).unwrap();
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset(sk).unwrap();
			state_4.update(data).unwrap();
			let res_4 = state_4.finalize().unwrap();

			assert_eq!(res_1, res_2);
			assert_eq!(res_2, res_3);
			assert_eq!(res_3, res_4);

			// Tests for the assumption that returning Ok() on empty update() calls
			// with streaming API's, gives the correct result. This is done by testing
			// the reasoning that if update() is empty, returns Ok(), it is the same as
			// calling init() -> finalize(). i.e not calling update() at all.
			if data.is_empty() {
				// init(), finalize()
				let mut state_5 = init(sk, size).unwrap();
				let res_5 = state_5.finalize().unwrap();

				// init(), reset(), finalize()
				let mut state_6 = init(sk, size).unwrap();
				state_6.reset(sk).unwrap();
				let res_6 = state_6.finalize().unwrap();

				// init(), update(), reset(), finalize()
				let mut state_7 = init(sk, size).unwrap();
				state_7.update(b"Wrong data").unwrap();
				state_7.reset(sk).unwrap();
				let res_7 = state_7.finalize().unwrap();

				assert_eq!(res_4, res_5);
				assert_eq!(res_5, res_6);
				assert_eq!(res_6, res_7);
			}
		}

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest/Tag.
		fn produces_same_state(sk: Option<&SecretKey>, size: usize, data: &[u8]) {
			// init()
			let state_1 = init(sk, size).unwrap();

			// init(), reset()
			let mut state_2 = init(sk, size).unwrap();
			state_2.reset(sk).unwrap();

			// init(), update(), reset()
			let mut state_3 = init(sk, size).unwrap();
			state_3.update(data).unwrap();
			state_3.reset(sk).unwrap();

			// init(), update(), finalize(), reset()
			let mut state_4 = init(sk, size).unwrap();
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset(sk).unwrap();

			compare_blake2b_states(&state_1, &state_2);
			compare_blake2b_states(&state_2, &state_3);
			compare_blake2b_states(&state_3, &state_4);
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_state() {
			produces_same_state(None, 1, b"Tests");
			produces_same_state(None, 32, b"Tests");
			produces_same_state(None, 64, b"Tests");
			produces_same_state(None, 28, b"Tests");

			let sk = SecretKey::from_slice(b"Testing").unwrap();
			produces_same_state(Some(&sk), 1, b"Tests");
			produces_same_state(Some(&sk), 32, b"Tests");
			produces_same_state(Some(&sk), 64, b"Tests");
			produces_same_state(Some(&sk), 28, b"Tests");
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_hash() {
			produces_same_hash(None, 1, b"Tests");
			produces_same_hash(None, 32, b"Tests");
			produces_same_hash(None, 64, b"Tests");
			produces_same_hash(None, 28, b"Tests");

			let sk = SecretKey::from_slice(b"Testing").unwrap();
			produces_same_hash(Some(&sk), 1, b"Tests");
			produces_same_hash(Some(&sk), 32, b"Tests");
			produces_same_hash(Some(&sk), 64, b"Tests");
			produces_same_hash(Some(&sk), 28, b"Tests");
		}

		#[test]
		#[cfg(feature = "safe_api")]
		// Test for issues when incrementally processing data
		// with leftover
		fn test_streaming_consistency() {
			for len in 0..BLAKE2B_BLOCKSIZE * 4 {
				let data = vec![0u8; len];
				let mut state = init(None, 64).unwrap();
				let mut other_data: Vec<u8> = Vec::new();

				other_data.extend_from_slice(&data);
				state.update(&data).unwrap();

				if data.len() > BLAKE2B_BLOCKSIZE {
					other_data.extend_from_slice(b"");
					state.update(b"").unwrap();
				}
				if data.len() > BLAKE2B_BLOCKSIZE * 2 {
					other_data.extend_from_slice(b"Extra");
					state.update(b"Extra").unwrap();
				}
				if data.len() > BLAKE2B_BLOCKSIZE * 3 {
					other_data.extend_from_slice(&[0u8; 256]);
					state.update(&[0u8; 256]).unwrap();
				}

				let digest_one_shot = Hasher::Blake2b512.digest(&other_data).unwrap();

				assert!(state.finalize().unwrap().as_bytes() == digest_one_shot.as_bytes());
			}
		}
		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_hash_different_usage(data: Vec<u8>, size: usize) -> bool {
					if size >= 1 && size <= BLAKE2B_OUTSIZE {
						// Will panic on incorrect results.
						produces_same_hash(None, size, &data[..]);
						let sk = SecretKey::generate().unwrap();
						produces_same_hash(Some(&sk), size, &data[..]);
					}

					true
				}
			}

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_state_different_usage(data: Vec<u8>, size: usize) -> bool {
					if size >= 1 && size <= BLAKE2B_OUTSIZE {
						// Will panic on incorrect results.
						produces_same_state(None, size, &data[..]);
						let sk = SecretKey::generate().unwrap();
						produces_same_state(Some(&sk), size, &data[..]);
					}

					true
				}
			}
		}
	}
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
	use super::*;
	// One function tested per submodule.

	mod test_increment_offset {
		use super::*;

		#[test]
		fn test_offset_increase_values() {
			let mut context = Blake2b {
				init_state: [0u64; 8],
				internal_state: IV,
				buffer: [0u8; BLAKE2B_BLOCKSIZE],
				leftover: 0,
				t: [0u64; 2],
				f: [0u64; 2],
				is_finalized: false,
				is_keyed: false,
				size: 1,
			};

			context.increment_offset(1);
			assert!(context.t == [1u64, 0u64]);
			context.increment_offset(17);
			assert!(context.t == [18u64, 0u64]);
			context.increment_offset(12);
			assert!(context.t == [30u64, 0u64]);
			// Overflow
			context.increment_offset(u64::max_value());
			assert!(context.t == [29u64, 1u64]);
		}

		#[test]
		#[should_panic]
		fn test_panic_on_second_overflow() {
			let mut context = Blake2b {
				init_state: [0u64; 8],
				internal_state: IV,
				buffer: [0u8; BLAKE2B_BLOCKSIZE],
				leftover: 0,
				t: [1u64, u64::max_value()],
				f: [0u64; 2],
				is_finalized: false,
				is_keyed: false,
				size: 1,
			};

			context.increment_offset(u64::max_value());
		}
	}
}
