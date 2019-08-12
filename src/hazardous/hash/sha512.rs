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
//! - `data`: The data to be hashed.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2*(2^64-1) __bits__ of data are hashed.
//!
//! # Security:
//! - SHA512 is vulnerable to length extension attacks.
//!
//! # Recommendation:
//! - It is recommended to use [BLAKE2b] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha512;
//!
//! // Using the streaming interface
//! let mut state = sha512::init();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = sha512::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: https://docs.rs/orion/latest/orion/hazardous/hash/sha512/struct.Sha512.html
//! [`reset()`]: https://docs.rs/orion/latest/orion/hazardous/hash/sha512/struct.Sha512.html
//! [`finalize()`]: https://docs.rs/orion/latest/orion/hazardous/hash/sha512/struct.Sha512.html
//! [BLAKE2b]: https://docs.rs/orion/latest/orion/hazardous/hash/blake2b/index.html

use crate::{
	endianness::{load_u64_into_be, store_u64_into_be},
	errors::UnknownCryptoError,
};

/// The blocksize for the hash function SHA512.
pub const SHA512_BLOCKSIZE: usize = 128;
/// The output size for the hash function SHA512.
pub const SHA512_OUTSIZE: usize = 64;

construct_public! {
	/// A type to represent the `Digest` that SHA512 returns.
	///
	/// # Errors:
	/// An error will be returned if:
	/// - `slice` is not 64 bytes.
	(Digest, test_digest, SHA512_OUTSIZE, SHA512_OUTSIZE)
}

impl_from_trait!(Digest, SHA512_OUTSIZE);

#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
/// The SHA512 constants as defined in the FIPS 180-4.
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
/// The SHA512 initial hash value H(0) as defined in the FIPS 180-4.
const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

#[derive(Clone)]
/// SHA512 streaming state.
pub struct Sha512 {
	working_state: [u64; 8],
	buffer: [u8; SHA512_BLOCKSIZE],
	leftover: usize,
	message_len: [u64; 2],
	is_finalized: bool,
}

impl Drop for Sha512 {
	fn drop(&mut self) {
		use zeroize::Zeroize;
		self.working_state.zeroize();
		self.buffer.zeroize();
		self.message_len.zeroize();
	}
}

impl core::fmt::Debug for Sha512 {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"Sha512 {{ working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: {:?}, \
			 message_len: {:?}, is_finalized: {:?} }}",
			self.leftover, self.message_len, self.is_finalized
		)
	}
}

impl Sha512 {
	#[inline]
	/// The Ch function as specified in FIPS 180-4 section 4.1.3.
	fn ch(x: u64, y: u64, z: u64) -> u64 {
		z ^ (x & (y ^ z))
	}

	#[inline]
	/// The Maj function as specified in FIPS 180-4 section 4.1.3.
	fn maj(x: u64, y: u64, z: u64) -> u64 {
		(x & y) | (z & (x | y))
	}

	#[inline]
	/// The Big Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
	fn big_sigma_0(x: u64) -> u64 {
		(x.rotate_right(28)) ^ x.rotate_right(34) ^ x.rotate_right(39)
	}

	#[inline]
	/// The Big Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
	fn big_sigma_1(x: u64) -> u64 {
		(x.rotate_right(14)) ^ x.rotate_right(18) ^ x.rotate_right(41)
	}

	#[inline]
	/// The Small Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
	fn small_sigma_0(x: u64) -> u64 {
		(x.rotate_right(1)) ^ x.rotate_right(8) ^ (x >> 7)
	}

	#[inline]
	/// The Small Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
	fn small_sigma_1(x: u64) -> u64 {
		(x.rotate_right(19)) ^ x.rotate_right(61) ^ (x >> 6)
	}

	#[inline]
	#[allow(clippy::many_single_char_names)]
	#[allow(clippy::too_many_arguments)]
	/// Message compression adopted from [mbed TLS](https://tls.mbed.org/sha-512-source-code).
	fn compress(
		a: u64,
		b: u64,
		c: u64,
		d: &mut u64,
		e: u64,
		f: u64,
		g: u64,
		h: &mut u64,
		x: u64,
		ki: u64,
	) {
		let temp1 = h
			.wrapping_add(Self::big_sigma_1(e))
			.wrapping_add(Self::ch(e, f, g))
			.wrapping_add(ki)
			.wrapping_add(x);

		let temp2 = Self::big_sigma_0(a).wrapping_add(Self::maj(a, b, c));

		*d = d.wrapping_add(temp1);
		*h = temp1.wrapping_add(temp2);
	}

	#[inline]
	#[rustfmt::skip]
	#[allow(clippy::many_single_char_names)]
	/// Process data in `self.buffer`.
	fn process(&mut self, data: Option<&[u8]>) {
		let mut w = [0u64; 80];
		match data {
			Some(bytes) => {
				debug_assert!(bytes.len() == SHA512_BLOCKSIZE);
				load_u64_into_be(bytes, &mut w[..16]);
			}
			None => load_u64_into_be(&self.buffer, &mut w[..16]),
		}

		for t in 16..80 {
			w[t] = Self::small_sigma_1(w[t - 2])
				.wrapping_add(w[t - 7])
				.wrapping_add(Self::small_sigma_0(w[t - 15]))
				.wrapping_add(w[t - 16]);
		}

		// Initialize working variables
		let mut a = self.working_state[0];
		let mut b = self.working_state[1];
		let mut c = self.working_state[2];
		let mut d = self.working_state[3];
		let mut e = self.working_state[4];
		let mut f = self.working_state[5];
		let mut g = self.working_state[6];
		let mut h = self.working_state[7];

		let mut t = 0;
		while t < 80 {
			Self::compress(a, b, c, &mut d, e, f, g, &mut h, w[t], K[t]); t += 1;
			Self::compress(h, a, b, &mut c, d, e, f, &mut g, w[t], K[t]); t += 1;
			Self::compress(g, h, a, &mut b, c, d, e, &mut f, w[t], K[t]); t += 1;
			Self::compress(f, g, h, &mut a, b, c, d, &mut e, w[t], K[t]); t += 1;
			Self::compress(e, f, g, &mut h, a, b, c, &mut d, w[t], K[t]); t += 1;
			Self::compress(d, e, f, &mut g, h, a, b, &mut c, w[t], K[t]); t += 1;
			Self::compress(c, d, e, &mut f, g, h, a, &mut b, w[t], K[t]); t += 1;
			Self::compress(b, c, d, &mut e, f, g, h, &mut a, w[t], K[t]); t += 1;
		}

		self.working_state[0] = self.working_state[0].wrapping_add(a);
		self.working_state[1] = self.working_state[1].wrapping_add(b);
		self.working_state[2] = self.working_state[2].wrapping_add(c);
		self.working_state[3] = self.working_state[3].wrapping_add(d);
		self.working_state[4] = self.working_state[4].wrapping_add(e);
		self.working_state[5] = self.working_state[5].wrapping_add(f);
		self.working_state[6] = self.working_state[6].wrapping_add(g);
		self.working_state[7] = self.working_state[7].wrapping_add(h);
	}

	/// Reset to `init()` state.
	pub fn reset(&mut self) {
		self.working_state = H0;
		self.buffer = [0u8; SHA512_BLOCKSIZE];
		self.leftover = 0;
		self.message_len = [0u64; 2];
		self.is_finalized = false;
	}

	#[inline]
	/// Increment the message length during processing of data.
	fn increment_mlen(&mut self, length: u64) {
		// The checked shift checks that the right-hand side is a legal shift.
		// The result can still overflow if length > u64::max_value() / 8.
		// Should be impossible for a user to trigger.
		debug_assert!(length <= u64::max_value() / 8);

		// left-shift to get bit-sized representation of length
		// using .unwrap() because it should not panic in practice
		let len = length.checked_shl(3).unwrap();
		let (res, was_overflow) = self.message_len[1].overflowing_add(len);
		self.message_len[1] = res;

		if was_overflow {
			// If this panics size limit is reached.
			self.message_len[0] = self.message_len[0].checked_add(1).unwrap();
		}
	}

	#[must_use]
	/// Update state with `data`. This can be called multiple times.
	pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
		if self.is_finalized {
			return Err(UnknownCryptoError);
		}
		if data.is_empty() {
			return Ok(());
		}

		let mut bytes = data;

		if self.leftover != 0 {
			debug_assert!(self.leftover <= SHA512_BLOCKSIZE);

			let mut want = SHA512_BLOCKSIZE - self.leftover;
			if want > bytes.len() {
				want = bytes.len();
			}

			for (idx, itm) in bytes.iter().enumerate().take(want) {
				self.buffer[self.leftover + idx] = *itm;
			}

			// Reduce by slice
			bytes = &bytes[want..];
			self.leftover += want;
			self.increment_mlen(want as u64);

			if self.leftover < SHA512_BLOCKSIZE {
				return Ok(());
			}

			self.process(None);
			self.leftover = 0;
		}

		while bytes.len() >= SHA512_BLOCKSIZE {
			// Process data
			self.process(Some(bytes[..SHA512_BLOCKSIZE].as_ref()));
			self.increment_mlen(SHA512_BLOCKSIZE as u64);
			// Reduce by slice
			bytes = &bytes[SHA512_BLOCKSIZE..];
		}

		if !bytes.is_empty() {
			debug_assert!(self.leftover == 0);

			self.buffer[..bytes.len()].copy_from_slice(bytes);
			self.leftover = bytes.len();
			self.increment_mlen(bytes.len() as u64);
		}

		Ok(())
	}

	#[must_use]
	/// Return a SHA512 digest.
	pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
		if self.is_finalized {
			return Err(UnknownCryptoError);
		}

		self.is_finalized = true;

		// self.leftover should not be greater than SHA2_BLCOKSIZE
		// as that would have been processed in the update call
		debug_assert!(self.leftover < SHA512_BLOCKSIZE);
		self.buffer[self.leftover] = 0x80;
		self.leftover += 1;

		for itm in self.buffer.iter_mut().skip(self.leftover) {
			*itm = 0;
		}

		// Check for available space for length padding
		if (SHA512_BLOCKSIZE - self.leftover) < 16 {
			self.process(None);
			for itm in self.buffer.iter_mut().take(self.leftover) {
				*itm = 0;
			}
		}

		// Pad with length
		self.buffer[SHA512_BLOCKSIZE - 16..SHA512_BLOCKSIZE - 8]
			.copy_from_slice(&self.message_len[0].to_be_bytes());
		self.buffer[SHA512_BLOCKSIZE - 8..SHA512_BLOCKSIZE]
			.copy_from_slice(&self.message_len[1].to_be_bytes());

		self.process(None);

		let mut digest = [0u8; SHA512_OUTSIZE];
		store_u64_into_be(&self.working_state, &mut digest);

		Ok(Digest::from(digest))
	}
}

#[must_use]
/// Initialize a `Sha512` struct.
pub fn init() -> Sha512 {
	Sha512 {
		working_state: H0,
		buffer: [0u8; SHA512_BLOCKSIZE],
		leftover: 0,
		message_len: [0u64; 2],
		is_finalized: false,
	}
}

#[must_use]
/// Calculate a SHA512 digest of some `data`.
pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
	let mut state = init();
	state.update(data)?;
	state.finalize()
}

#[cfg(test)]
/// Compare two Sha512 state objects to check if their fields
/// are the same.
pub fn compare_sha512_states(state_1: &Sha512, state_2: &Sha512) {
	assert_eq!(state_1.working_state, state_2.working_state);
	assert_eq!(state_1.buffer[..], state_2.buffer[..]);
	assert_eq!(state_1.leftover, state_2.leftover);
	assert_eq!(state_1.message_len, state_2.message_len);
	assert_eq!(state_1.is_finalized, state_2.is_finalized);
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	// One function tested per submodule.
	mod test_reset {
		use super::*;

		#[test]
		fn test_double_reset_ok() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			state.reset();
		}
	}

	mod test_update {
		use super::*;

		#[test]
		fn test_update_after_finalize_with_reset_ok() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			state.update(data).unwrap();
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/28
		fn test_update_after_finalize_err() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.update(data).is_err());
		}
	}

	mod test_finalize {
		use super::*;

		#[test]
		fn test_double_finalize_with_reset_no_update_ok() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			state.reset();
			let _ = state.finalize().unwrap();
		}

		#[test]
		fn test_double_finalize_with_reset_ok() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let one = state.finalize().unwrap();
			state.reset();
			state.update(data).unwrap();
			let two = state.finalize().unwrap();
			assert_eq!(one.as_ref(), two.as_ref());
		}

		#[test]
		fn test_double_finalize_err() {
			let data = "what do ya want for nothing?".as_bytes();

			let mut state = init();
			state.update(data).unwrap();
			let _ = state.finalize().unwrap();
			assert!(state.finalize().is_err());
		}

	}

	mod test_streaming_interface {
		use super::*;

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest.
		fn produces_same_hash(data: &[u8]) {
			// init(), update(), finalize()
			let mut state_1 = init();
			state_1.update(data).unwrap();
			let res_1 = state_1.finalize().unwrap();

			// init(), reset(), update(), finalize()
			let mut state_2 = init();
			state_2.reset();
			state_2.update(data).unwrap();
			let res_2 = state_2.finalize().unwrap();

			// init(), update(), reset(), update(), finalize()
			let mut state_3 = init();
			state_3.update(data).unwrap();
			state_3.reset();
			state_3.update(data).unwrap();
			let res_3 = state_3.finalize().unwrap();

			// init(), update(), finalize(), reset(), update(), finalize()
			let mut state_4 = init();
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset();
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
				let mut state_5 = init();
				let res_5 = state_5.finalize().unwrap();

				// init(), reset(), finalize()
				let mut state_6 = init();
				state_6.reset();
				let res_6 = state_6.finalize().unwrap();

				// init(), update(), reset(), finalize()
				let mut state_7 = init();
				state_7.update(b"Wrong data").unwrap();
				state_7.reset();
				let res_7 = state_7.finalize().unwrap();

				assert_eq!(res_4, res_5);
				assert_eq!(res_5, res_6);
				assert_eq!(res_6, res_7);
			}
		}

		/// Related bug: https://github.com/brycx/orion/issues/46
		/// Testing different usage combinations of init(), update(),
		/// finalize() and reset() produce the same Digest.
		fn produces_same_state(data: &[u8]) {
			// init()
			let state_1 = init();

			// init(), reset()
			let mut state_2 = init();
			state_2.reset();

			// init(), update(), reset()
			let mut state_3 = init();
			state_3.update(data).unwrap();
			state_3.reset();

			// init(), update(), finalize(), reset()
			let mut state_4 = init();
			state_4.update(data).unwrap();
			let _ = state_4.finalize().unwrap();
			state_4.reset();

			compare_sha512_states(&state_1, &state_2);
			compare_sha512_states(&state_2, &state_3);
			compare_sha512_states(&state_3, &state_4);
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_state() {
			produces_same_state(b"Tests");
		}

		#[test]
		/// Related bug: https://github.com/brycx/orion/issues/46
		fn test_produce_same_hash() {
			produces_same_hash(b"Tests");
			produces_same_hash(b"");
		}

		#[test]
		#[cfg(feature = "safe_api")]
		// Test for issues when incrementally processing data
		// with leftover
		fn test_streaming_consistency() {
			for len in 0..SHA512_BLOCKSIZE * 4 {
				let data = vec![0u8; len];
				let mut state = init();
				let mut other_data: Vec<u8> = Vec::new();

				other_data.extend_from_slice(&data);
				state.update(&data).unwrap();

				if data.len() > SHA512_BLOCKSIZE {
					other_data.extend_from_slice(b"");
					state.update(b"").unwrap();
				}
				if data.len() > SHA512_BLOCKSIZE * 2 {
					other_data.extend_from_slice(b"Extra");
					state.update(b"Extra").unwrap();
				}
				if data.len() > SHA512_BLOCKSIZE * 3 {
					other_data.extend_from_slice(&[0u8; 256]);
					state.update(&[0u8; 256]).unwrap();
				}

				let digest_one_shot = digest(&other_data).unwrap();

				assert!(state.finalize().unwrap().as_ref() == digest_one_shot.as_ref());
			}
		}
		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(feature = "safe_api")]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_hash_different_usage(data: Vec<u8>) -> bool {
					// Will panic on incorrect results.
					produces_same_hash(&data[..]);

					true
				}
			}

			quickcheck! {
				/// Related bug: https://github.com/brycx/orion/issues/46
				/// Test different streaming state usage patterns.
				fn prop_same_state_different_usage(data: Vec<u8>) -> bool {
					// Will panic on incorrect results.
					produces_same_state(&data[..]);

					true
				}
			}

			quickcheck! {
				/// Using the one-shot function should always produce the
				/// same result as when using the streaming interface.
				fn prop_digest_same_as_streaming(data: Vec<u8>) -> bool {
					let mut state = init();
					state.update(&data[..]).unwrap();
					let stream = state.finalize().unwrap();
					let one_shot = digest(&data[..]).unwrap();

					(one_shot == stream)
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

	mod test_increment_mlen {
		use super::*;

		#[test]
		fn test_mlen_increase_values() {
			let mut context = Sha512 {
				working_state: H0,
				buffer: [0u8; SHA512_BLOCKSIZE],
				leftover: 0,
				message_len: [0u64; 2],
				is_finalized: false,
			};

			context.increment_mlen(1);
			assert!(context.message_len == [0u64, 8u64]);
			context.increment_mlen(17);
			assert!(context.message_len == [0u64, 144u64]);
			context.increment_mlen(12);
			assert!(context.message_len == [0u64, 240u64]);
			// Overflow
			context.increment_mlen(u64::max_value() / 8);
			assert!(context.message_len == [1u64, 232u64]);
		}

		#[test]
		#[should_panic]
		fn test_panic_on_second_overflow() {
			let mut context = Sha512 {
				working_state: H0,
				buffer: [0u8; SHA512_BLOCKSIZE],
				leftover: 0,
				message_len: [u64::max_value(), u64::max_value() - 7],
				is_finalized: false,
			};
			// u64::max_value() - 7, to leave so that the length represented
			// in bites should overflow by exactly one.

			context.increment_mlen(1);
		}
	}
}
