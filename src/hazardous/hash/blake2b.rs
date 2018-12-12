// MIT License

// Copyright (c) 2018 brycx

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
//! - `secret_key`: An optional secret key value.
//! - `size`: The desired output digest length.
//! - `data`: The bytes to be hashed.
//! - `expected`: The expected digest when verifying.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `size` is 0.
//! - `size` is greater than 64.
//! - Either `finalize()` or `finalize_with_dst()` is called twice without a
//!   `reset()` in between.
//! - `update()` is called after `finalize()` without a `reset()` in between.
//! - `reset()` is called with `Some(secret_key)` but the struct was initialized
//!   with `None`.
//! - `reset()` is called with `None` secret_key but the struct was initialized
//!   with `Some()`.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   `SecretKey::generate()` can be used
//! for this. It generates a secret key of 64 bytes.
//! - The minimum recommended size for a secret key is 64 bytes.
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

use byteorder::{ByteOrder, LittleEndian};
use errors::*;
use hazardous::constants::{BLAKE2B_BLOCKSIZE, BLAKE2B_OUTSIZE};

construct_blake2b_key! {
	/// A type to represent the `SecretKey` that BLAKE2b uses for keyed mode.
	///
	/// # Note:
	/// `SecretKey` pads the secret key for use with BLAKE2b, when initialized.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `slice` is empty.
	/// - `slice` is greater than 64 bytes.
	/// - The `OsRng` fails to initialize or read from its source.
	(SecretKey, BLAKE2B_BLOCKSIZE)
}

construct_blake2b_digest! {
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
		use clear_on_drop::clear::Clear;
		self.init_state.clear();
		self.internal_state.clear();
		self.buffer.clear();
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
	fn increment_offset(&mut self, value: u64) -> Result<(), UnknownCryptoError> {
		// Check for overflow
		if self.t[0].checked_add(value).is_none() {
			return Err(UnknownCryptoError);
		}

		self.t[0] = self.t[0].checked_add(value).unwrap();
		if self.t[0] < value {
			self.t[1] += 1;
		}

		Ok(())
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

	#[inline(always)]
	#[allow(clippy::needless_range_loop)]
	/// The compression function f as defined in the RFC.
	fn compress_f(&mut self) {
		let mut m_vec = [0u64; 16];
		LittleEndian::read_u64_into(&self.buffer, &mut m_vec);
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
	#[inline(always)]
	/// Reset to `init()` state.
	pub fn reset(&mut self, secret_key: Option<&SecretKey>) -> Result<(), UnknownCryptoError> {
		if self.is_finalized {
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
				self.update(secret_key.unwrap().unprotected_as_bytes())?;
			}

			Ok(())
		} else {
			Ok(())
		}
	}

	#[must_use]
	#[inline(always)]
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
			let fill = BLAKE2B_BLOCKSIZE - self.leftover;

			if bytes.len() <= fill {
				self.buffer[self.leftover..(self.leftover + bytes.len())].copy_from_slice(&bytes);
				self.leftover += bytes.len();
				return Ok(());
			}

			self.buffer[self.leftover..(self.leftover + fill)].copy_from_slice(&bytes[..fill]);
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64)?;
			self.compress_f();
			// Remve the amount of blocks we just prossed
			self.leftover = 0;
			// Reduce by slice
			bytes = &bytes[fill..];
		}

		while bytes.len() > BLAKE2B_BLOCKSIZE {
			self.buffer.copy_from_slice(&bytes[..BLAKE2B_BLOCKSIZE]);
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64)?;
			self.compress_f();
			// Reduce by slice
			bytes = &bytes[BLAKE2B_BLOCKSIZE..];
		}

		if !bytes.is_empty() {
			self.buffer[self.leftover..(self.leftover + bytes.len())].copy_from_slice(&bytes);
			self.leftover += bytes.len();
		}

		Ok(())
	}

	#[must_use]
	#[inline(always)]
	/// Return a BLAKE2b digest.
	pub fn finalize(&mut self) -> Result<Digest, FinalizationCryptoError> {
		if self.is_finalized {
			return Err(FinalizationCryptoError);
		}

		self.is_finalized = true;

		let mut digest = [0u8; 64];

		let in_buffer_len = self.leftover;
		self.increment_offset(in_buffer_len as u64)?;
		// Mark that it is the last block of data to be processed
		self.f[0] = !0;

		for leftover_block in self.buffer.iter_mut().skip(in_buffer_len) {
			*leftover_block = 0;
		}
		self.compress_f();

		LittleEndian::write_u64_into(&self.internal_state, &mut digest);

		Ok(Digest::from_slice(&digest[..self.size])?)
	}
}

#[must_use]
#[inline(always)]
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
		let key = secret_key.unwrap();
		let klen = key.get_original_length();
		context.internal_state[0] ^= 0x01010000 ^ ((klen as u64) << 8) ^ (size as u64);
		context.init_state.copy_from_slice(&context.internal_state);
		context.update(key.unprotected_as_bytes())?;
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

#[test]
fn test_init_bad_sizes() {
	assert!(init(None, 0).is_err());
	assert!(init(None, 65).is_err());
	assert!(init(None, 64).is_ok());
	assert!(init(None, 1).is_ok());
}

#[test]
fn test_hasher_interface() {
	let _digest_256 = Hasher::Blake2b256.digest(b"Test").unwrap();
	let _digest_384 = Hasher::Blake2b384.digest(b"Test").unwrap();
	let _digest_512 = Hasher::Blake2b512.digest(b"Test").unwrap();

	let _state_256 = Hasher::Blake2b256.init().unwrap();
	let _state_384 = Hasher::Blake2b384.init().unwrap();
	let _state_512 = Hasher::Blake2b512.init().unwrap();
}

#[test]
fn double_finalize_err() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	assert!(state.finalize().is_err());
}

#[test]
fn double_finalize_with_reset_ok_not_keyed() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let one = state.finalize().unwrap();
	state.reset(None).unwrap();
	state.update(data).unwrap();
	let two = state.finalize().unwrap();
	assert_eq!(one.as_bytes(), two.as_bytes());
}

#[test]
fn double_finalize_with_reset_ok_keyed() {
	let secret_key = SecretKey::from_slice(b"Testing").unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(Some(&secret_key), 64).unwrap();
	state.update(data).unwrap();
	let one = state.finalize().unwrap();
	state.reset(Some(&secret_key)).unwrap();
	state.update(data).unwrap();
	let two = state.finalize().unwrap();
	assert_eq!(one.as_bytes(), two.as_bytes());
}

#[test]
fn double_finalize_with_reset_no_update_ok() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	state.reset(None).unwrap();
	let _ = state.finalize().unwrap();
}

#[test]
fn update_after_finalize_err() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	assert!(state.update(data).is_err());
}

#[test]
fn update_after_finalize_with_reset_ok() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	state.reset(None).unwrap();
	state.update(data).unwrap();
}

#[test]
fn double_reset_ok() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	state.reset(None).unwrap();
	state.reset(None).unwrap();
}

#[test]
fn err_on_keyed_switch_on_reset() {
	let secret_key = SecretKey::from_slice(b"Testing").unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(Some(&secret_key), 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	assert!(state.reset(None).is_err());

	let mut state_second = init(None, 64).unwrap();
	state_second.update(data).unwrap();
	let _ = state_second.finalize().unwrap();
	assert!(state_second.reset(Some(&secret_key)).is_err());
}
