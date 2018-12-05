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
//!
//! # Exceptions:
//! An exception will be thrown if:
//!
//! # Security:
//!
//! # Example:
//! ```
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
	/// - `slice` is greater than 64 bytes.
	/// - The `OsRng` fails to initialize or read from its source.
	(SecretKey, BLAKE2B_BLOCKSIZE)
}

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

#[must_use]
/// BLAKE2b as specified in the [RFC 7693](https://tools.ietf.org/html/rfc7693).
pub struct Blake2b {
	init_state: [u64; 8],
	internal_state: [u64; 8],
	w_vec: [u64; 16],
	buffer: [u8; BLAKE2B_BLOCKSIZE],
	leftover: usize,
	t: [u64; 2],
	f: [u64; 2],
	is_finalized: bool,
	is_keyed: bool,
}

impl Drop for Blake2b {
	fn drop(&mut self) {
		use clear_on_drop::clear::Clear;
		self.init_state.clear();
		self.internal_state.clear();
		self.w_vec.clear();
		self.buffer.clear();
	}
}

impl core::fmt::Debug for Blake2b {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(
			f,
			"Blake2b {{ init_state: [***OMITTED***], internal_state: [***OMITTED***], w_vec: [***OMITTED***],
            buffer: [***OMITTED***], leftover: {:?}, t: {:?}, f: {:?}, is_finalized: {:?} }}",
			self.leftover, self.t, self.f, self.is_finalized
		)
	}
}

impl Blake2b {
	#[inline(always)]
	///
	fn increment_offset(&mut self, value: u64) {
		self.t[0] = self.t[0].checked_add(value).expect("FUME");
		if self.t[0] < value {
			self.t[1] += 1;
		}
	}

	#[inline(always)]
	///
	fn prim_mix_g(&mut self, x: u64, y: u64, a: usize, b: usize, c: usize, d: usize) {
		let mut word_a = self.w_vec[a];
		let mut word_b = self.w_vec[b];
		let mut word_c = self.w_vec[c];
		let mut word_d = self.w_vec[d];

		word_a = word_a.wrapping_add(word_b).wrapping_add(x);
		word_d ^= word_a;
		word_d = (word_d).rotate_right(32u32);
		word_c = word_c.wrapping_add(word_d);
		word_b ^= word_c;
		word_b = (word_b).rotate_right(24u32);
		word_a = word_a.wrapping_add(word_b).wrapping_add(y);;
		word_d ^= word_a;
		word_d = (word_d).rotate_right(16u32);
		word_c = word_c.wrapping_add(word_d);
		word_b ^= word_c;
		word_b = (word_b).rotate_right(63u32);

		self.w_vec[a] = word_a;
		self.w_vec[b] = word_b;
		self.w_vec[c] = word_c;
		self.w_vec[d] = word_d;
	}

	#[inline(always)]
	#[cfg_attr(feature = "cargo-clippy", allow(clippy::needless_range_loop))]
	/// The compression function f.
	fn compress_f(&mut self) {
		let mut m_vec = [0u64; 16];
		LittleEndian::read_u64_into(&self.buffer, &mut m_vec);

		// Setup with IV constants
		self.w_vec[12] = self.t[0] ^ IV[4];
		self.w_vec[13] = self.t[1] ^ IV[5];
		self.w_vec[14] = self.f[0] ^ IV[6];
		self.w_vec[15] = self.f[1] ^ IV[7];

		for round_number in 0..12 {
			// Select message schedule based on round number
			let ms = SIGMA[round_number];

			self.prim_mix_g(m_vec[ms[0]], m_vec[ms[1]], 0, 4, 8, 12);
			self.prim_mix_g(m_vec[ms[2]], m_vec[ms[3]], 1, 5, 9, 13);
			self.prim_mix_g(m_vec[ms[4]], m_vec[ms[5]], 2, 6, 10, 14);
			self.prim_mix_g(m_vec[ms[6]], m_vec[ms[7]], 3, 7, 11, 15);
			self.prim_mix_g(m_vec[ms[8]], m_vec[ms[9]], 0, 5, 10, 15);
			self.prim_mix_g(m_vec[ms[10]], m_vec[ms[11]], 1, 6, 11, 12);
			self.prim_mix_g(m_vec[ms[12]], m_vec[ms[13]], 2, 7, 8, 13);
			self.prim_mix_g(m_vec[ms[14]], m_vec[ms[15]], 3, 4, 9, 14);
		}

		// XOR the two halves together and into the state
		self.internal_state[0] ^= self.w_vec[0] ^ self.w_vec[8];
		self.internal_state[1] ^= self.w_vec[1] ^ self.w_vec[9];
		self.internal_state[2] ^= self.w_vec[2] ^ self.w_vec[10];
		self.internal_state[3] ^= self.w_vec[3] ^ self.w_vec[11];
		self.internal_state[4] ^= self.w_vec[4] ^ self.w_vec[12];
		self.internal_state[5] ^= self.w_vec[5] ^ self.w_vec[13];
		self.internal_state[6] ^= self.w_vec[6] ^ self.w_vec[14];
		self.internal_state[7] ^= self.w_vec[7] ^ self.w_vec[15];

		// Update working vector
		self.w_vec[0] = self.internal_state[0];
		self.w_vec[1] = self.internal_state[1];
		self.w_vec[2] = self.internal_state[2];
		self.w_vec[3] = self.internal_state[3];
		self.w_vec[4] = self.internal_state[4];
		self.w_vec[5] = self.internal_state[5];
		self.w_vec[6] = self.internal_state[6];
		self.w_vec[7] = self.internal_state[7];

		// Re-insert the IV into working vector
		self.w_vec[8] = IV[0];
		self.w_vec[9] = IV[1];
		self.w_vec[10] = IV[2];
		self.w_vec[11] = IV[3];
	}

	#[must_use]
	#[inline(always)]
	///
	pub fn reset(&mut self, secret_key: Option<&SecretKey>) {
		if self.is_finalized {
			self.internal_state.copy_from_slice(&self.init_state);

			self.w_vec[..8].copy_from_slice(&self.internal_state);
			self.w_vec[8..12].copy_from_slice(&IV[0..4]);
			self.buffer = [0u8; BLAKE2B_BLOCKSIZE];
			self.leftover = 0;
			self.t = [0u64; 2];
			self.f = [0u64; 2];
			self.is_finalized = false;

			if secret_key.is_some() && self.is_keyed {
				self.update(secret_key.unwrap().unprotected_as_bytes()).unwrap();
			}
		} else {
		}
	}

	#[must_use]
	#[inline(always)]
	///
	pub fn update(&mut self, data: &[u8]) -> Result<(), FinalizationCryptoError> {
		if self.is_finalized {
			return Err(FinalizationCryptoError);
		}

		if data.is_empty() {
			return Ok(());
		}

		let mut bytes = data;
		// First fill up if there is leftover space
		if self.leftover > 0 {
			let fill = BLAKE2B_BLOCKSIZE - self.leftover;

			if bytes.len() <= fill {
				self.buffer[self.leftover..(self.leftover + bytes.len())].copy_from_slice(&bytes);
				self.leftover += bytes.len();
				return Ok(());
			}

			self.buffer[self.leftover..(self.leftover + fill)].copy_from_slice(&bytes[..fill]);
			// Process data
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64);
			self.compress_f();
			// Remve the amount of blocks we just prossed
			self.leftover = 0;
			// Reduce by slice
			bytes = &bytes[fill..];
		}

		while bytes.len() > BLAKE2B_BLOCKSIZE {
			// Process data
			self.buffer.copy_from_slice(&bytes[..BLAKE2B_BLOCKSIZE]);
			self.increment_offset(BLAKE2B_BLOCKSIZE as u64);
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
	///
	pub fn finalize(&mut self) -> Result<[u8; 64], FinalizationCryptoError> {
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

		LittleEndian::write_u64_into(&self.internal_state, &mut digest);

		Ok(digest)
	}
}

#[must_use]
#[inline(always)]
///
pub fn init(secret_key: Option<&SecretKey>, size: usize) -> Result<Blake2b, UnknownCryptoError> {
	if size < 1 || size > BLAKE2B_OUTSIZE {
		return Err(UnknownCryptoError);
	}

	let mut context = Blake2b {
		init_state: [0u64; 8],
		internal_state: IV,
		w_vec: [0u64; 16],
		buffer: [0u8; BLAKE2B_BLOCKSIZE],
		leftover: 0,
		t: [0u64; 2],
		f: [0u64; 2],
		is_finalized: false,
		is_keyed: false,
	};

	if secret_key.is_some() {
		context.is_keyed = true;
		let key = secret_key.unwrap();
		let klen = key.get_original_length();
		context.internal_state[0] ^= 0x01010000 ^ ((klen as u64) << 8) ^ (size as u64);
		context.init_state.copy_from_slice(&context.internal_state);
		// Prepad the working vector with the state
		context.w_vec[..8].copy_from_slice(&context.internal_state);
		// Prepoad the working vector with the IV
		context.w_vec[8..12].copy_from_slice(&IV[0..4]);
		context.update(key.unprotected_as_bytes())?;
	} else {
		context.internal_state[0] ^= 0x01010000 ^ ((0u64) << 8) ^ (size as u64);
		context.init_state.copy_from_slice(&context.internal_state);
		// Prepad the working vector with the state
		context.w_vec[..8].copy_from_slice(&context.internal_state);
		// Prepoad the working vector with the IV
		context.w_vec[8..12].copy_from_slice(&IV[0..4]);
	}

	Ok(context)
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
	state.reset(None);
	state.update(data).unwrap();
	let two = state.finalize().unwrap();
	assert_eq!(one[..], two[..]);
}

#[test]
fn double_finalize_with_reset_ok_keyed() {
	let secret_key = SecretKey::from_slice(b"Testing").unwrap();
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(Some(&secret_key), 64).unwrap();
	state.update(data).unwrap();
	let one = state.finalize().unwrap();
	state.reset(Some(&secret_key));
	state.update(data).unwrap();
	let two = state.finalize().unwrap();
	assert_eq!(one[..], two[..]);
}

#[test]
fn double_finalize_with_reset_no_update_ok() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	state.reset(None);
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
	state.reset(None);
	state.update(data).unwrap();
}

#[test]
fn double_reset_ok() {
	let data = "what do ya want for nothing?".as_bytes();

	let mut state = init(None, 64).unwrap();
	state.update(data).unwrap();
	let _ = state.finalize().unwrap();
	state.reset(None);
	state.reset(None);
}
