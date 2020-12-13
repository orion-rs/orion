// MIT License

// Copyright (c) 2020 The orion Developers

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
//!
//! # Security:
//! - SHA256 is vulnerable to length extension attacks.
//! 
//! # Recommendation:
//! - It is recommended to use [BLAKE2b] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha256::Sha256;
//!
//! // Using the streaming interface
//! let mut state = Sha256::new();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = Sha256::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: struct.Sha256.html
//! [`reset()`]: struct.Sha256.html
//! [`finalize()`]: struct.Sha256.html
//! [BLAKE2b]: ../blake2b/index.html

use crate::{
    errors::UnknownCryptoError,
    util::endianness::{load_u32_into_be, store_u32_into_be},
};

/// The blocksize for the hash function SHA256.
pub const SHA256_BLOCKSIZE: usize = 64;
/// The output size for the hash function SHA256.
pub const SHA256_OUTSIZE: usize = 32;

construct_public! {
    /// A type to represent the `Digest` that SHA256 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (Digest, test_digest, SHA256_OUTSIZE, SHA256_OUTSIZE)
}

impl_from_trait!(Digest, SHA256_OUTSIZE);

#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
/// The SHA256 constants as defined in FIPS 180-4.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
/// The SHA256 initial hash value H(0) as defined in FIPS 180-4.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
/// SHA256 streaming state.
pub struct Sha256 {
    working_state: [u32; 8],
    buffer: [u8; SHA256_BLOCKSIZE],
    leftover: usize,
    message_len: [u32; 2],
    is_finalized: bool,
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.working_state.zeroize();
        self.buffer.zeroize();
        self.message_len.zeroize();
    }
}

impl core::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Sha256 {{ working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: {:?}, \
             message_len: {:?}, is_finalized: {:?} }}",
            self.leftover, self.message_len, self.is_finalized
        )
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// The Ch function as specified in FIPS 180-4 section 4.1.3.
    ///
    /// TODO: Shared between all SHA2 functions. Make generic over data-types that
    /// implement the needed op traits.
    const fn ch(x: u32, y: u32, z: u32) -> u32 {
        z ^ (x & (y ^ z))
    }

    /// The Maj function as specified in FIPS 180-4 section 4.1.3.
    ///
    /// TODO: Shared between all SHA2 functions. Make generic over data-types that
    /// implement the needed op traits.
    const fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (z & (x | y))
    }

    /// The Big Sigma 0 function as specified in FIPS 180-4 section 4.1.2.
    const fn big_sigma_0(x: u32) -> u32 {
        (x.rotate_right(2)) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    /// The Big Sigma 1 function as specified in FIPS 180-4 section 4.1.2.
    const fn big_sigma_1(x: u32) -> u32 {
        (x.rotate_right(6)) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    /// The Small Sigma 0 function as specified in FIPS 180-4 section 4.1.2.
    const fn small_sigma_0(x: u32) -> u32 {
        (x.rotate_right(7)) ^ x.rotate_right(18) ^ (x >> 3)
    }

    /// The Small Sigma 1 function as specified in FIPS 180-4 section 4.1.2.
    const fn small_sigma_1(x: u32) -> u32 {
        (x.rotate_right(17)) ^ x.rotate_right(19) ^ (x >> 10)
    }

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_arguments)]
    /// Message compression adopted from [mbed
    /// TLS](https://github.com/ARMmbed/mbedtls/blob/master/library/sha512.c).
    fn compress(
        a: u32,
        b: u32,
        c: u32,
        d: &mut u32,
        e: u32,
        f: u32,
        g: u32,
        h: &mut u32,
        x: u32,
        ki: u32,
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

    #[rustfmt::skip]
	#[allow(clippy::many_single_char_names)]
    /// Process data in `self.buffer` or optionally `data`.
    fn process(&mut self, data: Option<&[u8]>) {
        let mut w = [0u32; 64];
		match data {
			Some(bytes) => {
                debug_assert!(bytes.len() == SHA256_BLOCKSIZE);
				load_u32_into_be(bytes, &mut w[..16]);
			}
			None => load_u32_into_be(&self.buffer, &mut w[..16]),
		}

		for t in 16..64 {
			w[t] = Self::small_sigma_1(w[t - 2])
				.wrapping_add(w[t - 7])
				.wrapping_add(Self::small_sigma_0(w[t - 15]))
				.wrapping_add(w[t - 16]);
		}

		let mut a = self.working_state[0];
		let mut b = self.working_state[1];
		let mut c = self.working_state[2];
		let mut d = self.working_state[3];
		let mut e = self.working_state[4];
		let mut f = self.working_state[5];
		let mut g = self.working_state[6];
		let mut h = self.working_state[7];

		let mut t = 0;
		while t < 64 {
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

    /// Increment the message length during processing of data.
    fn increment_mlen(&mut self, length: u32) {
        // The checked shift checks that the right-hand side is a legal shift.
        // The result can still overflow if length > u32::max_value() / 8.
        // Should be impossible for a user to trigger, because update() processes
        // in SHA256_BLOCKSIZE chunks.
        debug_assert!(length <= u32::max_value() / 8);

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

    /// Initialize a `Sha256` struct.
    pub fn new() -> Self {
        Self {
            working_state: H0,
            buffer: [0u8; SHA256_BLOCKSIZE],
            leftover: 0,
            message_len: [0u32; 2],
            is_finalized: false,
        }
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self.working_state = H0;
        self.buffer = [0u8; SHA256_BLOCKSIZE];
        self.leftover = 0;
        self.message_len = [0u32; 2];
        self.is_finalized = false;
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
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
            debug_assert!(self.leftover <= SHA256_BLOCKSIZE);

            let mut want = SHA256_BLOCKSIZE - self.leftover;
            if want > bytes.len() {
                want = bytes.len();
            }

            for (idx, itm) in bytes.iter().enumerate().take(want) {
                self.buffer[self.leftover + idx] = *itm;
            }

            bytes = &bytes[want..];
            self.leftover += want;
            self.increment_mlen(want as u32);

            if self.leftover < SHA256_BLOCKSIZE {
                return Ok(());
            }

            self.process(None);
            self.leftover = 0;
        }

        while bytes.len() >= SHA256_BLOCKSIZE {
            self.process(Some(bytes[..SHA256_BLOCKSIZE].as_ref()));
            self.increment_mlen(SHA256_BLOCKSIZE as u32);
            bytes = &bytes[SHA256_BLOCKSIZE..];
        }

        if !bytes.is_empty() {
            debug_assert!(self.leftover == 0);
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.leftover = bytes.len();
            self.increment_mlen(bytes.len() as u32);
        }

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a SHA256 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;

        // self.leftover should not be greater than SHA256_BLOCKSIZE
        // as that would have been processed in the update call
        debug_assert!(self.leftover < SHA256_BLOCKSIZE);
        self.buffer[self.leftover] = 0x80;
        self.leftover += 1;

        for itm in self.buffer.iter_mut().skip(self.leftover) {
            *itm = 0;
        }

        // Check for available space for length padding
        if (SHA256_BLOCKSIZE - self.leftover) < 8 {
            self.process(None);
            for itm in self.buffer.iter_mut().take(self.leftover) {
                *itm = 0;
            }
        }

        self.buffer[SHA256_BLOCKSIZE - 8..SHA256_BLOCKSIZE - 4]
            .copy_from_slice(&self.message_len[0].to_be_bytes());
        self.buffer[SHA256_BLOCKSIZE - 4..SHA256_BLOCKSIZE]
            .copy_from_slice(&self.message_len[1].to_be_bytes());

        self.process(None);

        let mut digest = [0u8; SHA256_OUTSIZE];
        store_u32_into_be(&self.working_state, &mut digest);

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA256 digest of some `data`.
    pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let mut state = Self::new();
        state.update(data)?;
        state.finalize()
    }
}

#[cfg(test)]
/// Compare two Sha256 state objects to check if their fields
/// are the same.
pub fn compare_sha256_states(state_1: &Sha256, state_2: &Sha256) {
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

    #[test]
    fn test_default_equals_new() {
        let new = Sha256::new();
        let default = Sha256::default();
        compare_sha256_states(&new, &default);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha256::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Sha256 { working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: 0, message_len: [0, 0], is_finalized: false }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha256 {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                Ok(self.reset())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Digest, UnknownCryptoError> {
                Sha256::digest(input)
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual: Digest = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Sha256, state_2: &Sha256) {
                compare_sha256_states(state_1, state_2)
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Sha256 = Sha256::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha256>::new(
                initial_state,
                SHA256_BLOCKSIZE,
            );
            test_runner.run_all_tests();
        }

        // Proptests. Only executed when NOT testing no_std.
        #[cfg(feature = "safe_api")]
        mod proptest {
            use super::*;

            quickcheck! {
                /// Related bug: https://github.com/brycx/orion/issues/46
                /// Test different streaming state usage patterns.
                fn prop_input_to_consistency(data: Vec<u8>) -> bool {
                    let initial_state: Sha256 = Sha256::new();

                    let test_runner = StreamingContextConsistencyTester::<Digest, Sha256>::new(
                        initial_state,
                        SHA256_BLOCKSIZE,
                    );
                    test_runner.run_all_tests_property(&data);
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

    mod test_increment_mlen {
        use super::*;

        #[test]
        fn test_mlen_increase_values() {
            let mut context = Sha256 {
                working_state: H0,
                buffer: [0u8; SHA256_BLOCKSIZE],
                leftover: 0,
                message_len: [0u32; 2],
                is_finalized: false,
            };

            context.increment_mlen(1);
            assert!(context.message_len == [0u32, 8u32]);
            context.increment_mlen(17);
            assert!(context.message_len == [0u32, 144u32]);
            context.increment_mlen(12);
            assert!(context.message_len == [0u32, 240u32]);
            // Overflow
            context.increment_mlen(u32::max_value() / 8);
            assert!(context.message_len == [1u32, 232u32]);
        }

        #[test]
        #[should_panic]
        fn test_panic_on_second_overflow() {
            let mut context = Sha256 {
                working_state: H0,
                buffer: [0u8; SHA256_BLOCKSIZE],
                leftover: 0,
                message_len: [u32::max_value(), u32::max_value() - 7],
                is_finalized: false,
            };
            // u32::max_value() - 7, to leave so that the length represented
            // in bites should overflow by exactly one.
            context.increment_mlen(1);
        }
    }
}
