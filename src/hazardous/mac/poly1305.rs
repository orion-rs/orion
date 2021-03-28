// MIT License

// Copyright (c) 2018-2021 The orion Developers
// Based on the algorithm from https://github.com/floodyberry/poly1305-donna

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

//! # About:
//! This implementation is based on [poly1305-donna] by Andrew Moon.
//!
//! # Parameters:
//! - `data`: Data to be authenticated.
//! - `one_time_key`: One-time key used to authenticate.
//! - `expected`: The expected tag that needs to be verified.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//! - The calculated tag does not match the expected when verifying.
//!
//! # Security:
//! - A given key must never be used more than once. A unique [`OneTimeKey`],
//!   for each message authenticated, is required. If a key is used more than once,
//!   it reveals enough information for an attacker to forge future authentications with the same key.
//! - The one-time key should be generated using a CSPRNG.
//!   [`OneTimeKey::generate()`] can be used for this.
//!
//! # Recommendation:
//! - If you are unsure of whether to use HMAC or Poly1305, it is most often
//!   easier to just use HMAC. See also [Cryptographic Right Answers].
//!
//! # Example:
//! ```rust
//! use orion::hazardous::mac::poly1305::{OneTimeKey, Poly1305};
//!
//! let one_time_key = OneTimeKey::generate();
//! let msg = "Some message.";
//!
//! let mut poly1305_state = Poly1305::new(&one_time_key);
//! poly1305_state.update(msg.as_bytes())?;
//! let tag = poly1305_state.finalize()?;
//!
//! assert!(Poly1305::verify(&tag, &one_time_key, msg.as_bytes()).is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: poly1305::Poly1305::update
//! [`reset()`]: poly1305::Poly1305::reset
//! [`finalize()`]: poly1305::Poly1305::finalize
//! [`OneTimeKey::generate()`]: poly1305::OneTimeKey::generate
//! [`OneTimeKey`]: poly1305::OneTimeKey
//! [poly1305-donna]: https://github.com/floodyberry/poly1305-donna
//! [Cryptographic Right Answers]: https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html

use crate::{
    errors::UnknownCryptoError,
    util::endianness::{load_u32_le, store_u32_into_le},
};

/// The blocksize which Poly1305 operates on.
const POLY1305_BLOCKSIZE: usize = 16;
/// The output size for Poly1305.
pub const POLY1305_OUTSIZE: usize = 16;
/// The key size for Poly1305.
pub const POLY1305_KEYSIZE: usize = 32;
/// Type for a Poly1305 tag.
type Poly1305Tag = [u8; POLY1305_OUTSIZE];

construct_secret_key! {
    /// A type to represent the `OneTimeKey` that Poly1305 uses for authentication.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (OneTimeKey, test_one_time_key, POLY1305_KEYSIZE, POLY1305_KEYSIZE, POLY1305_KEYSIZE)
}

impl_from_trait!(OneTimeKey, POLY1305_KEYSIZE);

construct_tag! {
    /// A type to represent the `Tag` that Poly1305 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 16 bytes.
    (Tag, test_tag, POLY1305_OUTSIZE, POLY1305_OUTSIZE)
}

impl_from_trait!(Tag, POLY1305_OUTSIZE);

#[derive(Clone)]
/// Poly1305 streaming state.
pub struct Poly1305 {
    a: [u32; 5],
    r: [u32; 5],
    s: [u32; 4],
    leftover: usize,
    buffer: [u8; POLY1305_BLOCKSIZE],
    is_finalized: bool,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.a.zeroize();
        self.r.zeroize();
        self.s.zeroize();
        self.buffer.zeroize();
    }
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Poly1305 {{ a: [***OMITTED***], r: [***OMITTED***], s: [***OMITTED***], leftover: [***OMITTED***], buffer: [***OMITTED***], is_finalized: {:?} }}",
            self.is_finalized
        )
    }
}

impl Poly1305 {
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless)]
    #[allow(clippy::identity_op)]
    #[allow(clippy::unreadable_literal)]
    #[allow(clippy::assign_op_pattern)]
    /// Process a datablock of `POLY1305_BLOCKSIZE` length.
    fn process_block(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if data.len() != POLY1305_BLOCKSIZE {
            return Err(UnknownCryptoError);
        }

        let hibit: u32 = if self.is_finalized {
            0
        } else {
            1 << 24
        };

        let r0: u32 = self.r[0];
        let r1: u32 = self.r[1];
        let r2: u32 = self.r[2];
        let r3: u32 = self.r[3];
        let r4: u32 = self.r[4];

        let s1: u32 = r1 * 5;
        let s2: u32 = r2 * 5;
        let s3: u32 = r3 * 5;
        let s4: u32 = r4 * 5;

        let mut h0: u32 = self.a[0];
        let mut h1: u32 = self.a[1];
        let mut h2: u32 = self.a[2];
        let mut h3: u32 = self.a[3];
        let mut h4: u32 = self.a[4];

        // h += m[i]
        h0 += (load_u32_le(&data[0..4])) & 0x3ffffff;
        h1 += (load_u32_le(&data[3..7]) >> 2) & 0x3ffffff;
        h2 += (load_u32_le(&data[6..10]) >> 4) & 0x3ffffff;
        h3 += (load_u32_le(&data[9..13]) >> 6) & 0x3ffffff;
        h4 += (load_u32_le(&data[12..16]) >> 8) | hibit;

        // h *= r
        let d0: u64 =
            (h0 as u64 * r0 as u64) +
            (h1 as u64 * s4 as u64) +
            (h2 as u64 * s3 as u64) +
            (h3 as u64 * s2 as u64) +
            (h4 as u64 * s1 as u64);
        let mut d1: u64 =
            (h0 as u64 * r1 as u64) +
            (h1 as u64 * r0 as u64) +
            (h2 as u64 * s4 as u64) +
            (h3 as u64 * s3 as u64) +
            (h4 as u64 * s2 as u64);
        let mut d2: u64 =
            (h0 as u64 * r2 as u64) +
            (h1 as u64 * r1 as u64) +
            (h2 as u64 * r0 as u64) +
            (h3 as u64 * s4 as u64) +
            (h4 as u64 * s3 as u64);
        let mut d3: u64 =
            (h0 as u64 * r3 as u64) +
            (h1 as u64 * r2 as u64) +
            (h2 as u64 * r1 as u64) +
            (h3 as u64 * r0 as u64) +
            (h4 as u64 * s4 as u64);
        let mut d4: u64 =
            (h0 as u64 * r4 as u64) +
            (h1 as u64 * r3 as u64) +
            (h2 as u64 * r2 as u64) +
            (h3 as u64 * r1 as u64) +
            (h4 as u64 * r0 as u64);

        // (partial) h %= p
        let mut c: u32 = (d0 >> 26) as u32; h0 = (d0 & 0x3ffffff) as u32;
        d1 += c as u64; c = (d1 >> 26) as u32; h1 = (d1 & 0x3ffffff) as u32;
        d2 += c as u64; c = (d2 >> 26) as u32; h2 = (d2 & 0x3ffffff) as u32;
        d3 += c as u64; c = (d3 >> 26) as u32; h3 = (d3 & 0x3ffffff) as u32;
        d4 += c as u64; c = (d4 >> 26) as u32; h4 = (d4 & 0x3ffffff) as u32;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;

        self.a[0] = h0;
        self.a[1] = h1;
        self.a[2] = h2;
        self.a[3] = h3;
        self.a[4] = h4;

        Ok(())
    }

    #[rustfmt::skip]
    #[allow(clippy::cast_lossless)]
    #[allow(clippy::identity_op)]
    #[allow(clippy::unreadable_literal)]
    #[allow(clippy::assign_op_pattern)]
    /// Remaining processing after all data blocks have been processed.
    fn process_end_of_stream(&mut self) {
        // full carry h
        let mut h0: u32 = self.a[0];
        let mut h1: u32 = self.a[1];
        let mut h2: u32 = self.a[2];
        let mut h3: u32 = self.a[3];
        let mut h4: u32 = self.a[4];

        let mut c: u32 = h1 >> 26; h1 = h1 & 0x3ffffff;
        h2 += c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
        h3 += c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
        h4 += c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;

        // compute h + -p
        let mut g0: u32 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1: u32 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2: u32 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3: u32 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4: u32 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
    	h1 = (h1 & mask) | g1;
    	h2 = (h2 & mask) | g2;
    	h3 = (h3 & mask) | g3;
    	h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

        // mac = (h + pad) % (2^128)
        let mut f: u64 = (h0 as u64) + (self.s[0] as u64); h0 = f as u32;
        f = (h1 as u64) + (self.s[1] as u64) + (f >> 32); h1 = f as u32;
        f = (h2 as u64) + (self.s[2] as u64) + (f >> 32); h2 = f as u32;
        f = (h3 as u64) + (self.s[3] as u64) + (f >> 32); h3 = f as u32;

        // Set self.a to MAC result
        self.a[0] = h0;
        self.a[1] = h1;
        self.a[2] = h2;
        self.a[3] = h3;
    }

    #[allow(clippy::unreadable_literal)]
    /// Initialize a `Poly1305` struct with a given one-time key.
    pub fn new(one_time_key: &OneTimeKey) -> Self {
        let mut state = Self {
            a: [0u32; 5],
            r: [0u32; 5],
            s: [0u32; 4],
            leftover: 0,
            buffer: [0u8; POLY1305_BLOCKSIZE],
            is_finalized: false,
        };

        state.r[0] = (load_u32_le(&one_time_key.unprotected_as_bytes()[0..4])) & 0x3ffffff;
        state.r[1] = (load_u32_le(&one_time_key.unprotected_as_bytes()[3..7]) >> 2) & 0x3ffff03;
        state.r[2] = (load_u32_le(&one_time_key.unprotected_as_bytes()[6..10]) >> 4) & 0x3ffc0ff;
        state.r[3] = (load_u32_le(&one_time_key.unprotected_as_bytes()[9..13]) >> 6) & 0x3f03fff;
        state.r[4] = (load_u32_le(&one_time_key.unprotected_as_bytes()[12..16]) >> 8) & 0x00fffff;

        state.s[0] = load_u32_le(&one_time_key.unprotected_as_bytes()[16..20]);
        state.s[1] = load_u32_le(&one_time_key.unprotected_as_bytes()[20..24]);
        state.s[2] = load_u32_le(&one_time_key.unprotected_as_bytes()[24..28]);
        state.s[3] = load_u32_le(&one_time_key.unprotected_as_bytes()[28..32]);

        state
    }

    /// Update state with a `data` and pad it to blocksize with 0, if not
    /// evenly divisible by blocksize.
    pub(crate) fn process_pad_to_blocksize(
        &mut self,
        data: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }
        if data.is_empty() {
            return Ok(());
        }

        let mut blocksize_iter = data.chunks_exact(POLY1305_BLOCKSIZE);
        for block in &mut blocksize_iter {
            self.process_block(block).unwrap();
        }

        let remaining = blocksize_iter.remainder();
        if !remaining.is_empty() {
            let mut pad = [0u8; POLY1305_BLOCKSIZE];
            pad[..remaining.len()].copy_from_slice(remaining);
            self.process_block(&pad).unwrap();
        }

        Ok(())
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self.a = [0u32; 5];
        self.leftover = 0;
        self.is_finalized = false;
        self.buffer = [0u8; POLY1305_BLOCKSIZE];
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
            debug_assert!(self.leftover <= POLY1305_BLOCKSIZE);

            let mut want = POLY1305_BLOCKSIZE - self.leftover;
            if want > bytes.len() {
                want = bytes.len();
            }

            for (idx, itm) in bytes.iter().enumerate().take(want) {
                self.buffer[self.leftover + idx] = *itm;
            }

            bytes = &bytes[want..];
            self.leftover += want;
            if self.leftover < POLY1305_BLOCKSIZE {
                return Ok(());
            }

            let tmp = self.buffer;
            self.process_block(&tmp)?;
            self.leftover = 0;
        }

        while bytes.len() >= POLY1305_BLOCKSIZE {
            self.process_block(&bytes[0..POLY1305_BLOCKSIZE])?;
            bytes = &bytes[POLY1305_BLOCKSIZE..];
        }

        self.buffer[..bytes.len()].copy_from_slice(&bytes);
        self.leftover = bytes.len();

        Ok(())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a Poly1305 tag.
    pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;

        let mut local_buffer: Poly1305Tag = self.buffer;

        if self.leftover != 0 {
            local_buffer[self.leftover] = 1;
            // Pad the last block with zeroes before processing it
            for buf_itm in local_buffer
                .iter_mut()
                .take(POLY1305_BLOCKSIZE)
                .skip(self.leftover + 1)
            {
                *buf_itm = 0u8;
            }

            self.process_block(&local_buffer)?;
        }

        self.process_end_of_stream();
        store_u32_into_le(&self.a[0..4], &mut local_buffer);

        Ok(Tag::from(local_buffer))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// One-shot function for generating a Poly1305 tag of `data`.
    pub fn poly1305(one_time_key: &OneTimeKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
        let mut poly_1305_state = Self::new(one_time_key);
        poly_1305_state.update(data)?;
        poly_1305_state.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify a Poly1305 tag in constant time.
    pub fn verify(
        expected: &Tag,
        one_time_key: &OneTimeKey,
        data: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        if &Self::poly1305(one_time_key, data)? == expected {
            Ok(())
        } else {
            Err(UnknownCryptoError)
        }
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let secret_key = OneTimeKey::generate();
        let initial_state = Poly1305::new(&secret_key);
        let debug = format!("{:?}", initial_state);
        let expected = "Poly1305 { a: [***OMITTED***], r: [***OMITTED***], s: [***OMITTED***], leftover: [***OMITTED***], buffer: [***OMITTED***], is_finalized: false }";
        assert_eq!(debug, expected);
    }

    #[cfg(feature = "safe_api")]
    mod test_verify {
        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// When using a different key, verify() should always yield an error.
        /// NOTE: Using different and same input data is tested with TestableStreamingContext.
        fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
            let sk = OneTimeKey::generate();
            let mut state = Poly1305::new(&sk);
            state.update(&data[..]).unwrap();
            let tag = state.finalize().unwrap();
            let bad_sk = OneTimeKey::generate();

            Poly1305::verify(&tag, &bad_sk, &data[..]).is_err()
        }
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::{
            StreamingContextConsistencyTester, TestableStreamingContext,
        };

        // If a Poly1305 one-time key is all 0's then the tag will also be, regardless
        // of which message data has been processed.
        const KEY: [u8; 32] = [24u8; 32];

        impl TestableStreamingContext<Tag> for Poly1305 {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                Ok(self.reset())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                Poly1305::poly1305(&OneTimeKey::from_slice(&KEY).unwrap(), input)
            }

            fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
                // This will only run verification tests on differing input. They do not
                // include tests for different secret keys.
                Poly1305::verify(expected, &OneTimeKey::from_slice(&KEY).unwrap(), input)
            }

            fn compare_states(state_1: &Poly1305, state_2: &Poly1305) {
                assert_eq!(state_1.a, state_2.a);
                assert_eq!(state_1.r, state_2.r);
                assert_eq!(state_1.s, state_2.s);
                assert_eq!(state_1.leftover, state_2.leftover);
                assert_eq!(state_1.buffer[..], state_2.buffer[..]);
                assert_eq!(state_1.is_finalized, state_2.is_finalized);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Poly1305 = Poly1305::new(&OneTimeKey::from_slice(&KEY).unwrap());

            let test_runner = StreamingContextConsistencyTester::<Tag, Poly1305>::new(
                initial_state,
                POLY1305_BLOCKSIZE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Poly1305 = Poly1305::new(&OneTimeKey::from_slice(&KEY).unwrap());

            let test_runner = StreamingContextConsistencyTester::<Tag, Poly1305>::new(
                initial_state,
                POLY1305_BLOCKSIZE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
    use super::*;

    mod test_process_pad_to_blocksize {
        use super::*;

        #[test]
        fn test_process_err_on_finalized() {
            let sk = OneTimeKey::from_slice(&[0u8; 32]).unwrap();
            let mut state = Poly1305::new(&sk);

            state.process_pad_to_blocksize(&[0u8; 16]).unwrap();
            let _ = state.finalize().unwrap();
            assert!(state.process_pad_to_blocksize(&[0u8; 16]).is_err());
        }

        #[test]
        fn test_process_pad_no_pad() {
            let sk = OneTimeKey::from_slice(&[0u8; 32]).unwrap();
            let mut state_pad = Poly1305::new(&sk);
            let mut state_no_pad = Poly1305::new(&sk);

            // 15 missing to be evenly divisible by 16.
            state_pad.process_pad_to_blocksize(&[0u8; 17]).unwrap();
            state_no_pad.process_pad_to_blocksize(&[0u8; 32]).unwrap();

            assert_eq!(
                state_no_pad.finalize().unwrap(),
                state_pad.finalize().unwrap()
            );
        }
    }

    mod test_process_block {
        use super::*;

        #[test]
        fn test_process_block_len() {
            let block_0 = [0u8; 0];
            let block_1 = [0u8; 15];
            let block_2 = [0u8; 17];
            let block_3 = [0u8; 16];

            let sk = OneTimeKey::from_slice(&[0u8; 32]).unwrap();
            let mut state = Poly1305::new(&sk);

            assert!(state.process_block(&block_0).is_err());
            assert!(state.process_block(&block_1).is_err());
            assert!(state.process_block(&block_2).is_err());
            assert!(state.process_block(&block_3).is_ok());
        }
    }

    mod test_process_end_of_stream {
        use super::*;

        #[test]
        fn test_process_no_panic() {
            let block = [0u8; 16];
            let sk = OneTimeKey::from_slice(&[0u8; 32]).unwrap();
            let mut state = Poly1305::new(&sk);
            // Should not panic
            state.process_end_of_stream();
            state.reset();
            state.process_end_of_stream();

            let mut state = Poly1305::new(&sk);
            state.process_block(&block).unwrap();
            // Should not panic
            state.process_end_of_stream();
            state.reset();
            state.process_end_of_stream();
        }
    }
}
