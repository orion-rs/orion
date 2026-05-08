// MIT License

// Copyright (c) 2018-2026 The orion Developers
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
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::mac::poly1305::{OneTimeKey, Poly1305};
//!
//! let one_time_key = OneTimeKey::generate()?;
//! let msg = "Some message.";
//!
//! let mut poly1305_state = Poly1305::new(&one_time_key);
//! poly1305_state.update(msg.as_bytes())?;
//! let tag = poly1305_state.finalize()?;
//!
//! assert!(Poly1305::verify(&tag, &one_time_key, msg.as_bytes()).is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: poly1305::Poly1305::update
//! [`reset()`]: poly1305::Poly1305::reset
//! [`finalize()`]: poly1305::Poly1305::finalize
//! [`OneTimeKey::generate()`]: poly1305::OneTimeKey::generate
//! [`OneTimeKey`]: poly1305::OneTimeKey
//! [poly1305-donna]: https://github.com/floodyberry/poly1305-donna
//! [Cryptographic Right Answers]: https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html

use crate::generics::GenerateSecret;
use crate::{
    errors::UnknownCryptoError,
    generics::{ByteArrayData, Secret, TypeSpec, sealed::Sealed},
    util::endianness::{load_u32_le, store_u32_into_le},
};
#[cfg(feature = "serde")]
use alloc::vec::Vec;
use fiat_crypto::poly1305_32::{
    fiat_poly1305_add, fiat_poly1305_carry, fiat_poly1305_carry_mul, fiat_poly1305_from_bytes,
    fiat_poly1305_loose_field_element, fiat_poly1305_relax, fiat_poly1305_selectznz,
    fiat_poly1305_subborrowx_u26, fiat_poly1305_tight_field_element, fiat_poly1305_u1,
};

#[cfg(feature = "safe_api")]
use crate::generics::sealed::Data;

/// The blocksize which Poly1305 operates on.
pub(crate) const POLY1305_BLOCKSIZE: usize = 16;
/// The output size for Poly1305.
pub const POLY1305_OUTSIZE: usize = 16;
/// The key size for Poly1305.
pub const POLY1305_KEYSIZE: usize = 32;

#[derive(Debug)]
/// Marker type for Poly1305 onetime-key. See [`OneTimeKey`] type for convenience.
pub struct Poly1305Key {}
impl Sealed for Poly1305Key {}

impl TypeSpec for Poly1305Key {
    const NAME: &'static str = stringify!(OneTimeKey);
    type TypeData = ByteArrayData<POLY1305_KEYSIZE>;
}

impl From<[u8; POLY1305_KEYSIZE]> for Secret<Poly1305Key> {
    fn from(value: [u8; POLY1305_KEYSIZE]) -> Self {
        Self::from_data(<Poly1305Key as TypeSpec>::TypeData::from(value))
    }
}

impl GenerateSecret for Poly1305Key {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<Poly1305Key>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(POLY1305_KEYSIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// A type to represent the [`OneTimeKey`] that [`Poly1305`] uses for authentication.
pub type OneTimeKey = Secret<Poly1305Key>;

#[derive(Debug, Clone)]
/// Marker type for Poly1305 MAC/Tag. See [`Tag`] type for convenience.
pub struct Poly1305Tag {}
impl Sealed for Poly1305Tag {}

impl TypeSpec for Poly1305Tag {
    const NAME: &'static str = stringify!(Tag);
    type TypeData = ByteArrayData<POLY1305_OUTSIZE>;
}

impl From<[u8; POLY1305_OUTSIZE]> for Secret<Poly1305Tag> {
    fn from(value: [u8; POLY1305_OUTSIZE]) -> Self {
        Self::from_data(<Poly1305Tag as TypeSpec>::TypeData::from(value))
    }
}

/// A type to represent the MAC/Tag that Poly1305 returns.
pub type Tag = Secret<Poly1305Tag>;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to serialize as a `&[u8]` would. Note that the serialized
/// type likely does not have the same protections that Orion provides, such
/// as constant-time operations. A good rule of thumb is to only serialize
/// these types for storage. Don't operate on the serialized types.
impl serde::Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let bytes: &[u8] = self.data.as_ref();
        bytes.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to deserialize as a `Vec<u8>` would. If it succeeds, the public data
/// will be built using `Self::try_from`.
///
/// Note that **this allocates** once to store the referenced bytes on the heap.
impl<'de> serde::Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        TryFrom::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
/// Poly1305 streaming state.
pub struct Poly1305 {
    a: fiat_poly1305_tight_field_element,
    r: fiat_poly1305_loose_field_element,
    s: [u32; 4],
    leftover: usize,
    buffer: [u8; POLY1305_BLOCKSIZE],
    is_finalized: bool,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.a.0.zeroize();
            self.r.0.zeroize();
            self.s.zeroize();
            self.buffer.zeroize();
        }
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
    /// Prime 2^130-5 in little-endian.
    const PRIME: [u8; 17] = [
        251, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 3,
    ];

    /// Process a datablock of `POLY1305_BLOCKSIZE` length.
    fn process_block(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if data.len() != POLY1305_BLOCKSIZE {
            return Err(UnknownCryptoError);
        }

        let mut mb = [0u8; 17];
        mb[..16].copy_from_slice(data);
        // One byte is appended to detect trailing zeroes if not last chunk.
        // See https://cr.yp.to/mac/poly1305-20050329.pdf, Section 2 "Conversion and padding".
        mb[16] = u8::from(!self.is_finalized);
        let mut m = fiat_poly1305_tight_field_element([0u32; 5]);
        fiat_poly1305_from_bytes(&mut m, &mb);

        // h += m
        let mut h = fiat_poly1305_loose_field_element([0u32; 5]);
        fiat_poly1305_add(&mut h, &self.a, &m);
        // h *= r with partial reduction modulo p
        fiat_poly1305_carry_mul(&mut self.a, &h, &self.r);

        Ok(())
    }

    #[rustfmt::skip]
    #[allow(clippy::identity_op)]
    /// Remaining processing after all data blocks have been processed.
    fn process_end_of_stream(&mut self) {
        // full carry h
        let mut buf_h = fiat_poly1305_tight_field_element([0u32; 5]);
        let mut a_relaxed = fiat_poly1305_loose_field_element([0u32; 5]);
        fiat_poly1305_relax(&mut a_relaxed, &self.a);
        fiat_poly1305_carry(&mut buf_h, &a_relaxed);

        // compute h + -p
        let mut p = fiat_poly1305_tight_field_element([0u32; 5]);
        fiat_poly1305_from_bytes(&mut p, &Self::PRIME);

        let mut carry: fiat_poly1305_u1 = 0;
        let mut g0: u32 = 0; let c = carry; fiat_poly1305_subborrowx_u26(&mut g0, &mut carry, c, buf_h[0], p[0]);
        let mut g1: u32 = 0; let c = carry; fiat_poly1305_subborrowx_u26(&mut g1, &mut carry, c, buf_h[1], p[1]);
        let mut g2: u32 = 0; let c = carry; fiat_poly1305_subborrowx_u26(&mut g2, &mut carry, c, buf_h[2], p[2]);
        let mut g3: u32 = 0; let c = carry; fiat_poly1305_subborrowx_u26(&mut g3, &mut carry, c, buf_h[3], p[3]);
        let mut g4: u32 = 0; let c = carry; fiat_poly1305_subborrowx_u26(&mut g4, &mut carry, c, buf_h[4], p[4]);

        // select h if h < p, or h + -p if h >= p
        let mut ret = [0u32; 5];
        fiat_poly1305_selectznz(&mut ret, carry,&[g0, g1, g2, g3, g4], &buf_h.0);

        let mut h0 = ret[0];
        let mut h1 = ret[1];
        let mut h2 = ret[2];
        let mut h3 = ret[3];
        let h4 = ret[4];

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
            a: fiat_poly1305_tight_field_element([0u32; 5]),
            r: fiat_poly1305_loose_field_element([0u32; 5]),
            s: [0u32; 4],
            leftover: 0,
            buffer: [0u8; POLY1305_BLOCKSIZE],
            is_finalized: false,
        };

        state.r[0] = (load_u32_le(&one_time_key.unprotected_as_ref()[0..4])) & 0x3ffffff;
        state.r[1] = (load_u32_le(&one_time_key.unprotected_as_ref()[3..7]) >> 2) & 0x3ffff03;
        state.r[2] = (load_u32_le(&one_time_key.unprotected_as_ref()[6..10]) >> 4) & 0x3ffc0ff;
        state.r[3] = (load_u32_le(&one_time_key.unprotected_as_ref()[9..13]) >> 6) & 0x3f03fff;
        state.r[4] = (load_u32_le(&one_time_key.unprotected_as_ref()[12..16]) >> 8) & 0x00fffff;

        state.s[0] = load_u32_le(&one_time_key.unprotected_as_ref()[16..20]);
        state.s[1] = load_u32_le(&one_time_key.unprotected_as_ref()[20..24]);
        state.s[2] = load_u32_le(&one_time_key.unprotected_as_ref()[24..28]);
        state.s[3] = load_u32_le(&one_time_key.unprotected_as_ref()[28..32]);

        state
    }

    /// Update state with a `data` and pad it to blocksize with 0's, if not
    /// evenly divisible by blocksize.
    pub(crate) fn process_pad_to_blocksize(
        &mut self,
        data: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(self.leftover, 0);

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

        debug_assert_eq!(self.leftover, 0);

        Ok(())
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self.a = fiat_poly1305_tight_field_element([0u32; 5]);
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

        self.buffer[..bytes.len()].copy_from_slice(bytes);
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

        let mut local_buffer: [u8; POLY1305_OUTSIZE] = self.buffer;

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
        store_u32_into_le(&self.a.0[0..4], &mut local_buffer);

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
    fn test_onetime_key() {
        use super::*;
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_with_generate::<
            POLY1305_KEYSIZE,
            POLY1305_KEYSIZE,
            POLY1305_KEYSIZE,
            Poly1305Key,
        >();
        // Test of From<[u8; N]>
        assert_ne!(
            OneTimeKey::from([0u8; POLY1305_KEYSIZE]),
            OneTimeKey::from([1u8; POLY1305_KEYSIZE])
        )
    }

    #[test]
    fn test_tag() {
        use super::*;
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_no_generate::<POLY1305_OUTSIZE, POLY1305_OUTSIZE, Poly1305Tag>();
        // Test of From<[u8; N]>
        assert_ne!(
            Tag::from([0u8; POLY1305_OUTSIZE]),
            Tag::from([1u8; POLY1305_OUTSIZE])
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_serialized_equivalence_to_bytes_fn() {
        let bytes = [38u8; POLY1305_OUTSIZE];
        let secret_type = Tag::try_from(&bytes).unwrap();
        let serialized_from_bytes = serde_json::to_value(bytes.as_slice()).unwrap();
        let serialized_from_secret_type = serde_json::to_value(&secret_type).unwrap();
        assert_eq!(serialized_from_bytes, serialized_from_secret_type);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_deserialized_equivalence_to_bytes_fn() {
        let bytes = [38u8; POLY1305_OUTSIZE];
        let serialized_from_bytes = serde_json::to_value(bytes.as_slice()).unwrap();
        let secret_type: Tag = serde_json::from_value(serialized_from_bytes).unwrap();
        assert_eq!(secret_type.unprotected_as_ref(), bytes.as_slice());
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let secret_key = OneTimeKey::generate().unwrap();
        let initial_state = Poly1305::new(&secret_key);
        let debug = format!("{initial_state:?}");
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
            let sk = OneTimeKey::generate().unwrap();
            let mut state = Poly1305::new(&sk);
            state.update(&data[..]).unwrap();
            let tag = state.finalize().unwrap();
            let bad_sk = OneTimeKey::generate().unwrap();

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
                self.reset();
                Ok(())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                Poly1305::poly1305(&OneTimeKey::try_from(&KEY).unwrap(), input)
            }

            fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
                // This will only run verification tests on differing input. They do not
                // include tests for different secret keys.
                Poly1305::verify(expected, &OneTimeKey::try_from(&KEY).unwrap(), input)
            }

            fn compare_states(state_1: &Poly1305, state_2: &Poly1305) {
                assert_eq!(state_1.a.0, state_2.a.0);
                assert_eq!(state_1.r.0, state_2.r.0);
                assert_eq!(state_1.s, state_2.s);
                assert_eq!(state_1.leftover, state_2.leftover);
                assert_eq!(state_1.buffer[..], state_2.buffer[..]);
                assert_eq!(state_1.is_finalized, state_2.is_finalized);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Poly1305 = Poly1305::new(&OneTimeKey::try_from(&KEY).unwrap());

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
            let initial_state: Poly1305 = Poly1305::new(&OneTimeKey::try_from(&KEY).unwrap());

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
            let sk = OneTimeKey::try_from(&[0u8; 32]).unwrap();
            let mut state = Poly1305::new(&sk);

            state.process_pad_to_blocksize(&[0u8; 16]).unwrap();
            let _ = state.finalize().unwrap();
            assert!(state.process_pad_to_blocksize(&[0u8; 16]).is_err());
        }

        #[test]
        fn test_process_pad_no_pad() {
            let sk = OneTimeKey::try_from(&[0u8; 32]).unwrap();
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

            let sk = OneTimeKey::try_from(&[0u8; 32]).unwrap();
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
            let sk = OneTimeKey::try_from(&[0u8; 32]).unwrap();
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
