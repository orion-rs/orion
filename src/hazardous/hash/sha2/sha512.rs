// MIT License

// Copyright (c) 2018-2025 The orion Developers

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
//! use orion::hazardous::hash::sha2::sha512::Sha512;
//!
//! // Using the streaming interface
//! let mut state = Sha512::new();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = Sha512::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: sha512::Sha512::update
//! [`reset()`]: sha512::Sha512::reset
//! [`finalize()`]: sha512::Sha512::finalize
//! [BLAKE2b]: super::blake2::blake2b

use crate::errors::UnknownCryptoError;

#[cfg(feature = "safe_api")]
use std::io;

construct_public! {
    /// A type to represent the `Digest` that SHA512 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 64 bytes.
    (Digest, test_digest, SHA512_OUTSIZE, SHA512_OUTSIZE)
}

impl_from_trait!(Digest, SHA512_OUTSIZE);

use super::sha2_core::{State, Variant, Word};
use super::w64::WordU64;

/// The blocksize for the hash function SHA512.
pub const SHA512_BLOCKSIZE: usize = 128;
/// The output size for the hash function SHA512.
pub const SHA512_OUTSIZE: usize = 64;
/// The number of constants for the hash function SHA512.
const N_CONSTS: usize = 80;

#[derive(Clone)]
pub(crate) struct V512;

impl Variant<WordU64, N_CONSTS> for V512 {
    #[rustfmt::skip]
    #[allow(clippy::unreadable_literal)]
    /// The SHA512 constants as defined in FIPS 180-4.
    const K: [WordU64; N_CONSTS] = [
            WordU64(0x428a2f98d728ae22), WordU64(0x7137449123ef65cd), WordU64(0xb5c0fbcfec4d3b2f), WordU64(0xe9b5dba58189dbbc),
            WordU64(0x3956c25bf348b538), WordU64(0x59f111f1b605d019), WordU64(0x923f82a4af194f9b), WordU64(0xab1c5ed5da6d8118),
            WordU64(0xd807aa98a3030242), WordU64(0x12835b0145706fbe), WordU64(0x243185be4ee4b28c), WordU64(0x550c7dc3d5ffb4e2),
            WordU64(0x72be5d74f27b896f), WordU64(0x80deb1fe3b1696b1), WordU64(0x9bdc06a725c71235), WordU64(0xc19bf174cf692694),
            WordU64(0xe49b69c19ef14ad2), WordU64(0xefbe4786384f25e3), WordU64(0x0fc19dc68b8cd5b5), WordU64(0x240ca1cc77ac9c65),
            WordU64(0x2de92c6f592b0275), WordU64(0x4a7484aa6ea6e483), WordU64(0x5cb0a9dcbd41fbd4), WordU64(0x76f988da831153b5),
            WordU64(0x983e5152ee66dfab), WordU64(0xa831c66d2db43210), WordU64(0xb00327c898fb213f), WordU64(0xbf597fc7beef0ee4),
            WordU64(0xc6e00bf33da88fc2), WordU64(0xd5a79147930aa725), WordU64(0x06ca6351e003826f), WordU64(0x142929670a0e6e70),
            WordU64(0x27b70a8546d22ffc), WordU64(0x2e1b21385c26c926), WordU64(0x4d2c6dfc5ac42aed), WordU64(0x53380d139d95b3df),
            WordU64(0x650a73548baf63de), WordU64(0x766a0abb3c77b2a8), WordU64(0x81c2c92e47edaee6), WordU64(0x92722c851482353b),
            WordU64(0xa2bfe8a14cf10364), WordU64(0xa81a664bbc423001), WordU64(0xc24b8b70d0f89791), WordU64(0xc76c51a30654be30),
            WordU64(0xd192e819d6ef5218), WordU64(0xd69906245565a910), WordU64(0xf40e35855771202a), WordU64(0x106aa07032bbd1b8),
            WordU64(0x19a4c116b8d2d0c8), WordU64(0x1e376c085141ab53), WordU64(0x2748774cdf8eeb99), WordU64(0x34b0bcb5e19b48a8),
            WordU64(0x391c0cb3c5c95a63), WordU64(0x4ed8aa4ae3418acb), WordU64(0x5b9cca4f7763e373), WordU64(0x682e6ff3d6b2b8a3),
            WordU64(0x748f82ee5defb2fc), WordU64(0x78a5636f43172f60), WordU64(0x84c87814a1f0ab72), WordU64(0x8cc702081a6439ec),
            WordU64(0x90befffa23631e28), WordU64(0xa4506cebde82bde9), WordU64(0xbef9a3f7b2c67915), WordU64(0xc67178f2e372532b),
            WordU64(0xca273eceea26619c), WordU64(0xd186b8c721c0c207), WordU64(0xeada7dd6cde0eb1e), WordU64(0xf57d4f7fee6ed178),
            WordU64(0x06f067aa72176fba), WordU64(0x0a637dc5a2c898a6), WordU64(0x113f9804bef90dae), WordU64(0x1b710b35131c471b),
            WordU64(0x28db77f523047d84), WordU64(0x32caab7b40c72493), WordU64(0x3c9ebe0a15c9bebc), WordU64(0x431d67c49c100d4c),
            WordU64(0x4cc5d4becb3e42b6), WordU64(0x597f299cfc657e2a), WordU64(0x5fcb6fab3ad6faec), WordU64(0x6c44198c4a475817),
        ];

    #[rustfmt::skip]
    #[allow(clippy::unreadable_literal)]
    /// The SHA512 initial hash value H(0) as defined in FIPS 180-4.
    const H0: [WordU64; 8] = [
            WordU64(0x6a09e667f3bcc908), WordU64(0xbb67ae8584caa73b), WordU64(0x3c6ef372fe94f82b), WordU64(0xa54ff53a5f1d36f1),
            WordU64(0x510e527fade682d1), WordU64(0x9b05688c2b3e6c1f), WordU64(0x1f83d9abfb41bd6b), WordU64(0x5be0cd19137e2179),
        ];

    /// The Big Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
    fn big_sigma_0(x: WordU64) -> WordU64 {
        (x.rotate_right(28)) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    /// The Big Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
    fn big_sigma_1(x: WordU64) -> WordU64 {
        (x.rotate_right(14)) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    /// The Small Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
    fn small_sigma_0(x: WordU64) -> WordU64 {
        (x.rotate_right(1)) ^ x.rotate_right(8) ^ (x >> WordU64(7))
    }

    /// The Small Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
    fn small_sigma_1(x: WordU64) -> WordU64 {
        (x.rotate_right(19)) ^ x.rotate_right(61) ^ (x >> WordU64(6))
    }
}

#[derive(Clone, Debug)]
/// SHA512 streaming state.
pub struct Sha512 {
    pub(crate) _state: State<WordU64, V512, SHA512_BLOCKSIZE, SHA512_OUTSIZE, N_CONSTS>,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Initialize a `Sha512` struct.
    pub fn new() -> Self {
        Self {
            _state: State::<WordU64, V512, SHA512_BLOCKSIZE, SHA512_OUTSIZE, N_CONSTS>::_new(),
        }
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self._state._reset();
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self._state._update(data)
    }

    /// Finalize the hash and put the final digest into `dest`.
    pub(crate) fn _finalize_internal(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self._state._finalize(dest)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a SHA512 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut digest = [0u8; SHA512_OUTSIZE];
        self._finalize_internal(&mut digest)?;

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA512 digest of some `data`.
    pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finalize()
    }
}

impl crate::hazardous::mac::hmac::HmacHashFunction for Sha512 {
    /// The blocksize of the hash function.
    const _BLOCKSIZE: usize = SHA512_BLOCKSIZE;

    /// The output size of the hash function.
    const _OUTSIZE: usize = SHA512_OUTSIZE;

    /// Create a new instance of the hash function.
    fn _new() -> Self {
        Self::new()
    }

    /// Update the internal state with `data`.
    fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    /// Finalize the hash and put the final digest into `dest`.
    fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self._finalize_internal(dest)
    }

    /// Compute a digest of `data` and copy it into `dest`.
    fn _digest(data: &[u8], dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx._finalize_internal(dest)
    }

    #[cfg(test)]
    fn compare_state_to_other(&self, other: &Self) {
        self._state.compare_state_to_other(&other._state);
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: hashing from a [`Read`](std::io::Read)er with SHA512.
/// ```rust
/// use orion::{
///     hazardous::hash::sha2::sha512::{Sha512, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Sha512::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Sha512 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Sha512::update`](crate::hazardous::hash::sha2::sha512::Sha512::update).
    ///
    /// ## Errors:
    /// This function will only ever return the [`std::io::ErrorKind::Other`]()
    /// variant when it returns an error. Additionally, this will always contain Orion's
    /// [`UnknownCryptoError`] type.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.update(bytes).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    /// This type doesn't buffer writes, so flushing is a no-op.
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_default_equals_new() {
        let new = Sha512::new();
        let default = Sha512::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha512::new();
        let debug = format!("{initial_state:?}");
        let expected = "Sha512 { _state: State { working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: 0, message_len: [WordU64(0), WordU64(0)], is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha512 {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                self.reset();
                Ok(())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Digest, UnknownCryptoError> {
                Sha512::digest(input)
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual: Digest = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Sha512, state_2: &Sha512) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Sha512 = Sha512::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha512>::new(
                initial_state,
                SHA512_BLOCKSIZE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Sha512 = Sha512::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha512>::new(
                initial_state,
                SHA512_BLOCKSIZE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha2::sha512::Sha512;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Sha512::new();
            let mut hasher_b = hasher_a.clone();

            hasher_a.update(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            // Additionally make sure flush() is a no-op, which we expect.
            hasher_b.flush().unwrap();
            hasher_a._state.compare_state_to_other(&hasher_b._state);

            let hash_a = hasher_a.finalize().unwrap();
            let hash_b = hasher_b.finalize().unwrap();

            // Additionally make sure flush() is a no-op, which we expect.
            hasher_b.flush().unwrap();
            hasher_a._state.compare_state_to_other(&hasher_b._state);

            hash_a == hash_b
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
            let mut context = Sha512::default();

            context._state.increment_mlen(&WordU64::from(1u64));
            assert_eq!(context._state.message_len[0], WordU64::from(0u64));
            assert_eq!(context._state.message_len[1], WordU64::from(8u64));

            context._state.increment_mlen(&WordU64::from(17u64));
            assert_eq!(context._state.message_len[0], WordU64::from(0u64));
            assert_eq!(context._state.message_len[1], WordU64::from(144u64));

            context._state.increment_mlen(&WordU64::from(12u64));
            assert_eq!(context._state.message_len[0], WordU64::from(0u64));
            assert_eq!(context._state.message_len[1], WordU64::from(240u64));

            // Overflow
            context._state.increment_mlen(&WordU64::from(u64::MAX / 8));
            assert_eq!(context._state.message_len[0], WordU64::from(1u64));
            assert_eq!(context._state.message_len[1], WordU64::from(232u64));
        }

        #[test]
        #[should_panic]
        fn test_panic_on_second_overflow() {
            let mut context = Sha512::default();
            context._state.message_len = [WordU64::MAX, WordU64::from(u64::MAX - 7)];
            // u64::MAX - 7, to leave so that the length represented
            // in bites should overflow by exactly one.
            context._state.increment_mlen(&WordU64::from(1u64));
        }
    }
}
