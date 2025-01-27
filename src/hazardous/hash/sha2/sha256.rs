// MIT License

// Copyright (c) 2020-2025 The orion Developers

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
//! - More than 2*(2^32-1) __bits__ of data are hashed.
//!
//! # Security:
//! - SHA256 is vulnerable to length extension attacks.
//!
//! # Recommendation:
//! - It is recommended to use [BLAKE2b] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha2::sha256::Sha256;
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
//! [`update()`]: sha256::Sha256::update
//! [`reset()`]: sha256::Sha256::reset
//! [`finalize()`]: sha256::Sha256::finalize
//! [BLAKE2b]: super::blake2::blake2b

use crate::errors::UnknownCryptoError;

#[cfg(feature = "safe_api")]
use std::io;

/// The blocksize for the hash function SHA256.
pub const SHA256_BLOCKSIZE: usize = 64;
/// The output size for the hash function SHA256.
pub const SHA256_OUTSIZE: usize = 32;
/// The number of constants for the hash function SHA256.
const N_CONSTS: usize = 64;

construct_public! {
    /// A type to represent the `Digest` that SHA256 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (Digest, test_digest, SHA256_OUTSIZE, SHA256_OUTSIZE)
}

impl_from_trait!(Digest, SHA256_OUTSIZE);

use super::sha2_core::{State, Variant, Word};
use super::w32::WordU32;

#[derive(Clone)]
/// SHA256 streaming state.
pub(crate) struct V256;

impl Variant<WordU32, N_CONSTS> for V256 {
    #[rustfmt::skip]
    #[allow(clippy::unreadable_literal)]
    /// The SHA256 constants as defined in FIPS 180-4.
    const K: [WordU32; N_CONSTS] = [
            WordU32(0x428a2f98), WordU32(0x71374491), WordU32(0xb5c0fbcf), WordU32(0xe9b5dba5),
            WordU32(0x3956c25b), WordU32(0x59f111f1), WordU32(0x923f82a4), WordU32(0xab1c5ed5),
            WordU32(0xd807aa98), WordU32(0x12835b01), WordU32(0x243185be), WordU32(0x550c7dc3),
            WordU32(0x72be5d74), WordU32(0x80deb1fe), WordU32(0x9bdc06a7), WordU32(0xc19bf174),
            WordU32(0xe49b69c1), WordU32(0xefbe4786), WordU32(0x0fc19dc6), WordU32(0x240ca1cc),
            WordU32(0x2de92c6f), WordU32(0x4a7484aa), WordU32(0x5cb0a9dc), WordU32(0x76f988da),
            WordU32(0x983e5152), WordU32(0xa831c66d), WordU32(0xb00327c8), WordU32(0xbf597fc7),
            WordU32(0xc6e00bf3), WordU32(0xd5a79147), WordU32(0x06ca6351), WordU32(0x14292967),
            WordU32(0x27b70a85), WordU32(0x2e1b2138), WordU32(0x4d2c6dfc), WordU32(0x53380d13),
            WordU32(0x650a7354), WordU32(0x766a0abb), WordU32(0x81c2c92e), WordU32(0x92722c85),
            WordU32(0xa2bfe8a1), WordU32(0xa81a664b), WordU32(0xc24b8b70), WordU32(0xc76c51a3),
            WordU32(0xd192e819), WordU32(0xd6990624), WordU32(0xf40e3585), WordU32(0x106aa070),
            WordU32(0x19a4c116), WordU32(0x1e376c08), WordU32(0x2748774c), WordU32(0x34b0bcb5),
            WordU32(0x391c0cb3), WordU32(0x4ed8aa4a), WordU32(0x5b9cca4f), WordU32(0x682e6ff3),
            WordU32(0x748f82ee), WordU32(0x78a5636f), WordU32(0x84c87814), WordU32(0x8cc70208),
            WordU32(0x90befffa), WordU32(0xa4506ceb), WordU32(0xbef9a3f7), WordU32(0xc67178f2),
        ];

    #[rustfmt::skip]
    #[allow(clippy::unreadable_literal)]
    /// The SHA256 initial hash value H(0) as defined in FIPS 180-4.
    const H0: [WordU32; 8] = [
            WordU32(0x6a09e667), WordU32(0xbb67ae85), WordU32(0x3c6ef372), WordU32(0xa54ff53a),
            WordU32(0x510e527f), WordU32(0x9b05688c), WordU32(0x1f83d9ab), WordU32(0x5be0cd19),
        ];

    /// The Big Sigma 0 function as specified in FIPS 180-4 section 4.1.2.
    fn big_sigma_0(x: WordU32) -> WordU32 {
        (x.rotate_right(2)) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    /// The Big Sigma 1 function as specified in FIPS 180-4 section 4.1.2.
    fn big_sigma_1(x: WordU32) -> WordU32 {
        (x.rotate_right(6)) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    /// The Small Sigma 0 function as specified in FIPS 180-4 section 4.1.2.
    fn small_sigma_0(x: WordU32) -> WordU32 {
        (x.rotate_right(7)) ^ x.rotate_right(18) ^ (x >> WordU32(3))
    }

    /// The Small Sigma 1 function as specified in FIPS 180-4 section 4.1.2.
    fn small_sigma_1(x: WordU32) -> WordU32 {
        (x.rotate_right(17)) ^ x.rotate_right(19) ^ (x >> WordU32(10))
    }
}

#[derive(Clone, Debug)]
/// SHA256 streaming state.
pub struct Sha256 {
    pub(crate) _state: State<WordU32, V256, SHA256_BLOCKSIZE, SHA256_OUTSIZE, N_CONSTS>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Initialize a `Sha256` struct.
    pub fn new() -> Self {
        Self {
            _state: State::<WordU32, V256, SHA256_BLOCKSIZE, SHA256_OUTSIZE, N_CONSTS>::_new(),
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
    /// Return a SHA256 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut digest = [0u8; SHA256_OUTSIZE];
        self._finalize_internal(&mut digest)?;

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA256 digest of some `data`.
    pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finalize()
    }
}

impl crate::hazardous::mac::hmac::HmacHashFunction for Sha256 {
    /// The blocksize of the hash function.
    const _BLOCKSIZE: usize = SHA256_BLOCKSIZE;

    /// The output size of the hash function.
    const _OUTSIZE: usize = SHA256_OUTSIZE;

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
/// Example: hashing from a [`Read`](std::io::Read)er with SHA256.
/// ```rust
/// use orion::{
///     hazardous::hash::sha2::sha256::{Sha256, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Sha256::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Sha256 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Sha256::update`](crate::hazardous::hash::sha2::sha256::Sha256::update).
    ///
    /// ## Errors:
    /// This function will only ever return the [`std::io::ErrorKind::Other`]()
    /// variant when it returns an error. Additionally, this will always contain Orion's
    /// [`UnknownCryptoError`] type.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.update(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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
        let new = Sha256::new();
        let default = Sha256::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha256::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Sha256 { _state: State { working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: 0, message_len: [WordU32(0), WordU32(0)], is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha256 {
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
                state_1._state.compare_state_to_other(&state_2._state);
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

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
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

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha2::sha256::Sha256;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Sha256::new();
            let mut hasher_b = hasher_a.clone();

            hasher_a.update(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            let hash_a = hasher_a.finalize().unwrap();
            let hash_b = hasher_b.finalize().unwrap();

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
            let mut context = Sha256::default();

            context._state.increment_mlen(&WordU32::from(1u32));
            assert_eq!(context._state.message_len[0], WordU32::from(0u32));
            assert_eq!(context._state.message_len[1], WordU32::from(8u32));

            context._state.increment_mlen(&WordU32::from(17u32));
            assert_eq!(context._state.message_len[0], WordU32::from(0u32));
            assert_eq!(context._state.message_len[1], WordU32::from(144u32));

            context._state.increment_mlen(&WordU32::from(12u32));
            assert_eq!(context._state.message_len[0], WordU32::from(0u32));
            assert_eq!(context._state.message_len[1], WordU32::from(240u32));

            // Overflow
            context._state.increment_mlen(&WordU32::from(u32::MAX / 8));
            assert_eq!(context._state.message_len[0], WordU32::from(1u32));
            assert_eq!(context._state.message_len[1], WordU32::from(232u32));
        }

        #[test]
        #[should_panic]
        fn test_panic_on_second_overflow() {
            let mut context = Sha256::default();
            context._state.message_len = [WordU32::MAX, WordU32::from(u32::MAX - 7)];
            // u32::MAX - 7, to leave so that the length represented
            // in bites should overflow by exactly one.
            context._state.increment_mlen(&WordU32::from(1u32));
        }
    }
}
