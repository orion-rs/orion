// MIT License

// Copyright (c) 2020-2021 The orion Developers

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
//! - SHA384 is vulnerable to length extension attacks.
//!
//! # Recommendation:
//! - It is recommended to use [BLAKE2b] when possible.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha2::sha384::Sha384;
//!
//! // Using the streaming interface
//! let mut state = Sha384::new();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = Sha384::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: sha384::Sha384::update
//! [`reset()`]: sha384::Sha384::reset
//! [`finalize()`]: sha384::Sha384::finalize
//! [BLAKE2b]: super::blake2::blake2b

use crate::errors::UnknownCryptoError;

#[cfg(feature = "safe_api")]
use std::io;

construct_public! {
    /// A type to represent the `Digest` that SHA384 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 48 bytes.
    (Digest, test_digest, SHA384_OUTSIZE, SHA384_OUTSIZE)
}

impl_from_trait!(Digest, SHA384_OUTSIZE);

use super::sha2_core::{State, Variant};
use super::w64::WordU64;

/// The blocksize for the hash function SHA384.
pub const SHA384_BLOCKSIZE: usize = 128;
/// The output size for the hash function SHA384.
pub const SHA384_OUTSIZE: usize = 48;
/// The number of constants for the hash function SHA384.
const N_CONSTS: usize = 80;

#[derive(Clone)]
pub(crate) struct V384;

impl Variant<WordU64, { N_CONSTS }> for V384 {
    /// The SHA384 constants as defined in FIPS 180-4.
    const K: [WordU64; N_CONSTS] = super::sha512::V512::K;

    #[rustfmt::skip]
    #[allow(clippy::unreadable_literal)]
    /// The SHA384 initial hash value H(0) as defined in FIPS 180-4.
    const H0: [WordU64; 8] = [
            WordU64(0xcbbb9d5dc1059ed8), WordU64(0x629a292a367cd507), WordU64(0x9159015a3070dd17), WordU64(0x152fecd8f70e5939),
            WordU64(0x67332667ffc00b31), WordU64(0x8eb44a8768581511), WordU64(0xdb0c2e0d64f98fa7), WordU64(0x47b5481dbefa4fa4),
        ];

    /// The Big Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
    fn big_sigma_0(x: WordU64) -> WordU64 {
        super::sha512::V512::big_sigma_0(x)
    }

    /// The Big Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
    fn big_sigma_1(x: WordU64) -> WordU64 {
        super::sha512::V512::big_sigma_1(x)
    }

    /// The Small Sigma 0 function as specified in FIPS 180-4 section 4.1.3.
    fn small_sigma_0(x: WordU64) -> WordU64 {
        super::sha512::V512::small_sigma_0(x)
    }

    /// The Small Sigma 1 function as specified in FIPS 180-4 section 4.1.3.
    fn small_sigma_1(x: WordU64) -> WordU64 {
        super::sha512::V512::small_sigma_1(x)
    }
}

#[derive(Clone, Debug)]
/// SHA384 streaming state.
pub struct Sha384 {
    pub(crate) _state: State<WordU64, V384, { SHA384_BLOCKSIZE }, { SHA384_OUTSIZE }, { N_CONSTS }>,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    /// Initialize a `Sha384` struct.
    pub fn new() -> Self {
        Self {
            _state:
                State::<WordU64, V384, { SHA384_BLOCKSIZE }, { SHA384_OUTSIZE }, { N_CONSTS }>::_new(
                ),
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
    /// Return a SHA384 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut digest = [0u8; SHA384_OUTSIZE];
        self._finalize_internal(&mut digest)?;

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA384 digest of some `data`.
    pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finalize()
    }
}

impl crate::hazardous::mac::hmac::HmacHashFunction for Sha384 {
    /// The blocksize of the hash function.
    const _BLOCKSIZE: usize = SHA384_BLOCKSIZE;

    /// The output size of the hash function.
    const _OUTSIZE: usize = SHA384_OUTSIZE;

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
/// Example: hashing from a [`Read`](std::io::Read)er with SHA384.
/// ```rust
/// use orion::{
///     hazardous::hash::sha2::sha384::{Sha384, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Sha384::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Sha384 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Sha384::update`](crate::hazardous::hash::sha2::sha384::Sha384::update).
    ///
    /// ## Errors:
    /// This function will only ever return the [`std::io::ErrorKind::Other`]()
    /// variant when it returns an error. Additionally, this will always contain Orion's
    /// [`UnknownCryptoError`](crate::errors::UnknownCryptoError) type.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.update(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(bytes.len())
    }

    /// This type doesn't buffer writes, so flushing is a no-op.
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_default_equals_new() {
        let new = Sha384::new();
        let default = Sha384::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha384::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Sha384 { _state: State { working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: 0, message_len: [WordU64(0), WordU64(0)], is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha384 {
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
                Sha384::digest(input)
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual: Digest = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Sha384, state_2: &Sha384) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Sha384 = Sha384::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha384>::new(
                initial_state,
                SHA384_BLOCKSIZE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Sha384 = Sha384::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha384>::new(
                initial_state,
                SHA384_BLOCKSIZE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha2::sha384::Sha384;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Sha384::new();
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
            let mut context = Sha384::default();

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
            use crate::hazardous::hash::sha2::sha2_core::Word;

            let mut context = Sha384::default();
            context._state.message_len = [WordU64::MAX, WordU64::from(u64::MAX - 7)];
            // u64::MAX - 7, to leave so that the length represented
            // in bites should overflow by exactly one.
            context._state.increment_mlen(&WordU64::from(1u64));
        }
    }
}
