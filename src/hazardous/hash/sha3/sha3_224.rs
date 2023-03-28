// MIT License

// Copyright (c) 2023 The orion Developers

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
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha3::sha3_224::Sha3_224;
//!
//! // Using the streaming interface
//! let mut state = Sha3_224::new();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = Sha3_224::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: sha3_224::Sha3_224::update
//! [`reset()`]: sha3_224::Sha3_224::reset
//! [`finalize()`]: sha3_224::Sha3_224::finalize

use crate::errors::UnknownCryptoError;
#[cfg(feature = "safe_api")]
use std::io;

use super::Sha3;

/// Rate of SHA3-224 (equivalent to blocksize in SHA2).
pub const SHA3_224_RATE: usize = 144;

/// Output size of SHA3-224 in bytes.
pub const SHA3_224_OUTSIZE: usize = 28;

construct_public! {
    /// A type to represent the `Digest` that SHA3-224 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 28 bytes.
    (Digest, test_digest, SHA3_224_OUTSIZE, SHA3_224_OUTSIZE)
}

impl_from_trait!(Digest, SHA3_224_OUTSIZE);

#[derive(Clone, Debug)]
/// SHA3-224 streaming state.
pub struct Sha3_224 {
    pub(crate) _state: Sha3<SHA3_224_RATE>,
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: hashing from a [`Read`](std::io::Read)er with SHA3-224.
/// ```rust
/// use orion::{
///     hazardous::hash::sha3::sha3_224::{Sha3_224, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Sha3_224::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Sha3_224 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Sha3_224::update`](crate::hazardous::hash::sha3::sha3_224::Sha3_224::update).
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

impl Sha3_224 {
    /// Initialize a `Sha3_224` struct.
    pub fn new() -> Self {
        Self {
            _state: Sha3::<SHA3_224_RATE>::_new(56),
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
    /// Return a SHA3-224 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut digest = [0u8; SHA3_224_OUTSIZE];
        self._finalize_internal(&mut digest)?;

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA3-224 digest of some `data`.
    pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finalize()
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_default_equals_new() {
        let new = Sha3_224::new();
        let default = Sha3_224::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha3_224::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Sha3_224 { _state: State { state: [***OMITTED***], buffer: [***OMITTED***], capacity: 56, leftover: 0, is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha3_224 {
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
                Sha3_224::digest(input)
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual: Digest = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Sha3_224, state_2: &Sha3_224) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Sha3_224 = Sha3_224::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha3_224>::new(
                initial_state,
                SHA3_224_RATE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Sha3_224 = Sha3_224::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha3_224>::new(
                initial_state,
                SHA3_224_RATE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha3::sha3_224::Sha3_224;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Sha3_224::new();
            let mut hasher_b = hasher_a.clone();

            hasher_a.update(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            let hash_a = hasher_a.finalize().unwrap();
            let hash_b = hasher_b.finalize().unwrap();

            hash_a == hash_b
        }
    }
}
