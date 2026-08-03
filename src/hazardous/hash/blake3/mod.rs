// MIT License

// Copyright (c) 2026 The orion Developers

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
//! - `out_slice`: The variable-sized output buffer.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 1024*(2^64-1) bytes of data are hashed.
//!
//! # Security:
//! - The recommended minimum output size is 32. The security provided by the hash function cannot
//! exceed 256 bits, so choosing output sizes larger than 32 bytes provides no additional security over
//! the 32 exactly. Choosing a smaller output size however decreases the security provided.
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used for this. It generates
//!   a secret key of 32 bytes.
//! - When using [`Blake3Keyed`] the output digest can be used as a MAC. If this is done, it is crucial
//! to use constant-time comparisons for such digest and take care not to leak them through [`Debug`].
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::blake3::Blake3;
//!
//! // Using the streaming interface.
//! let mut hash_out = [0u8; 32];
//! let mut state = Blake3::new();
//! state.update(b"Some data")?;
//! state.finalize(&mut hash_out)?;
//!
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: blake3::Blake3::update
//! [`reset()`]: blake3::Blake3::reset
//! [`finalize()`]: blake3::Blake3::finalize

mod cvstack;
mod internal;
mod state;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake3::internal::{IV, KEYED_HASH, KEY_SIZE};
use crate::hazardous::hash::blake3::state::Blake3State;

#[cfg(feature = "safe_api")]
use std::io;

construct_secret_key! {
    /// A type to represent the secret key that BLAKE3 uses for keyed mode.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    ///
    /// # Panics:
    /// A panic will occur during:
    /// - Failure to generate random bytes securely.
    ///
    (SecretKey, test_secret_key, KEY_SIZE, KEY_SIZE, KEY_SIZE)
}

/// BLAKE3 configuration for standard hashing.
#[derive(PartialEq, Debug, Clone)]
pub struct Blake3 {
    internal: Blake3State,
}

/// Represents the standard `hash` mode for [Blake3] for producing
/// hashes without a secret key.
impl Default for Blake3 {
    /// Create a new [`Blake3`] instance for standard hashing (`hash` mode).
    fn default() -> Self {
        Self {
            internal: Blake3State::new(IV, 0),
        }
    }
}

impl Blake3 {
    /// Create a new [`Blake3`] instance for standard hashing (`hash` mode).
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to [`Self::new()`] state.
    pub fn reset(&mut self) {
        self.internal = Blake3State::new(IV, 0)
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.internal.update(data, IV, 0)
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(&mut self, out_slice: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self.internal.finalize(out_slice, IV, 0)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: custom digest size.
/// ```rust
/// use orion::{
///     hazardous::hash::blake3::Blake3,
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Blake3::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let mut digest = [0u8; 32];
/// hasher.finalize(&mut digest)?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Blake3 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Blake3::update`](crate::hazardous::hash::blake3::Blake3::update).
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

/// Represents the "keyed hash" mode for BLAKE3 for producing
/// hashes using a secret key.
#[derive(Clone, Debug, PartialEq)]
pub struct Blake3Keyed<'key> {
    internal: Blake3State,
    key: &'key SecretKey,
}

impl<'key> Blake3Keyed<'key> {
    /// Create a new [`Blake3Keyed`] instance for keyed hashing (`keyed hash` mode).
    pub fn new(key: &'key SecretKey) -> Self {
        Self {
            internal: Blake3State::new(Self::parse_key(key), KEYED_HASH),
            key,
        }
    }

    fn parse_key(key: &SecretKey) -> [u32; 8] {
        let bytes = key.unprotected_as_bytes();
        core::array::from_fn(|i| {
            let start = i * 4;
            u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ])
        })
    }

    /// Reset to [`Self::new()`] state.
    pub fn reset(&mut self) {
        self.internal = Blake3State::new(Self::parse_key(self.key), KEYED_HASH);
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.internal
            .update(data, Self::parse_key(self.key), KEYED_HASH)
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(&mut self, out_slice: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self.internal
            .finalize(out_slice, Self::parse_key(self.key), KEYED_HASH)
    }
}

#[cfg(test)]
mod test_streaming_interface {
    mod hash_streaming_interface {
        use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
        use crate::hazardous::hash::blake3::*;
        use crate::test_framework::incremental_interface::{
            StreamingContextConsistencyTester, TestableStreamingContext,
        };

        impl TestableStreamingContext<[u8; 32]> for Blake3 {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                self.reset();
                Ok(())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<[u8; 32], UnknownCryptoError> {
                let mut out = [0u8; 32];
                self.finalize(&mut out)?;
                Ok(out)
            }

            fn one_shot(input: &[u8]) -> Result<[u8; 32], UnknownCryptoError> {
                let mut hasher = Blake3::new();
                hasher.update(input)?;

                let mut out = [0u8; 32];
                hasher.finalize(&mut out)?;
                Ok(out)
            }

            fn verify_result(expected: &[u8; 32], input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual = Self::one_shot(input)?;
                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Self, state_2: &Self) {
                assert_eq!(state_1, state_2)
            }
        }

        #[test]
        fn default_consistency_states() {
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3>::new(
                Blake3::new(),
                BLOCK_LEN,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3>::new(
                Blake3::new(),
                BLOCK_LEN,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    mod keyed_streaming_interface {
        use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
        use crate::hazardous::hash::blake3::*;
        use crate::test_framework::incremental_interface::{
            StreamingContextConsistencyTester, TestableStreamingContext,
        };

        impl<'key> TestableStreamingContext<[u8; 32]> for Blake3Keyed<'key> {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                self.reset();
                Ok(())
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<[u8; 32], UnknownCryptoError> {
                let mut out = [0u8; 32];
                self.finalize(&mut out)?;
                Ok(out)
            }

            fn one_shot(input: &[u8]) -> Result<[u8; 32], UnknownCryptoError> {
                let secret_key = get_secret_key();
                let mut hasher = Blake3Keyed::new(&secret_key);
                hasher.update(input)?;

                let mut out = [0u8; 32];
                hasher.finalize(&mut out)?;
                Ok(out)
            }

            fn verify_result(expected: &[u8; 32], input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual = Self::one_shot(input)?;
                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Self, state_2: &Self) {
                assert_eq!(state_1, state_2)
            }
        }

        #[test]
        fn keyed_consistency_states() {
            let secret_key = get_secret_key();
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3Keyed<'_>>::new(
                Blake3Keyed::new(&secret_key),
                BLOCK_LEN,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let secret_key = get_secret_key();
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3Keyed<'_>>::new(
                Blake3Keyed::new(&secret_key),
                BLOCK_LEN,
            );
            test_runner.run_all_tests_property(&data);
            true
        }

        fn get_secret_key() -> SecretKey {
            SecretKey::from_slice(&[0x42; 32]).unwrap()
        }
    }
}
