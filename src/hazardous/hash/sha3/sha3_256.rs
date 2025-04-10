// MIT License

// Copyright (c) 2023-2025 The orion Developers

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
//! use orion::hazardous::hash::sha3::sha3_256::Sha3_256;
//!
//! // Using the streaming interface
//! let mut state = Sha3_256::new();
//! state.update(b"Hello world")?;
//! let hash = state.finalize()?;
//!
//! // Using the one-shot function
//! let hash_one_shot = Sha3_256::digest(b"Hello world")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: sha3_256::Sha3_256::update
//! [`reset()`]: sha3_256::Sha3_256::reset
//! [`finalize()`]: sha3_256::Sha3_256::finalize

use crate::errors::UnknownCryptoError;
#[cfg(feature = "safe_api")]
use std::io;

use super::Sha3;

/// Rate of SHA3-256 (equivalent to blocksize in SHA2).
pub const SHA3_256_RATE: usize = 136;

/// Output size of SHA3-256 in bytes.
pub const SHA3_256_OUTSIZE: usize = 32;

construct_public! {
    /// A type to represent the `Digest` that SHA3-256 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (Digest, test_digest, SHA3_256_OUTSIZE, SHA3_256_OUTSIZE)
}

impl_from_trait!(Digest, SHA3_256_OUTSIZE);

#[derive(Clone, Debug)]
/// SHA3-256 streaming state.
pub struct Sha3_256 {
    pub(crate) _state: Sha3<SHA3_256_RATE>,
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: hashing from a [`Read`](std::io::Read)er with SHA3-256.
/// ```rust
/// use orion::{
///     hazardous::hash::sha3::sha3_256::{Sha3_256, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Sha3_256::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Sha3_256 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Sha3_256::update`](crate::hazardous::hash::sha3::sha3_256::Sha3_256::update).
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

impl Sha3_256 {
    /// Initialize a `Sha3_256` struct.
    pub fn new() -> Self {
        Self {
            _state: Sha3::<{ SHA3_256_RATE }>::_new(64),
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
    /// Return a SHA3-256 digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut digest = [0u8; SHA3_256_OUTSIZE];
        self._finalize_internal(&mut digest)?;

        Ok(Digest::from(digest))
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Calculate a SHA3-256 digest of some `data`.
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
        let new = Sha3_256::new();
        let default = Sha3_256::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Sha3_256::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Sha3_256 { _state: State { state: [***OMITTED***], buffer: [***OMITTED***], capacity: 64, leftover: 0, is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    #[test]
    // <https://github.com/ziglang/zig/issues/14851>
    fn test_zig_cryptofuzz() {
        let expected_hash: [u8; 32] = [
            0x57, 0x80, 0x4, 0x8d, 0xfa, 0x38, 0x1a, 0x1d, 0x1, 0xc7, 0x47, 0x90, 0x6e, 0x4a, 0x8,
            0x71, 0x1d, 0xd3, 0x4f, 0xd7, 0x12, 0xec, 0xd7, 0xc6, 0x80, 0x1d, 0xd2, 0xb3, 0x8f,
            0xd8, 0x1a, 0x89,
        ];
        let msg: [u8; 613] = [
            0x97, 0xd1, 0x2d, 0x1a, 0x16, 0x2d, 0x36, 0x4d, 0x20, 0x62, 0x19, 0x0b, 0x14, 0x93,
            0xbb, 0xf8, 0x5b, 0xea, 0x04, 0xc2, 0x61, 0x8e, 0xd6, 0x08, 0x81, 0xa1, 0x1d, 0x73,
            0x27, 0x48, 0xbf, 0xa4, 0xba, 0xb1, 0x9a, 0x48, 0x9c, 0xf9, 0x9b, 0xff, 0x34, 0x48,
            0xa9, 0x75, 0xea, 0xc8, 0xa3, 0x48, 0x24, 0x9d, 0x75, 0x27, 0x48, 0xec, 0x03, 0xb0,
            0xbb, 0xdf, 0x33, 0x90, 0xe3, 0x93, 0xed, 0x68, 0x24, 0x39, 0x12, 0xdf, 0xea, 0xee,
            0x8c, 0x9f, 0x96, 0xde, 0x42, 0x46, 0x8c, 0x2b, 0x17, 0x83, 0x36, 0xfb, 0xf4, 0xf7,
            0xff, 0x79, 0xb9, 0x45, 0x41, 0xc9, 0x56, 0x1a, 0x6b, 0x0c, 0xa4, 0x1a, 0xdd, 0x6b,
            0x95, 0xe8, 0x03, 0x0f, 0x09, 0x29, 0x40, 0x1b, 0xea, 0x87, 0xfa, 0xb9, 0x18, 0xa9,
            0x95, 0x07, 0x7c, 0x2f, 0x7c, 0x33, 0xfb, 0xc5, 0x11, 0x5e, 0x81, 0x0e, 0xbc, 0xae,
            0xec, 0xb3, 0xe1, 0x4a, 0x26, 0x56, 0xe8, 0x5b, 0x11, 0x9d, 0x37, 0x06, 0x9b, 0x34,
            0x31, 0x6e, 0xa3, 0xba, 0x41, 0xbc, 0x11, 0xd8, 0xc5, 0x15, 0xc9, 0x30, 0x2c, 0x9b,
            0xb6, 0x71, 0xd8, 0x7c, 0xbc, 0x38, 0x2f, 0xd5, 0xbd, 0x30, 0x96, 0xd4, 0xa3, 0x00,
            0x77, 0x9d, 0x55, 0x4a, 0x33, 0x53, 0xb6, 0xb3, 0x35, 0x1b, 0xae, 0xe5, 0xdc, 0x22,
            0x23, 0x85, 0x95, 0x88, 0xf9, 0x3b, 0xbf, 0x74, 0x13, 0xaa, 0xcb, 0x0a, 0x60, 0x79,
            0x13, 0x79, 0xc0, 0x4a, 0x02, 0xdb, 0x1c, 0xc9, 0xff, 0x60, 0x57, 0x9a, 0x70, 0x28,
            0x58, 0x60, 0xbc, 0x57, 0x07, 0xc7, 0x47, 0x1a, 0x45, 0x71, 0x76, 0x94, 0xfb, 0x05,
            0xad, 0xec, 0x12, 0x29, 0x5a, 0x44, 0x6a, 0x81, 0xd9, 0xc6, 0xf0, 0xb6, 0x9b, 0x97,
            0x83, 0x69, 0xfb, 0xdc, 0x0d, 0x4a, 0x67, 0xbc, 0x72, 0xf5, 0x43, 0x5e, 0x9b, 0x13,
            0xf2, 0xe4, 0x6d, 0x49, 0xdb, 0x76, 0xcb, 0x42, 0x6a, 0x3c, 0x9f, 0xa1, 0xfe, 0x5e,
            0xca, 0x0a, 0xfc, 0xfa, 0x39, 0x27, 0xd1, 0x3c, 0xcb, 0x9a, 0xde, 0x4c, 0x6b, 0x09,
            0x8b, 0x49, 0xfd, 0x1e, 0x3d, 0x5e, 0x67, 0x7c, 0x57, 0xad, 0x90, 0xcc, 0x46, 0x5f,
            0x5c, 0xae, 0x6a, 0x9c, 0xb2, 0xcd, 0x2c, 0x89, 0x78, 0xcf, 0xf1, 0x49, 0x96, 0x55,
            0x1e, 0x04, 0xef, 0x0e, 0x1c, 0xde, 0x6c, 0x96, 0x51, 0x00, 0xee, 0x9a, 0x1f, 0x8d,
            0x61, 0xbc, 0xeb, 0xb1, 0xa6, 0xa5, 0x21, 0x8b, 0xa7, 0xf8, 0x25, 0x41, 0x48, 0x62,
            0x5b, 0x01, 0x6c, 0x7c, 0x2a, 0xe8, 0xff, 0xf9, 0xf9, 0x1f, 0xe2, 0x79, 0x2e, 0xd1,
            0xff, 0xa3, 0x2e, 0x1c, 0x3a, 0x1a, 0x5d, 0x2b, 0x7b, 0x87, 0x25, 0x22, 0xa4, 0x90,
            0xea, 0x26, 0x9d, 0xdd, 0x13, 0x60, 0x4c, 0x10, 0x03, 0xf6, 0x99, 0xd3, 0x21, 0x0c,
            0x69, 0xc6, 0xd8, 0xc8, 0x9e, 0x94, 0x89, 0x51, 0x21, 0xe3, 0x9a, 0xcd, 0xda, 0x54,
            0x72, 0x64, 0xae, 0x94, 0x79, 0x36, 0x81, 0x44, 0x14, 0x6d, 0x3a, 0x0e, 0xa6, 0x30,
            0xbf, 0x95, 0x99, 0xa6, 0xf5, 0x7f, 0x4f, 0xef, 0xc6, 0x71, 0x2f, 0x36, 0x13, 0x14,
            0xa2, 0x9d, 0xc2, 0x0c, 0x0d, 0x4e, 0xc0, 0x02, 0xd3, 0x6f, 0xee, 0x98, 0x5e, 0x24,
            0x31, 0x74, 0x11, 0x96, 0x6e, 0x43, 0x57, 0xe8, 0x8e, 0xa0, 0x8d, 0x3d, 0x79, 0x38,
            0x20, 0xc2, 0x0f, 0xb4, 0x75, 0x99, 0x3b, 0xb1, 0xf0, 0xe8, 0xe1, 0xda, 0xf9, 0xd4,
            0xe6, 0xd6, 0xf4, 0x8a, 0x32, 0x4a, 0x4a, 0x25, 0xa8, 0xd9, 0x60, 0xd6, 0x33, 0x31,
            0x97, 0xb9, 0xb6, 0xed, 0x5f, 0xfc, 0x15, 0xbd, 0x13, 0xc0, 0x3a, 0x3f, 0x1f, 0x2d,
            0x09, 0x1d, 0xeb, 0x69, 0x6a, 0xfe, 0xd7, 0x95, 0x3e, 0x8a, 0x4e, 0xe1, 0x6e, 0x61,
            0xb2, 0x6c, 0xe3, 0x2b, 0x70, 0x60, 0x7e, 0x8c, 0xe4, 0xdd, 0x27, 0x30, 0x7e, 0x0d,
            0xc7, 0xb7, 0x9a, 0x1a, 0x3c, 0xcc, 0xa7, 0x22, 0x77, 0x14, 0x05, 0x50, 0x57, 0x31,
            0x1b, 0xc8, 0xbf, 0xce, 0x52, 0xaf, 0x9c, 0x8e, 0x10, 0x2e, 0xd2, 0x16, 0xb6, 0x6e,
            0x43, 0x10, 0xaf, 0x8b, 0xde, 0x1d, 0x60, 0xb2, 0x7d, 0xe6, 0x2f, 0x08, 0x10, 0x12,
            0x7e, 0xb4, 0x76, 0x45, 0xb6, 0xd8, 0x9b, 0x26, 0x40, 0xa1, 0x63, 0x5c, 0x7a, 0x2a,
            0xb1, 0x8c, 0xd6, 0xa4, 0x6f, 0x5a, 0xae, 0x33, 0x7e, 0x6d, 0x71, 0xf5, 0xc8, 0x6d,
            0x80, 0x1c, 0x35, 0xfc, 0x3f, 0xc1, 0xa6, 0xc6, 0x1a, 0x15, 0x04, 0x6d, 0x76, 0x38,
            0x32, 0x95, 0xb2, 0x51, 0x1a, 0xe9, 0x3e, 0x89, 0x9f, 0x0c, 0x79,
        ];

        let mut ctx = Sha3_256::new();
        ctx.update(&msg[..64]).unwrap();
        ctx.update(&msg[64..]).unwrap();

        assert_eq!(ctx.finalize().unwrap().as_ref(), &expected_hash);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Sha3_256 {
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
                Sha3_256::digest(input)
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual: Digest = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Sha3_256, state_2: &Sha3_256) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Sha3_256 = Sha3_256::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha3_256>::new(
                initial_state,
                SHA3_256_RATE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Sha3_256 = Sha3_256::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Sha3_256>::new(
                initial_state,
                SHA3_256_RATE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha3::sha3_256::Sha3_256;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Sha3_256::new();
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
