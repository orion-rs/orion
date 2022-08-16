// MIT License

// Copyright (c) 2018-2022 The orion Developers

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
//! - `size`: The desired output length for the digest.
//! - `data`: The data to be hashed.
//! - `expected`: The expected digest when verifying.
//!
//! # Errors:
//! An error will be returned if:
//! - `size` is 0 or greater than 64.
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2*(2^64-1) bytes of data are hashed.
//!
//! # Security:
//! - The recommended minimum output size is 32.
//! - This interface only allows creating hash digest using BLAKE2b. If using a secret key is desired,
//! please refer to the [`mac::blake2b`] module.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::blake2::blake2b::{Blake2b, Hasher};
//!
//! // Using the streaming interface.
//! let mut state = Blake2b::new(64)?;
//! state.update(b"Some data")?;
//! let hash = state.finalize()?;
//!
//! // Using the `Hasher` for convenience functions.
//! let hash_one_shot = Hasher::Blake2b512.digest(b"Some data")?;
//!
//! assert_eq!(hash, hash_one_shot);
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: blake2b::Blake2b::update
//! [`reset()`]: blake2b::Blake2b::reset
//! [`finalize()`]: blake2b::Blake2b::finalize
//! [`mac::blake2b`]: crate::hazardous::mac::blake2b

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b_core;
use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_OUTSIZE;

#[cfg(feature = "safe_api")]
use std::io;

construct_public! {
    /// A type to represent the `Digest` that BLAKE2b returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `slice` is greater than 64 bytes.
    (Digest, test_digest, 1, BLAKE2B_OUTSIZE)
}

#[derive(Debug, Clone)]
/// BLAKE2b streaming state.
pub struct Blake2b {
    _state: blake2b_core::State,
}

impl Blake2b {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Initialize a `Blake2b` struct with a given size.
    pub fn new(size: usize) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            _state: blake2b_core::State::_new(&[], size)?,
        })
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Reset to `new()` state.
    pub fn reset(&mut self) -> Result<(), UnknownCryptoError> {
        self._state._reset(&[])
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self._state._update(data)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a BLAKE2b digest.
    pub fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
        let mut tmp = [0u8; BLAKE2B_OUTSIZE];
        self._state._finalize(&mut tmp)?;

        Digest::from_slice(&tmp[..self._state.size])
    }
}

#[derive(Debug, PartialEq)]
/// Convenience functions for common BLAKE2b operations.
pub enum Hasher {
    /// Blake2b with `32` as `size`.
    Blake2b256,
    /// Blake2b with `48` as `size`.
    Blake2b384,
    /// Blake2b with `64` as `size`.
    Blake2b512,
}

impl Hasher {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a digest selected by the given Blake2b variant.
    pub fn digest(&self, data: &[u8]) -> Result<Digest, UnknownCryptoError> {
        let size: usize = match *self {
            Hasher::Blake2b256 => 32,
            Hasher::Blake2b384 => 48,
            Hasher::Blake2b512 => 64,
        };

        let mut state = Blake2b::new(size)?;
        state.update(data)?;
        state.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a `Blake2b` state selected by the given Blake2b variant.
    pub fn init(&self) -> Result<Blake2b, UnknownCryptoError> {
        match *self {
            Hasher::Blake2b256 => Blake2b::new(32),
            Hasher::Blake2b384 => Blake2b::new(48),
            Hasher::Blake2b512 => Blake2b::new(64),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: custom digest size.
/// ```rust
/// use orion::{
///     hazardous::hash::blake2::blake2b::{Blake2b, Digest},
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Blake2b::new(64)?; // 512-bit hash
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let digest: Digest = hasher.finalize()?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Blake2b {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Blake2b::update`](crate::hazardous::hash::blake2::blake2b::Blake2b::update).
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

#[cfg(test)]
mod public {
    mod test_streaming_interface_no_key {
        use crate::errors::UnknownCryptoError;
        use crate::hazardous::hash::blake2::blake2b::{Blake2b, Digest};
        use crate::hazardous::hash::blake2::blake2b_core::{
            compare_blake2b_states, BLAKE2B_BLOCKSIZE, BLAKE2B_OUTSIZE,
        };
        use crate::test_framework::incremental_interface::{
            StreamingContextConsistencyTester, TestableStreamingContext,
        };

        impl TestableStreamingContext<Digest> for Blake2b {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                self.reset()
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Digest, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Digest, UnknownCryptoError> {
                let mut ctx = Blake2b::new(BLAKE2B_OUTSIZE)?;
                ctx.update(input)?;
                ctx.finalize()
            }

            fn verify_result(expected: &Digest, input: &[u8]) -> Result<(), UnknownCryptoError> {
                let actual = Self::one_shot(input)?;

                if &actual == expected {
                    Ok(())
                } else {
                    Err(UnknownCryptoError)
                }
            }

            fn compare_states(state_1: &Blake2b, state_2: &Blake2b) {
                compare_blake2b_states(&state_1._state, &state_2._state)
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Blake2b = Blake2b::new(BLAKE2B_OUTSIZE).unwrap();

            let test_runner = StreamingContextConsistencyTester::<Digest, Blake2b>::new(
                initial_state,
                BLAKE2B_BLOCKSIZE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Blake2b = Blake2b::new(BLAKE2B_OUTSIZE).unwrap();

            let test_runner = StreamingContextConsistencyTester::<Digest, Blake2b>::new(
                initial_state,
                BLAKE2B_BLOCKSIZE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    mod test_hasher {
        use crate::hazardous::hash::blake2::blake2b::Hasher;

        #[test]
        fn test_hasher_interface_no_panic_and_same_result() {
            let digest_256 = Hasher::Blake2b256.digest(b"Test").unwrap();
            let digest_384 = Hasher::Blake2b384.digest(b"Test").unwrap();
            let digest_512 = Hasher::Blake2b512.digest(b"Test").unwrap();

            assert_eq!(digest_256, Hasher::Blake2b256.digest(b"Test").unwrap());
            assert_eq!(digest_384, Hasher::Blake2b384.digest(b"Test").unwrap());
            assert_eq!(digest_512, Hasher::Blake2b512.digest(b"Test").unwrap());

            assert_ne!(digest_256, Hasher::Blake2b256.digest(b"Wrong").unwrap());
            assert_ne!(digest_384, Hasher::Blake2b384.digest(b"Wrong").unwrap());
            assert_ne!(digest_512, Hasher::Blake2b512.digest(b"Wrong").unwrap());

            let _state_256 = Hasher::Blake2b256.init().unwrap();
            let _state_384 = Hasher::Blake2b384.init().unwrap();
            let _state_512 = Hasher::Blake2b512.init().unwrap();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Given some data, digest() should never fail in practice and should
        /// produce the same output on a second call.
        /// Only panics if data is unreasonably large.
        fn prop_hasher_digest_no_panic_and_same_result(data: Vec<u8>) -> bool {
            let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();
            let d384 = Hasher::Blake2b384.digest(&data[..]).unwrap();
            let d512 = Hasher::Blake2b512.digest(&data[..]).unwrap();

            let d256_re = Hasher::Blake2b256.digest(&data[..]).unwrap();
            let d384_re = Hasher::Blake2b384.digest(&data[..]).unwrap();
            let d512_re = Hasher::Blake2b512.digest(&data[..]).unwrap();

            (d256 == d256_re) && (d384 == d384_re) && (d512 == d512_re)
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Given some data, .digest() should produce the same output as when
        /// calling with streaming state.
        fn prop_hasher_digest_256_same_as_streaming(data: Vec<u8>) -> bool {
            use crate::hazardous::hash::blake2::blake2b::Blake2b;

            let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();

            let mut state = Blake2b::new(32).unwrap();
            state.update(&data[..]).unwrap();

            d256 == state.finalize().unwrap()
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Given some data, .digest() should produce the same output as when
        /// calling with streaming state.
        fn prop_hasher_digest_384_same_as_streaming(data: Vec<u8>) -> bool {
            use crate::hazardous::hash::blake2::blake2b::Blake2b;

            let d384 = Hasher::Blake2b384.digest(&data[..]).unwrap();

            let mut state = Blake2b::new(48).unwrap();
            state.update(&data[..]).unwrap();

            d384 == state.finalize().unwrap()
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Given some data, .digest() should produce the same output as when
        /// calling with streaming state.
        fn prop_hasher_digest_512_same_as_streaming(data: Vec<u8>) -> bool {
            use crate::hazardous::hash::blake2::blake2b::Blake2b;

            let d512 = Hasher::Blake2b512.digest(&data[..]).unwrap();

            let mut state = Blake2b::new(64).unwrap();
            state.update(&data[..]).unwrap();

            d512 == state.finalize().unwrap()
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Given two different data, .digest() should never produce the
        /// same output.
        fn prop_hasher_digest_diff_input_diff_result(data: Vec<u8>) -> bool {
            let d256 = Hasher::Blake2b256.digest(&data[..]).unwrap();
            let d384 = Hasher::Blake2b384.digest(&data[..]).unwrap();
            let d512 = Hasher::Blake2b512.digest(&data[..]).unwrap();

            let d256_re = Hasher::Blake2b256.digest(b"Wrong data").unwrap();
            let d384_re = Hasher::Blake2b384.digest(b"Wrong data").unwrap();
            let d512_re = Hasher::Blake2b512.digest(b"Wrong data").unwrap();

            (d256 != d256_re) && (d384 != d384_re) && (d512 != d512_re)
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// .init() should never fail.
        fn prop_hasher_init_no_panic() -> bool {
            let _d256 = Hasher::Blake2b256.init().unwrap();
            let _d384 = Hasher::Blake2b384.init().unwrap();
            let _d512 = Hasher::Blake2b512.init().unwrap();

            true
        }
    }

    mod test_new {
        use crate::hazardous::hash::blake2::blake2b::Blake2b;

        #[test]
        fn test_init_size() {
            assert!(Blake2b::new(0).is_err());
            assert!(Blake2b::new(65).is_err());
            assert!(Blake2b::new(1).is_ok());
            assert!(Blake2b::new(64).is_ok());
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::blake2::blake2b::Blake2b;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Blake2b::new(64).unwrap();
            let mut hasher_b = hasher_a.clone();

            hasher_a.update(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            let hash_a = hasher_a.finalize().unwrap();
            let hash_b = hasher_b.finalize().unwrap();

            hash_a == hash_b
        }
    }
}
