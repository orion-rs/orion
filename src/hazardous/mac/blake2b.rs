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
//! - `secret_key`: The authentication key.
//! - `size`: The desired output length for the authentication tag.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication tag.
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
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used for this. It generates
//!   a secret key of 32 bytes.
//! - The minimum recommended size for a secret key is 32 bytes.
//! - The recommended minimum output size is 32.
//! - This interface only allows creating authentication tag using BLAKE2b. If hash digests are needed,
//! please refer to the [`hash::blake2::blake2b`] module.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::mac::blake2b::{Blake2b, SecretKey};
//!
//! let key = SecretKey::generate();
//!
//! let mut state = Blake2b::new(&key, 64)?;
//! state.update(b"Some data")?;
//! let tag = state.finalize()?;
//!
//! assert!(Blake2b::verify(&tag, &key, 64, b"Some data").is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: blake2b::Blake2b::update
//! [`reset()`]: blake2b::Blake2b::reset
//! [`finalize()`]: blake2b::Blake2b::finalize
//! [`SecretKey::generate()`]: blake2b::SecretKey::generate
//! [`hash::blake2::blake2b`]: crate::hazardous::hash::blake2::blake2b

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b_core::{self, BLAKE2B_KEYSIZE, BLAKE2B_OUTSIZE};
use core::ops::DerefMut;
use zeroize::Zeroizing;

construct_secret_key! {
    /// A type to represent the secret key that BLAKE2b uses for keyed mode.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `slice` is greater than 64 bytes.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (SecretKey, test_secret_key, 1, BLAKE2B_KEYSIZE, 32)
}

construct_tag! {
    /// A type to represent the `Tag` that BLAKE2b returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `slice` is greater than 64 bytes.
    (Tag, test_tag, 1, BLAKE2B_OUTSIZE)
}

#[derive(Debug, Clone)]
/// BLAKE2b streaming state.
pub struct Blake2b {
    _state: blake2b_core::State,
}

impl Blake2b {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Initialize a `Blake2b` struct with a given size (in bytes) and key.
    pub fn new(secret_key: &SecretKey, size: usize) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            _state: blake2b_core::State::_new(secret_key.unprotected_as_bytes(), size)?,
        })
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Reset to `new()` state.
    pub fn reset(&mut self, secret_key: &SecretKey) -> Result<(), UnknownCryptoError> {
        self._state._reset(secret_key.unprotected_as_bytes())
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self._state._update(data)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a BLAKE2b tag.
    pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
        let mut tmp: Zeroizing<[u8; BLAKE2B_OUTSIZE]> = Zeroizing::new([0u8; BLAKE2B_OUTSIZE]);
        self._state._finalize(tmp.deref_mut())?;

        Tag::from_slice(&tmp[..self._state.size])
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify a BLAKE2b tag in constant time.
    pub fn verify(
        expected: &Tag,
        secret_key: &SecretKey,
        size: usize,
        data: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new(secret_key, size)?;
        ctx.update(data)?;

        if &ctx.finalize()? == expected {
            Ok(())
        } else {
            Err(UnknownCryptoError)
        }
    }
}

#[cfg(test)]
mod public {
    mod test_streaming_interface_no_key {
        use crate::errors::UnknownCryptoError;
        use crate::hazardous::hash::blake2::blake2b_core::{
            compare_blake2b_states, BLAKE2B_BLOCKSIZE, BLAKE2B_OUTSIZE,
        };
        use crate::hazardous::mac::blake2b::{Blake2b, SecretKey, Tag};
        use crate::test_framework::incremental_interface::{
            StreamingContextConsistencyTester, TestableStreamingContext,
        };

        const KEY: [u8; 32] = [255u8; 32];

        impl TestableStreamingContext<Tag> for Blake2b {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                let key = SecretKey::from_slice(&KEY).unwrap();
                self.reset(&key)
            }

            fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.update(input)
            }

            fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                self.finalize()
            }

            fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                let key = SecretKey::from_slice(&KEY).unwrap();
                let mut ctx = Blake2b::new(&key, BLAKE2B_OUTSIZE)?;
                ctx.update(input)?;
                ctx.finalize()
            }

            fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
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
            let key = SecretKey::from_slice(&KEY).unwrap();
            let initial_state: Blake2b = Blake2b::new(&key, BLAKE2B_OUTSIZE).unwrap();

            let test_runner = StreamingContextConsistencyTester::<Tag, Blake2b>::new(
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
            let key = SecretKey::from_slice(&KEY).unwrap();
            let initial_state: Blake2b = Blake2b::new(&key, BLAKE2B_OUTSIZE).unwrap();

            let test_runner = StreamingContextConsistencyTester::<Tag, Blake2b>::new(
                initial_state,
                BLAKE2B_BLOCKSIZE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    mod test_new {
        use crate::hazardous::mac::blake2b::{Blake2b, SecretKey};

        #[test]
        fn test_init_size() {
            let sk = SecretKey::from_slice(&[0u8; 32]).unwrap();
            assert!(Blake2b::new(&sk, 0).is_err());
            assert!(Blake2b::new(&sk, 65).is_err());
            assert!(Blake2b::new(&sk, 1).is_ok());
            assert!(Blake2b::new(&sk, 64).is_ok());
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_verify {
        use crate::hazardous::mac::blake2b::{Blake2b, SecretKey};

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// When using a different key, verify() should always yield an error.
        /// NOTE: Using different and same input data is tested with TestableStreamingContext.
        fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
            let sk = SecretKey::generate();
            let mut state = Blake2b::new(&sk, 64).unwrap();
            state.update(&data[..]).unwrap();
            let tag = state.finalize().unwrap();
            let bad_sk = SecretKey::generate();

            Blake2b::verify(&tag, &bad_sk, 64, &data[..]).is_err()
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// When using a different size, verify() should always yield an error.
        /// NOTE: Using different and same input data is tested with TestableStreamingContext.
        fn prop_verify_diff_size_false(data: Vec<u8>, size_one: usize, size_two: usize) -> bool {
            let (size_one, size_two) = match (size_one, size_two) {
                (1..=64, 1..=64) => (size_one, size_two),
                (_, _) => (32, 64),
            };

            let sk = SecretKey::generate();
            let mut state = Blake2b::new(&sk, size_one).unwrap();
            state.update(&data[..]).unwrap();
            let tag = state.finalize().unwrap();

            if size_one != size_two {
                Blake2b::verify(&tag, &sk, size_two, &data[..]).is_err()
            } else {
                Blake2b::verify(&tag, &sk, size_two, &data[..]).is_ok()
            }
        }
    }

    mod test_streaming_interface {
        use crate::hazardous::hash::blake2::blake2b_core::compare_blake2b_states;
        use crate::hazardous::mac::blake2b::{Blake2b, SecretKey};

        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Testing different usage combinations of new(), update(),
        /// finalize() and reset() produce the same Digest/Tag.
        fn produces_same_hash(sk: &SecretKey, size: usize, data: &[u8]) {
            // new(), update(), finalize()
            let mut state_1 = Blake2b::new(sk, size).unwrap();
            state_1.update(data).unwrap();
            let res_1 = state_1.finalize().unwrap();

            // new(), reset(), update(), finalize()
            let mut state_2 = Blake2b::new(sk, size).unwrap();
            state_2.reset(sk).unwrap();
            state_2.update(data).unwrap();
            let res_2 = state_2.finalize().unwrap();

            // new(), update(), reset(), update(), finalize()
            let mut state_3 = Blake2b::new(sk, size).unwrap();
            state_3.update(data).unwrap();
            state_3.reset(sk).unwrap();
            state_3.update(data).unwrap();
            let res_3 = state_3.finalize().unwrap();

            // new(), update(), finalize(), reset(), update(), finalize()
            let mut state_4 = Blake2b::new(sk, size).unwrap();
            state_4.update(data).unwrap();
            let _ = state_4.finalize().unwrap();
            state_4.reset(sk).unwrap();
            state_4.update(data).unwrap();
            let res_4 = state_4.finalize().unwrap();

            assert_eq!(res_1, res_2);
            assert_eq!(res_2, res_3);
            assert_eq!(res_3, res_4);

            // Tests for the assumption that returning Ok() on empty update() calls
            // with streaming APIs, gives the correct result. This is done by testing
            // the reasoning that if update() is empty, returns Ok(), it is the same as
            // calling new() -> finalize(). i.e not calling update() at all.
            if data.is_empty() {
                // new(), finalize()
                let mut state_5 = Blake2b::new(sk, size).unwrap();
                let res_5 = state_5.finalize().unwrap();

                // new(), reset(), finalize()
                let mut state_6 = Blake2b::new(sk, size).unwrap();
                state_6.reset(sk).unwrap();
                let res_6 = state_6.finalize().unwrap();

                // new(), update(), reset(), finalize()
                let mut state_7 = Blake2b::new(sk, size).unwrap();
                state_7.update(b"Wrong data").unwrap();
                state_7.reset(sk).unwrap();
                let res_7 = state_7.finalize().unwrap();

                assert_eq!(res_4, res_5);
                assert_eq!(res_5, res_6);
                assert_eq!(res_6, res_7);
            }
        }

        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Testing different usage combinations of new(), update(),
        /// finalize() and reset() produce the same Digest/Tag.
        fn produces_same_state(sk: &SecretKey, size: usize, data: &[u8]) {
            // new()
            let state_1 = Blake2b::new(sk, size).unwrap();

            // new(), reset()
            let mut state_2 = Blake2b::new(sk, size).unwrap();
            state_2.reset(sk).unwrap();

            // new(), update(), reset()
            let mut state_3 = Blake2b::new(sk, size).unwrap();
            state_3.update(data).unwrap();
            state_3.reset(sk).unwrap();

            // new(), update(), finalize(), reset()
            let mut state_4 = Blake2b::new(sk, size).unwrap();
            state_4.update(data).unwrap();
            let _ = state_4.finalize().unwrap();
            state_4.reset(sk).unwrap();

            compare_blake2b_states(&state_1._state, &state_2._state);
            compare_blake2b_states(&state_2._state, &state_3._state);
            compare_blake2b_states(&state_3._state, &state_4._state);
        }

        #[test]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        fn test_produce_same_state() {
            let sk = SecretKey::from_slice(b"Testing").unwrap();
            produces_same_state(&sk, 1, b"Tests");
            produces_same_state(&sk, 32, b"Tests");
            produces_same_state(&sk, 64, b"Tests");
            produces_same_state(&sk, 28, b"Tests");
        }

        #[test]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        fn test_produce_same_hash() {
            let sk = SecretKey::from_slice(b"Testing").unwrap();
            produces_same_hash(&sk, 1, b"Tests");
            produces_same_hash(&sk, 32, b"Tests");
            produces_same_hash(&sk, 64, b"Tests");
            produces_same_hash(&sk, 28, b"Tests");

            produces_same_hash(&sk, 1, b"");
            produces_same_hash(&sk, 32, b"");
            produces_same_hash(&sk, 64, b"");
            produces_same_hash(&sk, 28, b"");
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_same_hash_different_usage(data: Vec<u8>, size: usize) -> bool {
            use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_OUTSIZE;

            if (1..=BLAKE2B_OUTSIZE).contains(&size) {
                // Will panic on incorrect results.
                let sk = SecretKey::generate();
                produces_same_hash(&sk, size, &data[..]);
            }

            true
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_same_state_different_usage(data: Vec<u8>, size: usize) -> bool {
            use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_OUTSIZE;

            if (1..=BLAKE2B_OUTSIZE).contains(&size) {
                // Will panic on incorrect results.
                let sk = SecretKey::generate();
                produces_same_state(&sk, size, &data[..]);
            }

            true
        }
    }
}
