//! TODO

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
    /// Initialize a `Blake2b` struct with a given size and key.
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
}
