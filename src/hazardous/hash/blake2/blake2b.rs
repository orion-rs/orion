//! TODO

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b_core;
use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_OUTSIZE;

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
}
