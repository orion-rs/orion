// MIT License

// Copyright (c) 2024 The orion Developers

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
//! - [`absorb()`] is called after [`squeeze()`] without a [`reset()`] in
//!   between.
//!
//! # Security:
//! - 128-bit security against all attacks requires a minimum of 256 bits output (32 bytes).
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha3::shake128::Shake128;
//!
//! // Using the streaming interface
//! let mut state = Shake128::new();
//! state.absorb(b"Hello world")?;
//!
//! let mut dest = [0u8; 32];
//! state.squeeze(&mut dest[..16])?;
//! state.squeeze(&mut dest[16..])?;
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`absorb()`]: shake128::Shake128::absorb
//! [`reset()`]: shake128::Shake128::reset
//! [`squeeze()`]: shake128::Shake128::squeeze

use super::Shake;
use crate::errors::UnknownCryptoError;

/// Rate of SHAKE-128.
pub const SHAKE_128_RATE: usize = 168;

#[derive(Clone, Debug)]
/// SHAKE-128 streaming state.
pub struct Shake128 {
    pub(crate) _state: Shake<SHAKE_128_RATE>,
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake128 {
    /// Initialize a `Shake128` struct.
    pub fn new() -> Self {
        Self {
            _state: Shake::<SHAKE_128_RATE>::_new(32),
        }
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self._state._reset();
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self._state._absorb(data)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Squeeze output of the XOF into `dest`. This can be called multiple times.
    pub fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self._state._squeeze(dest)
    }
}

#[test]
fn shake128_works() {
    // Len = 160, 20 bytes
    //
    // Len = 160
    // Msg = b0438cd9e8853e976cfc13abbbb62fb8b5a50d59
    // Output = c3ffe9ea9fa6c9cf59ad26f44ea0b82a

    let msg = hex::decode("b0438cd9e8853e976cfc13abbbb62fb8b5a50d59").unwrap();
    let expected_result = hex::decode("c3ffe9ea9fa6c9cf59ad26f44ea0b82a").unwrap();

    debug_assert_eq!(expected_result.len(), 16);
    let mut actual_result = [0u8; 16];

    let mut ctx = Shake128::new();
    ctx.absorb(&msg).unwrap();
    ctx.squeeze(&mut actual_result).unwrap();

    assert_eq!(&expected_result[..], &actual_result);
}

// TODO!: Find test values/KATs for repeated squeeze() calls

/*
#[test]
fn shake128_works_progessively() {
    // From https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakSpongeIntermediateValues_SHAKE128.txt

    let msg = hex::decode("53587B19").unwrap();
    let mut ctx = Shake128::new();
    ctx.absorb(&msg).unwrap();

    let expected_result_0 =
        hex::decode("fe8c476993b47b10c98303a04c6212dfb341426d748d3926140aee0a151fc80fa1").unwrap();
    let mut actual_result_0 = [0u8; 264usize / 8usize];
    ctx.squeeze(&mut actual_result_0).unwrap();
    assert_eq!(&expected_result_0[..], &actual_result_0);

    let expected_result_1 =
        hex::decode("0ed1e47c5a33592d182ccb6a28cac9b11d23d8038ddebbdd4ae6c584d7ec14269810b082a27655d073ac9bfda81650e18d972e5e96cf1b4279af91cf0bf61156ebf6f042fb70ba6f25be976880c257405e759e71790c5218d05985f5ffff05f9eb2da24053cb7df667").unwrap();
    let mut actual_result_1 = [0u8; 840usize / 8usize];
    ctx.squeeze(&mut actual_result_1).unwrap();
    assert_eq!(&expected_result_1[..], &actual_result_1);

    let expected_result_2 =
        hex::decode("14cea805075b2e0cb19e803b799dbbbcf4381d9517fb3d11c54ad32fd67d10c7f8f59e0cf2eaec82bb237e14c835").unwrap();
    let mut actual_result_2 = [0u8; 368usize / 8usize];
    ctx.squeeze(&mut actual_result_2).unwrap();
    assert_eq!(&expected_result_2[..], &actual_result_2);
}
*/
/*

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_default_equals_new() {
        let new = Shake128::new();
        let default = Shake128::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Shake128::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Shake128 { _state: State { state: [***OMITTED***], buffer: [***OMITTED***], capacity: 32, leftover: 0, is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::incremental_interface::*;

        impl TestableStreamingContext<Digest> for Shake128 {
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

            fn compare_states(state_1: &Shake128, state_2: &Shake128) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Shake128 = Shake128::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Shake128>::new(
                initial_state,
                SHAKE_128_RATE,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Shake128 = Shake128::new();

            let test_runner = StreamingContextConsistencyTester::<Digest, Shake128>::new(
                initial_state,
                SHAKE_128_RATE,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha3::shake128::Shake128;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>) -> bool {
            let mut hasher_a = Shake128::new();
            let mut hasher_b = hasher_a.clone();

            hasher_a.update(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            let hash_a = hasher_a.finalize().unwrap();
            let hash_b = hasher_b.finalize().unwrap();

            hash_a == hash_b
        }
    }
}
*/
