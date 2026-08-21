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
//! - More than 2^64 bytes of data are hashed.
//!
//! # Security:
//! - The recommended minimum output size is `32`. The security provided by the hash function cannot
//!   exceed `256` bits, so choosing output sizes larger than `32` bytes provides no additional security over
//!   the `32` exactly. Choosing a smaller output size however decreases the security provided.
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used for this. It generates
//!   a secret key of 32 bytes.
//! - When using [`Blake3Keyed`] the output digest can be used as a MAC. If this is done, it is crucial
//!   to use constant-time comparisons for such digest and take care not to leak them through [`Debug`].
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
//! [`SecretKey::generate()`]: blake3::SecretKey::generate
//! [`Blake3Keyed`]: blake3::Blake3Keyed

use crate::GenerateSecret;
use crate::Secret;
use crate::errors::UnknownCryptoError;
#[cfg(feature = "safe_api")]
use crate::generics::sealed::Data;
use crate::generics::sealed::Sealed;
use crate::generics::{ByteArrayData, TypeSpec};
use crate::hazardous::hash::blake3::internal::{KEY_SIZE, KEYED_HASH};
use crate::hazardous::hash::blake3::state::Blake3State;

#[derive(Debug)]
/// Marker type for BLAKE3 key. See [`SecretKey`] type for convenience.
pub struct Blake3Key {}
impl Sealed for Blake3Key {}

impl TypeSpec for Blake3Key {
    const NAME: &'static str = stringify!(SecretKey);
    type TypeData = ByteArrayData<KEY_SIZE>;
}

impl GenerateSecret for Blake3Key {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<Blake3Key>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(KEY_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// A type to represent the secret key that BLAKE3 uses for keyed mode.
pub type SecretKey = Secret<Blake3Key>;

impl From<[u8; KEY_SIZE]> for SecretKey {
    fn from(value: [u8; 32]) -> Self {
        Self::from_data(<Blake3Key as TypeSpec>::TypeData::from(value))
    }
}

/// Represents the "keyed hash" mode for BLAKE3 for producing
/// hashes using a secret key.
#[derive(Clone, Debug, PartialEq)]
pub struct Blake3 {
    internal: Blake3State,
}

impl Blake3 {
    /// Create a new [`Blake3`] instance for keyed hashing (`keyed hash` mode).
    pub fn new(key: &SecretKey) -> Self {
        Self {
            internal: Blake3State::new(key, KEYED_HASH),
        }
    }

    /// Reset to [`Self::new()`] state.
    pub fn reset(&mut self) {
        self.internal.reset();
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.internal.update(data, KEYED_HASH)
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(&mut self, out_slice: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self.internal.finalize(out_slice, KEYED_HASH)
    }
}

#[cfg(test)]
mod test_streaming_interface {

    mod keyed_streaming_interface {
        use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
        use crate::hazardous::mac::blake3::*;
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
                let secret_key = SecretKey::from([0x42; 32]);
                let mut hasher = Blake3::new(&secret_key);
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
            let secret_key = SecretKey::from([0x42; 32]);
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3>::new(
                Blake3::new(&secret_key),
                BLOCK_LEN,
            );
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let secret_key = SecretKey::from([0x42; 32]);
            let test_runner = StreamingContextConsistencyTester::<[u8; 32], Blake3>::new(
                Blake3::new(&secret_key),
                BLOCK_LEN,
            );
            test_runner.run_all_tests_property(&data);
            true
        }
    }
}
