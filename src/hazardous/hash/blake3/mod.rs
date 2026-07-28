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

mod cvstack;
mod internal;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake3::cvstack::{FinalizeCommand, PushCommand, TreeStack};
use crate::hazardous::hash::blake3::internal::{
    compress, ChunkState, CHUNK_LEN, CHUNK_START, IV, KEYED_HASH, KEY_SIZE, PARENT,
};
use core::cmp::min;

construct_secret_key! {
    /// A type to represent the secret key that Blake3 uses for keyed mode.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty
    /// - `slice` is greater than 256b (32B)
    ///
    /// # Panics:
    /// A panic will occur during:
    /// - failure to generate random bytes securely
    ///
    (SecretKey, test_secret_key, KEY_SIZE, KEY_SIZE, KEY_SIZE)
}

/// Blake3 can run in different modes based on usage.
/// Currently, only Hash and KeyedHash is supported.
#[derive(PartialEq, Debug, Clone)]
pub enum Mode {
    /// Regular hashing
    Hash,
    /// Hashing parametrized with a key. Useful for MACs.
    KeyedHash {
        /// A 256-bit long key
        key: [u32; 8],
    },
}

enum FlagContext {
    // Indicates START_FLAG plus other flags based on mode
    Initial,
    // Indicates PARENT plus other flags based on mode
    Parent,
}

impl Mode {
    fn derive_init_state(&self) -> ChunkState {
        let key_words = self.key_words();
        let chunk_counter = 0;
        let flags = self.derive_flags(FlagContext::Initial);

        ChunkState::new(key_words, chunk_counter, flags)
    }

    fn derive_flags(&self, ctx: FlagContext) -> u32 {
        match &self {
            Mode::Hash => match ctx {
                FlagContext::Initial => CHUNK_START,
                FlagContext::Parent => PARENT,
            },
            Mode::KeyedHash { key: _ } => match ctx {
                FlagContext::Initial => CHUNK_START | KEYED_HASH,
                FlagContext::Parent => PARENT | KEYED_HASH,
            },
        }
    }

    fn key_words(&self) -> [u32; 8] {
        match &self {
            Mode::Hash => IV,
            Mode::KeyedHash { key } => *key,
        }
    }
}

/// Blake3 configuration
#[derive(PartialEq, Debug, Clone)]
pub struct Blake3 {
    chunk: ChunkState,
    chain_values: TreeStack,
    mode: Mode,
    total_chunks: u64,
}

/// Represents the standard `hash` mode for `Blake3` for producing
/// hashes without a secret key.
impl Default for Blake3 {
    /// Create a new `Blake3` instance for standard hashing (`hash` mode).
    fn default() -> Self {
        let mode = Mode::Hash;
        Self {
            chunk: mode.derive_init_state(),
            chain_values: TreeStack::new(compress),
            mode,
            total_chunks: 0,
        }
    }
}

impl Drop for Blake3 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;

            if let Mode::KeyedHash { key } = &mut self.mode {
                key.iter_mut().zeroize();
            };
        }
    }
}

impl Blake3 {
    /// Create a new `Blake3` instance for standard hashing (`hash` mode).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `Blake3` instance for keyed hashing (`keyed hash` mode).
    pub fn new_keyed(secret_key: &SecretKey) -> Self {
        let bytes = secret_key.unprotected_as_bytes();
        let key_words = core::array::from_fn(|i| {
            let start = i * 4;
            u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ])
        });
        let mode = Mode::KeyedHash { key: key_words };

        Self {
            chunk: mode.derive_init_state(),
            chain_values: TreeStack::new(compress),
            mode,
            total_chunks: 0,
        }
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        // Old values are zeroized as `drop()` is guaranteed
        // to be called.
        self.chunk = self.mode.derive_init_state();
        self.chain_values = TreeStack::new(compress);
        self.total_chunks = 0;
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) {
        let mut data_view = data;
        while !data_view.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                self.flush_state();
            }

            let want = CHUNK_LEN - self.chunk.len();
            let take = min(want, data_view.len());
            self.chunk.update(&data_view[..take]);

            data_view = &data_view[take..]
        }
    }

    fn flush_state(&mut self) {
        // Get final chaining value
        let is_root = false;
        let cv = self.chunk.finalize_chunk(is_root).truncate();
        self.total_chunks = self.total_chunks.checked_add(1).unwrap();

        // Push it to the tree stack
        let key_words = self.mode.key_words();
        self.chain_values.push(PushCommand {
            next_cv: cv,
            total_chunks: self.total_chunks,
            key_words,
            flags: self.mode.derive_flags(FlagContext::Parent),
        });

        // Reset state
        let next_flags = self.mode.derive_flags(FlagContext::Initial);
        self.chunk = ChunkState::new(key_words, self.total_chunks, next_flags);
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(mut self, out_slice: &mut [u8]) {
        let key_words = self.mode.key_words();
        let is_root = self.total_chunks == 0;

        let reader = if is_root {
            self.chunk.root_output(is_root)
        } else {
            let current_state = self.chunk.finalize_chunk(is_root);
            self.chain_values.root_output(FinalizeCommand {
                current_cv: current_state.truncate(),
                key_words,
                flags: self.mode.derive_flags(FlagContext::Parent),
            })
        };

        reader.fill(out_slice);
    }
}

#[cfg(test)]
mod test_streaming_interface {
    use super::*;
    use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
    use crate::test_framework::incremental_interface::{
        StreamingContextConsistencyTester, TestableStreamingContext,
    };

    // A wrapper exclusively for testing. The expected API for `.finalize()` is
    // that it accepts `mut& self`, requiring a manual check for double use.
    // Our solution consumes itself, solving the problem, but panicking in the tests.
    #[derive(PartialEq, Debug, Clone)]
    struct Blake3Tester {
        inner: Blake3,
        is_finalized: bool,
    }

    impl TestableStreamingContext<Vec<u8>> for Blake3Tester {
        fn reset(&mut self) -> Result<(), UnknownCryptoError> {
            self.inner.reset();
            self.is_finalized = false;
            Ok(())
        }

        fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
            if self.is_finalized {
                return Err(UnknownCryptoError);
            }
            self.inner.update(input);
            Ok(())
        }

        fn finalize(&mut self) -> Result<Vec<u8>, UnknownCryptoError> {
            if self.is_finalized {
                return Err(UnknownCryptoError);
            }

            self.is_finalized = true;
            let mut out = vec![0u8; 32];
            // `finalize()` consumes `self`, cloning solely for testing purposes
            self.inner.clone().finalize(&mut out);
            Ok(out)
        }

        fn one_shot(input: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
            let mut hasher = Blake3::new();
            hasher.update(input);

            let mut out = vec![0u8; 32];
            hasher.finalize(&mut out);
            Ok(out)
        }

        fn verify_result(expected: &Vec<u8>, input: &[u8]) -> Result<(), UnknownCryptoError> {
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
        let init_state = Blake3Tester {
            inner: Blake3::new(),
            is_finalized: false,
        };
        let test_runner =
            StreamingContextConsistencyTester::<Vec<u8>, Blake3Tester>::new(init_state, BLOCK_LEN);
        test_runner.run_all_tests();
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
        let init_state = Blake3Tester {
            inner: Blake3::new(),
            is_finalized: false,
        };
        let test_runner =
            StreamingContextConsistencyTester::<Vec<u8>, Blake3Tester>::new(init_state, BLOCK_LEN);
        test_runner.run_all_tests_property(&data);
        true
    }
}
