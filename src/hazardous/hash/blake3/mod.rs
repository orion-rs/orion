// MIT License

// Copyright (c) 2018-2026 The orion Developers

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

use crate::hazardous::hash::blake3::cvstack::{FinalizeCommand, PushCommand, TreeStack};
use crate::hazardous::hash::blake3::internal::{compress, ChunkState, CHUNK_LEN, CHUNK_START, IV};
use core::cmp::min;

/// Blake3 can run in different modes based on usage
pub enum Mode {
    /// Regular hashing
    Hash,
    /// Hashing parametrized with a key. Useful for MACs.
    KeyedHash {
        /// A 256-bit long key
        key: [u32; 8],
    },
}

impl Mode {
    fn derive_state(&self) -> ChunkState {
        let key_words = self.key_words();
        let chunk_counter = 0;
        let flags = CHUNK_START;

        ChunkState::new(key_words, chunk_counter, flags)
    }

    fn key_words(&self) -> [u32; 8] {
        match &self {
            Mode::Hash => IV,
            Mode::KeyedHash { key } => *key,
        }
    }
}

/// Blake3 configuration
pub struct Blake3 {
    state: ChunkState,
    chain_values: TreeStack,
    mode: Mode,
    total_chunks: u64,
}

impl Blake3 {
    /// Create a new `Blake3` instance of the given `Mode`.
    pub fn new(mode: Mode) -> Self {
        Self {
            state: mode.derive_state(),
            chain_values: TreeStack::new(compress),
            mode,
            total_chunks: 0,
        }
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.state.len() == CHUNK_LEN {
            self.flush_state();
        }

        let want = CHUNK_LEN - self.state.len();
        let take = min(want, data.len());
        self.state.update(&data[..take]);

        self.update(&data[take..])
    }

    fn flush_state(&mut self) {
        // Get final chaining value
        let is_root = false;
        let cv = self.state.finalize_chunk(is_root);
        self.total_chunks += 1;

        // Push it to the tree stack
        let key_words = self.mode.key_words();
        let parent_flags = 0;
        self.chain_values.push(PushCommand {
            next_cv: cv,
            total_chunks: self.total_chunks,
            key_words,
            flags: parent_flags,
        });

        // Reset state
        self.state = ChunkState::new(key_words, self.total_chunks, CHUNK_START);
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    pub fn finalize(mut self, out_slice: &mut [u8]) {
        let key_words = self.mode.key_words();
        let is_root = self.total_chunks == 0;
        let current_cv = self.state.finalize_chunk(is_root);

        let final_cv = if is_root {
            current_cv
        } else {
            self.chain_values.finalize(FinalizeCommand {
                current_cv,
                key_words,
                flags: 0,
            })
        };

        for (i, word) in final_cv.iter().enumerate() {
            if i * 4 < out_slice.len() {
                let bytes = word.to_le_bytes();
                let end = min(out_slice.len(), (i + 1) * 4);
                out_slice[i * 4..end].copy_from_slice(&bytes[..end - (i * 4)]);
            }
        }
    }
}
