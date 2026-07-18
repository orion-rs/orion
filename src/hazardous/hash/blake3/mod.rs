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
use crate::hazardous::hash::blake3::internal::{
    compress, ChunkState, CHUNK_LEN, CHUNK_START, IV, KEYED_HASH, PARENT,
};
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

enum FlagContext {
    Initial,
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
            state: mode.derive_init_state(),
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
        let cv = self.state.finalize_chunk(is_root).truncate();
        self.total_chunks += 1;

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
        self.state = ChunkState::new(key_words, self.total_chunks, next_flags);
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(mut self, out_slice: &mut [u8]) {
        let key_words = self.mode.key_words();
        let is_root = self.total_chunks == 0;

        let reader = if is_root {
            self.state.root_output(is_root)
        } else {
            let current_state = self.state.finalize_chunk(is_root);
            self.chain_values.root_output(FinalizeCommand {
                current_cv: current_state.truncate(),
                key_words,
                flags: self.mode.derive_flags(FlagContext::Parent),
            })
        };

        reader.fill(out_slice);
    }
}
