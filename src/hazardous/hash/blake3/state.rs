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

use crate::hazardous::hash::blake3::{
    cvstack::{FinalizeCommand, PushCommand, TreeStack},
    internal::{compress, ChunkState, CHUNK_LEN, CHUNK_START, PARENT},
};
use core::cmp::min;

/// Blake3 internal state
#[derive(PartialEq, Debug, Clone)]
pub struct Blake3State {
    chunk: ChunkState,
    chain_values: TreeStack,
    total_chunks: u64,
}

impl Blake3State {
    pub(crate) fn new(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk: ChunkState::new(key_words, 0, CHUNK_START | flags),
            chain_values: TreeStack::new(compress),
            total_chunks: 0,
        }
    }

    /// Update state with `data`. This can be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8], key_words: [u32; 8], flags: u32) {
        let mut data_view = data;
        while !data_view.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                self.flush_state(key_words, flags);
            }

            let want = CHUNK_LEN - self.chunk.len();
            let take = min(want, data_view.len());
            self.chunk.update(&data_view[..take]);

            data_view = &data_view[take..]
        }
    }

    fn flush_state(&mut self, key_words: [u32; 8], flags: u32) {
        // Get final chaining value
        let is_root = false;
        let cv = self.chunk.finalize_chunk(is_root).truncate();
        self.total_chunks = self.total_chunks.checked_add(1).unwrap();

        // Push it to the tree stack
        self.chain_values.push(PushCommand {
            next_cv: cv,
            total_chunks: self.total_chunks,
            key_words,
            flags: flags | PARENT,
        });

        // Reset state
        self.chunk = ChunkState::new(key_words, self.total_chunks, flags | CHUNK_START);
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(mut self, out_slice: &mut [u8], key_words: [u32; 8], flags: u32) {
        let is_root = self.total_chunks == 0;

        let reader = if is_root {
            self.chunk.root_output(is_root)
        } else {
            let current_state = self.chunk.finalize_chunk(is_root);
            self.chain_values.root_output(FinalizeCommand {
                current_cv: current_state.truncate(),
                key_words,
                flags: flags | PARENT,
            })
        };

        reader.fill(out_slice);
    }
}
