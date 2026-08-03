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

use subtle::ConstantTimeEq;

use crate::{
    errors::UnknownCryptoError,
    hazardous::hash::blake3::{
        cvstack::{FinalizeCommand, PushCommand, TreeStack},
        internal::{compress, ChunkState, CHUNK_LEN, CHUNK_START, PARENT},
        SecretKey,
    },
};
use core::cmp::min;

/// BLAKE3 internal state.
#[derive(Clone)]
pub struct Blake3State {
    key: [u32; 8],
    chunk: ChunkState,
    chain_values: TreeStack,
    total_chunks: u64,
    is_finalized: bool,
}

impl PartialEq<Blake3State> for Blake3State {
    fn eq(&self, other: &Blake3State) -> bool {
        Into::<bool>::into(self.key.ct_eq(&other.key))
            & (self.chunk == other.chunk)
            & (self.chain_values == other.chain_values)
            & (self.total_chunks == other.total_chunks)
            & (self.is_finalized == other.is_finalized)
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Blake3State {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl core::fmt::Debug for Blake3State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Blake3State {{ [***OMITTED***] }}",)
    }
}

impl Blake3State {
    fn parse_key(key: &SecretKey) -> [u32; 8] {
        let bytes = key.unprotected_as_bytes();
        core::array::from_fn(|i| {
            let start = i * 4;
            u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ])
        })
    }

    pub(crate) fn new(key: &SecretKey, flags: u32) -> Self {
        let key_words = Self::parse_key(key);
        Self {
            key: key_words,
            chunk: ChunkState::new(&key_words, 0, CHUNK_START | flags),
            chain_values: TreeStack::new(compress),
            total_chunks: 0,
            is_finalized: false,
        }
    }

    /// Update state with `data`. This can be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8], flags: u32) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        let mut data_view = data;
        while !data_view.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                self.flush_state(flags);
            }

            let want = CHUNK_LEN - self.chunk.len();
            let take = min(want, data_view.len());
            self.chunk.update(&data_view[..take]);

            data_view = &data_view[take..]
        }

        Ok(())
    }

    fn flush_state(&mut self, flags: u32) {
        // Get final chaining value
        let is_root = false;
        let cv = self.chunk.finalize_chunk(is_root).truncate();
        self.total_chunks = self.total_chunks.checked_add(1).unwrap();

        // Push it to the tree stack
        self.chain_values.push(PushCommand {
            next_cv: cv,
            total_chunks: self.total_chunks,
            key_words: self.key,
            flags: flags | PARENT,
        });

        // Reset state
        self.chunk = ChunkState::new(&self.key, self.total_chunks, flags | CHUNK_START);
    }

    /// Return a BLAKE3 digest in the `out_slice` parameter.
    /// The length of the `out_slice` parameter dictates the
    /// length of the output.
    pub fn finalize(&mut self, out_slice: &mut [u8], flags: u32) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }
        self.is_finalized = true;
        let is_root = self.total_chunks == 0;

        let reader = if is_root {
            self.chunk.root_output(is_root)
        } else {
            let current_state = self.chunk.finalize_chunk(is_root);
            self.chain_values.root_output(FinalizeCommand {
                current_cv: current_state.truncate(),
                key_words: self.key,
                flags: flags | PARENT,
            })
        };

        reader.fill(out_slice);
        Ok(())
    }
}
