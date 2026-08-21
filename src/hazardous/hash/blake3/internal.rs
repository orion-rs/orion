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

use core::array;
use core::cmp::min;
use core::ops::{Index, IndexMut};

use subtle::ConstantTimeEq;

use crate::errors::UnknownCryptoError;

pub(crate) const BLOCK_LEN: usize = 64;
pub(crate) const CHUNK_LEN: usize = 1024;
pub(crate) const KEY_SIZE: usize = 32;
const ROUND_ITERS: usize = 7;

// Flags for the compression function
// See Table 3 in section 2.2 Compression Function
pub(crate) const CHUNK_START: u32 = 1 << 0;
pub(crate) const CHUNK_END: u32 = 1 << 1;
pub(crate) const PARENT: u32 = 1 << 2;
pub(crate) const ROOT: u32 = 1 << 3;
pub(crate) const KEYED_HASH: u32 = 1 << 4;
// const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
// const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

fn chunk_end_flags(is_root: bool) -> u32 {
    if is_root { ROOT | CHUNK_END } else { CHUNK_END }
}

// Initial state inside the compression function
pub(crate) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// Permutation done after each round (except for the last one)
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// 32B intermediate hash output (a.k.a. chaining value)
pub(crate) type ChainingValue = [u32; 8];

#[derive(Clone)]
pub(crate) struct ChunkState {
    /// The resulting chaining value of the last compressed block.
    cv: ChainingValue,
    /// The number of fully compressed chunks so far.
    chunk_counter: u64,
    /// Input buffer for the next block. When full, it is compressed
    /// and flushed.
    block: [u8; BLOCK_LEN],
    /// The number of valid bytes in the input_block_buffer
    block_len: u8,
    /// The number of already compressed block. It must not extend
    /// CHUNK_LEN / BLOCK_LEN.
    blocks_compressed: u8,
    flags: u32,
}

impl PartialEq<ChunkState> for ChunkState {
    fn eq(&self, other: &ChunkState) -> bool {
        Into::<bool>::into(self.cv.ct_eq(&other.cv))
            & (self.chunk_counter == other.chunk_counter)
            & (self.block == other.block)
            & (self.block_len == other.block_len)
            & (self.blocks_compressed == other.blocks_compressed)
            & (self.flags == other.flags)
    }
}

impl Drop for ChunkState {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.cv.iter_mut().zeroize();
        }
    }
}

impl core::fmt::Debug for ChunkState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The *cv* contains the key before the first iteration in
        // *keyed hash* mode. It is omitted.
        f.debug_struct("ChunkState")
            .field("chunk_counter", &self.chunk_counter)
            .field("block", &self.block)
            .field("block_len", &self.block_len)
            .field("blocks_compressed", &self.blocks_compressed)
            .field("flags", &self.flags)
            .finish()
    }
}

impl ChunkState {
    pub(crate) fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: *key_words,
            block: [0; BLOCK_LEN],
            block_len: 0,
            chunk_counter,
            blocks_compressed: 0,
            flags,
        }
    }

    /// Returns the length of the already consumed chunk content in bytes.
    /// Invariant: len <= CHUNK_LEN
    pub(crate) fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    /// Consumes the provided `input`. The size of the input must not be
    /// greater than CHUNK_LEN - len().
    pub(crate) fn update(&mut self, input: &[u8]) {
        debug_assert!(input.len() <= CHUNK_LEN - self.len());
        let mut input_view = input;

        while !input_view.is_empty() {
            if self.block_len == BLOCK_LEN as u8 {
                self.compress_block();
            }

            let taken: usize = self.append_to_block(input_view);
            self.block_len += taken as u8;

            input_view = &input_view[taken..]
        }
    }

    pub(crate) fn root_output(&mut self, is_root: bool) -> OutputReader {
        self.flags |= chunk_end_flags(is_root);
        let state = CFState::from(self);
        let msgs = self.accumulate_blocks();

        OutputReader::new(state, msgs)
    }

    pub(crate) fn finalize_chunk(&mut self, is_root: bool) -> CFState {
        self.flags |= chunk_end_flags(is_root);
        let state = CFState::from(self);
        let msgs = self.accumulate_blocks();

        compress(state, &msgs)
    }

    fn append_to_block(&mut self, input: &[u8]) -> usize {
        let want = BLOCK_LEN - self.block_len as usize;
        let take = min(input.len(), want);

        let start = self.block_len as usize;
        let end = start + take;
        self.block[start..end].clone_from_slice(&input[..take]);

        take
    }

    // No checks done whether the block is filled properly. Make sure
    // self.block_len == BLOCK_LEN
    fn compress_block(&mut self) {
        let msgs = self.accumulate_blocks();
        let compressed_state = compress(CFState::from(&*self), &msgs);

        self.cv = compressed_state.truncate();
        self.update_after_block()
    }

    fn accumulate_blocks(&self) -> [u32; 16] {
        let mut chunks = self.block.chunks_exact(4);
        let msgs: [u32; 16] = array::from_fn(|_| {
            let chunk = chunks.next().unwrap();
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        });

        msgs
    }

    fn update_after_block(&mut self) {
        self.blocks_compressed += 1;
        self.block_len = 0;
        self.block = [0; BLOCK_LEN];
        self.flags &= !CHUNK_START;
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct OutputReader {
    base_state: CFState,
    msgs: [u32; 16],
    /// Block positions to determine amount of bytes already produced.
    position: u64,
    buffer: [u8; 64],
    block_n: u64,
}

impl OutputReader {
    pub(crate) fn new(base_state: CFState, msgs: [u32; 16]) -> Self {
        Self {
            base_state,
            msgs,
            position: 0,
            buffer: [0u8; 64],
            block_n: 0,
        }
    }

    pub(crate) fn squeeze(&mut self, out_slice: &mut [u8]) -> Result<(), UnknownCryptoError> {
        let mut squeezed = 0usize;
        while squeezed < out_slice.len() {
            if let Some(block_idx) = self.position.checked_div(64) {
                // we're requesting a different block than what we have cached
                if block_idx != self.block_n {
                    self.compute_block(block_idx);
                    self.block_n = block_idx;
                }
            } else {
                return Err(UnknownCryptoError);
            }

            let buffer_idx = (self.position % 64) as usize;
            let available = &self.buffer[buffer_idx..];
            let want = min(available.len(), out_slice.len() - squeezed);
            out_slice[squeezed..squeezed + want].copy_from_slice(&available[..want]);

            squeezed += want; // should not overflow because the below err on 2^64 would errors first
            if let Some(pos) = self.position.checked_add(want as u64) {
                self.position = pos;
            } else {
                return Err(UnknownCryptoError);
            }
        }

        Ok(())
    }

    fn compute_block(&mut self, block_idx: u64) {
        let state = CFState {
            counter: CFState::to_le_array(block_idx),
            ..self.base_state.clone()
        };

        let compressed = compress(state.clone(), &self.msgs);
        let block_output = Self::block_output(&compressed, &state);
        for (word, chunk_bytes) in block_output
            .iter()
            .zip(self.buffer.chunks_mut(size_of::<u32>()))
        {
            chunk_bytes.copy_from_slice(&word.to_le_bytes());
        }
    }

    // Constructs the output as defined in the standard: 32B words
    fn block_output(compressed: &CFState, init_state: &CFState) -> [u32; 16] {
        let block_words: [u32; 16] = array::from_fn(|i| {
            if i < 8 {
                compressed[i] ^ compressed[i + 8]
            } else {
                compressed[i] ^ init_state[i - 8]
            }
        });

        block_words
    }
}

// Internal compression function state
#[derive(Clone, PartialEq)]
pub(crate) struct CFState {
    input_chaining_values: ChainingValue,
    iv: [u32; 4],
    counter: [u32; 2],
    block_amount: u32,
    flags: u32,
}

impl CFState {
    pub fn new(cv: ChainingValue, counter: u64, block_amount: u32, flags: u32) -> Self {
        Self {
            input_chaining_values: cv,
            iv: [IV[0], IV[1], IV[2], IV[3]],
            counter: Self::to_le_array(counter),
            block_amount,
            flags,
        }
    }

    fn from(chunk: &ChunkState) -> CFState {
        CFState {
            input_chaining_values: chunk.cv,
            iv: [IV[0], IV[1], IV[2], IV[3]],
            counter: Self::to_le_array(chunk.chunk_counter),
            block_amount: chunk.block_len as u32,
            flags: chunk.flags,
        }
    }

    pub fn truncate(self) -> ChainingValue {
        array::from_fn(|i| self[i] ^ self[i + 8])
    }

    fn to_le_array(counter: u64) -> [u32; 2] {
        [counter as u32, (counter >> 32) as u32]
    }
}

impl Index<usize> for CFState {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0..=7 => &self.input_chaining_values[index],
            8..=11 => &self.iv[index - 8],
            12..=13 => &self.counter[index - 12],
            14 => &self.block_amount,
            15 => &self.flags,
            _ => panic!("accessing by invalid index"),
        }
    }
}

impl IndexMut<usize> for CFState {
    fn index_mut(&mut self, index: usize) -> &mut u32 {
        match index {
            0..=7 => &mut self.input_chaining_values[index],
            8..=11 => &mut self.iv[index - 8],
            12..=13 => &mut self.counter[index - 12],
            14 => &mut self.block_amount,
            15 => &mut self.flags,
            _ => panic!("accessing by invalid index"),
        }
    }
}

pub(crate) type CompressionFn = fn(CFState, &[u32; 16]) -> CFState;

// Quater round, also called 'G', representing the round function similarly
// to BLAKE2 or ChaCha
fn quater_round(state: &mut CFState, a: usize, b: usize, c: usize, d: usize, msg1: u32, msg2: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(msg1);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);

    state[a] = state[a].wrapping_add(state[b]).wrapping_add(msg2);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn mix_columns(state: &mut CFState, msgs: &[u32; 16]) {
    quater_round(state, 0, 4, 8, 12, msgs[0], msgs[1]);
    quater_round(state, 1, 5, 9, 13, msgs[2], msgs[3]);
    quater_round(state, 2, 6, 10, 14, msgs[4], msgs[5]);
    quater_round(state, 3, 7, 11, 15, msgs[6], msgs[7]);
}

fn mix_diagonals(state: &mut CFState, msgs: &[u32; 16]) {
    quater_round(state, 0, 5, 10, 15, msgs[8], msgs[9]);
    quater_round(state, 1, 6, 11, 12, msgs[10], msgs[11]);
    quater_round(state, 2, 7, 8, 13, msgs[12], msgs[13]);
    quater_round(state, 3, 4, 9, 14, msgs[14], msgs[15]);
}

fn round(state: &mut CFState, msgs: &[u32; 16]) {
    mix_columns(state, msgs);
    mix_diagonals(state, msgs);
}

fn permute_msgs(msgs: [u32; 16]) -> [u32; 16] {
    array::from_fn(|i| msgs[MSG_PERMUTATION[i]])
}

pub(crate) fn compress(mut init_state: CFState, msgs: &[u32; 16]) -> CFState {
    let mut msgs_copy = *msgs;
    for _ in 0..ROUND_ITERS {
        round(&mut init_state, &msgs_copy);
        msgs_copy = permute_msgs(msgs_copy);
    }
    init_state
}

// -- TEST -- //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfstate_counter_endianness() {
        // Arrange
        // Use a counter that spans both halves of a 64-bit integer
        let chunk_counter: u64 = 0x00000001_FFFFFFFF;
        let key_words = [0; 8];
        let chunk = ChunkState::new(&key_words, chunk_counter, 0);

        // Act
        let state = CFState::from(&chunk);

        // Assert
        // BLAKE3 spec requires the low 32-bits first, then high 32-bits
        assert_eq!(
            state.counter[0], 0xFFFFFFFF,
            "Low 32-bits mapped incorrectly"
        );
        assert_eq!(
            state.counter[1], 0x00000001,
            "High 32-bits mapped incorrectly"
        );
    }

    #[test]
    fn test_chunk_state_block_boundaries() {
        // Arrange
        let mut chunk = ChunkState::new(&IV, 0, 0);
        // 65 bytes is exactly one block (64) plus 1 byte overlapping into the next
        let data = [0x42; 65];

        // Act
        chunk.update(&data);

        // Assert
        assert_eq!(
            chunk.blocks_compressed, 1,
            "Should have compressed exactly 1 full block"
        );
        assert_eq!(
            chunk.block_len, 1,
            "Should have 1 byte lingering in the next block buffer"
        );
        assert_eq!(chunk.block[0], 0x42, "Lingering byte should match input");
    }

    #[test]
    fn test_compress_mutates_state_deterministically() {
        // Arrange
        let cv = [0x11223344; 8];
        let init_state = CFState::new(cv, 1, 64, CHUNK_START);
        let msgs = [0x55667788; 16];

        // Act
        let final_state_1 = compress(init_state, &msgs);

        // Re-create the identical initial state to test determinism
        let init_state_again = CFState::new(cv, 1, 64, CHUNK_START);
        let final_state_2 = compress(init_state_again, &msgs);

        // Assert
        // The state must have changed from the initial CV
        assert_ne!(
            final_state_1.input_chaining_values, cv,
            "Compression failed to mutate the state"
        );
        // The compression must be purely deterministic
        assert_eq!(
            final_state_1.input_chaining_values, final_state_2.input_chaining_values,
            "Repeated compression of the same state yielded different results"
        );
    }

    #[test]
    fn test_ietf_execution_trace() {
        // Arrange
        // The message to hash is "IETF" padded with zeros
        let msgs: [u32; 16] = [0x46544549, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let initial_flags = CHUNK_START | CHUNK_END | ROOT;
        let mut state = CFState::new(IV, 0, 4, initial_flags);

        // The expected 16-word state after each of the 7 rounds
        let expected_rounds: [[u32; 16]; 7] = [
            [
                // after round 0
                0xd7737c52, 0xa0d29b6a, 0xd3b4f608, 0xe20caed2, 0x49091c17, 0xb1abb189, 0x961f03ba,
                0xc3474f4e, 0xa7590324, 0x9c110e95, 0xf77c59cc, 0xb47c3370, 0x9c1aed89, 0xb7c28f82,
                0xbab6db43, 0xe634ca3e,
            ],
            [
                // after round 1
                0x4cce55f2, 0x9cdfa58b, 0x297f68b4, 0x887fd036, 0x4e620c26, 0x321af343, 0xb8e634b0,
                0x72737ae9, 0x6f6ecf4a, 0x628788fb, 0xdf9428c1, 0xa2c42d78, 0xa51ddf7b, 0x6cf97481,
                0x72dccb9c, 0x1878acb8,
            ],
            [
                // after round 2
                0x8e99a713, 0xbd202a18, 0xd70c8d18, 0x603ba3ad, 0xf411ae76, 0x88ff9580, 0x03db2909,
                0xa12e939f, 0x19b81233, 0x69787f12, 0xd2b0c5b7, 0x52034613, 0x21baaea8, 0x84e5fe6d,
                0xc8c96ae8, 0x422a96d8,
            ],
            [
                // after round 3
                0xeeb6ec2a, 0x22f4289a, 0x64900193, 0xd9f751b3, 0x216a610d, 0xf5aadf41, 0xddf5584d,
                0xae312167, 0xc8f40fb3, 0x97f06701, 0x6eee4503, 0x4827825d, 0x3c59d243, 0x473585da,
                0x90d24798, 0xc5957f9d,
            ],
            [
                // after round 4
                0x11876617, 0x4a71dc87, 0x23a5b774, 0x185e51fa, 0xa1ed35c0, 0x729a3348, 0x6da19311,
                0x9716237c, 0xf66bbb71, 0xf303cf35, 0x585dd137, 0xe5c9c363, 0x8b2b32ed, 0x6add0d37,
                0x12b87a10, 0xf96fde3e,
            ],
            [
                // after round 5
                0x02b010fc, 0x345f4920, 0xce96e963, 0x018a8afd, 0xc0e0faca, 0x651d2baf, 0x0b24a23d,
                0xd1ffa8fc, 0xaa7de2ee, 0xd80796c0, 0xff96b6bd, 0x7cfbf53a, 0x292b8630, 0x8d8e1a78,
                0x31c6cb9d, 0xb471de23,
            ],
            [
                // after round 6
                0xa4839e1a, 0x064b478f, 0xbb47c942, 0x3f4a0350, 0xefd0bb79, 0x61167ed0, 0x356b01f5,
                0xb40f5364, 0xba5d3c99, 0xadadb369, 0x9fcea12a, 0xf08a4ddf, 0x7ba07e35, 0x9e94d896,
                0xe3dfca24, 0x568e0272,
            ],
        ];

        let mut current_msgs = msgs;
        (0..7).for_each(|i| {
            round(&mut state, &current_msgs);
            current_msgs = permute_msgs(current_msgs);

            for j in 0..16 {
                assert_eq!(
                    state[j], expected_rounds[i][j],
                    "State mismatch at round {} word {:02}",
                    i, j
                );
            }
        });

        // Verify the 8-word compression function output
        let compress_output = state.truncate();
        let expected_compress_output = [
            0x1edea283, 0xabe6f4e6, 0x24896868, 0xcfc04e8f, 0x9470c54c, 0xff82a646, 0xd6b4cbd1,
            0xe2815116,
        ];
        assert_eq!(
            compress_output, expected_compress_output,
            "Compression output mismatch"
        );
    }
}
