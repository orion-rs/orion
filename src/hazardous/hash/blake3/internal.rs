use core::array;
use core::cmp::min;
use core::ops::{Index, IndexMut};

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
pub(crate) const BLOCK_LEN: usize = 64;
pub(crate) const CHUNK_LEN: usize = 1024;
const ROUND_ITERS: usize = 7;

// Flags for the compression function
// See Table 3 in section 2.2 Compression Function
pub(crate) const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
pub(crate) const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

fn chunk_end_flags(is_root: bool) -> u32 {
    if is_root {
        ROOT | CHUNK_END
    } else {
        CHUNK_END
    }
}

// Initial state inside the compression function
pub(crate) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// Permutation done after each round (except for the last one)
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// 32B intermediate hash output (a.k.a. chaining value)
pub(crate) type ChainingValue = [u32; 8];

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

impl ChunkState {
    pub(crate) fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: key_words,
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
        assert!(input.len() <= CHUNK_LEN - self.len());

        if input.is_empty() {
            return;
        }

        let taken: usize = self.append_to_block(input);
        self.block_len += taken as u8;
        if self.block_len == BLOCK_LEN as u8 {
            self.compress_block();
        }

        self.update(&input[taken..])
    }

    pub(crate) fn finalize_chunk(&mut self, is_root: bool) -> ChainingValue {
        self.flags |= chunk_end_flags(is_root);
        let state = CFState::from(self);

        let msgs = self.accumulate_blocks();
        let compressed_state = compress(state, &msgs);

        compressed_state.truncate()
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
    }
}

// Internal compression function state
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
            counter: [(counter & 0xffffffff) as u32, (counter >> 32) as u32],
            block_amount,
            flags,
        }
    }

    fn from(chunk: &ChunkState) -> CFState {
        CFState {
            input_chaining_values: chunk.cv,
            iv: [IV[0], IV[1], IV[2], IV[3]],
            counter: [
                (chunk.chunk_counter >> 32) as u32,
                (chunk.chunk_counter & 0xffffffff) as u32,
            ],
            block_amount: chunk.blocks_compressed as u32,
            flags: chunk.flags,
        }
    }

    pub fn truncate(self) -> ChainingValue {
        self.input_chaining_values
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
    quater_round(state, 0, 5, 10, 15, msgs[0], msgs[1]);
    quater_round(state, 1, 6, 11, 12, msgs[2], msgs[3]);
    quater_round(state, 2, 7, 8, 13, msgs[4], msgs[5]);
    quater_round(state, 3, 4, 9, 14, msgs[6], msgs[7]);
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
        round(&mut init_state, msgs);
        msgs_copy = permute_msgs(msgs_copy);
    }
    init_state
}
