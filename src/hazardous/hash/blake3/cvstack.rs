use crate::hazardous::hash::blake3::blake3_core::{parent_cv, ChainingValue, CompressionFn};

// The maximum possible height of a BLAKE3 tree: the input is capped at 2^64B
// with 2^10B nodes => 2^54B nodes
const MAX_TREE_DEPTH: usize = 54;

pub(crate) struct TreeStack {
    stack: [ChainingValue; MAX_TREE_DEPTH],
    stack_len: u8,
}

impl TreeStack {
    pub const fn new() -> Self {
        Self {
            stack: [[0; 8]; MAX_TREE_DEPTH],
            stack_len: 0,
        }
    }

    // Creates a new leaf node with the cv and automatically merges adjacent
    // subtrees of the same height.
    //
    // Note: Call only after the at least 1 byte of the following chunk has
    // been supplied.
    pub fn push(&mut self, mut config: PushCommand) {
        while config.total_chunks & 1 == 0 {
            config.next_cv = parent_cv(
                self.pop(),
                config.next_cv,
                config.key_words,
                config.flags,
                config.compress,
            );
            config.total_chunks = config.total_chunks >> 1;
        }
        self.push_merged(config.next_cv);
    }

    fn push_merged(&mut self, cv: ChainingValue) {
        self.stack[self.stack_len as usize] = cv;
        self.stack_len += 1;
    }

    // Pops the top of the stack
    //
    // The popped value is not manually deleted, only the counter is decreased.
    fn pop(&mut self) -> ChainingValue {
        self.stack_len -= 1;
        self.stack[self.stack_len as usize] // Panics if out-of-bounds
    }

    // Produces the final output of the hash function
    //
    // Merges the current chaining value with every CV in the stack
    pub fn finalize(self, mut config: FinalizeCommand) -> ChainingValue {
        for i in (0..self.stack_len as usize).rev() {
            let sibling = self.stack[i];
            config.current_cv = parent_cv(
                sibling,
                config.current_cv,
                config.key_words,
                config.flags,
                config.compress,
            )
        }

        config.current_cv
    }
}

pub(crate) struct PushCommand {
    next_cv: ChainingValue,
    total_chunks: u64,
    key_words: [u32; 8],
    flags: u32,
    compress: CompressionFn,
}

pub(crate) struct FinalizeCommand {
    current_cv: ChainingValue,
    key_words: [u32; 8],
    flags: u32,
    compress: CompressionFn,
}
