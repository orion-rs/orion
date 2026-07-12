use crate::hazardous::hash::blake3::blake3_core::{
    cfstate_new, compress, CFState, ChainingValue, CompressionFn,
};

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
    pub fn push(&mut self, mut next_cv: ChainingValue, mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let sibling = self.pop();
            next_cv = self.merge(&mut next_cv, sibling);
            total_chunks = total_chunks >> 1;
        }
        self.push_merged(next_cv);
    }

    fn push_merged(&mut self, cv: ChainingValue) {
        self.stack[self.stack_len as usize] = cv;
        self.stack_len += 1;
    }

    fn merge(&mut self, left: &mut ChainingValue, right: ChainingValue) -> ChainingValue {
        let msgs = [left, right].as_flattened();
        let merge_state: CFState;
        let compressed_state = compress(merge_state, msgs);

        compressed_state.truncate();
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
    pub fn finalize(mut self, compress: CompressionFn) -> ChainingValue {}
}
