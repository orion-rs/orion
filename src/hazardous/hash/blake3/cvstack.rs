use crate::hazardous::hash::blake3::internal::{
    CFState, ChainingValue, CompressionFn, BLOCK_LEN, PARENT,
};

// The maximum possible height of a BLAKE3 tree: the input is capped at 2^64B
// with 2^10B nodes => 2^54B nodes
const MAX_TREE_DEPTH: usize = 54;

pub(crate) struct TreeStack {
    stack: [ChainingValue; MAX_TREE_DEPTH],
    compress: CompressionFn,
    stack_len: u8,
}

impl TreeStack {
    pub const fn new(compress: CompressionFn) -> Self {
        Self {
            stack: [[0; 8]; MAX_TREE_DEPTH],
            compress,
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
            let sibling = self.pop();
            config.next_cv =
                self.parent_cv(sibling, config.next_cv, config.key_words, config.flags);
            config.total_chunks >>= 1;
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
            config.current_cv =
                self.parent_cv(sibling, config.current_cv, config.key_words, config.flags)
        }

        config.current_cv
    }

    fn parent_cv(
        &self,
        left: ChainingValue,
        right: ChainingValue,
        key_words: [u32; 8],
        flags: u32,
    ) -> ChainingValue {
        let msg = merge_msgs(left, right);
        let merge_state = CFState::new(key_words, 0, BLOCK_LEN as u32, flags | PARENT);
        let compressed_state = (self.compress)(merge_state, &msg);

        compressed_state.truncate()
    }
}

fn merge_msgs(first: ChainingValue, second: ChainingValue) -> [u32; 16] {
    let mut msgs = [0u32; 16];
    msgs[..8].copy_from_slice(&first);
    msgs[8..].copy_from_slice(&second);

    msgs
}

pub(crate) struct PushCommand {
    pub next_cv: ChainingValue,
    pub total_chunks: u64,
    pub key_words: [u32; 8],
    pub flags: u32,
}

pub(crate) struct FinalizeCommand {
    pub current_cv: ChainingValue,
    pub key_words: [u32; 8],
    pub flags: u32,
}

// -- TEST -- //

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_IV: [u32; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    // Mock compression function that just returns a fixed value so we can trace it
    fn mock_compress(_state: CFState, _msgs: &[u32; 16]) -> CFState {
        CFState::new([99; 8], 0, 0, 0)
    }

    #[test]
    fn test_tree_stack_push_merge_logic() {
        // Arrange
        let mut tree = TreeStack::new(mock_compress);
        let dummy_cv_1 = [1; 8];
        let dummy_cv_2 = [2; 8];

        // Act
        // Push first chunk (total_chunks = 1 -> odd, shouldn't merge)
        tree.push(PushCommand {
            next_cv: dummy_cv_1,
            total_chunks: 1,
            key_words: MOCK_IV,
            flags: 0,
        });

        // Push second chunk (total_chunks = 2 -> even, MUST merge with chunk 1)
        tree.push(PushCommand {
            next_cv: dummy_cv_2,
            total_chunks: 2,
            key_words: MOCK_IV,
            flags: 0,
        });

        // Assert
        assert_eq!(
            tree.stack_len, 1,
            "Stack should merge down to a single parent node"
        );
        assert_eq!(
            tree.stack[0], [99; 8],
            "Parent CV should be the output of mock_compress"
        );
    }
}
