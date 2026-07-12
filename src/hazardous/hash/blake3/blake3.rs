use crate::hazardous::hash::blake3::blake3_core::{ChainingValue, ChunkState, IV};
use crate::hazardous::hash::blake3::cvstack::TreeStack;

pub struct Blake3 {
    state: ChunkState,
    chain_values: TreeStack,
    mode: Mode,
}

impl Blake3 {
    pub fn new(mode: Mode) -> Self {}

    pub fn update() {}

    pub fn finalize() {}
}
