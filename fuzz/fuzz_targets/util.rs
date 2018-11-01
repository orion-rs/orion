/// Apply fuzzer input data to an array that needs to be a fixed length.
/// Fuzzer input is applied to `apply_to` and it is assumed that `apply_to` has a pre-defined
/// length and is not empty. `lower_bound` is used to specify how much data from the fuzzers input
/// has been used already, to avoid reuse of data.
pub fn apply_from_input_fixed(apply_to: &mut [u8], input: &[u8], lower_bound: usize) {
    if apply_to.is_empty() {
        panic!("Cannot apply data to an empty array");
    }
    if lower_bound > input.len() {
        return;
    }

    let a_len = apply_to.len();
    if input.len() >= (lower_bound + a_len) {
        apply_to.copy_from_slice(&input[lower_bound..(lower_bound + a_len)]);
    } else if lower_bound < input.len() {
            let size = input.len() - lower_bound;
            apply_to[..size].copy_from_slice(&input[lower_bound..]);
    } else { }
}

/// Apply fuzzer input data to a vector that can be any size, except for none. `lower_bound` is
/// used to specify how much data from the fuzzers input has been used already, to avoid reuse of data.
pub fn apply_from_input_heap(apply_to: &mut Vec<u8>, input: &[u8], lower_bound: usize) {
    if lower_bound >= input.len() {
        apply_to.push(0u8);
    } else {
        apply_to.extend_from_slice(&input[lower_bound..]);
    }
}
