pub fn apply_from_input_fixed(apply_to: &mut [u8], input: &[u8], lower_bound: usize) {
    if lower_bound > input.len() {
        return ();
    }

    let a_len = apply_to.len();
    if input.len() >= (lower_bound + a_len) {
        apply_to.copy_from_slice(&input[lower_bound..(lower_bound + a_len)]);
    } else {
        if lower_bound < input.len() {
            let size = input.len() - lower_bound;
            apply_to[..size].copy_from_slice(&input[lower_bound..]);
        } else {
            ()
        }
    }
}

pub fn apply_from_input_heap(apply_to: &mut Vec<u8>, input: &[u8], lower_bound: usize) {
    if lower_bound >= input.len() {
        apply_to.push(0u8);
    } else {
        apply_to.extend_from_slice(&input[lower_bound..]);
    }
}
