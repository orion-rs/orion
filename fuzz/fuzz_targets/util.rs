// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
    } else {
    }
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

/// Helper function to setup key and nonce for ChaCha20/XChaCha20/hchacha20.
pub fn chacha_key_nonce_setup(nonce_len: usize, data: &[u8]) -> ([u8; 32], Vec<u8>) {
    let mut key = [0u8; 32];
    let mut nonce = vec![0u8; nonce_len];

    apply_from_input_fixed(&mut key, data, 0);
    apply_from_input_fixed(&mut nonce, data, key.len());

    (key, nonce)
}

/// Helper function to setup key, nonce, plaintext and aad for AEAD constructions.
pub fn aead_setup_with_nonce_len(
    nonce_len: usize,
    data: &[u8],
) -> ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>) {
    let (key, nonce) = chacha_key_nonce_setup(nonce_len, data);
    let mut aad = Vec::new();
    apply_from_input_heap(&mut aad, data, key.len() + nonce.len());
    let mut plaintext = Vec::new();
    apply_from_input_heap(&mut plaintext, data, key.len() + nonce.len() + aad.len());

    (key, nonce, aad, plaintext)
}

/// Helper function to setup secret key and message for HMAC.
pub fn hmac_setup(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut secret_key = vec![0u8; input[0] as usize];
    let mut message = Vec::new();
    apply_from_input_heap(&mut secret_key, &input, 0);
    apply_from_input_heap(&mut message, &input, secret_key.len());

    (secret_key, message)
}

/// Helper function to setup ikm, salt, info and okm_out for HKDF.
pub fn hkdf_setup(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut ikm = vec![0u8; input[0] as usize];
    let mut salt = Vec::new();
    let mut info = Vec::new();
    apply_from_input_heap(&mut ikm, &input, 0);
    apply_from_input_heap(&mut salt, &input, ikm.len());
    apply_from_input_heap(&mut info, &input, ikm.len() + salt.len());

    // Max iteration count will be (255*63) + 1 = 16066
    let out_len = (input[0] as usize * 63) + 1;
    let okm_out = vec![0u8; out_len];

    (ikm, salt, info, okm_out)
}

/// Helper function to setup password, salt, dk_out and iteration count for PBKDF2.
pub fn pbkdf2_setup(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, usize) {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }
    // Using the same setup from HMAC to determine password and salt
    let (password, salt) = hmac_setup(data);
    let dk_out = vec![0u8; input.len()];
    // Max iteration count will be (255*40) + 1 = 10201
    let iter = (input[0] as usize * 40) + 1;

    (password, salt, dk_out, iter)
}

/// Helper function to setup one time key and message for Poly1305.
pub fn poly1305_setup(data: &[u8]) -> ([u8; 32], Vec<u8>) {
    let mut key = [0u8; 32];
    apply_from_input_fixed(&mut key, &data, 0);
    let mut message = Vec::new();
    apply_from_input_heap(&mut message, data, key.len());

    (key, message)
}
