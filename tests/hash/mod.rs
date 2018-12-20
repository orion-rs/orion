// Copyright (c) 2018 brycx

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

pub mod blake2b_kat;
pub mod sha512_nist_cavp;

extern crate orion;
use self::orion::hazardous::hash::{blake2b, sha512};

fn blake2b_test_runner(input: &[u8], key: &[u8], output: &[u8]) {
	// Only make SecretKey if test case key value is not empty, otherwise it will be
	// BLOCKSIZE zero bytes.
	let mut state = if key.is_empty() {
		blake2b::init(None, output.len()).unwrap()
	} else {
		let secret_key = blake2b::SecretKey::from_slice(key).unwrap();
		blake2b::init(Some(&secret_key), output.len()).unwrap()
	};

	state.update(input).unwrap();
	let digest = state.finalize().unwrap();
	// All KAT test vectors are 64 bytes in length
	assert!(digest.as_bytes().len() == output.len());
	assert!(digest.as_bytes() == &output[..]);
}

fn sha512_test_runner(data: &[u8], output: &[u8]) {
	// Test streaming
	let mut state = sha512::init();
	state.update(data).unwrap();
	let digest = state.finalize().unwrap();
	// Test one-shot function
	let digest_one_shot = sha512::digest(data).unwrap();

	assert!(digest.as_bytes() == digest_one_shot.as_bytes());
	assert!(digest.as_bytes() == output);
}
