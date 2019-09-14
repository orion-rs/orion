// MIT License

// Copyright (c) 2018-2019 The orion Developers

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

use crate::errors::UnknownCryptoError;

/// Trait to define default streaming contexts that can be tested.
pub trait TestableStreamingContext<T: PartialEq> {
	/// Interface to streaming API.
	fn reset(&mut self) -> Result<(), UnknownCryptoError>;
	fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError>;
	fn finalize(&mut self) -> Result<T, UnknownCryptoError>;
	fn one_shot(input: &[u8]) -> Result<T, UnknownCryptoError>;
	fn verify_result(expected: &T, input: &[u8]) -> Result<(), UnknownCryptoError>;

	/// Testing utiliy-functions.
	fn compare_states(state_1: &Self, state_2: &Self);
}

/// A streaming context tester.
pub struct StreamingContextConsistencyTester<R, T> {
	_return_type: R,
	// The initial context to base further calls upon.
	_initial_context: T,
	blocksize: usize,
}

impl<R, T> StreamingContextConsistencyTester<R, T>
where
	R: PartialEq + core::fmt::Debug,
	T: TestableStreamingContext<R> + Clone,
{
	/// The streaming interface tester is created utilizing an initialized
	/// streaming state and a return type. The contents of the return type
	/// do not matter.
	pub fn new(streaming_context: T, return_type: R, blocksize: usize) -> Self {
		Self {
			_return_type: return_type,
			_initial_context: streaming_context,
			blocksize,
		}
	}

	// Default input to process.
	// The number 37 has no particular meaning.
	const DEFAULT_INPUT: [u8; 37] = [255u8; 37];

	#[cfg(feature = "safe_api")]
	pub fn run_all_tests_property(&self, data: &[u8]) {
		self.consistency(data);
		self.consistency(&[0u8; 0]);
		self.produces_same_state(data);
		// Following test requires std.
		self.incremental_and_one_shot(data);
		self.double_finalize_with_reset_no_update_ok(data);
		self.double_finalize_with_reset_ok(data);
		self.double_finalize_err(data);
		self.update_after_finalize_with_reset_ok(data);
		self.update_after_finalize_err(data);
		self.double_reset_ok(data);
		Self::verify_same_input_ok(data);
		Self::verify_diff_input_err(data);
	}

	#[cfg(feature = "safe_api")]
	/// Used when quickcheck is not available to generate input.
	/// Default input `data` is used instead.
	pub fn run_all_tests(&self) {
		self.consistency(&Self::DEFAULT_INPUT);
		self.consistency(&[0u8; 0]);
		self.produces_same_state(&Self::DEFAULT_INPUT);
		// Following test requires std.
		self.incremental_processing_with_leftover(self.blocksize);
		self.incremental_and_one_shot(&Self::DEFAULT_INPUT);
		self.double_finalize_with_reset_no_update_ok(&Self::DEFAULT_INPUT);
		self.double_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
		self.double_finalize_err(&Self::DEFAULT_INPUT);
		self.update_after_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
		self.update_after_finalize_err(&Self::DEFAULT_INPUT);
		self.double_reset_ok(&Self::DEFAULT_INPUT);
		Self::verify_same_input_ok(&Self::DEFAULT_INPUT);
		Self::verify_diff_input_err(&Self::DEFAULT_INPUT);
	}

	#[cfg(not(feature = "safe_api"))]
	/// Used when quickcheck is not available to generate input.
	/// Default input `data` is used instead.
	pub fn run_all_tests(&self) {
		self.consistency(&Self::DEFAULT_INPUT);
		self.consistency(&[0u8; 0]);
		self.produces_same_state(&Self::DEFAULT_INPUT);
		self.incremental_and_one_shot(&Self::DEFAULT_INPUT);
		self.double_finalize_with_reset_no_update_ok(&Self::DEFAULT_INPUT);
		self.double_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
		self.double_finalize_err(&Self::DEFAULT_INPUT);
		self.update_after_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
		self.update_after_finalize_err(&Self::DEFAULT_INPUT);
		self.double_reset_ok(&Self::DEFAULT_INPUT);
		Self::verify_same_input_ok(&Self::DEFAULT_INPUT);
		Self::verify_diff_input_err(&Self::DEFAULT_INPUT);
	}

	/// Related bug: https://github.com/brycx/orion/issues/46
	/// Testing different usage combinations of new(), update(),
	/// finalize() and reset() produce the same Digest.
	///
	/// It is important to ensure this is also called with empty
	/// `data`.
	pub fn consistency(&self, data: &[u8]) {
		// new(), update(), finalize()
		let mut state_1 = self._initial_context.clone();
		state_1.update(data).unwrap();
		let res_1 = state_1.finalize().unwrap();

		// new(), reset(), update(), finalize()
		let mut state_2 = self._initial_context.clone();
		state_2.reset().unwrap();
		state_2.update(data).unwrap();
		let res_2 = state_2.finalize().unwrap();

		// new(), update(), reset(), update(), finalize()
		let mut state_3 = self._initial_context.clone();
		state_3.update(data).unwrap();
		state_3.reset().unwrap();
		state_3.update(data).unwrap();
		let res_3 = state_3.finalize().unwrap();

		// new(), update(), finalize(), reset(), update(), finalize()
		let mut state_4 = self._initial_context.clone();
		state_4.update(data).unwrap();
		let _ = state_4.finalize().unwrap();
		state_4.reset().unwrap();
		state_4.update(data).unwrap();
		let res_4 = state_4.finalize().unwrap();

		assert!(res_1 == res_2);
		assert!(res_2 == res_3);
		assert!(res_3 == res_4);

		// Tests for the assumption that returning Ok() on empty update() calls
		// with streaming API's, gives the correct result. This is done by testing
		// the reasoning that if update() is empty, returns Ok(), it is the same as
		// calling new() -> finalize(). i.e not calling update() at all.
		if data.is_empty() {
			// new(), finalize()
			let mut state_5 = self._initial_context.clone();
			let res_5 = state_5.finalize().unwrap();

			// new(), reset(), finalize()
			let mut state_6 = self._initial_context.clone();
			state_6.reset().unwrap();
			let res_6 = state_6.finalize().unwrap();

			// new(), update(), reset(), finalize()
			let mut state_7 = self._initial_context.clone();
			state_7.update(b"WRONG DATA").unwrap();
			state_7.reset().unwrap();
			let res_7 = state_7.finalize().unwrap();

			assert!(res_4 == res_5);
			assert!(res_5 == res_6);
			assert!(res_6 == res_7);
		}
	}

	/// Related bug: https://github.com/brycx/orion/issues/46
	/// Testing different usage combinations of new(), update(),
	/// finalize() and reset() produce the same Digest.
	pub fn produces_same_state(&self, data: &[u8]) {
		// new()
		let state_1 = self._initial_context.clone();

		// new(), reset()
		let mut state_2 = self._initial_context.clone();
		state_2.reset().unwrap();

		// new(), update(), reset()
		let mut state_3 = self._initial_context.clone();
		state_3.update(data).unwrap();
		state_3.reset().unwrap();

		// new(), update(), finalize(), reset()
		let mut state_4 = self._initial_context.clone();
		state_4.update(data).unwrap();
		let _ = state_4.finalize().unwrap();
		state_4.reset().unwrap();

		T::compare_states(&state_1, &state_2);
		T::compare_states(&state_2, &state_3);
		T::compare_states(&state_3, &state_4);
	}

	#[cfg(feature = "safe_api")]
	/// Test for issues when incrementally processing data
	/// with leftover in the internal buffer. It should produce
	/// the same results as processing the same data in a single pass.
	pub fn incremental_processing_with_leftover(&self, blocksize: usize) {
		for len in 0..blocksize * 4 {
			let data = vec![0u8; len];
			let mut state = self._initial_context.clone();
			let mut other_data: Vec<u8> = Vec::new();

			other_data.extend_from_slice(&data);
			state.update(&data).unwrap();

			if data.len() > blocksize {
				other_data.extend_from_slice(b"");
				state.update(b"").unwrap();
			}
			if data.len() > blocksize * 2 {
				other_data.extend_from_slice(b"Extra");
				state.update(b"Extra").unwrap();
			}
			if data.len() > blocksize * 3 {
				other_data.extend_from_slice(&[0u8; 256]);
				state.update(&[0u8; 256]).unwrap();
			}

			let streaming_result = state.finalize().unwrap();
			let one_shot_result = T::one_shot(&other_data).unwrap();

			assert!(streaming_result == one_shot_result);
		}
	}

	/// new(), update(), finalize() == one_shot()
	pub fn incremental_and_one_shot(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(&data).unwrap();
		let streaming_result = state.finalize().unwrap();
		let one_shot_result = T::one_shot(&data).unwrap();

		assert!(streaming_result == one_shot_result);
	}

	/// finalize(), reset(), finalize(): OK
	pub fn double_finalize_with_reset_no_update_ok(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		state.reset().unwrap();
		assert!(state.finalize().is_ok());
	}

	/// finalize(), reset(), update(), finalize(): OK
	pub fn double_finalize_with_reset_ok(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		state.reset().unwrap();
		state.update(data).unwrap();
		assert!(state.finalize().is_ok());
	}

	/// finalize(), finalize(): ERR
	pub fn double_finalize_err(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		assert!(state.finalize().is_err());
	}

	/// finalize(), reset(), update(): OK
	pub fn update_after_finalize_with_reset_ok(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		state.reset().unwrap();
		assert!(state.update(data).is_ok());
	}

	/// Related bug: https://github.com/brycx/orion/issues/28
	/// finalize(), update(): ERR
	pub fn update_after_finalize_err(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		assert!(state.update(data).is_err());
	}

	/// reset(), reset(): OK
	pub fn double_reset_ok(&self, data: &[u8]) {
		let mut state = self._initial_context.clone();
		state.update(data).unwrap();
		let _ = state.finalize().unwrap();
		state.reset().unwrap();
		assert!(state.reset().is_ok());
	}

	/// Using the same input should always result in a succesfull verification.
	pub fn verify_same_input_ok(data: &[u8]) {
		let expected = T::one_shot(&data).unwrap();
		assert!(T::verify_result(&expected, data).is_ok());
	}

	/// Using different input should result in a failed verification.
	pub fn verify_diff_input_err(data: &[u8]) {
		let expected = T::one_shot(&data).unwrap();
		assert!(T::verify_result(&expected, "Bad data".as_bytes()).is_err());
	}
}
