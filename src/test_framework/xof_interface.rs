// MIT License

// Copyright (c) 2024 The orion Developers

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

/// Trait to define default XOF contexts that can be tested.
///
/// Based on `TestableStreamingContext` but with some corrections
/// towards a XOF.
pub trait TestableXofContext {
    /// Streaming context function to reset the internal state.
    fn reset(&mut self) -> Result<(), UnknownCryptoError>;

    /// Streaming context function to update the internal state.
    fn absorb(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError>;

    /// Streaming context function to finalize the internal state.
    fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError>;

    /// Testing utility-function that compares the internal state to another.
    fn compare_states(state_1: &Self, state_2: &Self);
}

#[allow(dead_code)] // Allow because blocksize field is only used with std.
/// A streaming context tester.
pub struct XofContextConsistencyTester<T> {
    // The initial context to base further calls upon.
    _initial_context: T,
    blocksize: usize,
}

impl<T> XofContextConsistencyTester<T>
where
    T: TestableXofContext + Clone,
{
    /// The streaming interface tester is created utilizing an initialized
    /// streaming state.
    pub fn new(streaming_context: T, blocksize: usize) -> Self {
        Self {
            _initial_context: streaming_context,
            blocksize,
        }
    }

    // Default input to process.
    // The number 37 has no particular meaning.
    const DEFAULT_INPUT: [u8; 37] = [255u8; 37];

    #[cfg(feature = "safe_api")]
    /// Run all consistency tests given some input data.
    /// Usually used with quickcheck.
    pub fn run_all_tests_property(&self, data: &[u8]) {
        self.consistency(data);
        self.consistency(&[0u8; 0]);
        self.produces_same_state(data);

        self.double_finalize_with_reset_no_update_ok(data);
        self.double_finalize_with_reset_ok(data);
        self.update_after_finalize_err(data);
        self.double_reset_ok();
        self.immediate_finalize();
    }

    #[cfg(feature = "safe_api")]
    /// Used when quickcheck is not available to generate input.
    /// Default input data is used instead. Requires std.
    pub fn run_all_tests(&self) {
        self.consistency(&Self::DEFAULT_INPUT);
        self.consistency(&[0u8; 0]);
        self.produces_same_state(&Self::DEFAULT_INPUT);

        // Following test requires std.
        self.incremental_processing_with_leftover();
        self.incremental_squeezing_with_leftover();

        self.double_finalize_with_reset_no_update_ok(&Self::DEFAULT_INPUT);
        self.double_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
        self.update_after_finalize_err(&Self::DEFAULT_INPUT);
        self.double_reset_ok();
        self.immediate_finalize();
    }

    #[cfg(not(feature = "safe_api"))]
    /// Used when quickcheck is not available to generate input.
    /// Default input data is used instead. Without std.
    pub fn run_all_tests(&self) {
        self.consistency(&Self::DEFAULT_INPUT);
        self.consistency(&[0u8; 0]);
        self.produces_same_state(&Self::DEFAULT_INPUT);
        self.double_finalize_with_reset_no_update_ok(&Self::DEFAULT_INPUT);
        self.double_finalize_with_reset_ok(&Self::DEFAULT_INPUT);
        self.update_after_finalize_err(&Self::DEFAULT_INPUT);
        self.double_reset_ok();
        self.immediate_finalize();
    }

    fn consistency(&self, data: &[u8]) {
        // new(), update(), finalize()
        let mut state_1 = self._initial_context.clone();
        let mut res_1 = [0u8; 256]; // NOTE: 256 is just some arbitrarily chosen number.
        state_1.absorb(data).unwrap();
        state_1.squeeze(&mut res_1).unwrap();

        // new(), reset(), update(), finalize()
        let mut state_2 = self._initial_context.clone();
        let mut res_2 = [0u8; 256];
        state_2.reset().unwrap();
        state_2.absorb(data).unwrap();
        state_2.squeeze(&mut res_2).unwrap();

        // new(), update(), reset(), update(), finalize()
        let mut state_3 = self._initial_context.clone();
        let mut res_3 = [0u8; 256];
        state_3.absorb(data).unwrap();
        state_3.reset().unwrap();
        state_3.absorb(data).unwrap();
        state_3.squeeze(&mut res_3).unwrap();

        // new(), update(), finalize(), reset(), update(), finalize()
        let mut state_4 = self._initial_context.clone();
        let mut res_4 = [0u8; 256];
        state_4.absorb(data).unwrap();
        state_4.squeeze(&mut res_4).unwrap();
        state_4.reset().unwrap();
        state_4.absorb(data).unwrap();
        state_4.squeeze(&mut res_4).unwrap();

        assert_eq!(res_1, res_2);
        assert_eq!(res_2, res_3);
        assert_eq!(res_3, res_4);

        // Tests for the assumption that returning Ok() on empty update() calls
        // with streaming APIs, gives the correct result. This is done by testing
        // the reasoning that if update() is empty, returns Ok(), it is the same as
        // calling new() -> finalize(). i.e not calling update() at all.
        if data.is_empty() {
            // new(), finalize()
            let mut state_5 = self._initial_context.clone();
            let mut res_5 = [0u8; 256];
            state_5.squeeze(&mut res_5).unwrap();

            // new(), reset(), finalize()
            let mut state_6 = self._initial_context.clone();
            let mut res_6 = [0u8; 256];
            state_6.reset().unwrap();
            state_6.squeeze(&mut res_6).unwrap();

            // new(), update(), reset(), finalize()
            let mut state_7 = self._initial_context.clone();
            let mut res_7 = [0u8; 256];
            state_7.absorb(b"WRONG DATA").unwrap();
            state_7.reset().unwrap();
            state_7.squeeze(&mut res_7).unwrap();

            assert_eq!(res_4, res_5);
            assert_eq!(res_5, res_6);
            assert_eq!(res_6, res_7);
        }
    }

    /// Related bug: https://github.com/orion-rs/orion/issues/46
    /// Testing different usage combinations of new(), update(),
    /// finalize() and reset() produce the same output.
    fn produces_same_state(&self, data: &[u8]) {
        // new()
        let state_1 = self._initial_context.clone();

        // new(), reset()
        let mut state_2 = self._initial_context.clone();
        state_2.reset().unwrap();

        // new(), update(), reset()
        let mut state_3 = self._initial_context.clone();
        state_3.absorb(data).unwrap();
        state_3.reset().unwrap();

        // new(), update(), finalize(), reset()
        let mut state_4 = self._initial_context.clone();
        let mut res_4 = [0u8; 256];
        state_4.absorb(data).unwrap();
        state_4.squeeze(&mut res_4).unwrap();
        state_4.reset().unwrap();

        T::compare_states(&state_1, &state_2);
        T::compare_states(&state_2, &state_3);
        T::compare_states(&state_3, &state_4);
    }

    #[cfg(feature = "safe_api")]
    /// Test for issues when incrementally processing data
    /// with leftover in the internal buffer. It should produce
    /// the same results as processing the same data in a single pass.
    fn incremental_processing_with_leftover(&self) {
        for len in 0..self.blocksize * 4 {
            let data = vec![0u8; len];
            let mut state = self._initial_context.clone();
            let mut other_data: Vec<u8> = Vec::new();

            other_data.extend_from_slice(&data);
            state.absorb(&data).unwrap();

            if data.len() > self.blocksize {
                other_data.extend_from_slice(b"");
                state.absorb(b"").unwrap();
            }
            if data.len() > self.blocksize * 2 {
                other_data.extend_from_slice(b"Extra");
                state.absorb(b"Extra").unwrap();
            }
            if data.len() > self.blocksize * 3 {
                other_data.extend_from_slice(&[0u8; 256]);
                state.absorb(&[0u8; 256]).unwrap();
            }

            let mut streaming_result = [0u8; 384];
            state.squeeze(&mut streaming_result).unwrap();

            let mut state_one_shot = self._initial_context.clone();
            let mut one_shot_result = [0u8; 384];
            state_one_shot.absorb(&other_data).unwrap();
            state_one_shot.squeeze(&mut one_shot_result).unwrap();

            assert_eq!(streaming_result, one_shot_result);
        }
    }

    #[cfg(feature = "safe_api")]
    /// Test for issues when incrementally squeezing the XOF
    /// with leftover data in internal buffer. It should produce
    /// the same results as squeezing the same amount in a single pass.
    fn incremental_squeezing_with_leftover(&self) {
        let input = [127u8; 1543];
        let mut output1 = vec![0u8; self.blocksize * 4];
        let mut output2 = vec![0u8; self.blocksize * 4];

        let mut state = self._initial_context.clone();
        state.absorb(&input).unwrap();
        state.squeeze(&mut output2).unwrap();
        state.reset().unwrap();

        for n_squeeze in (0..(self.blocksize * 3)).step_by(2) {
            state
                .squeeze(&mut output1[n_squeeze..n_squeeze + 1])
                .unwrap();
        }
        state
            .squeeze(&mut output1[self.blocksize * 3..(self.blocksize * 3) + 3])
            .unwrap();
        state
            .squeeze(&mut output1[(self.blocksize * 3) + 3..])
            .unwrap();

        assert_eq!(output1, output2);
    }

    /// new(), update(), finalize(), reset(), finalize(): OK
    fn double_finalize_with_reset_no_update_ok(&self, data: &[u8]) {
        let mut state = self._initial_context.clone();
        let mut res = [0u8; 24];
        state.absorb(data).unwrap();
        state.squeeze(&mut res).unwrap();
        state.reset().unwrap();
        assert!(state.squeeze(&mut res).is_ok());
    }

    /// new(), update(), finalize(), reset(), update(), finalize(): OK
    fn double_finalize_with_reset_ok(&self, data: &[u8]) {
        let mut state = self._initial_context.clone();
        let mut res = [0u8; 24];
        state.absorb(data).unwrap();
        state.squeeze(&mut res).unwrap();
        state.reset().unwrap();
        state.absorb(data).unwrap();
        assert!(state.squeeze(&mut res).is_ok());
    }

    /// Related bug: https://github.com/orion-rs/orion/issues/28
    /// new(), update(), finalize(), update(): ERR
    fn update_after_finalize_err(&self, data: &[u8]) {
        let mut state = self._initial_context.clone();
        let mut res = [0u8; 24];
        state.absorb(data).unwrap();
        state.squeeze(&mut res).unwrap();
        assert!(state.absorb(data).is_err());
    }

    /// reset(), reset(): OK
    fn double_reset_ok(&self) {
        let mut state = self._initial_context.clone();
        state.reset().unwrap();
        assert!(state.reset().is_ok());
    }

    /// new(), finalize(): OK
    fn immediate_finalize(&self) {
        let mut state = self._initial_context.clone();
        let mut res = [0u8; 24];
        assert!(state.squeeze(&mut res).is_ok());
    }
}
