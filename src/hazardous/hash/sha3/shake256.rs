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

//! # Parameters:
//! - `data`: The data to be hashed.
//!
//! # Errors:
//! An error will be returned if:
//! - [`absorb()`] is called after [`squeeze()`] without a [`reset()`] in
//!   between.
//!
//! # Security:
//! - 256-bit security against all attacks requires a minimum of 512 bits output (64 bytes).
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::sha3::shake256::Shake256;
//!
//! // Using the streaming interface
//! let mut state = Shake256::new();
//! state.absorb(b"Hello world")?;
//!
//! let mut dest = [0u8; 64];
//! state.squeeze(&mut dest[..32])?;
//! state.squeeze(&mut dest[32..])?;
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`absorb()`]: shake256::Shake256::absorb
//! [`reset()`]: shake256::Shake256::reset
//! [`squeeze()`]: shake256::Shake256::squeeze

use super::Shake;
use crate::errors::UnknownCryptoError;
#[cfg(feature = "safe_api")]
use std::io;

/// Rate of SHAKE-256.
pub const SHAKE_256_RATE: usize = 136;

#[derive(Clone, Debug)]
/// SHAKE-256 streaming state.
pub struct Shake256 {
    pub(crate) _state: Shake<SHAKE_256_RATE>,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: hashing from a [`Read`](std::io::Read)er with Shake256.
/// ```rust
/// use orion::{
///     hazardous::hash::sha3::shake256::Shake256,
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Shake256::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let mut dest = [0u8; 64];
/// hasher.squeeze(&mut dest)?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Shake256 {
    /// Update the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Shake256::absorb`](crate::hazardous::hash::sha3::shake256::Shake256::absorb).
    ///
    /// ## Errors:
    /// This function will only ever return the [`std::io::ErrorKind::Other`]()
    /// variant when it returns an error. Additionally, this will always contain Orion's
    /// [`UnknownCryptoError`] type.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.absorb(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(bytes.len())
    }

    /// This type doesn't buffer writes, so flushing is a no-op.
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Shake256 {
    /// Initialize a `Shake256` struct.
    pub fn new() -> Self {
        Self {
            _state: Shake::<SHAKE_256_RATE>::_new(64),
        }
    }

    /// Reset to `new()` state.
    pub fn reset(&mut self) {
        self._state._reset();
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self._state._absorb(data)
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Squeeze output of the XOF into `dest`. This can be called multiple times.
    pub fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self._state._squeeze(dest)
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_default_equals_new() {
        let new = Shake256::new();
        let default = Shake256::default();
        new._state.compare_state_to_other(&default._state);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = Shake256::new();
        let debug = format!("{:?}", initial_state);
        let expected = "Shake256 { _state: State { state: [***OMITTED***], buffer: [***OMITTED***], capacity: 64, until_absorb: 0, to_squeeze: 0, is_finalized: false } }";
        assert_eq!(debug, expected);
    }

    mod test_streaming_interface {
        use super::*;
        use crate::test_framework::xof_interface::*;

        impl TestableXofContext for Shake256 {
            fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                self.reset();
                Ok(())
            }

            fn absorb(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                self.absorb(input)
            }

            fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
                self.squeeze(dest)
            }

            fn compare_states(state_1: &Shake256, state_2: &Shake256) {
                state_1._state.compare_state_to_other(&state_2._state);
            }
        }

        #[test]
        fn default_consistency_tests() {
            let initial_state: Shake256 = Shake256::new();

            let test_runner =
                XofContextConsistencyTester::<Shake256>::new(initial_state, SHAKE_256_RATE);
            test_runner.run_all_tests();
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        /// Related bug: https://github.com/orion-rs/orion/issues/46
        /// Test different streaming state usage patterns.
        fn prop_input_to_consistency(data: Vec<u8>) -> bool {
            let initial_state: Shake256 = Shake256::new();

            let test_runner =
                XofContextConsistencyTester::<Shake256>::new(initial_state, SHAKE_256_RATE);
            test_runner.run_all_tests_property(&data);
            true
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_io_impls {
        use crate::hazardous::hash::sha3::shake256::Shake256;
        use std::io::Write;

        #[quickcheck]
        fn prop_hasher_write_same_as_update(data: Vec<u8>, outlen: u16) -> bool {
            let mut hasher_a = Shake256::new();
            let mut hasher_b = hasher_a.clone();

            hasher_a.absorb(&data).unwrap();
            hasher_b.write_all(&data).unwrap();

            let mut hash_a = vec![0u8; outlen as usize];
            let mut hash_b = vec![0u8; outlen as usize];
            hasher_a.squeeze(&mut hash_a).unwrap();
            hasher_b.squeeze(&mut hash_b).unwrap();

            hash_a == hash_b
        }
    }
}
