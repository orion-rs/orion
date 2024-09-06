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
//!
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
//! [`update()`]: shake256::Shake256::absorb
//! [`reset()`]: shake256::Shake256::reset
//! [`finalize()`]: shake256::Shake256::squeeze

use super::Shake;
use crate::errors::UnknownCryptoError;

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

#[test]
fn shake256_works() {
    // Len = 120
    // Msg = 765db6ab3af389b8c775c8eb99fe72
    // Output = ccb6564a655c94d714f80b9f8de9e2610c4478778eac1b9256237dbf90e50581

    let msg = hex::decode("765db6ab3af389b8c775c8eb99fe72").unwrap();
    let expected_result =
        hex::decode("ccb6564a655c94d714f80b9f8de9e2610c4478778eac1b9256237dbf90e50581").unwrap();

    debug_assert_eq!(expected_result.len(), 32);
    let mut actual_result = [0u8; 32];

    let mut ctx = Shake256::new();
    ctx.absorb(&msg).unwrap();
    ctx.squeeze(&mut actual_result).unwrap();

    assert_eq!(&expected_result[..], &actual_result);
}
