// MIT License

// Copyright (c) 2026 The orion Developers

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
//! - `dest`: The variable-sized output buffer.
//!
//! # Errors:
//! An error will be returned if:
//! - [`absorb()`] is called after [`squeeze()`] without a [`reset()`] in
//!   between.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^64 bytes of data are hashed.
//!
//! # Security:
//! - The recommended minimum output size is `32`. The security provided by the hash function cannot
//!   exceed `256` bits, so choosing output sizes larger than `32` bytes provides no additional security over
//!   the `32` exactly. Choosing a smaller output size however decreases the security provided.
//! - While there exists a [`Blake3::new_keyed`] function, it's usage is recommended against unless
//!   strictly needed. It's main purpose is for uses where a keyed hash needs to be longer than
//!   `32` bytes. If this is not the case, use [`mac::blake3`] where more protections are offered for
//!   handling authentication tags.
//!
//! # Example:
//! ```rust
//! use orion::hazardous::hash::blake3::Blake3;
//!
//! let mut state = Blake3::new();
//! state.absorb(b"Hello world")?;
//!
//! let mut dest = [0u8; 32];
//! state.squeeze(&mut dest[..16])?;
//! state.squeeze(&mut dest[16..])?;
//!
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`absorb()`]: blake3::Blake3::absorb
//! [`reset()`]: blake3::Blake3::reset
//! [`squeeze()`]: blake3::Blake3::squeeze
//! [`Blake3::new_keyed`]: blake3::Blake3::new_keyed
//! [`mac::blake3`]: crate::hazardous::mac::blake3

pub(crate) mod cvstack;
pub(crate) mod internal;
pub(crate) mod state;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake3::internal::KEYED_HASH;
use crate::hazardous::hash::blake3::state::Blake3State;
use crate::hazardous::mac::blake3::SecretKey;

#[cfg(feature = "safe_api")]
use std::io;

/// BLAKE3 configuration for standard hashing.
#[derive(PartialEq, Debug, Clone)]
pub struct Blake3 {
    internal: Blake3State,
    flags: u32,
}

/// Represents the standard `hash` mode for [Blake3] for producing
/// hashes without a secret key.
impl Default for Blake3 {
    /// Create a new [`Blake3`] instance for standard hashing (`hash` mode).
    fn default() -> Self {
        Self {
            internal: Blake3State::new_with_iv(0),
            flags: 0,
        }
    }
}

impl Blake3 {
    /// Create a new [`Blake3`] instance for standard hashing (`hash` mode).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`Blake3`] instance for keyed hashing (`keyed` mode).
    pub fn new_keyed(secret_key: &SecretKey) -> Self {
        Self {
            internal: Blake3State::new(secret_key, KEYED_HASH),
            flags: KEYED_HASH,
        }
    }

    /// Reset to [`Self::new()`] or [`Self::new_keyed()`] state.
    pub fn reset(&mut self) {
        self.internal.reset();
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.internal.absorb(data, self.flags)
    }

    /// Squeeze output of the XOF into `dest`. This can be called multiple times.
    pub fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self.internal.squeeze(dest, self.flags)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
/// Example: custom digest size.
/// ```rust
/// use orion::{
///     hazardous::hash::blake3::Blake3,
///     errors::UnknownCryptoError,
/// };
/// use std::io::{self, Read, Write};
///
/// // `reader` could also be a `File::open(...)?`.
/// let mut reader = io::Cursor::new(b"some data");
/// let mut hasher = Blake3::new();
/// std::io::copy(&mut reader, &mut hasher)?;
///
/// let mut digest = [0u8; 32];
/// hasher.squeeze(&mut digest)?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "safe_api")]
impl io::Write for Blake3 {
    /// absorb the hasher's internal state with *all* of the bytes given.
    /// If this function returns the `Ok` variant, it's guaranteed that it
    /// will contain the length of the buffer passed to [`Write`](std::io::Write).
    /// Note that this function is just a small wrapper over
    /// [`Blake3::absorb`](crate::hazardous::hash::blake3::Blake3::absorb).
    ///
    /// ## Errors:
    /// This function will only ever return the [`std::io::ErrorKind::Other`]()
    /// variant when it returns an error. Additionally, this will always contain Orion's
    /// [`UnknownCryptoError`] type.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.absorb(bytes).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    /// This type doesn't buffer writes, so flushing is a no-op.
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test_xof_interface {
    use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
    use crate::hazardous::hash::blake3::*;
    use crate::test_framework::xof_interface::{TestableXofContext, XofContextConsistencyTester};

    impl TestableXofContext for Blake3 {
        fn reset(&mut self) -> Result<(), UnknownCryptoError> {
            self.reset();
            Ok(())
        }

        fn absorb(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
            self.absorb(input)
        }

        fn squeeze(&mut self, dst: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self.squeeze(dst)
        }

        fn compare_states(state_1: &Self, state_2: &Self) {
            assert_eq!(state_1, state_2)
        }
    }

    #[test]
    fn default_consistency_states() {
        let test_runner = XofContextConsistencyTester::<Blake3>::new(Blake3::new(), BLOCK_LEN);
        test_runner.run_all_tests();
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
        let test_runner = XofContextConsistencyTester::<Blake3>::new(Blake3::new(), BLOCK_LEN);
        test_runner.run_all_tests_property(&data);
        true
    }
}
