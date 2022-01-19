// MIT License

// Copyright (c) 2020-2021 The orion Developers

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

//! Hashing.
//!
//! # Use case:
//! `orion::hash` can be used to hash some given data.
//!
//! An example of this could be using hashes of files to ensure integrity.
//! Meaning, checking if a file has been modified since the time the hash was
//! recorded.
//!
//! If you are looking for a keyed hash, please see the [`orion::auth`](super::auth) module.
//!
//! # About:
//! - Uses BLAKE2b with an output size of 32 bytes (i.e BLAKE2b-256).
//!
//! # Parameters:
//! - `data`:  The data to be hashed.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2*(2^64-1) bytes of data are hashed.
//!
//! # Security:
//! - This interface does not support supplying BLAKE2b with a secret key, and
//!   the hashes retrieved
//! from using `orion::hash` are therefore not suitable as MACs.
//! - BLAKE2b is not suitable for password hashing. See [`orion::pwhash`](super::pwhash)
//!   instead.
//!
//! # Examples
//!
//! ## Hashing in-memory data
//! ```rust
//! use orion::hash::{digest, Digest};
//!
//! let hash: Digest = digest(b"Some data")?;
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//!
//! ## Hashing data from an arbitrary reader
//! ```rust
//! use orion::hash::{digest_from_reader, Digest};
//!
//! // `reader` could instead be `File::open("file.txt")?`
//! let reader = std::io::Cursor::new(b"some data");
//! let hash: Digest = digest_from_reader(reader)?;
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use crate::hazardous::hash::blake2::blake2b::Digest;
use crate::{errors::UnknownCryptoError, hazardous::hash::blake2::blake2b};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Hashing using BLAKE2b-256.
pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
    blake2b::Hasher::Blake2b256.digest(data)
}

/// Hash data from a [`Read`](std::io::Read)` type using BLAKE2b-256.
///
/// See the [module-level docs](crate::hash) for an example of how to use this function.
/// Internally calls [`std::io::copy`]() to move data from the reader into the Blake2b writer.
/// Note that the [`std::io::copy`]() function buffers reads, so passing in a
/// [`BufReader`](std::io::BufReader) may be unnecessary.
///
/// For lower-level control over reads, writes, buffer sizes, *etc.*, consider using the
/// [`Blake2b`](crate::hazardous::hash::blake2::blake2b::Blake2b) type and its
/// [`Write`](std::io::Write) implementation directly. See `Blake2b`'s `Write` implementation
/// and/or its `Write` documentation for an example.
///
/// ## Errors:
/// This function will only ever return the [`std::io::ErrorKind::Other`]()
/// variant when it returns an error. Additionally, this will always contain Orion's
/// [`UnknownCryptoError`](crate::errors::UnknownCryptoError) type.
///
/// Note that if an error is returned, data may still have been consumed from the given reader.
#[cfg(feature = "safe_api")]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
pub fn digest_from_reader(mut reader: impl std::io::Read) -> Result<Digest, UnknownCryptoError> {
    let mut hasher = blake2b::Blake2b::new(32)?;
    std::io::copy(&mut reader, &mut hasher).map_err(|_| UnknownCryptoError)?;
    hasher.finalize()
}

// Testing public functions in the module.
#[cfg(feature = "safe_api")]
#[cfg(test)]
mod public {
    use super::*;

    #[quickcheck]
    /// Hashing twice with same input should always produce same output.
    fn prop_digest_same_result(input: Vec<u8>) -> bool {
        digest(&input[..]).unwrap() == digest(&input[..]).unwrap()
    }

    #[quickcheck]
    /// Hashing all input should be the same as wrapping it in a
    /// cursor and using digest_from_reader.
    fn prop_digest_same_as_digest_from_reader(input: Vec<u8>) -> bool {
        let digest_a = digest_from_reader(std::io::Cursor::new(&input)).unwrap();
        let digest_b = digest(&input).unwrap();
        digest_a == digest_b
    }

    #[quickcheck]
    /// Hashing twice with different input should never produce same output.
    fn prop_digest_diff_result(input: Vec<u8>) -> bool {
        digest(&input[..]).unwrap() != digest(b"Completely wrong input").unwrap()
    }
}
