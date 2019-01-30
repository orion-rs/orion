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

//! Hashing.
//!
//! # Use case:
//! `orion::hash` can be used to hash some given data.
//!
//! An example of this could be using hashes of files to ensure integrity.
//! Meaning, checking if a file has been modified since the time the hash was
//! recorded.
//!
//! # About:
//! - Uses BLAKE2b with an output size of 32 bytes (i.e BLAKE2b-256).
//!
//! # Parameters:
//! - `data`:  The data to be hashed.
//!
//! # Exceptions:
//! An exception will be thrown if:
//!
//! # Security:
//! - This interface does not support supplying BLAKE2b with a secret key, and
//!   the hashes retrived
//! from using `orion::hash` are therefore not suitable as MACs.
//! - BLAKE2b is not suitable for password hashing. See `orion::pwhash` instead.
//!
//! # Example:
//! ```
//! use orion::hash::{digest, Digest};
//!
//! let hash: Digest = digest(b"Some data").unwrap();
//! ```

pub use crate::hazardous::hash::blake2b::Digest;
use crate::{errors::UnknownCryptoError, hazardous::hash::blake2b};

#[must_use]
/// Hashing using BLAKE2b-256.
pub fn digest(data: &[u8]) -> Result<Digest, UnknownCryptoError> {
	Ok(blake2b::Hasher::Blake2b256.digest(data)?)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	mod test_digest {
		use super::*;
		#[test]
		fn basic_test() { let _digest = digest(b"Some data").unwrap(); }

		// Proptests. Only exectued when NOT testing no_std.
		#[cfg(not(feature = "no_std"))]
		mod proptest {
			use super::*;

			quickcheck! {
				/// Hashing twice with same input should always produce same output.
				fn prop_digest_same_result(input: Vec<u8>) -> bool {
					(digest(&input[..]).unwrap() ==  digest(&input[..]).unwrap())
				}
			}

			quickcheck! {
				/// Hashing twice with different input should never produce same output.
				fn prop_digest_diff_result(input: Vec<u8>) -> bool {
					(digest(&input[..]).unwrap() !=  digest(b"Completely wrong input").unwrap())
				}
			}
		}
	}
}
