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
//! - `secret_key`: The authentication key.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication tag.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//!
//! # Panics:
//! A panic will occur if:
//! - More than 2^64 bytes of data are hashed.
//!
//! # Security:
//! - The recommended minimum output size is `32`, which is what [`Tag`] enforces.
//!   The security provided by the hash function cannot exceed `256` bits, so
//!   choosing output sizes larger than `32` bytes provides no additional security over
//!   the `32` exactly. Choosing a smaller output size however decreases the security provided.
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used for this. It generates
//!   a secret key of 32 bytes.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::mac::blake3::{Blake3, SecretKey};
//!
//! let key = SecretKey::generate()?;
//!
//! let mut state = Blake3::new(&key);
//! state.update(b"Some data")?;
//! let tag = state.finalize()?;
//!
//! assert!(Blake3::verify(&tag, &key, b"Some data").is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: blake3::Blake3::update
//! [`reset()`]: blake3::Blake3::reset
//! [`finalize()`]: blake3::Blake3::finalize
//! [`SecretKey::generate()`]: blake3::SecretKey::generate
//! [`Blake3`]: blake3::Blake3
//! [`Tag`]: blake3::Tag

use crate::GenerateSecret;
use crate::Secret;
use crate::errors::UnknownCryptoError;
#[cfg(feature = "safe_api")]
use crate::generics::sealed::Data;
use crate::generics::sealed::Sealed;
use crate::generics::{ByteArrayData, TypeSpec};
use crate::hazardous::hash::blake3::internal::KEYED_HASH;
use crate::hazardous::hash::blake3::state::Blake3State;

#[cfg(feature = "serde")]
use alloc::vec::Vec;

/// Size for a BLAKE3 [`SecretKey`].
pub const KEY_SIZE: usize = crate::hazardous::hash::blake3::internal::KEY_SIZE;

/// Size out the authentication tag [`Tag`].
pub const TAG_SIZE: usize = 32;

/// A type to represent the secret key that BLAKE3 uses for keyed mode.
pub type SecretKey = Secret<Blake3Key>;

/// A type to represent the authentication tag that BLAKE3 produces.
pub type Tag = Secret<Blake3Tag>;

#[derive(Debug)]
/// Marker type for BLAKE3 key. See [`SecretKey`] type for convenience.
pub struct Blake3Key {}
impl Sealed for Blake3Key {}

impl TypeSpec for Blake3Key {
    const NAME: &'static str = stringify!(SecretKey);
    type TypeData = ByteArrayData<KEY_SIZE>;
}

impl GenerateSecret for Blake3Key {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<Blake3Key>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(KEY_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

impl From<[u8; KEY_SIZE]> for SecretKey {
    fn from(value: [u8; KEY_SIZE]) -> Self {
        Self::from_data(<Blake3Key as TypeSpec>::TypeData::from(value))
    }
}

#[derive(Debug)]
/// Marker type for BLAKE3 authentication tag. See [`Tag`] type for convenience.
pub struct Blake3Tag {}
impl Sealed for Blake3Tag {}

impl TypeSpec for Blake3Tag {
    const NAME: &'static str = stringify!(Tag);
    type TypeData = ByteArrayData<TAG_SIZE>;
}

impl From<[u8; TAG_SIZE]> for Tag {
    fn from(value: [u8; TAG_SIZE]) -> Self {
        Self::from_data(<Blake3Tag as TypeSpec>::TypeData::from(value))
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to serialize as a `&[u8]` would. Note that the serialized
/// type likely does not have the same protections that Orion provides, such
/// as constant-time operations. A good rule of thumb is to only serialize
/// these types for storage. Don't operate on the serialized types.
impl serde::Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let bytes: &[u8] = self.data.as_ref();
        bytes.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// This type tries to deserialize as a `Vec<u8>` would. If it succeeds, the public data
/// will be built using `Self::try_from`.
///
/// Note that **this allocates** once to store the referenced bytes on the heap.
impl<'de> serde::Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        TryFrom::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// Represents the "keyed hash" mode for BLAKE3 for producing
/// hashes using a secret key.
#[derive(Clone, Debug, PartialEq)]
pub struct Blake3 {
    internal: Blake3State,
    // NOTE(brycx): Blake3State has internal is_finalized
    // but that is used in conjunction with multi-part squeeze
    // calls. So we add this here, to make the API connsistent
    // and avoid confusion. Blake3State should in this case only
    // ever be able to squeeze once
    is_finalized: bool,
}

impl Blake3 {
    /// Initialize a [`Blake3`] struct with a given and key.
    pub fn new(key: &SecretKey) -> Self {
        Self {
            internal: Blake3State::new(key, KEYED_HASH),
            is_finalized: false,
        }
    }

    /// Reset to [`Self::new()`] state.
    pub fn reset(&mut self) {
        self.internal.reset();
        self.is_finalized = false;
    }

    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.internal.absorb(data, KEYED_HASH)
    }

    /// Return a BLAKE3 tag.
    pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;
        let mut tag = Tag::from([0u8; TAG_SIZE]);
        self.internal.squeeze(&mut tag.data.bytes, KEYED_HASH)?;

        Ok(tag)
    }

    /// Verify a BLAKE3 tag in constant time.
    pub fn verify(
        expected: &Tag,
        secret_key: &SecretKey,
        data: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new(secret_key);
        ctx.update(data)?;

        if &ctx.finalize()? == expected {
            Ok(())
        } else {
            Err(UnknownCryptoError)
        }
    }
}

#[cfg(test)]
mod keyed_streaming_interface {
    use crate::hazardous::hash::blake3::internal::BLOCK_LEN;
    use crate::hazardous::mac::blake3::*;
    use crate::test_framework::incremental_interface::{
        StreamingContextConsistencyTester, TestableStreamingContext,
    };

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_serialized_equivalence_to_bytes_fn() {
        let bytes = [38u8; TAG_SIZE];
        let secret_type = Tag::try_from(&bytes).unwrap();
        let serialized_from_bytes = serde_json::to_value(bytes.as_slice()).unwrap();
        let serialized_from_secret_type = serde_json::to_value(&secret_type).unwrap();
        assert_eq!(serialized_from_bytes, serialized_from_secret_type);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_deserialized_equivalence_to_bytes_fn() {
        let bytes = [38u8; TAG_SIZE];
        let serialized_from_bytes = serde_json::to_value(bytes.as_slice()).unwrap();
        let secret_type: Tag = serde_json::from_value(serialized_from_bytes).unwrap();
        assert_eq!(secret_type.unprotected_as_ref(), bytes.as_slice());
    }

    impl TestableStreamingContext<Tag> for Blake3 {
        fn reset(&mut self) -> Result<(), UnknownCryptoError> {
            self.reset();
            Ok(())
        }

        fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
            self.update(input)
        }

        fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            self.finalize()
        }

        fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let secret_key = SecretKey::from([0x42; 32]);
            let mut hasher = Blake3::new(&secret_key);
            hasher.update(input)?;
            hasher.finalize()
        }

        fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
            let actual = Self::one_shot(input)?;
            if &actual == expected {
                Ok(())
            } else {
                Err(UnknownCryptoError)
            }
        }

        fn compare_states(state_1: &Self, state_2: &Self) {
            assert_eq!(state_1, state_2)
        }
    }

    #[test]
    fn keyed_consistency_states() {
        let secret_key = SecretKey::from([0x42; 32]);
        let test_runner = StreamingContextConsistencyTester::<Tag, Blake3>::new(
            Blake3::new(&secret_key),
            BLOCK_LEN,
        );
        test_runner.run_all_tests();
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
        let secret_key = SecretKey::from([0x42; 32]);
        let test_runner = StreamingContextConsistencyTester::<Tag, Blake3>::new(
            Blake3::new(&secret_key),
            BLOCK_LEN,
        );
        test_runner.run_all_tests_property(&data);
        true
    }
}
