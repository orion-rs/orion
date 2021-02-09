// MIT License

// Copyright (c) 2018-2021 The orion Developers

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
//! - `secret_key`:  The authentication key.
//! - `data`: Data to be authenticated.
//! - `expected`: The expected authentication tag.
//!
//! # Errors:
//! An error will be returned if:
//! - [`finalize()`] is called twice without a [`reset()`] in between.
//! - [`update()`] is called after [`finalize()`] without a [`reset()`] in
//!   between.
//! - The HMAC does not match the expected when verifying.
//!
//! # Security:
//! - The secret key should always be generated using a CSPRNG.
//!   [`SecretKey::generate()`] can be used for this.
//! - The minimum recommended size for a secret key is 64 bytes.
//!
//! # Recommendation:
//! - If you are unsure of whether to use HMAC or Poly1305, it is most often
//!   easier to just use HMAC. See also [Cryptographic Right Answers].
//!
//! # Example:
//! ```rust
//! use orion::hazardous::mac::hmac::sha512::{HmacSha512, SecretKey};
//!
//! let key = SecretKey::generate();
//!
//! let mut state = HmacSha512::new(&key);
//! state.update(b"Some message.")?;
//! let tag = state.finalize()?;
//!
//! assert!(HmacSha512::verify(&tag, &key, b"Some message.").is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`update()`]: struct.Hmac.html
//! [`reset()`]: struct.Hmac.html
//! [`finalize()`]: struct.Hmac.html
//! [`SecretKey::generate()`]: struct.SecretKey.html
//! [Cryptographic Right Answers]: https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html

use crate::errors::UnknownCryptoError;
use zeroize::Zeroize;

#[derive(Clone)]
/// HMAC streaming state.
pub(crate) struct HmacGeneric<T, const BLOCKSIZE: usize, const OUTSIZE: usize> {
    working_hasher: T,
    opad_hasher: T,
    ipad_hasher: T,
    pub(crate) buffer: [u8; OUTSIZE],
    is_finalized: bool,
}

impl<T, const BLOCKSIZE: usize, const OUTSIZE: usize> HmacGeneric<T, BLOCKSIZE, OUTSIZE>
where
    T: crate::hazardous::hash::sha2::Sha2Hash,
{
    /// Pad the key according to the internal SHA used.
    /// This function should only be used in places where the SecretKey newtype
    /// isn't passed, since it also pads the key.
    fn pad_raw_key(secret_key: &[u8]) -> Result<[u8; BLOCKSIZE], UnknownCryptoError> {
        let mut sk = [0u8; BLOCKSIZE];

        let slice_len = secret_key.len();

        if slice_len > BLOCKSIZE {
            T::digest(secret_key, &mut sk[..OUTSIZE])?;
        } else {
            sk[..slice_len].copy_from_slice(secret_key);
        }

        Ok(sk)
    }

    /// Pad `key` with `ipad` and `opad`.
    fn pad_key_io(&mut self, key: &[u8]) {
        debug_assert!(key.len() == BLOCKSIZE);
        let mut ipad = [0x36; BLOCKSIZE];
        let mut opad = [0x5C; BLOCKSIZE];
        // The key is padded in SecretKey::from_slice
        for (idx, itm) in key.iter().enumerate() {
            opad[idx] ^= itm;
            ipad[idx] ^= itm;
        }

        self.ipad_hasher.update(ipad.as_ref()).unwrap();
        self.opad_hasher.update(opad.as_ref()).unwrap();
        self.working_hasher = self.ipad_hasher.clone();
        ipad.zeroize();
        opad.zeroize();
    }

    /// Initialize `Hmac` struct with a given key that already is padded.
    pub(crate) fn new_no_padding(secret_key: &[u8]) -> Self {
        let mut state = Self {
            working_hasher: T::new(),
            opad_hasher: T::new(),
            ipad_hasher: T::new(),
            buffer: [0u8; OUTSIZE],
            is_finalized: false,
        };

        state.pad_key_io(secret_key);
        state
    }

    /// Initialize `Hmac` struct with a given key that must be padded.
    pub(crate) fn new_with_padding(secret_key: &[u8]) -> Result<Self, UnknownCryptoError> {
        let mut state = Self {
            working_hasher: T::new(),
            opad_hasher: T::new(),
            ipad_hasher: T::new(),
            buffer: [0u8; OUTSIZE],
            is_finalized: false,
        };

        let mut sk = Self::pad_raw_key(secret_key)?;
        state.pad_key_io(&sk);
        sk.zeroize();

        Ok(state)
    }

    /// Reset to `new()` state.
    pub(crate) fn reset(&mut self) {
        self.working_hasher = self.ipad_hasher.clone();
        self.is_finalized = false;
        // TODO: Should we zero buffer here? It's always overwritten before reading from it, it seems
    }

    /// Update state with `data`. This can be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            Err(UnknownCryptoError)
        } else {
            self.working_hasher.update(data)
        }
    }

    /// Compute the HMAC tag and place into `self.buffer`.
    pub(crate) fn finalize(&mut self) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;
        let mut outer_hasher = self.opad_hasher.clone();
        self.working_hasher.finalize(&mut self.buffer)?;
        outer_hasher.update(&self.buffer)?;

        outer_hasher.finalize(&mut self.buffer)
    }
}

/// HMAC-SHA256 (Hash-based Message Authentication Code) as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub mod sha256 {
    use super::*;
    use crate::hazardous::hash::sha2::sha256::{self, Sha256};

    construct_hmac_key! {
        /// A type to represent the `SecretKey` that HMAC uses for authentication.
        ///
        /// # Note:
        /// `SecretKey` pads the secret key for use with HMAC to a length of 64, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the secret key with padding.
        ///
        /// `len()` will return the length with padding (always 64).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (SecretKey, Sha256, sha256::SHA256_OUTSIZE, test_hmac_key, sha256::SHA256_BLOCKSIZE)
    }

    construct_tag! {
        /// A type to represent the `Tag` that HMAC returns.
        ///
        /// # Errors:
        /// An error will be returned if:
        /// - `slice` is not 32 bytes.
        (Tag, test_tag, sha256::SHA256_OUTSIZE, sha256::SHA256_OUTSIZE)
    }

    impl_from_trait!(Tag, sha256::SHA256_OUTSIZE);

    #[derive(Clone)]
    /// HMAC-SHA256 streaming state.
    pub struct HmacSha256 {
        _internal: HmacGeneric<Sha256, { sha256::SHA256_BLOCKSIZE }, { sha256::SHA256_OUTSIZE }>,
    }

    impl core::fmt::Debug for HmacSha256 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                    f,
                    "HmacSha256 {{ working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
                    self._internal.is_finalized
                )
        }
    }

    impl HmacSha256 {
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self {
                _internal: HmacGeneric::<
                    Sha256,
                    { sha256::SHA256_BLOCKSIZE },
                    { sha256::SHA256_OUTSIZE },
                >::new_no_padding(secret_key.unprotected_as_bytes()),
            }
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._internal.reset();
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._internal.update(data)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA256 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            self._internal.finalize()?;

            Tag::from_slice(&self._internal.buffer)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA256 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut state = Self::new(secret_key);
            state.update(data)?;
            state.finalize()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Verify a HMAC-SHA256 tag in constant time.
        pub fn verify(
            expected: &Tag,
            secret_key: &SecretKey,
            data: &[u8],
        ) -> Result<(), UnknownCryptoError> {
            if &Self::hmac(secret_key, data)? == expected {
                Ok(())
            } else {
                Err(UnknownCryptoError)
            }
        }
    }

    #[cfg(test)]
    mod public {
        use super::*;

        #[test]
        #[cfg(feature = "safe_api")]
        fn test_debug_impl() {
            let secret_key = SecretKey::generate();
            let initial_state = HmacSha256::new(&secret_key);
            let debug = format!("{:?}", initial_state);
            let expected = "HmacSha256 { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// When using a different key, verify() should always yield an error.
                    /// NOTE: Using different and same input data is tested with TestableStreamingContext.
                    fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
                        let sk = SecretKey::generate();
                        let mut state = HmacSha256::new(&sk);
                        state.update(&data[..]).unwrap();
                        let tag = state.finalize().unwrap();
                        let bad_sk = SecretKey::generate();

                        HmacSha256::verify(&tag, &bad_sk, &data[..]).is_err()
                    }
                }
            }
        }

        mod test_streaming_interface {
            use super::*;
            use crate::hazardous::hash::sha2::sha256::compare_sha256_states;
            use crate::test_framework::incremental_interface::*;

            const KEY: [u8; 32] = [0u8; 32];

            impl TestableStreamingContext<Tag> for HmacSha256 {
                fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                    Ok(self.reset())
                }

                fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    self.update(input)
                }

                fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                    self.finalize()
                }

                fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                    HmacSha256::hmac(&SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    // This will only run verification tests on differing input. They do not
                    // include tests for different secret keys.
                    HmacSha256::verify(expected, &SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn compare_states(state_1: &HmacSha256, state_2: &HmacSha256) {
                    compare_sha256_states(
                        &state_1._internal.opad_hasher,
                        &state_2._internal.opad_hasher,
                    );
                    compare_sha256_states(
                        &state_1._internal.ipad_hasher,
                        &state_2._internal.ipad_hasher,
                    );
                    compare_sha256_states(
                        &state_1._internal.working_hasher,
                        &state_2._internal.working_hasher,
                    );
                    assert_eq!(
                        state_1._internal.is_finalized,
                        state_2._internal.is_finalized
                    );
                }
            }

            #[test]
            fn default_consistency_tests() {
                let initial_state = HmacSha256::new(&SecretKey::from_slice(&KEY).unwrap());

                let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha256>::new(
                    initial_state,
                    sha256::SHA256_BLOCKSIZE,
                );
                test_runner.run_all_tests();
            }

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// Related bug: https://github.com/brycx/orion/issues/46
                    /// Test different streaming state usage patterns.
                    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
                        let initial_state = HmacSha256::new(&SecretKey::from_slice(&KEY).unwrap());

                        let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha256>::new(
                            initial_state,
                            sha256::SHA256_BLOCKSIZE,
                        );
                        test_runner.run_all_tests_property(&data);
                        true
                    }
                }
            }
        }
    }
}

/// HMAC-SHA384 (Hash-based Message Authentication Code) as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub mod sha384 {
    use super::*;
    use crate::hazardous::hash::sha2::sha384::{self, Sha384};

    construct_hmac_key! {
        /// A type to represent the `SecretKey` that HMAC uses for authentication.
        ///
        /// # Note:
        /// `SecretKey` pads the secret key for use with HMAC to a length of 128, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the secret key with padding.
        ///
        /// `len()` will return the length with padding (always 128).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (SecretKey, Sha384, sha384::SHA384_OUTSIZE, test_hmac_key, sha384::SHA384_BLOCKSIZE)
    }

    construct_tag! {
        /// A type to represent the `Tag` that HMAC returns.
        ///
        /// # Errors:
        /// An error will be returned if:
        /// - `slice` is not 48 bytes.
        (Tag, test_tag, sha384::SHA384_OUTSIZE, sha384::SHA384_OUTSIZE)
    }

    impl_from_trait!(Tag, sha384::SHA384_OUTSIZE);

    #[derive(Clone)]
    /// HMAC-SHA384 streaming state.
    pub struct HmacSha384 {
        _internal: HmacGeneric<Sha384, { sha384::SHA384_BLOCKSIZE }, { sha384::SHA384_OUTSIZE }>,
    }

    impl core::fmt::Debug for HmacSha384 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                    f,
                    "HmacSha384 {{ working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
                    self._internal.is_finalized
                )
        }
    }

    impl HmacSha384 {
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self {
                _internal: HmacGeneric::<
                    Sha384,
                    { sha384::SHA384_BLOCKSIZE },
                    { sha384::SHA384_OUTSIZE },
                >::new_no_padding(secret_key.unprotected_as_bytes()),
            }
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._internal.reset();
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._internal.update(data)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA384 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            self._internal.finalize()?;

            Tag::from_slice(&self._internal.buffer)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA384 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut state = Self::new(secret_key);
            state.update(data)?;
            state.finalize()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Verify a HMAC-SHA384 tag in constant time.
        pub fn verify(
            expected: &Tag,
            secret_key: &SecretKey,
            data: &[u8],
        ) -> Result<(), UnknownCryptoError> {
            if &Self::hmac(secret_key, data)? == expected {
                Ok(())
            } else {
                Err(UnknownCryptoError)
            }
        }
    }

    #[cfg(test)]
    mod public {
        use super::*;

        #[test]
        #[cfg(feature = "safe_api")]
        fn test_debug_impl() {
            let secret_key = SecretKey::generate();
            let initial_state = HmacSha384::new(&secret_key);
            let debug = format!("{:?}", initial_state);
            let expected = "HmacSha384 { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// When using a different key, verify() should always yield an error.
                    /// NOTE: Using different and same input data is tested with TestableStreamingContext.
                    fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
                        let sk = SecretKey::generate();
                        let mut state = HmacSha384::new(&sk);
                        state.update(&data[..]).unwrap();
                        let tag = state.finalize().unwrap();
                        let bad_sk = SecretKey::generate();

                        HmacSha384::verify(&tag, &bad_sk, &data[..]).is_err()
                    }
                }
            }
        }

        mod test_streaming_interface {
            use super::*;
            use crate::hazardous::hash::sha2::sha384::compare_sha384_states;
            use crate::test_framework::incremental_interface::*;

            const KEY: [u8; 32] = [0u8; 32];

            impl TestableStreamingContext<Tag> for HmacSha384 {
                fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                    Ok(self.reset())
                }

                fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    self.update(input)
                }

                fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                    self.finalize()
                }

                fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                    HmacSha384::hmac(&SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    // This will only run verification tests on differing input. They do not
                    // include tests for different secret keys.
                    HmacSha384::verify(expected, &SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn compare_states(state_1: &HmacSha384, state_2: &HmacSha384) {
                    compare_sha384_states(
                        &state_1._internal.opad_hasher,
                        &state_2._internal.opad_hasher,
                    );
                    compare_sha384_states(
                        &state_1._internal.ipad_hasher,
                        &state_2._internal.ipad_hasher,
                    );
                    compare_sha384_states(
                        &state_1._internal.working_hasher,
                        &state_2._internal.working_hasher,
                    );
                    assert_eq!(
                        state_1._internal.is_finalized,
                        state_2._internal.is_finalized
                    );
                }
            }

            #[test]
            fn default_consistency_tests() {
                let initial_state = HmacSha384::new(&SecretKey::from_slice(&KEY).unwrap());

                let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha384>::new(
                    initial_state,
                    sha384::SHA384_BLOCKSIZE,
                );
                test_runner.run_all_tests();
            }

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// Related bug: https://github.com/brycx/orion/issues/46
                    /// Test different streaming state usage patterns.
                    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
                        let initial_state = HmacSha384::new(&SecretKey::from_slice(&KEY).unwrap());

                        let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha384>::new(
                            initial_state,
                            sha384::SHA384_BLOCKSIZE,
                        );
                        test_runner.run_all_tests_property(&data);
                        true
                    }
                }
            }
        }
    }
}

/// HMAC-SHA512 (Hash-based Message Authentication Code) as specified in the [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub mod sha512 {
    use super::*;
    use crate::hazardous::hash::sha2::sha512::{self, Sha512};

    construct_hmac_key! {
        /// A type to represent the `SecretKey` that HMAC uses for authentication.
        ///
        /// # Note:
        /// `SecretKey` pads the secret key for use with HMAC to a length of 128, when initialized.
        ///
        /// Using `unprotected_as_bytes()` will return the secret key with padding.
        ///
        /// `len()` will return the length with padding (always 128).
        ///
        /// # Panics:
        /// A panic will occur if:
        /// - Failure to generate random bytes securely.
        (SecretKey, Sha512, sha512::SHA512_OUTSIZE, test_hmac_key, sha512::SHA512_BLOCKSIZE)
    }

    construct_tag! {
        /// A type to represent the `Tag` that HMAC returns.
        ///
        /// # Errors:
        /// An error will be returned if:
        /// - `slice` is not 64 bytes.
        (Tag, test_tag, sha512::SHA512_OUTSIZE, sha512::SHA512_OUTSIZE)
    }

    impl_from_trait!(Tag, sha512::SHA512_OUTSIZE);

    #[derive(Clone)]
    /// HMAC-SHA512 streaming state.
    pub struct HmacSha512 {
        _internal: HmacGeneric<Sha512, { sha512::SHA512_BLOCKSIZE }, { sha512::SHA512_OUTSIZE }>,
    }

    impl core::fmt::Debug for HmacSha512 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                    f,
                    "HmacSha512 {{ working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
                    self._internal.is_finalized
                )
        }
    }

    impl HmacSha512 {
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self {
                _internal: HmacGeneric::<
                    Sha512,
                    { sha512::SHA512_BLOCKSIZE },
                    { sha512::SHA512_OUTSIZE },
                >::new_no_padding(secret_key.unprotected_as_bytes()),
            }
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._internal.reset();
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._internal.update(data)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA512 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            self._internal.finalize()?;

            Tag::from_slice(&self._internal.buffer)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA512 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut state = Self::new(secret_key);
            state.update(data)?;
            state.finalize()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Verify a HMAC-SHA512 tag in constant time.
        pub fn verify(
            expected: &Tag,
            secret_key: &SecretKey,
            data: &[u8],
        ) -> Result<(), UnknownCryptoError> {
            if &Self::hmac(secret_key, data)? == expected {
                Ok(())
            } else {
                Err(UnknownCryptoError)
            }
        }
    }

    #[cfg(test)]
    mod public {
        use super::*;

        #[test]
        #[cfg(feature = "safe_api")]
        fn test_debug_impl() {
            let secret_key = SecretKey::generate();
            let initial_state = HmacSha512::new(&secret_key);
            let debug = format!("{:?}", initial_state);
            let expected = "HmacSha512 { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// When using a different key, verify() should always yield an error.
                    /// NOTE: Using different and same input data is tested with TestableStreamingContext.
                    fn prop_verify_diff_key_false(data: Vec<u8>) -> bool {
                        let sk = SecretKey::generate();
                        let mut state = HmacSha512::new(&sk);
                        state.update(&data[..]).unwrap();
                        let tag = state.finalize().unwrap();
                        let bad_sk = SecretKey::generate();

                        HmacSha512::verify(&tag, &bad_sk, &data[..]).is_err()
                    }
                }
            }
        }

        mod test_streaming_interface {
            use super::*;
            use crate::hazardous::hash::sha2::sha512::compare_sha512_states;
            use crate::test_framework::incremental_interface::*;

            const KEY: [u8; 32] = [0u8; 32];

            impl TestableStreamingContext<Tag> for HmacSha512 {
                fn reset(&mut self) -> Result<(), UnknownCryptoError> {
                    Ok(self.reset())
                }

                fn update(&mut self, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    self.update(input)
                }

                fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
                    self.finalize()
                }

                fn one_shot(input: &[u8]) -> Result<Tag, UnknownCryptoError> {
                    HmacSha512::hmac(&SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn verify_result(expected: &Tag, input: &[u8]) -> Result<(), UnknownCryptoError> {
                    // This will only run verification tests on differing input. They do not
                    // include tests for different secret keys.
                    HmacSha512::verify(expected, &SecretKey::from_slice(&KEY).unwrap(), input)
                }

                fn compare_states(state_1: &HmacSha512, state_2: &HmacSha512) {
                    compare_sha512_states(
                        &state_1._internal.opad_hasher,
                        &state_2._internal.opad_hasher,
                    );
                    compare_sha512_states(
                        &state_1._internal.ipad_hasher,
                        &state_2._internal.ipad_hasher,
                    );
                    compare_sha512_states(
                        &state_1._internal.working_hasher,
                        &state_2._internal.working_hasher,
                    );
                    assert_eq!(
                        state_1._internal.is_finalized,
                        state_2._internal.is_finalized
                    );
                }
            }

            #[test]
            fn default_consistency_tests() {
                let initial_state = HmacSha512::new(&SecretKey::from_slice(&KEY).unwrap());

                let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha512>::new(
                    initial_state,
                    sha512::SHA512_BLOCKSIZE,
                );
                test_runner.run_all_tests();
            }

            // Proptests. Only executed when NOT testing no_std.
            #[cfg(feature = "safe_api")]
            mod proptest {
                use super::*;

                quickcheck! {
                    /// Related bug: https://github.com/brycx/orion/issues/46
                    /// Test different streaming state usage patterns.
                    fn prop_input_to_consistency(data: Vec<u8>) -> bool {
                        let initial_state = HmacSha512::new(&SecretKey::from_slice(&KEY).unwrap());

                        let test_runner = StreamingContextConsistencyTester::<Tag, HmacSha512>::new(
                            initial_state,
                            sha512::SHA512_BLOCKSIZE,
                        );
                        test_runner.run_all_tests_property(&data);
                        true
                    }
                }
            }
        }
    }
}
