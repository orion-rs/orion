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

/// A trait used to define a cryptographic hash function used by HMAC.
pub(crate) trait HmacHashFunction: Clone {
    /// The blocksize of the hash function.
    const _BLOCKSIZE: usize;

    /// The output size of the hash function.
    const _OUTSIZE: usize;

    /// Create a new instance of the hash function.
    fn _new() -> Self;

    /// Update the internal state with `data`.
    fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    /// Finalize the hash and put the final digest into `dest`.
    fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError>;

    /// Compute a digest of `data` and copy it into `dest`.
    fn _digest(data: &[u8], dest: &mut [u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(test)]
    /// Compare two Sha2 state objects to check if their fields
    /// are the same.
    fn compare_state_to_other(&self, other: &Self);
}

/// A trait used to define a HMAC function.
pub(crate) trait HmacFunction {
    // NOTE: Clippy complaints this is not used, however it is used in both HKDF and PBKDF2. Perhaps a bug
    // with min_const_generics?
    #[allow(dead_code)]
    /// The output size of the internal hash function used.
    const HASH_FUNC_OUTSIZE: usize;

    /// Create a new instance of the HMAC function, using a `secret_key` that may or may not be padded.
    fn _new(secret_key: &[u8]) -> Self;

    /// Update the internal state with `data`.
    fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    /// Finalize the MAC and put the final tag into `dest`.
    ///
    /// NOTE: `dest` may be less than the complete output size of the hash function
    /// (Self::HASH_FUNC_OUTSIZE). If that is the case, `dest.len()` bytes will be copied,
    /// but `dest` should NEVER be empty.
    fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError>;

    /// Reset the state.
    fn _reset(&mut self);
}

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

#[derive(Clone)]
pub(crate) struct Hmac<S: HmacHashFunction, const BLOCKSIZE: usize> {
    working_hasher: S,
    opad_hasher: S,
    ipad_hasher: S,
    is_finalized: bool,
}

impl<S: HmacHashFunction, const BLOCKSIZE: usize> core::fmt::Debug for Hmac<S, BLOCKSIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Hmac {{ working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: {:?} }}",
            self.is_finalized
        )
    }
}

impl<S: HmacHashFunction, const BLOCKSIZE: usize> Hmac<S, BLOCKSIZE> {
    // NOTE: Clippy complaints this is not used, however it is used in both HKDF and PBKDF2. Perhaps a bug
    // with min_const_generics?
    #[allow(dead_code)]
    const HASH_FUNC_OUTSIZE: usize = S::_OUTSIZE;

    /// Construct a state from a `secret_key`. The `secret_key` may be pre-padded or not.
    ///
    /// Ref: https://brycx.github.io/2018/08/06/hmac-and-precomputation-optimization.html
    fn _new(secret_key: &[u8]) -> Result<Self, UnknownCryptoError> {
        debug_assert!(S::_BLOCKSIZE == BLOCKSIZE);
        let mut ipad = [IPAD; BLOCKSIZE];

        if secret_key.len() > BLOCKSIZE {
            // SK is NOT pre-padded.
            debug_assert!(BLOCKSIZE > S::_OUTSIZE);
            S::_digest(secret_key, &mut ipad[..S::_OUTSIZE])?;
            for elem in ipad.iter_mut().take(S::_OUTSIZE) {
                *elem ^= IPAD;
            }
        } else {
            // SK has been pre-padded or SK.len() <= BLOCKSIZE.
            // Because 0x00 xor IPAD = IPAD, the existence of padding bytes (0x00)
            // within SK, during this operation, is inconsequential.
            xor_slices!(secret_key, &mut ipad);
        }

        let mut ih = S::_new();
        ih._update(&ipad)?;

        // Transform ipad into OPAD xor SK
        for elem in ipad.iter_mut() {
            *elem ^= IPAD ^ OPAD;
        }

        let mut oh = S::_new();
        oh._update(&ipad)?;

        ipad.iter_mut().zeroize();

        Ok(Self {
            working_hasher: ih.clone(),
            opad_hasher: oh,
            ipad_hasher: ih,
            is_finalized: false,
        })
    }

    fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            Err(UnknownCryptoError)
        } else {
            self.working_hasher._update(data)
        }
    }

    fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;
        let mut outer_hasher = self.opad_hasher.clone();
        self.working_hasher._finalize(dest)?;
        outer_hasher._update(&dest)?;
        outer_hasher._finalize(dest)
    }

    fn _reset(&mut self) {
        self.working_hasher = self.ipad_hasher.clone();
        self.is_finalized = false;
    }

    #[cfg(test)]
    /// Compare two Hmac state objects to check if their fields
    /// are the same.
    pub(crate) fn compare_state_to_other(&self, other: &Self) {
        self.working_hasher
            .compare_state_to_other(&other.working_hasher);
        self.opad_hasher.compare_state_to_other(&other.opad_hasher);
        self.ipad_hasher.compare_state_to_other(&other.ipad_hasher);
        assert_eq!(self.is_finalized, other.is_finalized);
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

    use super::Hmac;

    #[derive(Clone, Debug)]
    /// HMAC-SHA256 streaming state.
    pub struct HmacSha256 {
        _state: Hmac<Sha256, { sha256::SHA256_BLOCKSIZE }>,
    }

    impl HmacSha256 {
        fn _new(secret_key: &[u8]) -> Self {
            // TODO: Write why unwrap() here is fine.
            Self {
                _state: Hmac::<Sha256, { sha256::SHA256_BLOCKSIZE }>::_new(secret_key).unwrap(),
            }
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self::_new(secret_key.unprotected_as_bytes())
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._state._reset()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Return a HMAC-SHA256 tag.
        pub(crate) fn _finalize_internal(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA256 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            let mut dest = [0u8; sha256::SHA256_OUTSIZE];
            self._finalize_internal(&mut dest)?;

            Ok(Tag::from(dest))
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA256 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut ctx = Self::new(secret_key);
            ctx.update(data)?;
            ctx.finalize()
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

    impl HmacFunction for HmacSha256 {
        /// The output size of the internal hash function used.
        const HASH_FUNC_OUTSIZE: usize = sha256::SHA256_OUTSIZE;

        /// Create a new instance of the HMAC function, using a `secret_key` that may or may not be padded.
        fn _new(secret_key: &[u8]) -> Self {
            Self::_new(secret_key)
        }

        /// Update the internal state with `data`.
        fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Finalize the MAC and put the final tag into `dest`.
        ///
        /// NOTE: `dest` may be less than the complete output size of the hash function
        /// (Self::HASH_FUNC_OUTSIZE). If that is the case, `dest.len()` bytes will be copied,
        /// but `dest` should NEVER be empty.
        fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        /// Reset the state.
        fn _reset(&mut self) {
            self._state._reset()
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
            let expected = "HmacSha256 { _state: Hmac { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false } }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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

        mod test_streaming_interface {
            use super::*;
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
                    state_1._state.compare_state_to_other(&state_2._state);
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

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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

    use super::Hmac;

    #[derive(Clone, Debug)]
    /// HMAC-SHA384 streaming state.
    pub struct HmacSha384 {
        _state: Hmac<Sha384, { sha384::SHA384_BLOCKSIZE }>,
    }

    impl HmacSha384 {
        fn _new(secret_key: &[u8]) -> Self {
            // TODO: Write why unwrap() here is fine.
            Self {
                _state: Hmac::<Sha384, { sha384::SHA384_BLOCKSIZE }>::_new(secret_key).unwrap(),
            }
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self::_new(secret_key.unprotected_as_bytes())
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._state._reset()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Return a HMAC-SHA384 tag.
        pub(crate) fn _finalize_internal(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA384 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            let mut dest = [0u8; sha384::SHA384_OUTSIZE];
            self._finalize_internal(&mut dest)?;

            Ok(Tag::from(dest))
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA384 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut ctx = Self::new(secret_key);
            ctx.update(data)?;
            ctx.finalize()
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

    impl HmacFunction for HmacSha384 {
        /// The output size of the internal hash function used.
        const HASH_FUNC_OUTSIZE: usize = sha384::SHA384_OUTSIZE;

        /// Create a new instance of the HMAC function, using a `secret_key` that may or may not be padded.
        fn _new(secret_key: &[u8]) -> Self {
            Self::_new(secret_key)
        }

        /// Update the internal state with `data`.
        fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Finalize the MAC and put the final tag into `dest`.
        ///
        /// NOTE: `dest` may be less than the complete output size of the hash function
        /// (Self::HASH_FUNC_OUTSIZE). If that is the case, `dest.len()` bytes will be copied,
        /// but `dest` should NEVER be empty.
        fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        /// Reset the state.
        fn _reset(&mut self) {
            self._state._reset()
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
            let expected = "HmacSha384 { _state: Hmac { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false } }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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

        mod test_streaming_interface {
            use super::*;
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
                    state_1._state.compare_state_to_other(&state_2._state);
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

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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

    use super::Hmac;

    #[derive(Clone, Debug)]
    /// HMAC-SHA512 streaming state.
    pub struct HmacSha512 {
        _state: Hmac<Sha512, { sha512::SHA512_BLOCKSIZE }>,
    }

    impl HmacSha512 {
        fn _new(secret_key: &[u8]) -> Self {
            // TODO: Write why unwrap() here is fine.
            Self {
                _state: Hmac::<Sha512, { sha512::SHA512_BLOCKSIZE }>::_new(secret_key).unwrap(),
            }
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Initialize `Hmac` struct with a given key.
        pub fn new(secret_key: &SecretKey) -> Self {
            Self::_new(secret_key.unprotected_as_bytes())
        }

        /// Reset to `new()` state.
        pub fn reset(&mut self) {
            self._state._reset()
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Update state with `data`. This can be called multiple times.
        pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Return a HMAC-SHA512 tag.
        pub(crate) fn _finalize_internal(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// Return a HMAC-SHA512 tag.
        pub fn finalize(&mut self) -> Result<Tag, UnknownCryptoError> {
            let mut dest = [0u8; sha512::SHA512_OUTSIZE];
            self._finalize_internal(&mut dest)?;

            Ok(Tag::from(dest))
        }

        #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
        /// One-shot function for generating an HMAC-SHA512 tag of `data`.
        pub fn hmac(secret_key: &SecretKey, data: &[u8]) -> Result<Tag, UnknownCryptoError> {
            let mut ctx = Self::new(secret_key);
            ctx.update(data)?;
            ctx.finalize()
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

    impl HmacFunction for HmacSha512 {
        /// The output size of the internal hash function used.
        const HASH_FUNC_OUTSIZE: usize = sha512::SHA512_OUTSIZE;

        /// Create a new instance of the HMAC function, using a `secret_key` that may or may not be padded.
        fn _new(secret_key: &[u8]) -> Self {
            Self::_new(secret_key)
        }

        /// Update the internal state with `data`.
        fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self._state._update(data)
        }

        /// Finalize the MAC and put the final tag into `dest`.
        ///
        /// NOTE: `dest` may be less than the complete output size of the hash function
        /// (Self::HASH_FUNC_OUTSIZE). If that is the case, `dest.len()` bytes will be copied,
        /// but `dest` should NEVER be empty.
        fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self._state._finalize(dest)
        }

        /// Reset the state.
        fn _reset(&mut self) {
            self._state._reset()
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
            let expected = "HmacSha512 { _state: Hmac { working_hasher: [***OMITTED***], opad_hasher: [***OMITTED***], ipad_hasher: [***OMITTED***], is_finalized: false } }";
            assert_eq!(debug, expected);
        }

        #[cfg(feature = "safe_api")]
        mod test_verify {
            use super::*;

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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

        mod test_streaming_interface {
            use super::*;
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
                    state_1._state.compare_state_to_other(&state_2._state);
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

            #[quickcheck]
            #[cfg(feature = "safe_api")]
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
