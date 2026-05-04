// MIT License

// Copyright (c) 2018-2026 The orion Developers

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
//! - `sk`: The secret key.
//! - `n`: The nonce value.
//! - `blockctr`: The position within the keystream.
//! - `bytes`: Bytes to apply the keystream to.
//!
//! # Errors:
//! An error will be returned if:
//! - The [`XChaCha20::next_producible()`] returns err.
//! - If a keystream block (64 bytes) has been generated with [`XChaCha20::position()`] [`u32::MAX`],
//!   and [`XChaCha20::xor_keystream_into()`] is called subsequently. Generating the last keystream block
//!   moves [`XChaCha20`] into an exhausted state, which is non-resettable. In this case, the key/nonce pair
//!   has generated all possible keystream bytes and is thus not safe to use further.
//!   This can be checked with [`XChaCha20::is_exhausted()`].
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen, the security of all data that has been encrypted
//!   with that given key is compromised.
//! - Functions herein do not provide any data integrity. If you need
//!   data integrity, which is nearly ***always the case***, you should use an
//!   AEAD construction instead. See the [`aead`](super::aead) module for this.
//! - Only a nonce for XChaCha20 is big enough to be randomly generated using a
//!   CSPRNG. [`Nonce::generate()`] can be used for this.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [`XChaCha20Poly1305`] when possible.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::stream::xchacha20::{SecretKey, Nonce, XChaCha20};
//!
//! let sk = SecretKey::generate()?;
//! let n = Nonce::generate()?;
//! let mut ctx = XChaCha20::new(&sk, &n);
//!
//! // Encrypting a message:
//! let mut message: [u8; 15] = *b"Data to protect";
//! ctx.xor_keystream_into(&mut message)?;
//! // Decrypt (re-apply keystream):
//! ctx.set_position(0); // reset to beginning
//! ctx.xor_keystream_into(&mut message)?;
//!
//! assert_eq!("Data to protect".as_bytes(), message);
//!
//! // Seeking ahead in keystream. This example generates the 256th keystream block (64 bytes):
//! ctx.set_position(256);
//! let mut keystream_block = [0u8; 64];
//! ctx.xor_keystream_into(&mut keystream_block)?;
//!
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: xchacha20::SecretKey::generate()
//! [`Nonce::generate()`]: xchacha20::Nonce::generate()
//! [`XChaCha20Poly1305`]: super::aead::xchacha20poly1305
//! [`XChaCha20`]: xchacha20::XChaCha20
//! [`XChaCha20::xor_keystream_into()`]: xchacha20::XChaCha20::xor_keystream_into()
//! [`XChaCha20::position()`]: xchacha20::XChaCha20::position()
//! [`XChaCha20::is_exhausted()`]: xchacha20::XChaCha20::is_exhausted()
//! [`XChaCha20::next_producible()`]: xchacha20::XChaCha20::next_producible()

#[cfg(feature = "safe_api")]
use crate::generics::sealed::Data;
pub use crate::hazardous::stream::chacha20::CHACHA_BLOCKSIZE;
pub use crate::hazardous::stream::chacha20::SecretKey;
use crate::{
    errors::UnknownCryptoError,
    generics::{ByteArrayData, Public, TypeSpec, sealed::Sealed},
    hazardous::stream::chacha20::{IETF_CHACHA_NONCESIZE, Nonce as IETFNonce},
};
use crate::{
    generics::GeneratePublic,
    hazardous::stream::chacha20::{ChaCha20, HCHACHA_NONCESIZE},
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// The nonce size for XChaCha20.
pub const XCHACHA_NONCESIZE: usize = 24;

#[derive(Debug, Clone, Copy)]
/// Marker type for ChaCha20 nonce. See [`Nonce`] type for convenience.
pub struct XChaCha20Nonce {}
impl Sealed for XChaCha20Nonce {}

impl TypeSpec for XChaCha20Nonce {
    const NAME: &'static str = stringify!(Nonce);
    type TypeData = ByteArrayData<XCHACHA_NONCESIZE>;
}

impl From<[u8; XCHACHA_NONCESIZE]> for Public<XChaCha20Nonce> {
    fn from(value: [u8; XCHACHA_NONCESIZE]) -> Self {
        Self::from_data(<XChaCha20Nonce as TypeSpec>::TypeData::from(value))
    }
}

impl GeneratePublic for XChaCha20Nonce {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Public<XChaCha20Nonce>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(XCHACHA_NONCESIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Public::from_data(data))
    }
}

/// A type that represents a [`Nonce`] that XChaCha20 and XChaCha20-Poly1305 use.
pub type Nonce = Public<XChaCha20Nonce>;

#[derive(Clone, Debug)]
/// XChaCha20 as specified in the [draft RFC](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03).
pub struct XChaCha20 {
    chacha20: ChaCha20,
}

impl Drop for XChaCha20 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.chacha20.zeroize();
    }
}

impl XChaCha20 {
    /// Generate a subkey using HChaCha20 for XChaCha20 and corresponding nonce.
    pub(crate) fn subkey_and_ietf_nonce(sk: &SecretKey, n: &Nonce) -> (SecretKey, IETFNonce) {
        let mut hchacha_nonce = [0u8; HCHACHA_NONCESIZE];
        hchacha_nonce.copy_from_slice(&n.data.bytes[..16]);

        let subkey = SecretKey::from(ChaCha20::hchacha(sk, &hchacha_nonce));
        let mut prefixed_nonce = [0u8; IETF_CHACHA_NONCESIZE];
        prefixed_nonce[4..IETF_CHACHA_NONCESIZE].copy_from_slice(&n.data.bytes[16..24]);

        (subkey, IETFNonce::from(prefixed_nonce))
    }

    /// Create a new [`XChaCha20`] instance.
    pub fn new(sk: &SecretKey, n: &Nonce) -> Self {
        let (subkey, ietf_nonce) = Self::subkey_and_ietf_nonce(sk, n);

        Self {
            chacha20: ChaCha20::new(&subkey, &ietf_nonce),
        }
    }

    /// Return `true` if the last keystream block has been generated.
    pub fn is_exhausted(&self) -> bool {
        self.chacha20.is_exhausted()
    }

    /// Check that we can produce one more keystream block, given the current state.
    ///
    /// Return error if advancing the internal state position by one would overflow [`u32::MAX`],
    /// or the keystream has been exhausted (see [`Self::is_exhausted`]).
    pub fn next_producible(&self) -> Result<(), UnknownCryptoError> {
        self.chacha20.next_producible()
    }

    /// Given the current [`Self::position`], determine how many keystream
    /// bytes can be generated from here on out.
    pub fn keystream_remaining(&self) -> u64 {
        self.chacha20.keystream_remaining()
    }

    /// Set the position/counter of the [`XChaCha20`] state.
    /// This is equivalent to seeking ahead in the keystream output generated,
    /// for a given pair of [`SecretKey`] and [`Nonce`].
    pub fn set_position(&mut self, blockctr: u32) {
        self.chacha20.set_position(blockctr);
    }

    /// Return the current position within the keystream.
    pub fn position(&self) -> u32 {
        self.chacha20.position()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Produce keystream blocks, based on the [`XChaCha20::position()`], and XOR into `bytes`.
    ///
    /// # NOTE:
    /// When explicitly generating keystream blocks, e.g. with a combination of [`XChaCha20::set_position()`],
    /// and this one, no leftover handling is performed. If `bytes` is less than [`CHACHA_BLOCKSIZE`] or not
    /// a multiple thereof, the leftover bytes are not saved. This function will always generate a keystream block
    /// based on the current position and if `bytes` cannot hold all [`CHACHA_BLOCKSIZE`] bytes, then they are "forgotten".
    ///
    ///
    /// # SECURITY:
    /// If this returns [`UnknownCryptoError`], then not all `bytes` have been processed.
    /// Take care to zero out the bytes if this contains sensitive information.
    pub fn xor_keystream_into(&mut self, bytes: &mut [u8]) -> Result<(), UnknownCryptoError> {
        self.chacha20.xor_keystream_into(bytes)
    }
}

// Testing public functions in the module.
#[cfg(test)]
#[cfg(feature = "safe_api")]
mod public {
    use crate::{
        hazardous::stream::chacha20::{CHACHA_BLOCKSIZE, CHACHA_KEYSIZE},
        test_framework::streamcipher_interface::{StreamcipherTester, TestableStreamCipher},
    };

    use super::*;

    const ZERO_KEY: [u8; CHACHA_KEYSIZE] = [0u8; CHACHA_KEYSIZE];
    const ZERO_XNONCE: [u8; XCHACHA_NONCESIZE] = [0u8; XCHACHA_NONCESIZE];

    #[test]
    fn test_keystream_remaining() {
        let sk = SecretKey::from(ZERO_KEY);
        let nonce = Nonce::from(ZERO_XNONCE);
        let mut ctx = XChaCha20::new(&sk, &nonce);

        ctx.set_position(0);
        assert_eq!(ctx.position(), 0);
        assert_eq!(
            ctx.keystream_remaining(),
            (CHACHA_BLOCKSIZE as u64) * 2u64.pow(32)
        );

        ctx.set_position(1);
        assert_eq!(ctx.position(), 1);
        assert_eq!(
            ctx.keystream_remaining(),
            crate::hazardous::aead::chacha20poly1305::P_MAX
        );

        ctx.set_position(u32::MAX);
        assert_eq!(ctx.position(), u32::MAX);
        assert_eq!(ctx.keystream_remaining(), 64);
    }

    #[test]
    fn test_xchacha20_nonce() {
        use super::*;
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_with_generate::<
            XCHACHA_NONCESIZE,
            XCHACHA_NONCESIZE,
            XCHACHA_NONCESIZE,
            XChaCha20Nonce,
        >();

        #[cfg(feature = "serde")]
        PublicNewtype::test_serialization::<XCHACHA_NONCESIZE, XChaCha20Nonce>();
    }

    impl TestableStreamCipher for XChaCha20 {
        fn _new(sk: &[u8], n: &[u8]) -> Self {
            Self::new(
                &SecretKey::try_from(sk).unwrap(),
                &Nonce::try_from(n).unwrap(),
            )
        }

        #[cfg(test)]
        #[cfg(feature = "safe_api")]
        fn _random() -> Self {
            use rand::RngExt;
            let mut rng = rand::rng();
            let rand_sk: bool = rng.random();

            let (sk, n) = if rand_sk {
                (SecretKey::generate().unwrap(), Nonce::from(ZERO_XNONCE))
            } else {
                (SecretKey::from(ZERO_KEY), Nonce::generate().unwrap())
            };

            Self::_new(sk.unprotected_as_ref(), n.as_ref())
        }

        fn _next_producible(&self) -> Result<(), UnknownCryptoError> {
            self.next_producible()
        }

        fn _keystream_remaining(&self) -> u64 {
            self.keystream_remaining()
        }

        fn _set_position(&mut self, blockctr: u32) {
            self.set_position(blockctr);
        }

        fn _position(&self) -> u32 {
            self.position()
        }

        fn _xor_keystream_into(&mut self, bytes: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self.xor_keystream_into(bytes)
        }

        fn _is_exhausted(&self) -> bool {
            self.is_exhausted()
        }
    }

    #[test]
    fn test_streamcipher() {
        StreamcipherTester::<XChaCha20>::run_tests::<CHACHA_BLOCKSIZE, { u32::MAX }>(
            &ZERO_KEY,
            &ZERO_XNONCE,
            None,
            None,
        );
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    fn prop_streamcipher_interface(input: Vec<u8>) -> bool {
        let sk = SecretKey::generate().unwrap();
        let n = Nonce::from(ZERO_XNONCE);
        StreamcipherTester::<XChaCha20>::run_tests::<CHACHA_BLOCKSIZE, { u32::MAX }>(
            sk.unprotected_as_ref(),
            n.as_ref(),
            Some(&input),
            None,
        );

        true
    }
}
