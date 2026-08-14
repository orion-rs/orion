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

//! Digital signature creation and verification.
//!
//! # Use case:
//! `orion::signer` can be used to cryptographically sign data and validate signatures over such data.
//!
//! # About:
//! - Uses ML-DSA-65 in "hedged"/randomized mode.
//! - Keys are based exclusively on a seed. To interact with semi-expanded/serialized signing keys, users will have to reach for [`orion::hazardous::dsa`].
//!
//! # Parameters:
//! - `m`: Message to be signed or verified a signature of.
//! - `ctx`: Context string which must be the same on signing and verification.
//! - `sig`: Signature to be verified.
//!
//! # Errors:
//! An error will be returned if:
//! - Verification of a signature, message and context failed.
//! - Failure to generate random bytes securely during key-generation.
//! - `ctx` is not `<= 255` bytes.
//!
//! # Example:
//! ```ignore-windows
//! use orion::signer::*;
//!
//! // Randomly generate a fresh keypair
//! let kp = SigningKeyPair::generate()?;
//!
//! // Sign a message
//! let sig = kp.sign(b"Message to be signed", b"Context")?;
//!
//! // Verify the signature of the message and accompanying context
//! assert!(kp.verify(b"Message to be signed", b"Context", &sig).is_ok());
//!
//! // Parse a signature public key and signature from bytes
//! let verifying_key = VerifyingKey::try_from(kp.public().as_ref())?;
//! let signature = Signature::try_from(sig.as_ref())?;
//!
//! // Verify the signature of the message and accompanying context
//! assert!(verifying_key.verify(b"Message to be signed", b"Context", &sig).is_ok());
//!
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`orion::signer`]: crate::signer
//! [`orion::hazardous::dsa`]: crate::hazardous::dsa

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use crate::hazardous::dsa::mldsa65::Seed;
pub use crate::hazardous::dsa::mldsa65::Signature;
pub use crate::hazardous::dsa::mldsa65::VerifyingKey;
use crate::{errors::UnknownCryptoError, hazardous::dsa::mldsa65};

#[derive(Debug, PartialEq)]
/// ML-DSA-65 seed-based signing key pair.
pub struct SigningKeyPair {
    kp: mldsa65::KeyPair,
}

impl SigningKeyPair {
    /// Randomly generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        let seed = Seed::generate()?;

        Ok(Self {
            kp: mldsa65::KeyPair::try_from(&seed)?,
        })
    }

    /// Get a reference to this [`SigningKeyPair`]'s private seed.
    pub fn private(&self) -> &Seed {
        &self.kp.seed()
    }

    /// Get a reference to this [`SigningKeyPair`]'s public verifying key.
    pub fn public(&self) -> &VerifyingKey {
        &self.kp.verifying_key
    }

    /// Sign a message, with optional context (can be empty), using ML-DSA-65 hedged/randomized signing.
    pub fn sign(&self, m: &[u8], ctx: &[u8]) -> Result<Signature, UnknownCryptoError> {
        self.kp.signing_key.sign(m, ctx)
    }

    /// Verify a signature over a message, with optional context (can be empty), using ML-DSA-65.
    /// Returns nothing on success and [`UnknownCryptoError`] if verification failed.
    pub fn verify(&self, m: &[u8], ctx: &[u8], sig: &Signature) -> Result<(), UnknownCryptoError> {
        self.kp.verifying_key.verify(m, ctx, sig)
    }
}

impl TryFrom<&Seed> for SigningKeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &Seed) -> Result<Self, Self::Error> {
        Ok(Self {
            kp: mldsa65::KeyPair::try_from(value)?,
        })
    }
}
