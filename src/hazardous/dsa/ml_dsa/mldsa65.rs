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

//! ### ML-DSA key usage recommendations
//!
//! In general, it is highly recommended to use the [`KeyPair`] type to deal with signing operations, or private/signing keys in general.
//!
//! A [`KeyPair`] requires, or automatically generates, a [`Seed`]. It cannot be made solely from encoded/serialized signing key in bytes, unless a [`Seed`] is also provided.
//! A seed is only 32 bytes, is fully FIPS compliant.
//!
//! A set of keys expanded from a [`Seed`] are guaranteed to be valid, part expanded (aka. serialized) keys are not.
//!
//! #### Serialized signing keys
//! It is possible to instantiate a [`SigningKey`] directly, if strictly required, using [`SigningKey::try_from()`]. This use hereof is intended solely for
//! interoperability purposes. The lack of generate function for [`SigningKey`] is intentional.
//!
//! # Parameters:
//! - `m`: Message to be signed or verified a signature of.
//! - `ctx`: Context string which must be the same on signing and verification.
//! - `rnd`: [`ExplicitRandom`] provided during signing.
//! - `ph`: [`PreHash`] variant used during HashML-DSA.
//! - `mu`: ML-DSA `mu` parameter.
//! - `sig`: Signature to be verified.
//!
//! # Errors:
//! An error will be returned if:
//! - Verification of a signature, message and context failed.
//! - [`getrandom::fill()`] fails during signing.
//! - [`getrandom::fill()`] fails during [`KeyPair::generate()`].
//! - `mu` is not `64` bytes.
//! - `ctx` is not `<= 255` bytes.
//!
//! # Security:
//! - Using the randomized, non-deterministic signing hardens the ML-DSA signing routine against fault-injection attacks.
//! - It is critical that both the seed and explicit randomness `rnd`, used for key generation and signing
//! are generated using a strong CSPRNG.
//! - Users should always prefer the hedged/randomized if in doubt.
//! - While possible to use a single [`KeyPair`] for both HashML-DSA and ML-DSA, it is strongly recommended to utilize
//! two independent keypairs for these two variants.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::KP;
//! use orion::hazardous::dsa::mldsa65::*;
//!
//! let kp = KeyPair::generate()?;
//!
//! let pk = VerifyingKey::try_from(kp.public().as_ref())?;
//! let signature = kp.private().sign(b"Message to sign", b"additional context")?;
//!
//! assert!(pk.verify(b"Message to sign", b"additional context", &signature).is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`getrandom::fill()`]: getrandom::fill
//! [`KeyPair::generate()`]: mldsa65::KeyPair::generate
//! [`KeyPair`]: mldsa65::KeyPair
//! [`SigningKey`]: mldsa65::SigningKey
//! [`SigningKey::try_from()`]: mldsa65::SigningKey::try_from
//! [`Seed`]: mldsa65::Seed
//! [`ExplicitRandom`]: mldsa65::ExplicitRandom
//! [`PreHash`]: mldsa65::PreHash

use crate::KP;
use crate::errors::UnknownCryptoError;
use crate::generics::sealed::Sealed;
use crate::generics::{Public, Secret, TypeSpec};
use crate::hazardous::dsa::ml_dsa::internal::{
    InternalSignature, InternalSigningKey, InternalVerifyingKey, KeyPairInternal, MlDsa65,
    MlDsaParameters,
};

pub use crate::hazardous::dsa::ml_dsa::ExplicitRandom;
pub use crate::hazardous::dsa::ml_dsa::MlDsaExplicitRandom;
pub use crate::hazardous::dsa::ml_dsa::MlDsaSeed;
pub use crate::hazardous::dsa::ml_dsa::RAND_SIZE;
pub use crate::hazardous::dsa::ml_dsa::SEED_SIZE;
pub use crate::hazardous::dsa::ml_dsa::Seed;
pub use crate::hazardous::dsa::ml_dsa::internal::prehash::PreHash;

/// Size of private [`SigningKey`].
pub const SIGNING_KEY_SIZE: usize = MlDsa65::PRIVATE_KEY_SIZE;

/// Size of public [`VerifyingKey`].
pub const VERIFYING_KEY_SIZE: usize = MlDsa65::PUBLIC_KEY_SIZE;

/// Size of public [`Signature`].
pub const SIGNATURE_SIZE: usize = MlDsa65::SIGNATURE_SIZE;

/// ML-DSA-65 signature.
pub type Signature = Public<MlDsa65Signature>;

/// ML-DSA-65 signing key.
pub type SigningKey = Secret<MlDsa65SigningKey>;

/// ML-DSA-65 verifying key.
pub type VerifyingKey = Public<MlDsa65VerifyingKey>;

#[derive(Debug)]
/// ML-DSA-65 signing key implementation. See [`SigningKey`] type for convenience.
pub struct MlDsa65SigningKey {}
impl Sealed for MlDsa65SigningKey {}

impl TypeSpec for MlDsa65SigningKey {
    const NAME: &'static str = stringify!(SigningKey);
    // Key-check logic in Data-impl under [`InternalSigningKey`] (applies to `parse_bytes()`).
    type TypeData = InternalSigningKey<
        { MlDsa65::PRIVATE_KEY_SIZE },
        { MlDsa65::SIGNATURE_SIZE },
        { MlDsa65::CLEN },
        { MlDsa65::COMMITMENT_HASH_LEN },
        { MlDsa65::W1_BITPACK_SIZE * MlDsa65::DIM_K },
        { MlDsa65::DIM_K },
        { MlDsa65::DIM_L },
        MlDsa65,
    >;
}

#[derive(Debug)]
/// ML-DSA-65 verifying key implementation. See [`VerifyingKey`] type for convenience.
pub struct MlDsa65VerifyingKey {}
impl Sealed for MlDsa65VerifyingKey {}
impl TypeSpec for MlDsa65VerifyingKey {
    const NAME: &'static str = stringify!(VerifyingKey);
    // Key-check logic in Data-impl under [`InternalVerifyingKey`] (applies to `parse_bytes()`).
    type TypeData = InternalVerifyingKey<
        { MlDsa65::PUBLIC_KEY_SIZE },
        { MlDsa65::SIGNATURE_SIZE },
        { MlDsa65::CLEN },
        { MlDsa65::COMMITMENT_HASH_LEN },
        { MlDsa65::W1_BITPACK_SIZE * MlDsa65::DIM_K },
        { MlDsa65::DIM_K },
        { MlDsa65::DIM_L },
        MlDsa65,
    >;

    /// SECURITY: Override to vartime-[`PartialEq`] on a non-secret type, with a var-time one
    /// to selectively only compare the encoded representation of public key.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded public key, so make sure the other fields
        // aren't modifiable after instantiation, otherwise the encoded bytes might not correspond
        // to the RingElements/Polynomials.
        lhs.pk.as_ref() == rhs
    }
}

#[derive(Debug, Clone, Copy)]
/// ML-DSA-65 signature implementation. See [`Signature`] type for convenience.
pub struct MlDsa65Signature {}
impl Sealed for MlDsa65Signature {}

impl TypeSpec for MlDsa65Signature {
    const NAME: &'static str = stringify!(Signature);
    // Key-check logic in Data-impl under [`InternalSignature`] (applies to `parse_bytes()`).
    type TypeData = InternalSignature<
        { MlDsa65::SIGNATURE_SIZE },
        { MlDsa65::COMMITMENT_HASH_LEN },
        { MlDsa65::DIM_K },
        { MlDsa65::DIM_L },
        MlDsa65,
    >;

    /// SECURITY: Override to vartime-[`PartialEq`] on a non-secret type, with a var-time one
    /// to selectively only compare the encoded representation of signature.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded signature, so make sure the other fields
        // aren't modifiable after instantiation, otherwise the encoded bytes might not correspond
        // to the RingElements/Polynomials.
        lhs.sig.as_ref() == rhs
    }
}

impl SigningKey {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [`SigningKey`], sign a message `m` and context.
    pub fn sign(&self, m: &[u8], ctx: &[u8]) -> Result<Signature, UnknownCryptoError> {
        let rnd = ExplicitRandom::generate()?;

        self.sign_with_rnd(m, ctx, &rnd)
    }

    /// Given the [`SigningKey`], sign a message `m` and context.
    pub fn sign_deterministic(
        &self,
        m: &[u8],
        ctx: &[u8],
    ) -> Result<Signature, UnknownCryptoError> {
        self.sign_with_rnd(m, ctx, &ExplicitRandom::deterministic())
    }

    /// Given the [`SigningKey`], sign a message `m` and context, given specifically supplied `rnd`.
    pub fn sign_with_rnd(
        &self,
        m: &[u8],
        ctx: &[u8],
        rnd: &ExplicitRandom,
    ) -> Result<Signature, UnknownCryptoError> {
        Ok(Signature::from_data(self.data.sign(
            m,
            ctx,
            rnd.unprotected_as_ref(),
        )?))
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [`SigningKey`] and [`PreHash`], sign a message `m` and context.
    pub fn sign_prehash(
        &self,
        m: &[u8],
        ctx: &[u8],
        ph: &PreHash,
    ) -> Result<Signature, UnknownCryptoError> {
        let rnd = ExplicitRandom::generate()?;

        self.sign_prehash_with_rnd(m, ctx, ph, &rnd)
    }

    /// Given the [`SigningKey`] and [`PreHash`], sign a message `m` and context.
    pub fn sign_prehash_deterministic(
        &self,
        m: &[u8],
        ctx: &[u8],
        ph: &PreHash,
    ) -> Result<Signature, UnknownCryptoError> {
        self.sign_prehash_with_rnd(m, ctx, ph, &ExplicitRandom::deterministic())
    }

    /// Given the [`SigningKey`] and [`PreHash`], sign a message `m` and context.
    pub fn sign_prehash_with_rnd(
        &self,
        m: &[u8],
        ctx: &[u8],
        ph: &PreHash,
        rnd: &ExplicitRandom,
    ) -> Result<Signature, UnknownCryptoError> {
        Ok(Signature::from_data(self.data.sign_prehash(
            m,
            ctx,
            rnd.unprotected_as_ref(),
            ph,
        )?))
    }

    /// Given the [`SigningKey`], sign `mu`.
    ///
    /// Where `mu`: `H(BytesToBits(tr)||M ′, 64)`, FIPS-204, Algorithm 7.
    pub fn sign_external_mu_with_rnd(
        &self,
        mu: &[u8],
        rnd: &ExplicitRandom,
    ) -> Result<Signature, UnknownCryptoError> {
        if mu.len() != 64 {
            return Err(UnknownCryptoError);
        }

        Ok(Signature::from_data(
            self.data
                .sign_internal_with_mu(mu, rnd.unprotected_as_ref())?,
        ))
    }
}

impl VerifyingKey {
    /// Given the [`VerifyingKey`], verify a signature `sig` produced over message `m` and context.
    pub fn verify(&self, m: &[u8], ctx: &[u8], sig: &Signature) -> Result<(), UnknownCryptoError> {
        self.data.verify(m, &sig.data, ctx)
    }

    /// Given the [`VerifyingKey`] and [`PreHash`], verify a signature `sig` produced over message `m` and context.
    pub fn verify_prehash(
        &self,
        m: &[u8],
        ctx: &[u8],
        sig: &Signature,
        ph: &PreHash,
    ) -> Result<(), UnknownCryptoError> {
        self.data.verify_prehash(m, &sig.data, ctx, ph)
    }

    /// Given the [`VerifyingKey`], verify signature over `mu`.
    ///
    /// Where `mu`: `H(BytesToBits(tr)||M ′, 64)`, FIPS-204, Algorithm 7.
    pub fn verify_external_mu(&self, mu: &[u8], sig: &Signature) -> Result<(), UnknownCryptoError> {
        if mu.len() != 64 {
            return Err(UnknownCryptoError);
        }

        self.data.verify_internal_with_mu(mu, &sig.data)
    }
}

#[derive(Debug, PartialEq)]
/// ML-DSA-65 keypair.
pub struct KeyPair {
    seed: Seed,
    pub(crate) signing_key: SigningKey,
    pub(crate) verifying_key: VerifyingKey,
}

impl KP<MlDsa65SigningKey, MlDsa65VerifyingKey> for KeyPair {
    fn private(&self) -> &SigningKey {
        &self.signing_key
    }

    fn public(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl TryFrom<&Seed> for KeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &Seed) -> Result<Self, Self::Error> {
        let kp = KeyPairInternal::<
            { MlDsa65::PRIVATE_KEY_SIZE },
            { MlDsa65::PUBLIC_KEY_SIZE },
            { MlDsa65::SIGNATURE_SIZE },
            { MlDsa65::CLEN },
            { MlDsa65::COMMITMENT_HASH_LEN },
            { MlDsa65::W1_BITPACK_SIZE * MlDsa65::DIM_K },
            { MlDsa65::DIM_K },
            { MlDsa65::DIM_L },
            MlDsa65,
        >::keygen_internal(value.unprotected_as_ref())?;

        Ok(Self {
            seed: Seed::from_data(value.data.clone()),
            signing_key: Secret::<MlDsa65SigningKey>::from_data(kp.sk),
            verifying_key: Public::<MlDsa65VerifyingKey>::from_data(kp.pk),
        })
    }
}

impl KeyPair {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Generate a fresh [`KeyPair`].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        let seed = Seed::generate()?;
        Self::new(seed)
    }

    /// Reference to the private [`Seed`].
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// Create a new instance from a private [`Seed`].
    pub fn new(seed: Seed) -> Result<Self, UnknownCryptoError> {
        Self::try_from(&seed)
    }
}

#[cfg(test)]
mod tests {
    use crate::hazardous::hash::sha3::shake128::Shake128;

    use super::*;

    // TODO: Add https://github.com/C2SP/CCTV/blob/main/ML-DSA/accumulated/README.md#field-operation-tests

    #[test]
    fn c2sp_cctv_accumulated_mldsa65() {
        // src: https://github.com/C2SP/CCTV/commit/2ad7bcfdbf32721f43e10ccac78c3ecac1c9dfb5

        let mut s = Shake128::new();
        let mut a = Shake128::new();

        let expected_100 =
            hex::decode("8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199")
                .unwrap();
        let expected_10000 =
            hex::decode("5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329")
                .unwrap();
        // let expected_60000000 =
        //     hex::decode("0af0165db2b180f7a83dbecad1ccb758b9c2d834b7f801fc49dd572a9d4b1e83")
        //         .unwrap();

        // 60000000 takes very long..
        // just run once before release of v0.18.0
        let max = 10000;

        let mut seed = [0u8; 32];
        let mut result_100 = [0u8; 32];
        let mut result_10000 = [0u8; 32];
        let mut result_60000000 = [0u8; 32];

        for n in 1..=max {
            s.squeeze(&mut seed).unwrap();
            let kp = KeyPair::new(Seed::from(seed)).unwrap();
            a.absorb(kp.public().as_ref()).unwrap();
            let sig = kp.private().sign_deterministic(b"", b"").unwrap();
            a.absorb(sig.as_ref()).unwrap();
            assert!(kp.public().verify(b"", b"", &sig).is_ok());

            match n {
                100 => {
                    let mut a_ret = a.clone();
                    a_ret.squeeze(&mut result_100).unwrap();
                }
                10000 => {
                    let mut a_ret = a.clone();
                    a_ret.squeeze(&mut result_10000).unwrap();
                }
                60000000 => {
                    let mut a_ret = a.clone();
                    a_ret.squeeze(&mut result_60000000).unwrap();
                }
                _ => continue,
            }
        }

        assert_eq!(expected_100, result_100);
        assert_eq!(expected_10000, result_10000);
        // assert_eq!(expected_60000000, result_60000000);
    }
}
