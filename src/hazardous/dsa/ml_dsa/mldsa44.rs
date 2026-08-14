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
//! - It is critical that both the seed and explicit randomness `rnd`, used for key generation and encapsulation
//! are generated using a strong CSPRNG.
//! - Users should always prefer the hedged/randomized if in doubt.
//! - While possible to use a single [`KeyPair`] for both HashML-DSA and ML-DSA, it is strongly recommended to utilize
//! two independent keypairs for these two variants.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::KP;
//! use orion::hazardous::dsa::mldsa44::*;
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
//! [`KeyPair::generate()`]: mldsa44::KeyPair::generate
//! [`KeyPair`]: mldsa44::KeyPair
//! [`SigningKey`]: mldsa44::SigningKey
//! [`SigningKey::try_from()`]: mldsa44::SigningKey::try_from
//! [`Seed`]: mldsa44::Seed
//! [`ExplicitRandom`]: mldsa44::ExplicitRandom
//! [`PreHash`]: mldsa44::PreHash

use crate::KP;
use crate::errors::UnknownCryptoError;
use crate::generics::sealed::Sealed;
use crate::generics::{Public, Secret, TypeSpec};
use crate::hazardous::dsa::ml_dsa::internal::{
    InternalSignature, InternalSigningKey, InternalVerifyingKey, KeyPairInternal, MlDsa44,
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
pub const SIGNING_KEY_SIZE: usize = MlDsa44::PRIVATE_KEY_SIZE;

/// Size of public [`VerifyingKey`].
pub const VERIFYING_KEY_SIZE: usize = MlDsa44::PUBLIC_KEY_SIZE;

/// Size of public [`Signature`].
pub const SIGNATURE_SIZE: usize = MlDsa44::SIGNATURE_SIZE;

/// ML-DSA-44 signature.
pub type Signature = Public<MlDsa44Signature>;

/// ML-DSA-44 signing key.
pub type SigningKey = Secret<MlDsa44SigningKey>;

/// ML-DSA-44 verifying key.
pub type VerifyingKey = Public<MlDsa44VerifyingKey>;

#[derive(Debug)]
/// ML-DSA-44 signing key implementation. See [`SigningKey`] type for convenience.
pub struct MlDsa44SigningKey {}
impl Sealed for MlDsa44SigningKey {}

impl TypeSpec for MlDsa44SigningKey {
    const NAME: &'static str = stringify!(SigningKey);
    // Key-check logic in Data-impl under [`InternalSigningKey`] (applies to `parse_bytes()`).
    type TypeData = InternalSigningKey<
        { MlDsa44::PRIVATE_KEY_SIZE },
        { MlDsa44::SIGNATURE_SIZE },
        { MlDsa44::CLEN },
        { MlDsa44::COMMITMENT_HASH_LEN },
        { MlDsa44::W1_BITPACK_SIZE * MlDsa44::DIM_K },
        { MlDsa44::DIM_K },
        { MlDsa44::DIM_L },
        MlDsa44,
    >;
}

#[derive(Debug)]
/// ML-DSA-44 verifying key implementation. See [`VerifyingKey`] type for convenience.
pub struct MlDsa44VerifyingKey {}
impl Sealed for MlDsa44VerifyingKey {}
impl TypeSpec for MlDsa44VerifyingKey {
    const NAME: &'static str = stringify!(VerifyingKey);
    // Key-check logic in Data-impl under [`InternalVerifyingKey`] (applies to `parse_bytes()`).
    type TypeData = InternalVerifyingKey<
        { MlDsa44::PUBLIC_KEY_SIZE },
        { MlDsa44::SIGNATURE_SIZE },
        { MlDsa44::CLEN },
        { MlDsa44::COMMITMENT_HASH_LEN },
        { MlDsa44::W1_BITPACK_SIZE * MlDsa44::DIM_K },
        { MlDsa44::DIM_K },
        { MlDsa44::DIM_L },
        MlDsa44,
    >;

    /// SECURITY: Override to vartime-[`PartialEq`] on a non-secret type, with a var-time one
    /// to selectively only compare the encoded representation of encapsulation key.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded encapsulation key, so make sure the other fields
        // aren't modifiable after instantiation, otherwise the encoded bytes might not correspond
        // to the RingElements/Polynomials.
        lhs.pk.as_ref() == rhs
    }
}

#[derive(Debug, Clone, Copy)]
/// ML-DSA-44 signature implementation. See [`Signature`] type for convenience.
pub struct MlDsa44Signature {}
impl Sealed for MlDsa44Signature {}

impl TypeSpec for MlDsa44Signature {
    const NAME: &'static str = stringify!(Signature);
    // Key-check logic in Data-impl under [`InternalSignature`] (applies to `parse_bytes()`).
    type TypeData = InternalSignature<
        { MlDsa44::SIGNATURE_SIZE },
        { MlDsa44::COMMITMENT_HASH_LEN },
        { MlDsa44::DIM_K },
        { MlDsa44::DIM_L },
        MlDsa44,
    >;

    /// SECURITY: Override to vartime-[`PartialEq`] on a non-secret type, with a var-time one
    /// to selectively only compare the encoded representation of encapsulation key.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded encapsulation key, so make sure the other fields
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
/// ML-DSA-44 keypair.
pub struct KeyPair {
    seed: Seed,
    signing_key: SigningKey,
    pub(crate) verifying_key: VerifyingKey,
}

impl KP<MlDsa44SigningKey, MlDsa44VerifyingKey> for KeyPair {
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
            { MlDsa44::PRIVATE_KEY_SIZE },
            { MlDsa44::PUBLIC_KEY_SIZE },
            { MlDsa44::SIGNATURE_SIZE },
            { MlDsa44::CLEN },
            { MlDsa44::COMMITMENT_HASH_LEN },
            { MlDsa44::W1_BITPACK_SIZE * MlDsa44::DIM_K },
            { MlDsa44::DIM_K },
            { MlDsa44::DIM_L },
            MlDsa44,
        >::keygen_internal(value.unprotected_as_ref())?;

        Ok(Self {
            seed: Seed::from_data(value.data.clone()),
            signing_key: Secret::<MlDsa44SigningKey>::from_data(kp.sk),
            verifying_key: Public::<MlDsa44VerifyingKey>::from_data(kp.pk),
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
    fn c2sp_cctv_accumulated_mldsa44() {
        // src: https://github.com/C2SP/CCTV/commit/2ad7bcfdbf32721f43e10ccac78c3ecac1c9dfb5

        let mut s = Shake128::new();
        let mut a = Shake128::new();

        let expected_100 =
            hex::decode("d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4")
                .unwrap();
        let expected_10000 =
            hex::decode("e7fd21f6a59bcba60d65adc44404bb29a7c00e5d8d3ec06a732c00a306a7d143")
                .unwrap();
        // let expected_60000000 =
        //     hex::decode("080b48049257f5cd30dee17d6aa393d6c42fe52a29099df84a460ebaf4b02330")
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
