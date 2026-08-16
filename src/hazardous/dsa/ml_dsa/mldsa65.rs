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
//! [`KeyPair`] does not expose the streaming-based API, so in this case a [`SigningKey`] should preferrably be constructed
//! from a [`Seed`].
//!
//! #### Serialized signing keys
//! It is possible to instantiate a [`SigningKey`] directly, if strictly required, using [`SigningKey::try_from()`]. This use hereof is intended solely for
//! interoperability purposes. The lack of generate function for [`SigningKey`] is intentional.
//!
//! # Parameters:
//! - `m`: Message to be signed or verified a signature of.
//! - `ctx`: Context string which must be the same on signing and verification.
//! - `rnd`: [`ExplicitRandom`] provided during signing.
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
//! - If [`SigningKey::update()`] or [`VerifyingKey::update()`] is called without having initialized with [`SigningKey::init()`]/[`VerifyingKey::init()`] first.
//! - If [`SigningKey::finalize()`] or [`VerifyingKey::finalize()`] is called without having initialized with [`SigningKey::init()`]/[`VerifyingKey::init()`] first.
//! - If [`SigningKey::update()`], [`VerifyingKey::update()`], [`SigningKey::finalize()`] or [`VerifyingKey::finalize()`], is called after [`SigningKey::finalize()`] or [`VerifyingKey::finalize()`]
//!   without re-initialization beforehand.
//!
//! # Security:
//! - Using the randomized, non-deterministic signing hardens the ML-DSA signing routine against fault-injection attacks.
//! - It is critical that both the seed and explicit randomness `rnd`, used for key generation and signing
//! are generated using a strong CSPRNG.
//! - Users should always prefer the hedged/randomized if in doubt.
//!
//! # Example:
//! ```ignore-windows
//! # #[cfg(feature = "safe_api")] {
//! use orion::KP;
//! use orion::hazardous::dsa::mldsa65::*;
//!
//! let kp = KeyPair::generate()?;
//!
//! let signature = kp.private().sign(b"Message to sign", b"additional context")?;
//!
//! assert!(kp.public().verify(b"Message to sign", b"additional context", &signature).is_ok());
//!
//! // Streaming-based signing
//! let seed = Seed::generate()?;
//! let mut sk = SigningKey::try_from(&seed)?;
//!
//! sk.init(b"additional context")?;
//! sk.update(b"Message to ")?;
//! sk.update(b"sign")?;
//! let signature = sk.finalize()?;
//!
//! let mut vk = VerifyingKey::try_from(&sk)?;
//! vk.init(b"additional context")?;
//! vk.update(b"Message")?;
//! vk.update(b" to ")?;
//! vk.update(b"sign")?;
//! assert!(vk.finalize(&signature).is_ok());
//!
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
//! [`SigningKey::update()`]: mldsa65::SigningKey::update
//! [`SigningKey::finalize()`]: mldsa65::SigningKey::finalize
//! [`SigningKey::init()`]: mldsa65::SigningKey::init
//! [`VerifyingKey::update()`]: mldsa65::VerifyingKey::update
//! [`VerifyingKey::finalize()`]: mldsa65::VerifyingKey::finalize
//! [`VerifyingKey::init()`]: mldsa65::VerifyingKey::init

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
#[cfg_attr(test, derive(Clone))]
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

#[derive(Debug, Clone, Copy)]
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

impl TryFrom<&Seed> for SigningKey {
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

        Ok(Self::from_data(kp.sk))
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

    /// Given the [`SigningKey`] and `ctx`, initialize internal state
    /// for streaming processing of message digest to be signed.
    pub fn init(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
        self.data.init(ctx)
    }

    /// Update internal message digest state with message bytes.
    pub fn update(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError> {
        self.data.update(m)
    }

    /// Finalize and compute the signature given [`ExplicitRandom`].
    pub fn finalize_with_rnd(
        &mut self,
        rnd: &ExplicitRandom,
    ) -> Result<Signature, UnknownCryptoError> {
        Ok(Signature::from_data(
            self.data.finalize(rnd.unprotected_as_ref())?,
        ))
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Finalize and compute the signature.
    pub fn finalize(&mut self) -> Result<Signature, UnknownCryptoError> {
        let rnd = ExplicitRandom::generate()?;
        self.finalize_with_rnd(&rnd)
    }
}

impl VerifyingKey {
    /// Given the [`VerifyingKey`], verify a signature `sig` produced over message `m` and context.
    pub fn verify(&self, m: &[u8], ctx: &[u8], sig: &Signature) -> Result<(), UnknownCryptoError> {
        self.data.verify(m, &sig.data, ctx)
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

    /// Given the [`VerifyingKey`] and `ctx`, initialize internal state
    /// for streaming processing of message digest to be verified.
    pub fn init(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
        self.data.init(ctx)
    }

    /// Update internal message digest state with message bytes.
    pub fn update(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError> {
        self.data.update(m)
    }

    /// Finalize and verify the signature.
    pub fn finalize(&mut self, sig: &Signature) -> Result<(), UnknownCryptoError> {
        self.data.finalize(&sig.data)
    }
}

impl TryFrom<&SigningKey> for VerifyingKey {
    type Error = UnknownCryptoError;

    fn try_from(value: &SigningKey) -> Result<Self, Self::Error> {
        let vk = InternalVerifyingKey::<
            { MlDsa65::PUBLIC_KEY_SIZE },
            { MlDsa65::SIGNATURE_SIZE },
            { MlDsa65::CLEN },
            { MlDsa65::COMMITMENT_HASH_LEN },
            { MlDsa65::W1_BITPACK_SIZE * MlDsa65::DIM_K },
            { MlDsa65::DIM_K },
            { MlDsa65::DIM_L },
            MlDsa65,
        >::try_from(&value.data)?;

        Ok(Self::from_data(vk))
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Clone))]
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

    // src: https://github.com/C2SP/CCTV/commit/2ad7bcfdbf32721f43e10ccac78c3ecac1c9dfb5
    pub(crate) fn c2sp_cctv_accumulated_mldsa65_run(
        iter_max: u32,
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut s = Shake128::new();
        let mut a = Shake128::new();

        let mut seed = [0u8; 32];
        let mut result_100 = [0u8; 32];
        let mut result_10000 = [0u8; 32];
        let mut result_60000000 = [0u8; 32];

        for n in 1..=iter_max {
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

        (result_100, result_10000, result_60000000)
    }

    #[test]
    #[ignore = "runs too long - only meant for local development, not CI"] // cargo test -- --ignored
    fn c2sp_cctv_accumulated_60000000() {
        let mut expected_60000000 = [0u8; 32];
        hex::decode_to_slice(
            "0af0165db2b180f7a83dbecad1ccb758b9c2d834b7f801fc49dd572a9d4b1e83",
            &mut expected_60000000,
        )
        .unwrap();
        let (_result_100, _result_10000, result_60000000) =
            c2sp_cctv_accumulated_mldsa65_run(60000000);
        assert_eq!(expected_60000000, result_60000000);
    }

    #[test]
    fn c2sp_cctv_accumulated() {
        let mut expected_100 = [0u8; 32];
        let mut expected_10000 = [0u8; 32];

        hex::decode_to_slice(
            "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199",
            &mut expected_100,
        )
        .unwrap();
        hex::decode_to_slice(
            "5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329",
            &mut expected_10000,
        )
        .unwrap();

        let (result_100, result_10000, _result_60000000) = c2sp_cctv_accumulated_mldsa65_run(10000);
        assert_eq!(expected_100, result_100);
        assert_eq!(expected_10000, result_10000);
    }

    // NOTE(brycx): SecretNewtype/PublicNewtype tests aren't run for SigninngKey/VerifyinngKey/Signature types
    // because their underling TypeData structure is not compatible with the generic tests.

    #[test]
    #[cfg(all(feature = "serde", feature = "safe_api"))]
    fn test_signature_public_serialization() {
        use crate::test_framework::newtypes::public::PublicNewtype;

        let kp = KeyPair::new(Seed::from([0u8; 32])).unwrap();
        let sig = kp.private().sign(b"", b"").unwrap();

        PublicNewtype::test_serialization_non_arbitrary::<MlDsa65Signature>(&sig);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_verifyingkey_public_serialization() {
        use crate::test_framework::newtypes::public::PublicNewtype;

        let kp = KeyPair::new(Seed::from([0u8; 32])).unwrap();
        PublicNewtype::test_serialization_non_arbitrary::<MlDsa65VerifyingKey>(kp.public());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    use crate::test_framework::mldsa_interface::{DsaTester, TestableDsa};

    #[cfg(all(feature = "alloc", not(feature = "safe_api")))]
    use alloc::vec::*;

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    impl TestableDsa for KeyPair {
        const SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

        fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let seed = Seed::try_from(seed)?;
            let kp = KeyPair::new(seed)?;

            Ok((
                kp.signing_key.unprotected_as_ref().to_vec(),
                kp.verifying_key.as_ref().to_vec(),
            ))
        }

        #[cfg(feature = "safe_api")]
        fn keygen_rng() -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let seed = Seed::generate()?;
            Self::keygen(seed.unprotected_as_ref())
        }

        fn sign_deterministic(
            sk: &[u8],
            m: &[u8],
            ctx: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let signing_key = SigningKey::try_from(sk)?;
            let sig = signing_key.sign_deterministic(m, ctx)?;

            Ok(sig.as_ref().to_vec())
        }

        #[cfg(feature = "safe_api")]
        fn sign_randomized(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
            let signing_key = SigningKey::try_from(sk)?;
            let sig = signing_key.sign(m, ctx)?;

            Ok(sig.as_ref().to_vec())
        }

        fn verify(vk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), UnknownCryptoError> {
            let verifying_key = VerifyingKey::try_from(vk)?;
            let sig = Signature::try_from(sig)?;
            verifying_key.verify(m, ctx, &sig)
        }

        #[cfg(feature = "safe_api")]
        fn init_sign(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
            self.signing_key.init(ctx)
        }

        #[cfg(feature = "safe_api")]
        fn init_verify(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError> {
            self.verifying_key.init(ctx)
        }

        #[cfg(feature = "safe_api")]
        fn update_sign(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError> {
            self.signing_key.update(m)
        }

        #[cfg(feature = "safe_api")]
        fn update_verify(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError> {
            self.verifying_key.update(m)
        }

        #[cfg(feature = "safe_api")]
        fn finalize_sign(&mut self, rnd: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
            Ok(self
                .signing_key
                .finalize_with_rnd(&ExplicitRandom::try_from(rnd)?)?
                .as_ref()
                .to_vec())
        }

        #[cfg(feature = "safe_api")]
        fn finalize_verify(&mut self, sig: &[u8]) -> Result<(), UnknownCryptoError> {
            self.verifying_key.finalize(&Signature::try_from(sig)?)
        }

        #[cfg(feature = "safe_api")]
        fn sign_with_rnd(
            sk: &[u8],
            m: &[u8],
            ctx: &[u8],
            rnd: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let signing_key = SigningKey::try_from(sk)?;
            let sig = signing_key.sign_with_rnd(m, ctx, &ExplicitRandom::try_from(rnd)?)?;

            Ok(sig.as_ref().to_vec())
        }
    }

    #[test]
    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn run_basic_dsa_tests() {
        #[cfg(feature = "safe_api")]
        let seed = Seed::generate().unwrap();
        #[cfg(not(feature = "safe_api"))]
        let seed = Seed::from([123u8; 32]);

        let streaming_tester = DsaTester::<KeyPair>::new(KeyPair::new(seed.clone()).unwrap());
        DsaTester::<KeyPair>::run_all_tests(
            &streaming_tester,
            seed.unprotected_as_ref(),
            b"This message to sign with ML-DSA.",
        );
    }

    #[test]
    fn test_keypair_seed() {
        let seed = Seed::from([255u8; 32]);
        let kp = KeyPair::new(seed.clone()).unwrap();

        assert_eq!(&seed, kp.seed());
    }

    #[test]
    fn test_err_on_invalid_mu() {
        let seed = Seed::from([255u8; 32]);
        let rnd = ExplicitRandom::from([0u8; 32]);
        let kp = KeyPair::new(seed.clone()).unwrap();

        assert!(
            kp.private()
                .sign_external_mu_with_rnd(&[1u8; 63], &rnd)
                .is_err()
        );
        assert!(
            kp.private()
                .sign_external_mu_with_rnd(&[1u8; 65], &rnd)
                .is_err()
        );
        let sig = kp
            .private()
            .sign_external_mu_with_rnd(&[1u8; 64], &rnd)
            .unwrap();
        assert!(kp.public().verify_external_mu(&[1u8; 63], &sig).is_err());
        assert!(kp.public().verify_external_mu(&[1u8; 65], &sig).is_err());
        assert!(kp.public().verify_external_mu(&[1u8; 64], &sig).is_ok());
    }

    #[test]
    fn test_try_from_sk_to_vk() {
        let seed = Seed::from([255u8; 32]);
        let kp = KeyPair::new(seed).unwrap();

        assert_eq!(&VerifyingKey::try_from(kp.private()).unwrap(), kp.public());
    }

    #[test]
    fn test_one_shot_eq_streaming() {
        let seed = Seed::from([255u8; 32]);
        let kp = KeyPair::new(seed.clone()).unwrap();
        let oneshot = kp
            .private()
            .sign_deterministic(b"Message to sign", b"Context")
            .unwrap();

        let mut sk = SigningKey::try_from(&seed).unwrap();
        assert_eq!(kp.seed, seed);
        assert_eq!(kp.private(), &sk);

        sk.init(b"Context").unwrap();
        sk.update(b"Message to ").unwrap();
        sk.update(b"sign").unwrap();
        let multi = sk
            .finalize_with_rnd(&ExplicitRandom::deterministic())
            .unwrap();
        assert_eq!(oneshot, multi);

        let mut vk = VerifyingKey::try_from(&sk).unwrap();
        assert_eq!(kp.public(), &vk);
        vk.init(b"Context").unwrap();
        vk.update(b"Message").unwrap();
        vk.update(b" to ").unwrap();
        vk.update(b"sign").unwrap();

        assert!(vk.clone().finalize(&oneshot).is_ok());
        assert!(vk.clone().finalize(&multi).is_ok());
    }
}
