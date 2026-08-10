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
//! - __**TODO**__
//!
//! # Errors:
//! An error will be returned if:
//! - __**TODO**__
//!
//! # Security:
//! - __**TODO**__
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! __**TODO**__
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```

use crate::KP;
use crate::errors::UnknownCryptoError;
use crate::generics::sealed::Sealed;
use crate::generics::{Public, Secret, TypeSpec};
use crate::hazardous::dsa::ml_dsa::internal::{
    InternalSignature, InternalSigningKey, InternalVerifyingKey, KeyPairInternal, MlDsa87,
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
pub const SIGNING_KEY_SIZE: usize = MlDsa87::PRIVATE_KEY_SIZE;

/// Size of public [`VerifyingKey`].
pub const VERIFYING_KEY_SIZE: usize = MlDsa87::PUBLIC_KEY_SIZE;

/// Size of public [`Signature`].
pub const SIGNATURE_SIZE: usize = MlDsa87::SIGNATURE_SIZE;

/// ML-DSA-87 signature.
pub type Signature = Public<MlDsa87Signature>;

/// ML-DSA-87 signing key.
pub type SigningKey = Secret<MlDsa87SigningKey>;

/// ML-DSA-87 verifying key.
pub type VerifyingKey = Public<MlDsa87VerifyingKey>;

#[derive(Debug)]
/// ML-DSA-87 signing key implementaion. See [`SigningKey`] type for convenience.
pub struct MlDsa87SigningKey {}
impl Sealed for MlDsa87SigningKey {}

impl TypeSpec for MlDsa87SigningKey {
    const NAME: &'static str = stringify!(SigningKey);
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData = InternalSigningKey<
        { MlDsa87::PRIVATE_KEY_SIZE },
        { MlDsa87::SIGNATURE_SIZE },
        { MlDsa87::CLEN },
        { MlDsa87::COMMITMENT_HASH_LEN },
        { MlDsa87::W1_BITPACK_SIZE * MlDsa87::DIM_K },
        { MlDsa87::DIM_K },
        { MlDsa87::DIM_L },
        MlDsa87,
    >;
}

#[derive(Debug)]
/// ML-DSA-87 verifying key implementation. See [`VerifyingKey`] type for convenience.
pub struct MlDsa87VerifyingKey {}
impl Sealed for MlDsa87VerifyingKey {}
impl TypeSpec for MlDsa87VerifyingKey {
    const NAME: &'static str = stringify!(VerifyingKey);
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData = InternalVerifyingKey<
        { MlDsa87::PUBLIC_KEY_SIZE },
        { MlDsa87::SIGNATURE_SIZE },
        { MlDsa87::CLEN },
        { MlDsa87::COMMITMENT_HASH_LEN },
        { MlDsa87::W1_BITPACK_SIZE * MlDsa87::DIM_K },
        { MlDsa87::DIM_K },
        { MlDsa87::DIM_L },
        MlDsa87,
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
/// ML-DSA-87 signature implementation. See [`Signature`] type for convenience.
pub struct MlDsa87Signature {}
impl Sealed for MlDsa87Signature {}

impl TypeSpec for MlDsa87Signature {
    const NAME: &'static str = stringify!(Signature);
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData = InternalSignature<
        { MlDsa87::SIGNATURE_SIZE },
        { MlDsa87::COMMITMENT_HASH_LEN },
        { MlDsa87::DIM_K },
        { MlDsa87::DIM_L },
        MlDsa87,
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

// TODO:
// impl TryFrom<&SigningKey> for Public<MlDsa44VerifyingKey> {
//     type Error = UnknownCryptoError;

//     fn try_from(value: &DecapsulationKey) -> Result<Self, Self::Error> {
//         Ok(Self::from_data(EncapKey::<
//             { MlKem512Internal::K },
//             { MlKem512Internal::EK_SIZE },
//             MlKem512Internal,
//         >::from_bytes(
//             value.data.get_encapsulation_key_bytes()
//         )?))
//     }
// }

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

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [`SigningKey`] and [`PreHash`], sign a message `m` and context.
    pub fn sign_prehash_deterministic(
        &self,
        m: &[u8],
        ctx: &[u8],
        ph: &PreHash,
    ) -> Result<Signature, UnknownCryptoError> {
        self.sign_prehash_with_rnd(m, ctx, ph, &ExplicitRandom::deterministic())
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
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
}

#[derive(Debug, PartialEq)]
/// ML-DSA-87 keypair.
pub struct KeyPair {
    seed: Seed,
    signing_key: SigningKey,
    pub(crate) verifying_key: VerifyingKey,
}

impl KP<MlDsa87SigningKey, MlDsa87VerifyingKey> for KeyPair {
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
            { MlDsa87::PRIVATE_KEY_SIZE },
            { MlDsa87::PUBLIC_KEY_SIZE },
            { MlDsa87::SIGNATURE_SIZE },
            { MlDsa87::CLEN },
            { MlDsa87::COMMITMENT_HASH_LEN },
            { MlDsa87::W1_BITPACK_SIZE * MlDsa87::DIM_K },
            { MlDsa87::DIM_K },
            { MlDsa87::DIM_L },
            MlDsa87,
        >::keygen_internal(value.unprotected_as_ref())?;

        Ok(Self {
            seed: Seed::from_data(value.data.clone()),
            signing_key: Secret::<MlDsa87SigningKey>::from_data(kp.sk),
            verifying_key: Public::<MlDsa87VerifyingKey>::from_data(kp.pk),
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
    fn c2sp_cctv_accumulated_mldsa87() {
        // src: https://github.com/C2SP/CCTV/commit/2ad7bcfdbf32721f43e10ccac78c3ecac1c9dfb5

        let mut s = Shake128::new();
        let mut a = Shake128::new();

        let expected_100 =
            hex::decode("8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b")
                .unwrap();
        let expected_10000 =
            hex::decode("80a8cf39317f7d0be0e24972c51ac152bd2a3e09bc0c32ce29dd82c4e7385e60")
                .unwrap();
        // let expected_60000000 =
        //     hex::decode("011166e9d5032c9bdc5c9bbb5dbb6c86df1c3d9bf3570b65ebae942dd9830057")
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
