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
    InternalSignature, InternalSigningKey, InternalVerifyingKey, KeyPairInternal, MlDsa65,
    MlDsaParameters,
};

pub use crate::hazardous::dsa::ml_dsa::MlDsaSeed;
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
/// ML-DSA-65 signing key implementaion. See [`SigningKey`] type for convenience.
pub struct MlDsa65SigningKey {}
impl Sealed for MlDsa65SigningKey {}

impl TypeSpec for MlDsa65SigningKey {
    const NAME: &'static str = stringify!(SigningKey);
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
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
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
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
    /// to selectively only compare the encoded representation of encapsulation key.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded encapsulation key, so make sure the other fields
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
    // TODO:
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData = InternalSignature<
        { MlDsa65::SIGNATURE_SIZE },
        { MlDsa65::COMMITMENT_HASH_LEN },
        { MlDsa65::DIM_K },
        { MlDsa65::DIM_L },
        MlDsa65,
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
        use crate::util::secure_rand_bytes;

        let mut rnd = zeroize_wrap!([0u8; 32]);
        secure_rand_bytes(rnd.as_mut())?;

        Ok(Signature::from_data(self.data.sign(
            m,
            ctx,
            rnd.as_slice(),
        )?))
    }

    /// Given the [`SigningKey`], sign a message `m` and context.
    pub fn sign_deterministic(
        &self,
        m: &[u8],
        ctx: &[u8],
    ) -> Result<Signature, UnknownCryptoError> {
        Ok(Signature::from_data(self.data.sign(m, ctx, &[0u8; 32])?))
    }
}

impl VerifyingKey {
    /// Given the [`VerifyingKey`], verify a signature `sig` produced over message `m` and context.
    pub fn verify(&self, m: &[u8], ctx: &[u8], sig: &Signature) -> Result<(), UnknownCryptoError> {
        self.data.verify(m, &sig.data, ctx)
    }
}

#[derive(Debug, PartialEq)]
/// ML-DSA-65 keypair.
pub struct KeyPair {
    seed: Seed,
    signing_key: SigningKey,
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
