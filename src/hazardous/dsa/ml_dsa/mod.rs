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

use crate::generics::GenerateSecret;
use crate::generics::{ByteArrayData, Secret, TypeSpec, sealed::Sealed};
#[cfg(feature = "safe_api")]
use crate::{errors::UnknownCryptoError, generics::sealed::Data};

/// Internal implementation logic for ML-DSA.
pub mod internal;

/// ML-DSA-44 as specified in [FIPS-204](https://doi.org/10.6028/NIST.FIPS.204).
pub mod mldsa44;

/// ML-DSA-65 as specified in [FIPS-204](https://doi.org/10.6028/NIST.FIPS.204).
pub mod mldsa65;

/// ML-DSA-87 as specified in [FIPS-204](https://doi.org/10.6028/NIST.FIPS.204).
pub mod mldsa87;

/// Size of private [`Seed`].
pub const SEED_SIZE: usize = 32;

/// Size of explicit randomness ("`rnd`") used during signing [`ExplicitRandom`].
pub const RAND_SIZE: usize = 32;

#[derive(Debug)]
/// ML-DSA seed implementation. See [`Seed`] type for convenience.
pub struct MlDsaSeed {}
impl Sealed for MlDsaSeed {}

impl TypeSpec for MlDsaSeed {
    const NAME: &'static str = stringify!(Seed);
    type TypeData = ByteArrayData<SEED_SIZE>;
}

impl From<[u8; SEED_SIZE]> for Secret<MlDsaSeed> {
    fn from(value: [u8; SEED_SIZE]) -> Self {
        Self::from_data(<MlDsaSeed as TypeSpec>::TypeData::from(value))
    }
}

impl GenerateSecret for MlDsaSeed {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<MlDsaSeed>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(SEED_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// ML-DSA seed.
///
/// Represent the `ξ` seed used by ML-DSA to produce
/// a signing and verification key.
///
/// **SECURITY**: It it crucial for the security of ML-DSA that these be generated
/// using a CSPRNG.
pub type Seed = Secret<MlDsaSeed>;

#[derive(Debug)]
/// ML-DSA `rnd` explicit randomness implementation. See [`ExplicitRandom`] type for convenience.
pub struct MlDsaExplicitRandom {}
impl Sealed for MlDsaExplicitRandom {}

impl TypeSpec for MlDsaExplicitRandom {
    const NAME: &'static str = stringify!(ExplicitRandom);
    type TypeData = ByteArrayData<RAND_SIZE>;
}

impl From<[u8; RAND_SIZE]> for Secret<MlDsaExplicitRandom> {
    fn from(value: [u8; RAND_SIZE]) -> Self {
        Self::from_data(<MlDsaExplicitRandom as TypeSpec>::TypeData::from(value))
    }
}

impl ExplicitRandom {
    /// FIPS-204 deterministic `rnd`value, which is all 0's.
    pub fn deterministic() -> Self {
        Self::from([0u8; RAND_SIZE])
    }
}

impl GenerateSecret for MlDsaExplicitRandom {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<MlDsaExplicitRandom>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(RAND_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// ML-KEM explicit randomness ("`m`") used during encapsulation.
///
/// This type exists for the purpose of deterministic operations.
///
/// **SECURITY**: It it crucial for the security of ML-DSA that these be generated
/// using a CSPRNG.
///
/// If deterministic operation is wanted, supply with [`ExplicitRandom::deterministic()`].
pub type ExplicitRandom = Secret<MlDsaExplicitRandom>;

#[test]
fn test_mldsa_seed() {
    use crate::test_framework::newtypes::secret::SecretNewtype;
    SecretNewtype::test_with_generate::<SEED_SIZE, SEED_SIZE, SEED_SIZE, MlDsaSeed>();

    // Test of From<[u8; N]>
    assert_ne!(Seed::from([0u8; SEED_SIZE]), Seed::from([1u8; SEED_SIZE]));
}

#[test]
fn test_mldsa_explicitrandom() {
    use crate::test_framework::newtypes::secret::SecretNewtype;
    SecretNewtype::test_with_generate::<RAND_SIZE, RAND_SIZE, RAND_SIZE, MlDsaExplicitRandom>();

    // Test of From<[u8; N]>
    assert_ne!(
        ExplicitRandom::from([0u8; RAND_SIZE]),
        ExplicitRandom::from([1u8; RAND_SIZE])
    );
}
