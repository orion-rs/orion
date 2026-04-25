// MIT License

// Copyright (c) 2025-2026 The orion Developers

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

/// Internal implementation logic for ML-KEM.
pub mod internal;

/// ML-KEM-512 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem512;

/// ML-KEM-768 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem768;

/// ML-KEM-1024 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem1024;

/// Size of the seed used in ML-KEM.
pub const SEED_SIZE: usize = 64;

#[derive(Debug)]
/// ML-KEM seed implementation. See [`Seed`] type for convenience.
pub struct MlKemSeed {}
impl Sealed for MlKemSeed {}

impl TypeSpec for MlKemSeed {
    const NAME: &'static str = stringify!(Seed);
    type TypeData = ByteArrayData<SEED_SIZE>;
}

impl From<[u8; SEED_SIZE]> for Secret<MlKemSeed> {
    fn from(value: [u8; SEED_SIZE]) -> Self {
        Self::from_data(<MlKemSeed as TypeSpec>::TypeData::from(value))
    }
}

impl GenerateSecret for MlKemSeed {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<MlKemSeed>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(SEED_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

/// ML-KEM seed.
///
/// Represent the `d||z` seed used by ML-KEM to produce
/// a decapsulation key and its corresponding encapsulation key.
///
/// **SECURITY**: It it crucial for the security of ML-KEM that these be generated
/// using a CSPRNG.
pub type Seed = Secret<MlKemSeed>;

#[test]
fn test_mlkem_seed() {
    use crate::test_framework::newtypes::secret::SecretNewtype;
    SecretNewtype::test_with_generate::<SEED_SIZE, SEED_SIZE, SEED_SIZE, MlKemSeed>();

    // Test of From<[u8; N]>
    assert_ne!(Seed::from([0u8; SEED_SIZE]), Seed::from([1u8; SEED_SIZE]));
}
