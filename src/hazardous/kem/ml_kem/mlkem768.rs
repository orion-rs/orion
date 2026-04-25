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

//! ### ML-KEM key usage recommendations
//!
//! In general, it is highly recommended to use the [`KeyPair`] type to deal with decapsulating operations, or decapsulation keys in general.
//!
//! A [`KeyPair`] requires, or automatically generates, a [`Seed`]. It cannot be made solely from encoded/serialized decapsulation key in bytes, unless a [`Seed`] is also provided.
//! [`KeyPair`] also internally caches the [`EncapsulationKey`] used during decapsulation, making it more efficient when used to decapsulate multiple
//! KEM ciphertext with a given private [`DecapsulationKey`].
//!
//! A seed is only 64 bytes, is fully FIPS compliant, and hardens against attacks described [here](https://eprint.iacr.org/2024/523).
//!
//! #### Serialized decapsulation keys
//! It is possible to instantiate a [`DecapsulationKey`] directly, if strictly required, using [`DecapsulationKey::unchecked_from_slice()`].
//!
//! # Parameters:
//! - `ek`: The public encapsulation key, for which a shared secret and ciphertext is generated.
//! - `dk`: The secret decapsulation key, for which a ciphertext is used to derive a shared secret.
//! - `c`: The public ciphertext, sent to the decapsulating party.
//! - `m`: Explicit randomness used for encapsulation.
//!
//! # Errors:
//! An error will be returned if:
//! - [`getrandom::fill()`] fails during encapsulation.
//! - [`getrandom::fill()`] fails during [`KeyPair::generate()`].
//! - `m` is not 32 bytes.
//!
//! # Security:
//! - It is critical that both the seed and explicit randomness `m`, used for key generation and encapsulation
//! are generated using a strong CSPRNG.
//! - Users should always prefer encapsulation without specifying explicit randomness, if possible. [`EncapsulationKey::encap_deterministic()`]
//! exists mainly for `no_std` usage.
//! - Prefer using [`KeyPair`] to create and use ML-KEM keys, which is MAL-BIND-K-CT secure.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::KP;
//! use orion::hazardous::kem::mlkem768::*;
//!
//! let kp = KeyPair::generate()?;
//!
//! let ek = EncapsulationKey::try_from(kp.public().as_ref())?;
//! let (sender_shared_secret, sender_ciphertext) = ek.encap()?;
//! let recipient_shared_secret = kp.decap(&sender_ciphertext)?;
//!
//! assert_eq!(sender_shared_secret, recipient_shared_secret);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`getrandom::fill()`]: getrandom::fill
//! [`KeyPair::generate()`]: mlkem768::KeyPair::generate
//! [`KeyPair`]: mlkem768::KeyPair
//! [`EncapsulationKey`]: mlkem768::EncapsulationKey
//! [`EncapsulationKey::encap_deterministic()`]: mlkem768::EncapsulationKey::encap_deterministic
//! [`Seed`]: mlkem768::Seed
//! [`DecapsulationKey`]: mlkem768::DecapsulationKey
//! [`DecapsulationKey::unchecked_from_slice()`]: mlkem768::DecapsulationKey::unchecked_from_slice

use crate::KP;
use crate::errors::UnknownCryptoError;
use crate::generics::sealed::{Sealed, TryFromBytes};
use crate::generics::{ByteArrayData, Public, Secret, TypeSpec};
use crate::hazardous::kem::ml_kem::internal::*;

pub use crate::hazardous::kem::ml_kem::MlKemSeed;
pub use crate::hazardous::kem::ml_kem::SEED_SIZE;
pub use crate::hazardous::kem::ml_kem::Seed;

/// Size of private [`EncapsulationKey`].
pub const EK_SIZE: usize = MlKem768Internal::EK_SIZE;

/// Size of public [`DecapsulationKey`].
pub const DK_SIZE: usize = MlKem768Internal::DK_SIZE;

/// Size of public [`Ciphertext`].
pub const CIPHERTEXT_SIZE: usize = MlKem768Internal::CIPHERTEXT_SIZE;

/// Size of private [`SharedSecret`].
pub const SHARED_SECRET_SIZE: usize = MlKem768Internal::SHARED_SECRET_SIZE;

/// ML-KEM-768 ciphertext.
pub type Ciphertext = Public<Mlkem768Ciphertext>;

/// ML-KEM-768 shared secret.
pub type SharedSecret = Secret<MlKem768SharedSecret>;

/// ML-KEM-768 encapsulation key.
pub type EncapsulationKey = Public<MlKem768EncapKey>;

/// ML-KEM-768 decapsulation key.
pub type DecapsulationKey = Secret<MlKem768DecapKey>;

#[derive(Debug)]
/// ML-KEM-768 shared secret implementation. See [`SharedSecret`] type for convenience.
pub struct MlKem768SharedSecret {}
impl Sealed for MlKem768SharedSecret {}

impl TypeSpec for MlKem768SharedSecret {
    const NAME: &'static str = stringify!(SharedSecret);
    type TypeData = ByteArrayData<SHARED_SECRET_SIZE>;
}

impl From<[u8; SHARED_SECRET_SIZE]> for Secret<MlKem768SharedSecret> {
    fn from(value: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self::from_data(<MlKem768SharedSecret as TypeSpec>::TypeData::from(value))
    }
}

#[derive(Debug, Clone, Copy)]
/// ML-KEM-768 ciphertext implementation. See [`Ciphertext`] type for convenience.
pub struct Mlkem768Ciphertext {}
impl Sealed for Mlkem768Ciphertext {}

impl TypeSpec for Mlkem768Ciphertext {
    const NAME: &'static str = stringify!(Ciphertext);
    type TypeData = ByteArrayData<CIPHERTEXT_SIZE>;
}

impl From<[u8; CIPHERTEXT_SIZE]> for Public<Mlkem768Ciphertext> {
    fn from(value: [u8; CIPHERTEXT_SIZE]) -> Self {
        Self::from_data(<Mlkem768Ciphertext as TypeSpec>::TypeData::from(value))
    }
}

#[derive(Debug)]
/// ML-KEM-768 decapsulation key implementation. See [`DecapsulationKey`] type for convenience.
pub struct MlKem768DecapKey {}
impl Sealed for MlKem768DecapKey {}
impl TypeSpec for MlKem768DecapKey {
    const NAME: &'static str = stringify!(DecapsulationKey);
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData = DecapKey<
        { MlKem768Internal::K },
        { MlKem768Internal::EK_SIZE },
        { MlKem768Internal::DK_SIZE },
        MlKem768Internal,
    >;
}

#[derive(Debug, Clone, Copy)]
/// ML-KEM-768 encapsulation key implementation. See [`EncapsulationKey`] type for convenience.
pub struct MlKem768EncapKey {}
impl Sealed for MlKem768EncapKey {}
impl TypeSpec for MlKem768EncapKey {
    const NAME: &'static str = stringify!(EncapsulationKey);
    // Key-check logic in Data-impl under [`DecapKey`] (applies to `parse_bytes()`).
    type TypeData =
        EncapKey<{ MlKem768Internal::K }, { MlKem768Internal::EK_SIZE }, MlKem768Internal>;

    /// SECURITY: Override to vartime-[`PartialEq`] on a non-secret type, with a var-time one
    /// to selectively only compare the encoded representation of encapsulation key.
    fn vartime_partial_eq(lhs: &Self::TypeData, rhs: &[u8]) -> bool {
        // NOTE: This compares only the encoded encapsulation key, so make sure the other fields
        // aren't modifiable after instantiation, otherwise the encoded bytes might not correspond
        // to the RingElements/Polynomials.
        lhs.bytes.as_ref() == rhs
    }
}

impl TryFrom<&DecapsulationKey> for Public<MlKem768EncapKey> {
    type Error = UnknownCryptoError;

    fn try_from(value: &DecapsulationKey) -> Result<Self, Self::Error> {
        Ok(Self::from_data(EncapKey::<
            { MlKem768Internal::K },
            { MlKem768Internal::EK_SIZE },
            MlKem768Internal,
        >::from_bytes(
            value.data.get_encapsulation_key_bytes()
        )?))
    }
}

impl EncapsulationKey {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [`EncapsulationKey`], generate a [`SharedSecret`] and associated [`Ciphertext`].
    pub fn encap(&self) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        let mut m = zeroize_wrap!([0u8; 32]);
        getrandom::fill(m.as_mut())?;

        self.encap_deterministic(m.as_ref())
    }

    /// Given the [`EncapsulationKey`] and randomness `m`, generate a [`SharedSecret`] and associated [`Ciphertext`].
    pub fn encap_deterministic(
        &self,
        m: &[u8],
    ) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        if m.len() != 32 {
            return Err(UnknownCryptoError);
        }

        let mut c = Ciphertext::try_from(&[0u8; MlKem768Internal::CIPHERTEXT_SIZE])?;

        #[cfg(feature = "zeroize")]
        let mut k_internal = self
            .data
            .mlkem_encap_internal(m.as_ref(), c.data.as_mut())?;
        #[cfg(not(feature = "zeroize"))]
        let k_internal = self
            .data
            .mlkem_encap_internal(m.as_ref(), c.data.as_mut())?;

        let k = SharedSecret::try_from(k_internal.as_slice())?;
        zeroize_call!(k_internal);

        Ok((k, c))
    }
}

impl DecapsulationKey {
    /// Instantiate a [`DecapsulationKey`] with only key-checks from FIPS-203, section 7.3. Not MAL-BIND-K-CT secure.
    pub fn unchecked_from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        let dk_unchecked = DecapKey::<
            { MlKem768Internal::K },
            { MlKem768Internal::EK_SIZE },
            { MlKem768Internal::DK_SIZE },
            MlKem768Internal,
        >::try_from_bytes(slice)?;

        Ok(Self::from_data(dk_unchecked))
    }

    /// Perform decapsulation of a [`Ciphertext`].
    pub fn decap(&self, c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
        let ek = Public::<MlKem768EncapKey>::try_from(self.data.get_encapsulation_key_bytes())?;
        let mut c_prime_buf = [0u8; MlKem768Internal::CIPHERTEXT_SIZE];

        #[cfg(feature = "zeroize")]
        let mut k_internal =
            self.data
                .mlkem_decap_internal_with_ek(c.as_ref(), &mut c_prime_buf, &ek.data)?;
        #[cfg(not(feature = "zeroize"))]
        let k_internal =
            self.data
                .mlkem_decap_internal_with_ek(c.as_ref(), &mut c_prime_buf, &ek.data)?;

        let k = SharedSecret::try_from(&k_internal)?;
        zeroize_call!(k_internal);

        Ok(k)
    }
}

#[derive(Debug, PartialEq)]
/// ML-KEM-768 keypair.
///
/// This type uses cached encapsulation keys, saving the computation involved when doing decapsulation.
/// Meaning, once [`KeyPair`] has been instantiated, it is more efficient to use for decapsulation
/// than the [`DecapsulationKey`] type directly.
pub struct KeyPair {
    seed: Seed,
    private: DecapsulationKey,
    pub(crate) public: EncapsulationKey,
}

impl KP<MlKem768DecapKey, MlKem768EncapKey> for KeyPair {
    fn public(&self) -> &EncapsulationKey {
        &self.public
    }

    fn private(&self) -> &DecapsulationKey {
        &self.private
    }
}

impl TryFrom<&Seed> for KeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &Seed) -> Result<Self, Self::Error> {
        let (ek, dk) = KeyPairInternal::<MlKem768Internal>::from_seed::<
            { MlKem768Internal::K },
            { MlKem768Internal::EK_SIZE },
            { MlKem768Internal::DK_SIZE },
        >(value)?;

        Ok(Self {
            seed: Seed::from_data(value.data.clone()),
            private: Secret::<MlKem768DecapKey>::from_data(dk),
            public: Public::<MlKem768EncapKey>::from_data(ek),
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
        let (ek, dk) = KeyPairInternal::<MlKem768Internal>::from_seed::<
            { MlKem768Internal::K },
            { MlKem768Internal::EK_SIZE },
            { MlKem768Internal::DK_SIZE },
        >(&seed)?;

        Ok(Self {
            seed,
            private: DecapsulationKey::from_data(dk),
            public: EncapsulationKey::from_data(ek),
        })
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Instantiate a [`KeyPair`] with all key validation checks, described
    /// in FIPS-203, Section 7.1, 7.2 and 7.3.
    ///
    /// The output keypair is the equivalent of using [`Self::try_from`], but this
    /// can be used, in order to check whether a decapsulation key
    /// is valid in relation to the `seed` provided.
    pub fn from_keys(seed: &Seed, dk: &DecapsulationKey) -> Result<Self, UnknownCryptoError> {
        let unchecked_ek = Public::<MlKem768EncapKey>::try_from(dk)?;
        let (ek, dk) = KeyPairInternal::<MlKem768Internal>::from_keys::<
            { MlKem768Internal::K },
            { MlKem768Internal::EK_SIZE },
            { MlKem768Internal::DK_SIZE },
            { MlKem768Internal::CIPHERTEXT_SIZE },
        >(seed, &unchecked_ek.data, &dk.data)?;

        Ok(Self {
            seed: Seed::from_data(seed.data.clone()),
            private: Secret::<MlKem768DecapKey>::from_data(dk),
            public: Public::<MlKem768EncapKey>::from_data(ek),
        })
    }

    /// Perform decapsulation of a [`Ciphertext`], using internally cached [`EncapsulationKey`].
    pub fn decap(&self, c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
        let mut c_prime_buf = [0u8; MlKem768Internal::CIPHERTEXT_SIZE];

        #[cfg(feature = "zeroize")]
        let mut k_internal = self.private.data.mlkem_decap_internal_with_ek(
            c.as_ref(),
            &mut c_prime_buf,
            &self.public.data,
        )?;
        #[cfg(not(feature = "zeroize"))]
        let k_internal = self.private.data.mlkem_decap_internal_with_ek(
            c.as_ref(),
            &mut c_prime_buf,
            &self.public.data,
        )?;

        let k = SharedSecret::try_from(&k_internal)?;
        zeroize_call!(k_internal);

        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE(brycx): SecretNewtype/PublicNewtype tests aren't run for Encapsulation/Decapsulation keys
    // because their underling TypeData structure is not compatible with the generic tests.

    #[test]
    fn test_shared_secret() {
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_no_generate::<
            SHARED_SECRET_SIZE,
            SHARED_SECRET_SIZE,
            MlKem768SharedSecret,
        >();
        // Test of From<[u8; N]>
        assert_ne!(
            SharedSecret::from([0u8; SHARED_SECRET_SIZE]),
            SharedSecret::from([1u8; SHARED_SECRET_SIZE])
        )
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_encapuslation_key_serialization() {
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_serialization::<EK_SIZE, MlKem768EncapKey>();
    }

    #[test]
    fn test_ciphertext() {
        use super::*;
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_no_generate::<CIPHERTEXT_SIZE, CIPHERTEXT_SIZE, Mlkem768Ciphertext>();
        // Test of From<[u8; N]>
        assert_ne!(
            Ciphertext::from([0u8; CIPHERTEXT_SIZE]),
            Ciphertext::from([1u8; CIPHERTEXT_SIZE])
        );

        #[cfg(feature = "serde")]
        PublicNewtype::test_serialization::<CIPHERTEXT_SIZE, Mlkem768Ciphertext>();
    }

    #[cfg(feature = "safe_api")]
    use crate::test_framework::kem_interface::{KemTester, TestableKem};

    #[cfg(feature = "safe_api")]
    impl TestableKem<SharedSecret, Ciphertext> for KeyPair {
        fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = KeyPair::try_from(&Seed::try_from(seed)?)?;

            Ok((
                kp.public.data.bytes.as_ref().to_vec(),
                kp.private.data.bytes.as_ref().to_vec(),
            ))
        }

        fn ciphertext_from_bytes(b: &[u8]) -> Result<Ciphertext, UnknownCryptoError> {
            Ciphertext::try_from(b)
        }

        fn encap(ek: &[u8]) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
            let ek = Public::<MlKem768EncapKey>::try_from(ek)?;
            ek.encap()
        }

        fn decap(dk: &[u8], c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
            let dk = DecapsulationKey::unchecked_from_slice(dk)?;
            dk.decap(c)
        }
    }

    #[test]
    fn test_keypair_dk_ek_match_internal() {
        let seed = Seed::try_from(&[128u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();
        assert_eq!(
            &kp.public().as_ref(),
            &kp.private().data.get_encapsulation_key_bytes()
        );
        assert_eq!(kp.seed(), &seed);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_dk_cached_ek() {
        let seed = Seed::try_from(&[128u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();
        let (ss_pubapi, ct_pubapi) = kp.public().encap_deterministic(&[125u8; 32]).unwrap();
        let mut c_prime = [0u8; MlKem768Internal::CIPHERTEXT_SIZE];
        // This call re-computes encap key internally from the bytes a decapkey would store.
        let ss_privapi = kp
            .private()
            .data
            .mlkem_decap_internal(ct_pubapi.as_ref(), &mut c_prime)
            .unwrap();
        assert_eq!(ss_privapi.as_ref(), ss_pubapi.unprotected_as_ref());
        assert_eq!(kp.decap(&ct_pubapi).unwrap(), ss_pubapi);
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_dk_to_ek_conversions() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(
            Public::<MlKem768EncapKey>::try_from(kp.private()).unwrap(),
            kp.public.as_ref(),
        );
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_bad_m_length() {
        let kp = KeyPair::generate().unwrap();
        let mut m = [0u8; 32];
        getrandom::fill(m.as_mut()).unwrap();

        // Using the same deterministic seed is in fact deterministic,
        // also using correct length.
        assert_eq!(
            kp.public().encap_deterministic(&m).unwrap(),
            kp.public().encap_deterministic(&m).unwrap()
        );
        assert!(kp.public().encap_deterministic(&[0u8; 31]).is_err());
        assert!(kp.public().encap_deterministic(&[0u8; 33]).is_err());
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_dk_ek_partialeq() {
        let s0 = Seed::generate().unwrap();
        let kp = KeyPair::try_from(&s0).unwrap();

        let dk_bytes = kp.private().data.bytes;
        let ek_bytes = kp.public().data.bytes;

        assert_eq!(
            KeyPair::try_from(&s0).unwrap().private(),
            &dk_bytes.as_ref()
        );
        assert_eq!(KeyPair::try_from(&s0).unwrap().public(), &ek_bytes.as_ref());
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_keypair_from_keys() {
        let s0 = Seed::generate().unwrap();
        let s1 = Seed::generate().unwrap();

        let kp0 = KeyPair::try_from(&s0).unwrap();
        let kp1 = KeyPair::try_from(&s1).unwrap();

        assert!(KeyPair::from_keys(&s0, kp0.private()).is_ok());
        assert!(KeyPair::from_keys(&s1, kp1.private()).is_ok());
        assert!(KeyPair::from_keys(&s1, kp0.private()).is_err());
        assert!(KeyPair::from_keys(&s0, kp1.private()).is_err());

        let kp0_keys = KeyPair::from_keys(&s0, kp0.private()).unwrap();
        let kp1_keys = KeyPair::from_keys(&s1, kp1.private()).unwrap();

        assert_eq!(kp0.private(), kp0_keys.private());
        assert_eq!(kp0.public(), kp0_keys.public());
        assert_eq!(kp1.private(), kp1_keys.private());
        assert_eq!(kp1.public(), kp1_keys.public());
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn run_basic_kem_tests() {
        let seed = Seed::generate().unwrap();
        KemTester::<KeyPair, SharedSecret, Ciphertext>::run_all_tests(seed.unprotected_as_ref());
    }

    #[test]
    /// Basic no_std-compatible test.
    fn basic_roundtrip() {
        let seed = Seed::try_from(&[127u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        let (k, c) = kp.public().encap_deterministic(&[255u8; 32]).unwrap();
        let k_prime = kp.private().decap(&c).unwrap();

        assert_eq!(k, k_prime);
    }
}
