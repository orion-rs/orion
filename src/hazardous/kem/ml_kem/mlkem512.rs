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
//! - `m` is not 32 bytes.
//!
//! # Panics:
//! A panic will occur if:
//! - [`getrandom::fill()`] fails during [`KeyPair::generate()`].
//!
//! # Security:
//! - It is critical that both the seed and explicit randomness `m`, used for key generation and encapsulation
//! are generated using a strong CSPRNG.
//! - Users should always prefer encapsulation without specifying explicit randomness, if possible. `encap_deterministic()`
//! exists mainly for `no_std` usage.
//! - Prefer using [`KeyPair`] to create and use ML-KEM keys, which is MAL-BIND-K-CT secure.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::kem::mlkem512::*;
//!
//! let keypair = KeyPair::generate()?;
//!
//! let (sender_shared_secret, sender_ciphertext) = MlKem512::encap(keypair.public())?;
//! let recipient_shared_secret = MlKem512::decap(keypair.private(), &sender_ciphertext)?;
//!
//! assert_eq!(sender_shared_secret, recipient_shared_secret);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`getrandom::fill()`]: getrandom::fill
//! [`encap()`]: mlkem512::MlKem512::encap
//! [`decap()`]: mlkem512::MlKem512::decap
//! [`KeyPair::generate()`]: mlkem512::KeyPair::generate
//! [`KeyPair`]: mlkem512::KeyPair
//! [`Seed`]: mlkem512::Seed
//! [`DecapsulationKey`]: mlkem512::DecapsulationKey
//! [`DecapsulationKey::unchecked_from_slice()`]:  mlkem512::DecapsulationKey::unchecked_from_slice

use crate::errors::UnknownCryptoError;
use crate::hazardous::kem::ml_kem::internal::*;
pub use crate::hazardous::kem::ml_kem::Seed;

construct_secret_key! {
    /// A type to represent the `SharedSecret` that ML-KEM-512 produces.
    ///
    /// This type simply holds bytes. Creating an instance from slices or similar,
    /// performs no checks whatsoever.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (SharedSecret, test_shared_key, MlKem512Internal::SHARED_SECRET_SIZE, MlKem512Internal::SHARED_SECRET_SIZE)
}

impl_from_trait!(SharedSecret, MlKem512Internal::SHARED_SECRET_SIZE);

construct_public! {
    /// A type to represent the KEM `Ciphertext` that ML-KEM-512 returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 768 bytes.
    (Ciphertext, test_kem_ciphertext, MlKem512Internal::CIPHERTEXT_SIZE, MlKem512Internal::CIPHERTEXT_SIZE)
}

impl_from_trait!(Ciphertext, MlKem512Internal::CIPHERTEXT_SIZE);

#[derive(Debug, PartialEq)]
/// A keypair of ML-KEM-512 keys, that are derived from a given seed.
pub struct KeyPair {
    seed: Seed,
    dk: DecapsulationKey,
}

impl KeyPair {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Generate a fresh [KeyPair].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        let seed = Seed::generate();
        let (ek, dk) = KeyPairInternal::<MlKem512Internal>::from_seed::<2, 800, 1632>(&seed)?;

        Ok(Self {
            seed,
            dk: DecapsulationKey {
                value: dk,
                cached_ek: EncapsulationKey { value: ek },
            },
        })
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Instantiate a [KeyPair] with all key validation checks, described
    /// in FIPS-203, Section 7.1, 7.2 and 7.3.
    ///
    /// The output keypair is the equivalent of using `KeyPair::try_from(seed: &Seed)`, but this
    /// can be used, in order to check whether a decapsulation key
    /// is valid in relation to the `seed` provided.
    pub fn from_keys(seed: &Seed, dk: &DecapsulationKey) -> Result<Self, UnknownCryptoError> {
        let unchecked_ek = EncapsulationKey::try_from(dk)?;
        let (ek, dk) = KeyPairInternal::<MlKem512Internal>::from_keys::<2, 800, 1632, 768>(
            seed,
            &unchecked_ek.value,
            &dk.value,
        )?;

        Ok(Self {
            seed: Seed::from_slice(seed.unprotected_as_bytes()).unwrap(),
            dk: DecapsulationKey {
                value: dk,
                cached_ek: EncapsulationKey { value: ek },
            },
        })
    }

    /// Get the [Seed] used to generate this keypair. Use this function in order to store
    /// the private part of the keypair and regenerate it, when needed.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// Get the public [EncapsulationKey] corresponding to this keypair.
    pub fn public(&self) -> &EncapsulationKey {
        &self.dk.cached_ek
    }

    /// Get the private [DecapsulationKey] used to generate this keypair. In order to store the private
    /// part of this [KeyPair], use [KeyPair::seed()] instead.
    pub fn private(&self) -> &DecapsulationKey {
        &self.dk
    }
}

impl TryFrom<&Seed> for KeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &Seed) -> Result<Self, Self::Error> {
        let (ek, dk) = KeyPairInternal::<MlKem512Internal>::from_seed::<2, 800, 1632>(value)?;

        Ok(Self {
            seed: Seed::from_slice(value.unprotected_as_bytes()).unwrap(),
            dk: DecapsulationKey {
                value: dk,
                cached_ek: EncapsulationKey { value: ek },
            },
        })
    }
}

#[derive(Debug, PartialEq)]
/// A type to represent the `DecapsulationKey` that ML-KEM-512 produces.
pub struct DecapsulationKey {
    pub(crate) value: DecapKey<2, 800, 1632, MlKem512Internal>,
    // NOTE(brycx): This is simply a cache of the encapsulation key, so we avoid recomputing it
    // on decap() operations. This is not a part of PartialEq, AsRef<> implementations or other logic
    // pertaining to the `DecapsulationKey`, serving a purely internal purpose.
    pub(crate) cached_ek: EncapsulationKey,
}

impl PartialEq<&[u8]> for DecapsulationKey {
    fn eq(&self, other: &&[u8]) -> bool {
        // Defer to DecapKey<> impl ct-eq
        self.value == *other
    }
}

impl DecapsulationKey {
    /// Instantiate a [DecapsulationKey] with only key-checks from FIPS-203, section 7.3. Not MAL-BIND-K-CT secure.
    pub fn unchecked_from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        let dk_unchecked = DecapKey::<2, 800, 1632, MlKem512Internal>::unchecked_from_slice(slice)?;
        let ek_unchecked =
            EncapsulationKey::from_slice(dk_unchecked.get_encapsulation_key_bytes())?;

        Ok(Self {
            value: dk_unchecked,
            cached_ek: ek_unchecked,
        })
    }

    /// Perform decapsulation of a [Ciphertext].
    pub fn decap(&self, c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
        let mut c_prime_buf = [0u8; MlKem512Internal::CIPHERTEXT_SIZE];
        let mut k_internal = self.value.mlkem_decap_internal_with_ek(
            c.as_ref(),
            &mut c_prime_buf,
            &self.cached_ek.value,
        )?;
        let k = SharedSecret::from_slice(&k_internal)?;
        #[cfg(feature = "zeroize")]
        zeroize_call!(k_internal);

        Ok(k)
    }
}

#[derive(Debug, PartialEq, Clone)]
/// A type to represent the `EncapsulationKey` that ML-KEM-512 returns.
pub struct EncapsulationKey {
    pub(crate) value: EncapKey<2, 800, MlKem512Internal>,
}

impl PartialEq<&[u8]> for EncapsulationKey {
    fn eq(&self, other: &&[u8]) -> bool {
        self.value == *other
    }
}

impl TryFrom<&DecapsulationKey> for EncapsulationKey {
    type Error = UnknownCryptoError;

    fn try_from(value: &DecapsulationKey) -> Result<Self, Self::Error> {
        Ok(Self {
            value: EncapKey::<2, 800, MlKem512Internal>::from_slice(
                value.value.get_encapsulation_key_bytes(),
            )?,
        })
    }
}

impl AsRef<[u8]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl EncapsulationKey {
    /// Instantiate a [EncapsulationKey] with key-checks from FIPS-203, section 7.2.
    pub fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            value: EncapKey::<2, 800, MlKem512Internal>::from_slice(slice)?,
        })
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [EncapsulationKey], generate a [SharedSecret] and associated [Ciphertext].
    pub fn encap(&self) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        let mut m = zeroize_wrap!([0u8; 32]);
        getrandom::fill(m.as_mut())?;

        self.encap_deterministic(m.as_ref())
    }

    /// Given the [EncapsulationKey] and randomness `m`, generate a [SharedSecret] and associated [Ciphertext].
    pub fn encap_deterministic(
        &self,
        m: &[u8],
    ) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        if m.len() != 32 {
            return Err(UnknownCryptoError);
        }

        let mut c = Ciphertext::from_slice(&[0u8; MlKem512Internal::CIPHERTEXT_SIZE])?;
        let mut k_internal = self.value.mlkem_encap_internal(m.as_ref(), &mut c.value)?;
        let k = SharedSecret::from_slice(k_internal.as_slice())?;
        zeroize_call!(k_internal);

        Ok((k, c))
    }
}

#[derive(PartialEq, Debug)]
/// ML-KEM-512.
pub struct MlKem512;

impl MlKem512 {
    /// Encapsulation key size (bytes).
    pub const EK_SIZE: usize = MlKem512Internal::EK_SIZE;
    /// Decapsulation key size (bytes).
    pub const DK_SIZE: usize = MlKem512Internal::DK_SIZE;
    /// Ciphertext size (bytes).
    pub const CIPHERTEXT_SIZE: usize = MlKem512Internal::CIPHERTEXT_SIZE;
    /// Shared Secret size (bytes).
    pub const SHARED_SECRET_SIZE: usize = MlKem512Internal::SHARED_SECRET_SIZE;

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [EncapsulationKey], generate a [SharedSecret] and associated [Ciphertext].
    pub fn encap(ek: &EncapsulationKey) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        ek.encap()
    }

    /// Given the [DecapsulationKey], produce a [SharedSecret] using the [Ciphertext].
    pub fn decap(
        dk: &DecapsulationKey,
        c: &Ciphertext,
    ) -> Result<SharedSecret, UnknownCryptoError> {
        dk.decap(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "safe_api")]
    use crate::test_framework::kem_interface::{KemTester, TestableKem};

    #[cfg(feature = "safe_api")]
    impl TestableKem<SharedSecret, Ciphertext> for MlKem512 {
        fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = KeyPair::try_from(&Seed::from_slice(seed).unwrap()).unwrap();

            Ok((
                kp.dk.cached_ek.as_ref().to_vec(),
                kp.dk.value.unprotected_as_bytes().to_vec(),
            ))
        }

        fn ciphertext_from_bytes(b: &[u8]) -> Result<Ciphertext, UnknownCryptoError> {
            Ciphertext::from_slice(b)
        }

        fn encap(ek: &[u8]) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
            let ek = EncapsulationKey::from_slice(ek).unwrap();
            ek.encap()
        }

        fn decap(dk: &[u8], c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
            let dk = DecapsulationKey::unchecked_from_slice(dk).unwrap();
            dk.decap(c)
        }
    }

    #[test]
    fn test_keypair_dk_ek_match_internal() {
        let seed = Seed::from_slice(&[128u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();
        assert_eq!(kp.public(), &kp.private().cached_ek);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_dk_cached_ek() {
        let seed = Seed::from_slice(&[128u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();
        let (ss_pubapi, ct_pubapi) = kp.public().encap_deterministic(&[125u8; 32]).unwrap();
        let mut c_prime = [0u8; MlKem512Internal::CIPHERTEXT_SIZE];
        // This call re-computes encap key internally from the bytes a decapkey would store.
        let ss_privapi = kp
            .private()
            .value
            .mlkem_decap_internal(ct_pubapi.as_ref(), &mut c_prime)
            .unwrap();
        assert_eq!(ss_privapi.as_ref(), ss_pubapi.unprotected_as_bytes());
        assert_eq!(
            MlKem512::decap(kp.private(), &ct_pubapi).unwrap(),
            ss_pubapi
        );
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_dk_to_ek_conversions() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(
            kp.dk.cached_ek,
            EncapsulationKey::try_from(kp.private()).unwrap()
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
        let s0 = Seed::generate();
        let kp = KeyPair::try_from(&s0).unwrap();

        let dk_bytes = kp.private().value.bytes;
        let ek_bytes = kp.public().value.bytes;

        assert_eq!(
            KeyPair::try_from(&s0).unwrap().private(),
            &dk_bytes.as_ref()
        );
        assert_eq!(KeyPair::try_from(&s0).unwrap().public(), &ek_bytes.as_ref());
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_keypair_from_keys() {
        let s0 = Seed::generate();
        let s1 = Seed::generate();

        let kp0 = KeyPair::try_from(&s0).unwrap();
        let kp1 = KeyPair::try_from(&s1).unwrap();
        assert_eq!(kp0.seed(), &s0);
        assert_eq!(kp1.seed(), &s1);

        assert!(KeyPair::from_keys(&s0, kp0.private()).is_ok());
        assert!(KeyPair::from_keys(&s1, kp1.private()).is_ok());
        assert!(KeyPair::from_keys(&s1, kp0.private()).is_err());
        assert!(KeyPair::from_keys(&s0, kp1.private()).is_err());

        let kp0_keys = KeyPair::from_keys(&s0, kp0.private()).unwrap();
        let kp1_keys = KeyPair::from_keys(&s1, kp1.private()).unwrap();
        assert_eq!(kp0.seed(), kp0_keys.seed());
        assert_eq!(kp1.seed(), kp1_keys.seed());

        assert_eq!(kp0.private(), kp0_keys.private());
        assert_eq!(kp0.public(), kp0_keys.public());
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn run_basic_kem_tests() {
        let seed = Seed::generate();
        KemTester::<MlKem512, SharedSecret, Ciphertext>::run_all_tests(seed.unprotected_as_bytes());
    }

    #[test]
    /// Basic no_std-compatible test.
    fn basic_roundtrip() {
        let seed = Seed::from_slice(&[127u8; 64]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        let (k, c) = kp.public().encap_deterministic(&[255u8; 32]).unwrap();
        let k_prime = kp.private().decap(&c).unwrap();

        assert_eq!(k, k_prime);
    }
}
