// MIT License

// Copyright (c) 2025 The orion Developers

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
//! - `ek`: The public encapsulation key, for which a shared secret and ciphertext is generated.
//! - `dk`: The secret decapsulation key, for which a ciphertext is used to derive a shared secret.
//! - `c`: The public ciphertext, sent to the decapsulating party.
//! - `eseed`: Explicit randomness used for encapsulation.
//!
//! # Errors:
//! An error will be returned if:
//! - `eseed` is not 64 bytes.
//! - [`getrandom::fill()`] fails during encapsulation.
//!
//! # Panics:
//! A panic will occur if:
//! - [`getrandom::fill()`] fails during [`KeyPair::generate()`].
//!
//! # Security:
//! - It is critical that both the seed and explicit randomness `eseed`, used for key generation and encapsulation
//! are generated using a strong CSPRNG.
//! - Users should always prefer encapsulation without specifying explicit randomness, if possible. `encap_deterministic()`
//! exists mainly for `no_std` usage.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::kem::xwing::*;
//!
//! let keypair = KeyPair::generate()?;
//!
//! let (sender_shared_secret, sender_ciphertext) = XWing::encap(keypair.public())?;
//! let recipient_shared_secret = XWing::decap(keypair.private(), &sender_ciphertext)?;
//!
//! assert_eq!(sender_shared_secret, recipient_shared_secret);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`getrandom::fill()`]: getrandom::fill
//! [`KeyPair::generate()`]: mlkem1024::KeyPair::generate

use crate::errors::UnknownCryptoError;
use crate::hazardous::ecc::x25519;
use crate::hazardous::hash::sha3::sha3_256;
use crate::hazardous::hash::sha3::shake256::Shake256;
use crate::hazardous::kem::ml_kem::mlkem768;
use zeroize::Zeroizing;

/// Size of private [DecapsulationKey].
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of public [EncapsulationKey].
pub const PUBLIC_KEY_SIZE: usize = 1216;

/// Size of public [Ciphertext].
pub const CIPHERTEXT_SIZE: usize = 1120;

/// Size of private [SharedSecret].
pub const SHARED_SECRET_SIZE: usize = 32;

construct_public! {
    /// A type to represent the public `EncapsulationKey` that X-Wing uses.
    ///
    /// This type simply holds bytes and performs no checks whatsoever. If a invalid
    /// ML-KEM-768 is part of the bytes parsed from this type, the check will first surface
    /// when encapsulation is performed.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 1216 bytes.
    (EncapsulationKey, test_kem_encapkey, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE)
}

impl_from_trait!(EncapsulationKey, PUBLIC_KEY_SIZE);

construct_public! {
    /// A type to represent the KEM `Ciphertext` that X-Wing returns.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 1120 bytes.
    (Ciphertext, test_kem_ciphertext, CIPHERTEXT_SIZE, CIPHERTEXT_SIZE)
}

impl_from_trait!(Ciphertext, CIPHERTEXT_SIZE);

construct_secret_key! {
    /// A type to represent the private `SharedSecret` that X-Wing returns.
    ///
    /// This type simply holds bytes. Creating an instance from slices or similar,
    /// performs no checks whatsoever.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (SharedSecret, test_sharedsecret_key, SHARED_SECRET_SIZE, SHARED_SECRET_SIZE)
}

impl_from_trait!(SharedSecret, SHARED_SECRET_SIZE);

construct_secret_key! {
    /// A type to represent the private `Seed` that X-Wing uses.
    ///
    /// This type simply holds bytes. Creating an instance from slices or similar,
    /// performs no checks whatsoever.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (Seed, test_seed, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE)
}

impl_from_trait!(Seed, PRIVATE_KEY_SIZE);

#[derive(Debug, PartialEq)]
/// A type to represent the `DecapsulationKey` that X-Wing produces.
/// This type's foremost responsibility is to cache key-expansions,
/// to be re-used across multiple decapsulations with a single secret.
///
/// Calling [DecapsulationKey::unprotected_as_bytes] is equivalent to
/// calling [Seed::unprotected_as_bytes].
pub struct DecapsulationKey {
    seed: Seed,
    kp_m: mlkem768::KeyPair,
    sk_x: x25519::PrivateKey,
    pk_x: x25519::PublicKey,
}

impl DecapsulationKey {
    #[inline]
    /// Return the object as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.seed.unprotected_as_bytes()
    }
}

#[derive(Debug, PartialEq)]
/// A keypair of X-Wing keys.
pub struct KeyPair {
    ek: EncapsulationKey,
    dk: DecapsulationKey,
}

impl TryFrom<&Seed> for KeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &Seed) -> Result<Self, Self::Error> {
        KeyPair::generate_deterministic(value)
    }
}

impl KeyPair {
    /// Deterministically generate a [KeyPair] from a private [Seed].
    pub fn generate_deterministic(seed: &Seed) -> Result<Self, UnknownCryptoError> {
        let mut expanded = Zeroizing::new([0u8; 96]);

        let mut shake = Shake256::new();
        shake.absorb(seed.unprotected_as_bytes())?;
        shake.squeeze(expanded.as_mut())?;

        let seed_m = mlkem768::Seed::from_slice(&expanded[..64])?;
        let kp_m = mlkem768::KeyPair::try_from(&seed_m)?;
        let sk_x = x25519::PrivateKey::from_slice(&expanded[64..96])?;
        let pk_x = x25519::PublicKey::try_from(&sk_x)?;

        let mut xwing_pk = [0u8; mlkem768::MlKem768::EK_SIZE + x25519::PUBLIC_KEY_SIZE];
        xwing_pk[..mlkem768::MlKem768::EK_SIZE].copy_from_slice(kp_m.public().as_ref());
        xwing_pk[mlkem768::MlKem768::EK_SIZE..].copy_from_slice(&pk_x.to_bytes());

        Ok(Self {
            ek: EncapsulationKey::from(xwing_pk),
            dk: DecapsulationKey {
                seed: Seed::from_slice(seed.unprotected_as_bytes())?,
                kp_m,
                sk_x,
                pk_x,
            },
        })
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Generate a fresh [KeyPair].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        let seed = Seed::generate();
        Self::generate_deterministic(&seed)
    }

    /// Get the public [EncapsulationKey] corresponding to this keypair.
    pub fn public(&self) -> &EncapsulationKey {
        &self.ek
    }

    /// Get the private [DecapsulationKey] used to generate this keypair.
    pub fn private(&self) -> &DecapsulationKey {
        &self.dk
    }
}

#[derive(Debug, PartialEq)]
/// X-Wing hybrid KEM.
pub struct XWing;

impl XWing {
    const LABEL: &[u8; 6] = b"\\.//^\\";

    fn combiner(
        ss_m: &[u8],
        ss_x: &[u8],
        ct_x: &[u8],
        pk_x: &[u8],
    ) -> Result<SharedSecret, UnknownCryptoError> {
        let mut ctx = sha3_256::Sha3_256::new();
        ctx.update(ss_m)?;
        ctx.update(ss_x)?;
        ctx.update(ct_x)?;
        ctx.update(pk_x)?;
        ctx.update(Self::LABEL)?;

        let mut digest = Zeroizing::new([0u8; 32]);
        ctx._finalize_internal(digest.as_mut())?;

        Ok(SharedSecret::from(*digest))
    }

    /// Given the [EncapsulationKey] and securely generated randomness `eseed`, generate a [SharedSecret] and associated [Ciphertext].
    pub fn encap_deterministic(
        ek: &EncapsulationKey,
        eseed: &[u8],
    ) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        if eseed.len() != 64 {
            return Err(UnknownCryptoError);
        }

        let pk_m = &ek.as_ref()[..mlkem768::MlKem768::EK_SIZE];
        let pk_x = &ek.as_ref()[mlkem768::MlKem768::EK_SIZE..];
        let ek_x = x25519::PrivateKey::from_slice(&eseed[32..64])?;
        let ct_x = x25519::PublicKey::try_from(&ek_x)?.to_bytes();
        let ss_x = x25519::key_agreement(&ek_x, &x25519::PublicKey::from_slice(pk_x)?)?;
        let mlkem768_encapkey = mlkem768::EncapsulationKey::from_slice(pk_m)?;
        let (ss_m, ct_m) = mlkem768_encapkey.encap_deterministic(&eseed[..32])?;
        let ss = Self::combiner(
            ss_m.unprotected_as_bytes(),
            ss_x.unprotected_as_bytes(),
            &ct_x,
            pk_x,
        )?;

        let mut ct = [0u8; mlkem768::MlKem768::CIPHERTEXT_SIZE + x25519::PUBLIC_KEY_SIZE];
        ct[..mlkem768::MlKem768::CIPHERTEXT_SIZE].copy_from_slice(ct_m.as_ref());
        ct[mlkem768::MlKem768::CIPHERTEXT_SIZE..].copy_from_slice(&ct_x);

        Ok((ss, Ciphertext::from(ct)))
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [EncapsulationKey], generate a [SharedSecret] and associated [Ciphertext].
    pub fn encap(ek: &EncapsulationKey) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        let mut eseed = Zeroizing::new([0u8; 64]);
        getrandom::fill(eseed.as_mut())?;

        Self::encap_deterministic(ek, eseed.as_ref())
    }

    /// Given the [DecapsulationKey], produce a [SharedSecret] using the [Ciphertext].
    pub fn decap(
        dk: &DecapsulationKey,
        c: &Ciphertext,
    ) -> Result<SharedSecret, UnknownCryptoError> {
        let ct_m = &c.as_ref()[..mlkem768::MlKem768::CIPHERTEXT_SIZE];
        let ct_x = &c.as_ref()[mlkem768::MlKem768::CIPHERTEXT_SIZE..];

        let ss_m =
            mlkem768::MlKem768::decap(dk.kp_m.private(), &mlkem768::Ciphertext::from_slice(ct_m)?)?;
        let ss_x = x25519::key_agreement(&dk.sk_x, &x25519::PublicKey::from_slice(ct_x)?)?;

        Self::combiner(
            ss_m.unprotected_as_bytes(),
            ss_x.unprotected_as_bytes(),
            ct_x,
            &dk.pk_x.to_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "safe_api")]
    use crate::test_framework::kem_interface::{KemTester, TestableKem};

    #[cfg(feature = "safe_api")]
    impl TestableKem<SharedSecret, Ciphertext> for XWing {
        fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = KeyPair::try_from(&Seed::from_slice(seed).unwrap()).unwrap();

            Ok((
                kp.ek.as_ref().to_vec(),
                kp.dk.unprotected_as_bytes().to_vec(),
            ))
        }

        fn parse_encap_key(ek: &[u8]) -> Result<(), UnknownCryptoError> {
            EncapsulationKey::from_slice(ek)?;

            Ok(())
        }

        fn parse_decap_key(dk: &[u8]) -> Result<(), UnknownCryptoError> {
            Seed::from_slice(dk)?;

            Ok(())
        }

        fn ciphertext_from_bytes(b: &[u8]) -> Result<Ciphertext, UnknownCryptoError> {
            Ciphertext::from_slice(b)
        }

        fn encap(ek: &[u8]) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
            let ek = EncapsulationKey::from_slice(ek).unwrap();
            XWing::encap(&ek)
        }

        fn decap(dk: &[u8], c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
            let kp = KeyPair::try_from(&Seed::from_slice(dk)?).unwrap();
            XWing::decap(kp.private(), c)
        }
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn run_basic_kem_tests() {
        let seed = Seed::generate();
        KemTester::<XWing, SharedSecret, Ciphertext>::run_all_tests(seed.unprotected_as_bytes());
    }

    #[test]
    /// Basic no_std-compatible test.
    fn basic_roundtrip() {
        let seed = Seed::from_slice(&[127u8; 32]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        let (k, c) = XWing::encap_deterministic(kp.public(), &[255u8; 64]).unwrap();
        let k_prime = XWing::decap(kp.private(), &c).unwrap();

        assert_eq!(k, k_prime);
    }

    #[test]
    fn get_decapskey_as_bytes_is_seed() {
        let seed = Seed::from_slice(&[127u8; 32]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        assert_eq!(
            seed.unprotected_as_bytes(),
            kp.private().unprotected_as_bytes()
        );
    }

    #[test]
    fn bad_eseed_lens() {
        let seed = Seed::from_slice(&[127u8; 32]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        assert!(XWing::encap_deterministic(kp.public(), &[255u8; 64]).is_ok());
        assert!(XWing::encap_deterministic(kp.public(), &[255u8; 63]).is_err());
        assert!(XWing::encap_deterministic(kp.public(), &[255u8; 65]).is_err());
    }
}
