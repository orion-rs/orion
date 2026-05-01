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

//! ### X-Wing key usage recommendations
//!
//! In general, it is highly recommended to use the [`KeyPair`] type to deal with decapsulating operations, or decapsulation keys in general.
//! [`KeyPair`] internally caches the [`EncapsulationKey`]s used during decapsulation, making it more efficient when used to decapsulate multiple
//! KEM ciphertext with a given private [`DecapsulationKey`].
//!
//! # Parameters:
//! - `ek`: The public encapsulation key, for which a shared secret and ciphertext is generated.
//! - `dk`: The secret decapsulation key, for which a ciphertext is used to derive a shared secret.
//! - `c`: The public ciphertext, sent to the decapsulating party.
//! - `eseed`: Explicit randomness used for encapsulation.
//!
//! # Errors:
//! An error will be returned if:
//! - `eseed` is not 64 bytes.
//! - [`getrandom::fill()`] fails during [`EncapsulationKey::encap()`].
//! - [`getrandom::fill()`] fails during [`DecapsulationKey::generate()`]/[`KeyPair::generate()`].
//!
//! # Security:
//! - It is critical that both the seed and explicit randomness `eseed`, used for key generation and encapsulation
//! are generated using a strong CSPRNG.
//! - Users should always prefer encapsulation without specifying explicit randomness, if possible.
//! [`EncapsulationKey::encap_deterministic()`] exists mainly for `no_std` usage.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::KP;
//! use orion::hazardous::kem::xwing::*;
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
//! [`DecapsulationKey::generate()`]: xwing::DecapsulationKey::generate
//! [`KeyPair::generate()`]: xwing::KeyPair::generate
//! [`EncapsulationKey::encap()`]: xwing::EncapsulationKey::encap
//! [`EncapsulationKey::encap_deterministic()`]: xwing::EncapsulationKey::encap_deterministic
//! [`KeyPair`]: xwing::KeyPair
//! [`DecapsulationKey`]: xwing::DecapsulationKey
//! [`EncapsulationKey`]: xwing::EncapsulationKey

use crate::KP;
use crate::errors::UnknownCryptoError;
use crate::generics::GenerateSecret;
use crate::generics::sealed::Sealed;
use crate::generics::{ByteArrayData, Public, Secret, TypeSpec, sealed::Data};
use crate::hazardous::ecc::x25519;
use crate::hazardous::hash::sha3::sha3_256;
use crate::hazardous::hash::sha3::shake256::Shake256;
use crate::hazardous::kem::ml_kem::{self, mlkem768};

/// KEM-label used by X-Wing.
const LABEL: &[u8; 6] = b"\\.//^\\";

/// Size of private [`EncapsulationKey`].
pub const EK_SIZE: usize = 1216;

/// Size of public [`DecapsulationKey`].
pub const DK_SIZE: usize = 32;

/// Size of public [`Ciphertext`].
pub const CIPHERTEXT_SIZE: usize = 1120;

/// Size of private [`SharedSecret`].
pub const SHARED_SECRET_SIZE: usize = 32;

/// X-Wing encapsulation key.
pub type EncapsulationKey = Public<XWingEncapKey>;

/// X-Wing ciphertext.
pub type Ciphertext = Public<XWingCiphertext>;

/// X-Wing decapsulation key.
pub type DecapsulationKey = Secret<XWingDecapKey>;

/// X-Wing shared secret.
pub type SharedSecret = Secret<XWingSharedSecret>;

#[derive(Debug, Clone, Copy)]
/// X-Wing encapsulation key implementation. See [`EncapsulationKey`] type for convenience.
///
///
/// **SECURITY**: This type performs ML-KEM-768 key-checks and no checks for the X25519 part.
pub struct XWingEncapKey {}
impl Sealed for XWingEncapKey {}

impl TypeSpec for XWingEncapKey {
    const NAME: &'static str = stringify!(EncapsulationKey);
    type TypeData = ByteArrayData<EK_SIZE>;

    // Perform FIPS-203 Encapsulation Key checks, with without allocating
    // an actual EncapKey, to save work. It will be properly expanded later anyway.
    fn parse_bytes(bytes: &[u8]) -> Result<Self::TypeData, UnknownCryptoError> {
        use crate::hazardous::kem::ml_kem::internal::PkeParameters;

        let ek: [u8; EK_SIZE] = bytes.try_into().map_err(|_| UnknownCryptoError)?;
        ml_kem::internal::MlKem768Internal::encapsulation_key_check(&ek[..mlkem768::EK_SIZE])?;

        Ok(Self::TypeData::from(ek))
    }
}

#[derive(Debug)]
/// X-Wing decapsulation key implementation. See [`DecapsulationKey`] type for convenience.
pub struct XWingDecapKey {}
impl Sealed for XWingDecapKey {}

impl TypeSpec for XWingDecapKey {
    const NAME: &'static str = stringify!(DecapsulationKey);
    type TypeData = ByteArrayData<DK_SIZE>;
}

impl From<[u8; DK_SIZE]> for Secret<XWingDecapKey> {
    fn from(value: [u8; DK_SIZE]) -> Self {
        Self::from_data(<XWingDecapKey as TypeSpec>::TypeData::from(value))
    }
}

impl GenerateSecret for XWingDecapKey {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    fn generate() -> Result<Secret<XWingDecapKey>, UnknownCryptoError> {
        let mut data = Self::TypeData::new(DK_SIZE)?;
        crate::util::secure_rand_bytes(&mut data.bytes)?;
        Ok(Secret::from_data(data))
    }
}

#[derive(Debug, Clone, Copy)]
/// X-Wing ciphertext implementation. See [`Ciphertext`] type for convenience.
pub struct XWingCiphertext {}
impl Sealed for XWingCiphertext {}

impl TypeSpec for XWingCiphertext {
    const NAME: &'static str = stringify!(Ciphertext);
    type TypeData = ByteArrayData<CIPHERTEXT_SIZE>;
}

impl From<[u8; CIPHERTEXT_SIZE]> for Public<XWingCiphertext> {
    fn from(value: [u8; CIPHERTEXT_SIZE]) -> Self {
        Self::from_data(<XWingCiphertext as TypeSpec>::TypeData::from(value))
    }
}

#[derive(Debug)]
/// X-Wing shared secret implementation. See [`SharedSecret`] type for convenience.
pub struct XWingSharedSecret {}
impl Sealed for XWingSharedSecret {}

impl TypeSpec for XWingSharedSecret {
    const NAME: &'static str = stringify!(XWingSharedSecret);
    type TypeData = ByteArrayData<SHARED_SECRET_SIZE>;
}

impl From<[u8; SHARED_SECRET_SIZE]> for Secret<XWingSharedSecret> {
    fn from(value: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self::from_data(<XWingSharedSecret as TypeSpec>::TypeData::from(value))
    }
}

impl TryFrom<&DecapsulationKey> for EncapsulationKey {
    type Error = UnknownCryptoError;

    fn try_from(value: &DecapsulationKey) -> Result<Self, Self::Error> {
        let kp = value.expand_into_keypair()?;

        Ok(kp.public)
    }
}

/// [Section 5.3 - Combiner](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html#section-5.3).
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
    ctx.update(LABEL)?;

    let mut shared_secret = Secret::<XWingSharedSecret>::from_data(
        <XWingSharedSecret as TypeSpec>::TypeData::new(SHARED_SECRET_SIZE)?,
    );

    ctx._finalize_internal(&mut shared_secret.data.bytes)?;

    Ok(shared_secret)
}

impl EncapsulationKey {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Given the [`EncapsulationKey`], generate a [`SharedSecret`] and associated [`Ciphertext`].
    pub fn encap(&self) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        let mut m = zeroize_wrap!([0u8; 64]);
        getrandom::fill(m.as_mut())?;

        self.encap_deterministic(m.as_ref())
    }

    /// Given the [`EncapsulationKey`] and securely generated randomness `eseed`, generate a [`SharedSecret`] and associated [`Ciphertext`].
    pub fn encap_deterministic(
        &self,
        eseed: &[u8],
    ) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
        if eseed.len() != 64 {
            return Err(UnknownCryptoError);
        }

        let pk_m = &self.data.bytes[..mlkem768::EK_SIZE];
        let pk_x = &self.data.bytes[mlkem768::EK_SIZE..];
        let ek_x = x25519::PrivateKey::try_from(&eseed[32..64])?;
        let ct_x = x25519::PublicKey::try_from(&ek_x)?;
        let ss_x = x25519::key_agreement(&ek_x, &x25519::PublicKey::try_from(pk_x)?)?;
        let mlkem768_encapkey = mlkem768::EncapsulationKey::try_from(pk_m)?;
        let (ss_m, ct_m) = mlkem768_encapkey.encap_deterministic(&eseed[..32])?;
        let ss = combiner(
            ss_m.unprotected_as_ref(),
            ss_x.unprotected_as_ref(),
            ct_x.as_ref(),
            pk_x,
        )?;

        let mut ct = Public::<XWingCiphertext>::from_data(
            <XWingCiphertext as TypeSpec>::TypeData::new(CIPHERTEXT_SIZE)?,
        );

        ct.data.bytes[..mlkem768::CIPHERTEXT_SIZE].copy_from_slice(ct_m.as_ref());
        ct.data.bytes[mlkem768::CIPHERTEXT_SIZE..].copy_from_slice(ct_x.as_ref());

        Ok((ss, ct))
    }
}

impl DecapsulationKey {
    /// Equivalent to [Section 5.2 - Key generation](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html#section-5.2).
    fn expand_into_keypair(&self) -> Result<KeyPair, UnknownCryptoError> {
        let mut expanded = zeroize_wrap!([0u8; 96]);

        let mut shake = Shake256::new();
        shake.absorb(self.data.as_ref())?;
        shake.squeeze(expanded.as_mut())?;

        let seed_m = mlkem768::Seed::try_from(&expanded[..64])?;
        let kp_m = mlkem768::KeyPair::new(seed_m)?;
        let sk_x = x25519::PrivateKey::try_from(&expanded[64..96])?;
        let pk_x = x25519::PublicKey::try_from(&sk_x)?;

        let mut xwing_pk = Public::<XWingEncapKey>::from_data(
            <XWingEncapKey as TypeSpec>::TypeData::new(EK_SIZE)?,
        );

        xwing_pk.data.bytes[..mlkem768::EK_SIZE].copy_from_slice(kp_m.public().as_ref());
        xwing_pk.data.bytes[mlkem768::EK_SIZE..].copy_from_slice(pk_x.as_ref());

        Ok(KeyPair {
            private: DecapsulationKey::from_data(self.data.clone()),
            public: xwing_pk,
            kp_m,
            sk_x,
            pk_x,
        })
    }

    /// Perform decapsulation of a [`Ciphertext`].
    pub fn decap(&self, c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
        let kp = self.expand_into_keypair()?;
        let ct_m = &c.as_ref()[..mlkem768::CIPHERTEXT_SIZE];
        let ct_x = &c.as_ref()[mlkem768::CIPHERTEXT_SIZE..];

        let ss_m = kp.kp_m.decap(&mlkem768::Ciphertext::try_from(ct_m)?)?;
        let ss_x = x25519::key_agreement(&kp.sk_x, &x25519::PublicKey::try_from(ct_x)?)?;

        combiner(
            ss_m.unprotected_as_ref(),
            ss_x.unprotected_as_ref(),
            ct_x,
            kp.pk_x.as_ref(),
        )
    }
}

#[derive(Debug, PartialEq)]
/// X-Wing keypair.
///
/// This type uses cached encapsulation keys, saving the computation involved when doing decapsulation.
/// Meaning, once [`KeyPair`] has been instantiated, it is more efficient to use for decapsulation
/// than the [`DecapsulationKey`] type directly.
pub struct KeyPair {
    private: DecapsulationKey,
    public: EncapsulationKey,
    // The following variants are kept for caching purposes.
    kp_m: mlkem768::KeyPair,
    sk_x: x25519::PrivateKey,
    pk_x: x25519::PublicKey,
}

impl KP<XWingDecapKey, XWingEncapKey> for KeyPair {
    fn public(&self) -> &EncapsulationKey {
        &self.public
    }

    fn private(&self) -> &DecapsulationKey {
        &self.private
    }
}

impl TryFrom<&DecapsulationKey> for KeyPair {
    type Error = UnknownCryptoError;

    fn try_from(value: &DecapsulationKey) -> Result<Self, Self::Error> {
        value.expand_into_keypair()
    }
}

impl KeyPair {
    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Generate a fresh [`KeyPair`].
    pub fn generate() -> Result<Self, UnknownCryptoError> {
        DecapsulationKey::generate()?.expand_into_keypair()
    }

    /// Perform decapsulation of a [`Ciphertext`], using internally cached [`EncapsulationKey`].
    pub fn decap(&self, c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
        let ct_m = &c.as_ref()[..mlkem768::CIPHERTEXT_SIZE];
        let ct_x = &c.as_ref()[mlkem768::CIPHERTEXT_SIZE..];

        let ss_m = self.kp_m.decap(&mlkem768::Ciphertext::try_from(ct_m)?)?;
        let ss_x = x25519::key_agreement(&self.sk_x, &x25519::PublicKey::try_from(ct_x)?)?;

        combiner(
            ss_m.unprotected_as_ref(),
            ss_x.unprotected_as_ref(),
            ct_x,
            self.pk_x.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // NOTE: The spec operates on arbitrary bytes for encapsulation keys.
    // Internally, X25519 should ignore hibit, but since the raw bytes are
    // also used in hash-combiner, there can be a difference, meaning two
    // different shared secrets from two encapsulation keys where only hibit
    // of X25519 part differ!
    // The spec mentions nothing about canocnicality.
    fn test_highbit_not_ignored_in_x25519_parts_pk() {
        let eseed = &[111u8; 64];
        let dk = DecapsulationKey::try_from(&[127u8; DK_SIZE]).unwrap();
        let ek = EncapsulationKey::try_from(&dk).unwrap();
        let kp = KeyPair::try_from(&dk).unwrap();
        assert_eq!(&ek, kp.public());

        let (ss, _) = ek.encap_deterministic(eseed).unwrap();

        // Modify hibit in X25519-part of X-Wing key
        let mut ek_hibit_zero = ek.clone();
        ek_hibit_zero.data.bytes[EK_SIZE - 1] &= 0x7F;
        let mut ek_hibit_one = ek.clone();
        ek_hibit_one.data.bytes[EK_SIZE - 1] |= 0x80;

        let (ss_zero, _) = ek_hibit_zero.encap_deterministic(eseed).unwrap();
        let (ss_one, _) = ek_hibit_one.encap_deterministic(eseed).unwrap();

        assert_ne!(&ss_zero, &ss_one);
        // Our generated one is always masked
        assert_eq!(ek.data.bytes[EK_SIZE - 1] & 0x80, 0);
        assert_eq!(&ss, &ss_zero);
    }

    #[test]
    // NOTE: The spec operates on arbitrary bytes for ciphertexts.
    // Internally, X25519 should ignore hibit, but since the raw bytes are
    // also used in hash-combiner, there can be a difference, meaning two
    // different shared secrets from two ciphertexts where only hibit
    // of X25519 part differ!
    fn test_highbit_not_ignored_in_x25519_parts_ct() {
        let eseed = &[111u8; 64];
        let dk = DecapsulationKey::try_from(&[127u8; DK_SIZE]).unwrap();
        let kp = KeyPair::try_from(&dk).unwrap();
        assert_eq!(&dk, kp.private());
        let (ss, ct) = kp.public().encap_deterministic(eseed).unwrap();

        // Modify hibit in X25519-part of X-Wing ciphertext
        let mut ct_hibit_zero = ct.clone();
        ct_hibit_zero.data.bytes[CIPHERTEXT_SIZE - 1] &= 0x7F;

        let mut ct_hibit_one = ct.clone();
        ct_hibit_one.data.bytes[CIPHERTEXT_SIZE - 1] |= 0x80;

        let ss_zero = kp.decap(&ct_hibit_zero).unwrap();
        let ss_one = kp.decap(&ct_hibit_one).unwrap();

        assert_ne!(&ss_zero, &ss_one);
        // Our generated one is always masked
        assert_eq!(ct.data.bytes[CIPHERTEXT_SIZE - 1] & 0x80, 0);
        assert_eq!(&ss, &ss_zero);
    }

    #[test]
    fn test_higbit_handling_consistency_circl() {
        // These test vectors have been generated with Cloudflare CIRCL github.com/cloudflare/circl v1.6.3
        // to ensure the X25519 canonicality is handled the same way.
        let mut seed = [0u8; DK_SIZE];
        let mut eseed = [0u8; 64];
        let mut ct0 = [0u8; CIPHERTEXT_SIZE];
        let mut ct1 = [0u8; CIPHERTEXT_SIZE];
        let mut ek0 = [0u8; EK_SIZE];
        let mut ek1 = [0u8; EK_SIZE];
        let mut ss_ct0 = [0u8; SHARED_SECRET_SIZE];
        let mut ss_ct1 = [0u8; SHARED_SECRET_SIZE];
        let mut ss_ek0 = [0u8; SHARED_SECRET_SIZE];
        let mut ss_ek1 = [0u8; SHARED_SECRET_SIZE];

        hex::decode_to_slice(
            "babababababababababababababababababababababababababababababababa",
            &mut seed,
        )
        .unwrap();
        hex::decode_to_slice("abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab", &mut eseed).unwrap();
        hex::decode_to_slice("a4c2e17f7c9961c9d78771605e5620ba80502305bb07b22ef5dd35b7483d78eed714fc7060e08fdcaf46a726a3ae66043f709098bfe8980a87b4435878ce4551c8470289b64f158245ed91407bb2ddd754006548666d5999916c3feef8867fcd4f94a0bba5be3810ec13348ca93679020cc9b2a247c69a31520fe42fed5778907b9dfc3fffb7d8e79e4eac4eb9b034f0c9fa9037c5e6f3aa0e69661eba51d721539dfd71eac8f8a26220c710e8bea9ebbc82292f1d3cad8368b6f577f6e300a2125024f2b1a3c175efea0268f5ad68b28636954c3e8e68e5389eb6bd7e7725e467e0169ced4a8ee19992a1bffb539545be100071620d585867d9a9fd3773b5edf80b43fe7258b2df7ee6c2ab9e76c1b0cd6e39a10bb6060fb310a9e71d54ff4685616d9bf404377b47dbbe059ddfcbf6bf2c608851a6aee2a9f94ef0b7f86c249d2c186a514930f1725eeb0310dced247c74dc0f4d0b3a21880e28bb5bc9b203e674c373ffd20e8e8b4795499da8abc177de3c7fc99fc121b014d9288d5bf4e9cde18b7273722aedfaeca7804bf9a3ead7a066c9018fcc0e51280254641752f54a6600118644ab46f5add39cee3009774e488052b84c854e199833bc22238bbd70b645556c3a5b542ee4b8a69c15aec8a3c3db01e1e3ec8642207110c998c7d09ffe4417443f41c61490c210316c656d7a60063c20ebb9b56eb4b7e228a2a1b10044413ba563fccb1e6d1ba4d58823cb8d70bb28b6f76d428c9cee6036f53d8560a69b1dbec521af0c1c00badd504c71c0c9dfb974ffc4ae414487770f657cca648f98621aafa142bd11225cc4ba96a61d9df48fc6a553422ece6727e09c2cf4282fd2e9d03f2ca78797341119a4ef247176978eba2b0a5650d652012dd5632d98efd4cd98952762a90a4321d6ccb5b320a5a4f6191287887f29214415e7cec7a84120344110a0a8097bf5d6f147eddd1df1e545670f7f9bd4f06b167ded2a1265d74fadf8b511a93602e33bd4f288b22e00b316935739c25f2ff759d2caa64290040bbe4e43827f24230eaeba5dbd1ed91b93477fad7c0f684d80522c6573c91368334d933ad2b427222da05cbfff5e43bc9ffd243f5fca6771e0faa76cc3fcdaf59e0496708a05e7f62fa9f5b3978ec61e622552864518eafc8797b599ac7884e2c6aa9ae760c5c3fdc227a88d6d1c2848e4585efa3c635b2d68049726ed5d852f93755f7e9095584edf2761dbd37c78387faaccba3872c0bc0286ab4036ac223cb81ca2397b6c95751f3b0a85de92d5c5c6646cdc3aa79e3d90c3f54a398b9fde574d81ba34e62f2173ffe6989c0c0dfec846acec38f8293b0fdf6e733c739ff68c76a4df0271e42bd0bc64ae3585e5e649f5399d3e97443c1fdf554f2d93faa2a4abc5c35a0640e314faa9dd8d8fc56720704af30c4758096b99bf9040965424ed4f79569564c86b05527017608433271165818ed852e5e0740ca7c0ba5f0a5c6b56f00e216c4aaf0394b151fb0b1ac0f5f061af0999fe49274797a63819e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859", &mut ct0).unwrap();
        hex::decode_to_slice("a4c2e17f7c9961c9d78771605e5620ba80502305bb07b22ef5dd35b7483d78eed714fc7060e08fdcaf46a726a3ae66043f709098bfe8980a87b4435878ce4551c8470289b64f158245ed91407bb2ddd754006548666d5999916c3feef8867fcd4f94a0bba5be3810ec13348ca93679020cc9b2a247c69a31520fe42fed5778907b9dfc3fffb7d8e79e4eac4eb9b034f0c9fa9037c5e6f3aa0e69661eba51d721539dfd71eac8f8a26220c710e8bea9ebbc82292f1d3cad8368b6f577f6e300a2125024f2b1a3c175efea0268f5ad68b28636954c3e8e68e5389eb6bd7e7725e467e0169ced4a8ee19992a1bffb539545be100071620d585867d9a9fd3773b5edf80b43fe7258b2df7ee6c2ab9e76c1b0cd6e39a10bb6060fb310a9e71d54ff4685616d9bf404377b47dbbe059ddfcbf6bf2c608851a6aee2a9f94ef0b7f86c249d2c186a514930f1725eeb0310dced247c74dc0f4d0b3a21880e28bb5bc9b203e674c373ffd20e8e8b4795499da8abc177de3c7fc99fc121b014d9288d5bf4e9cde18b7273722aedfaeca7804bf9a3ead7a066c9018fcc0e51280254641752f54a6600118644ab46f5add39cee3009774e488052b84c854e199833bc22238bbd70b645556c3a5b542ee4b8a69c15aec8a3c3db01e1e3ec8642207110c998c7d09ffe4417443f41c61490c210316c656d7a60063c20ebb9b56eb4b7e228a2a1b10044413ba563fccb1e6d1ba4d58823cb8d70bb28b6f76d428c9cee6036f53d8560a69b1dbec521af0c1c00badd504c71c0c9dfb974ffc4ae414487770f657cca648f98621aafa142bd11225cc4ba96a61d9df48fc6a553422ece6727e09c2cf4282fd2e9d03f2ca78797341119a4ef247176978eba2b0a5650d652012dd5632d98efd4cd98952762a90a4321d6ccb5b320a5a4f6191287887f29214415e7cec7a84120344110a0a8097bf5d6f147eddd1df1e545670f7f9bd4f06b167ded2a1265d74fadf8b511a93602e33bd4f288b22e00b316935739c25f2ff759d2caa64290040bbe4e43827f24230eaeba5dbd1ed91b93477fad7c0f684d80522c6573c91368334d933ad2b427222da05cbfff5e43bc9ffd243f5fca6771e0faa76cc3fcdaf59e0496708a05e7f62fa9f5b3978ec61e622552864518eafc8797b599ac7884e2c6aa9ae760c5c3fdc227a88d6d1c2848e4585efa3c635b2d68049726ed5d852f93755f7e9095584edf2761dbd37c78387faaccba3872c0bc0286ab4036ac223cb81ca2397b6c95751f3b0a85de92d5c5c6646cdc3aa79e3d90c3f54a398b9fde574d81ba34e62f2173ffe6989c0c0dfec846acec38f8293b0fdf6e733c739ff68c76a4df0271e42bd0bc64ae3585e5e649f5399d3e97443c1fdf554f2d93faa2a4abc5c35a0640e314faa9dd8d8fc56720704af30c4758096b99bf9040965424ed4f79569564c86b05527017608433271165818ed852e5e0740ca7c0ba5f0a5c6b56f00e216c4aaf0394b151fb0b1ac0f5f061af0999fe49274797a63819e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c6248d9", &mut ct1).unwrap();
        hex::decode_to_slice("6573c7d6c029d9da4102d0aeccbac81924cf49270045629fdb192d5b761621c96b2ec3bb2d58c493d32d474524237b214462cf23dbcf637140558521acc5253eca4ff880b195e219b53bcb291990ef78476a9a0aaff555c13a502593c923a57c830c9d4d593ba5dc4fcf920c49f99a4c391167b2b8814959cb5c1e0c7437187522e87c71586a8712f117297593f25447aec86a6e1543e3e600594bb0ab28c1ee314a3fe561d6e2349529bb31888e58fac519934f26739723203ac27bbffc27cd1fb9982b3040fa626ebfa46d43680f2973106b5227f0f4c4f8e61ab2b27a248c3b6bab75b5075b6b34922e726a5252c4fcb00231d72e77e4818dd441e1d17af725905c3433eed2c2673a67a5cc01dc8754b6984a40f911bf0584bad031a277bc3a564c111218f06a350282360b1a03faea4134965b7c69a4a9e320cab0583662813ac7bc9e79a107f6c1d53858823197f478bdb9068bb4d6354df1b557a71e8f461b6b961548db6dab5342c2a4a4c9f390fae15166a72e6ac686790508fde275df5037929036bd3a1ec63b8e531551da2c4f5380b19f2310065a08cba60c24a33680169ac8061f97e39eac98b476ec9851a9033ac38bed54742da0a6738cb3c01190e0702bbf0216ada263728a48afe41d80925a475a5919b88394c216061a6c8c4b0094342e00a4970ff0a44f8633856127ab580a3eab8d407b99256abba2060ca633828624958dbc20ab91c5d46c3a7f594562eba603ec015e55867c835c7063beea9997d7586ef0e3b597448720224dc6c902a871114d7262f4f5c4b48268b9013b0fa237ca0c69be7c75b4410d4cfbbf023bc361b54b5e63312029199b18bb7709cc47a0bfe1a5bbe8a29d95e98331f8c355db01ee526a13882b62c45d221b17acd6cfbfb048637c5f55f31dfd74bd1cd57714a93f8928cf9bc461ef92728a88ccbab621118102c9b681dc095bb59158a472b3860c5e4788c6a6fa38294499a47140985c3eddcc20fd315759401e61421cf8b7b6b3b63d92e2784587c23bf797940ba1e4b815a3d946a3537563e04b20d499f155721ae459a7eca871aa7c094233711037fb32170916032bd90a1f6b8c55b68fa6952b7478120e00afbaf4ca14e72ffab8a34cca269dd403a5545a40b0211a9867fba2c8811598d173986f193a28f191a363105421c4eb774f2861376afac847145c53c7b038db0462ac66bef256b9961cc1a5a819ab52f61c3172f072a0f5129d4aa8f6a8637a8c2064959606a22befc38070c9a8b7c5bd606519da64af71a7083cd29ee1ebb7089459aaf92f16463ccbcbc30f5c99b9322444851653eb8a4b8acb997522c2825a3971373b3117bce88b657395b0d6aaf6178022543151c09d74471fa0c68e7d8143417aaf2a30bf4fb2c5c90625bdb5744b179b12d8565a199ac7d30ea3b0565b124d33304057391751ac54bf520d9a434cf0c3508b57a596417b57464fc91894c13cb8167ca8f655ba0fd60ab1114592b70c01da79c2d9c487b462c6bb298bf29ad813443eea44c42cba27987d33e651ab894ec4e827a4d27e05469e609032a90211a48791966c0c1bb98f61872321300ff3199ac39b8d46971a84a0ca8dfa2096c0844408a0853cd4a86eac43a68250cadbf9af2b2edc0ab44b8b986da75f9eee966b0ad23485a7d52f335a8934962eccd40886795e7ecca991812775e7bc66c46809", &mut ek0).unwrap();
        hex::decode_to_slice("6573c7d6c029d9da4102d0aeccbac81924cf49270045629fdb192d5b761621c96b2ec3bb2d58c493d32d474524237b214462cf23dbcf637140558521acc5253eca4ff880b195e219b53bcb291990ef78476a9a0aaff555c13a502593c923a57c830c9d4d593ba5dc4fcf920c49f99a4c391167b2b8814959cb5c1e0c7437187522e87c71586a8712f117297593f25447aec86a6e1543e3e600594bb0ab28c1ee314a3fe561d6e2349529bb31888e58fac519934f26739723203ac27bbffc27cd1fb9982b3040fa626ebfa46d43680f2973106b5227f0f4c4f8e61ab2b27a248c3b6bab75b5075b6b34922e726a5252c4fcb00231d72e77e4818dd441e1d17af725905c3433eed2c2673a67a5cc01dc8754b6984a40f911bf0584bad031a277bc3a564c111218f06a350282360b1a03faea4134965b7c69a4a9e320cab0583662813ac7bc9e79a107f6c1d53858823197f478bdb9068bb4d6354df1b557a71e8f461b6b961548db6dab5342c2a4a4c9f390fae15166a72e6ac686790508fde275df5037929036bd3a1ec63b8e531551da2c4f5380b19f2310065a08cba60c24a33680169ac8061f97e39eac98b476ec9851a9033ac38bed54742da0a6738cb3c01190e0702bbf0216ada263728a48afe41d80925a475a5919b88394c216061a6c8c4b0094342e00a4970ff0a44f8633856127ab580a3eab8d407b99256abba2060ca633828624958dbc20ab91c5d46c3a7f594562eba603ec015e55867c835c7063beea9997d7586ef0e3b597448720224dc6c902a871114d7262f4f5c4b48268b9013b0fa237ca0c69be7c75b4410d4cfbbf023bc361b54b5e63312029199b18bb7709cc47a0bfe1a5bbe8a29d95e98331f8c355db01ee526a13882b62c45d221b17acd6cfbfb048637c5f55f31dfd74bd1cd57714a93f8928cf9bc461ef92728a88ccbab621118102c9b681dc095bb59158a472b3860c5e4788c6a6fa38294499a47140985c3eddcc20fd315759401e61421cf8b7b6b3b63d92e2784587c23bf797940ba1e4b815a3d946a3537563e04b20d499f155721ae459a7eca871aa7c094233711037fb32170916032bd90a1f6b8c55b68fa6952b7478120e00afbaf4ca14e72ffab8a34cca269dd403a5545a40b0211a9867fba2c8811598d173986f193a28f191a363105421c4eb774f2861376afac847145c53c7b038db0462ac66bef256b9961cc1a5a819ab52f61c3172f072a0f5129d4aa8f6a8637a8c2064959606a22befc38070c9a8b7c5bd606519da64af71a7083cd29ee1ebb7089459aaf92f16463ccbcbc30f5c99b9322444851653eb8a4b8acb997522c2825a3971373b3117bce88b657395b0d6aaf6178022543151c09d74471fa0c68e7d8143417aaf2a30bf4fb2c5c90625bdb5744b179b12d8565a199ac7d30ea3b0565b124d33304057391751ac54bf520d9a434cf0c3508b57a596417b57464fc91894c13cb8167ca8f655ba0fd60ab1114592b70c01da79c2d9c487b462c6bb298bf29ad813443eea44c42cba27987d33e651ab894ec4e827a4d27e05469e609032a90211a48791966c0c1bb98f61872321300ff3199ac39b8d46971a84a0ca8dfa2096c0844408a0853cd4a86eac43a68250cadbf9af2b2edc0ab44b8b986da75f9eee966b0ad23485a7d52f335a8934962eccd40886795e7ecca991812775e7bc66c46889", &mut ek1).unwrap();
        hex::decode_to_slice(
            "b0c2808b0a0441a6b8889470c05a7a3e5bcf891b16511408237ceb8128c83ef4",
            &mut ss_ct0,
        )
        .unwrap();
        hex::decode_to_slice(
            "fbd7a487e9d7e9e26489c6993a786d02c9abc7e48a45112ebde1b182ada3578a",
            &mut ss_ct1,
        )
        .unwrap();
        hex::decode_to_slice(
            "b0c2808b0a0441a6b8889470c05a7a3e5bcf891b16511408237ceb8128c83ef4",
            &mut ss_ek0,
        )
        .unwrap();
        hex::decode_to_slice(
            "03ff3eb147f85d888230b72e599a7c2b06ba747cdd2b4c6642e6ae5be437a5e7",
            &mut ss_ek1,
        )
        .unwrap();

        let dk = DecapsulationKey::from(seed);
        assert_eq!(dk.unprotected_as_ref(), &seed);
        let kp = KeyPair::try_from(&dk).unwrap();
        assert_eq!(kp.private(), &dk);

        let ek0 = EncapsulationKey::try_from(&ek0).unwrap();
        assert_eq!(kp.public(), &ek0);
        let ek1 = EncapsulationKey::try_from(&ek1).unwrap();
        assert_ne!(kp.public(), &ek1);

        let (ss0, _ct0_rt) = ek0.encap_deterministic(&eseed).unwrap();
        let (ss1, _ct1_rt) = ek1.encap_deterministic(&eseed).unwrap();
        assert_eq!(ss0.unprotected_as_ref(), &ss_ek0);
        assert_eq!(ss1.unprotected_as_ref(), &ss_ek1);

        assert_eq!(
            &ss_ct0,
            kp.decap(&Ciphertext::from(ct0))
                .unwrap()
                .unprotected_as_ref()
        );
        assert_eq!(
            &ss_ct1,
            kp.decap(&Ciphertext::from(ct1))
                .unwrap()
                .unprotected_as_ref()
        );
    }

    #[test]
    fn test_decapsulation_key() {
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_with_generate::<DK_SIZE, DK_SIZE, DK_SIZE, XWingDecapKey>();

        // Test of From<[u8; N]>
        assert_ne!(
            DecapsulationKey::from([0u8; DK_SIZE]),
            DecapsulationKey::from([1u8; DK_SIZE])
        )
    }

    #[test]
    fn test_shared_secret() {
        use crate::test_framework::newtypes::secret::SecretNewtype;
        SecretNewtype::test_no_generate::<SHARED_SECRET_SIZE, SHARED_SECRET_SIZE, XWingSharedSecret>(
        );

        // Test of From<[u8; N]>
        assert_ne!(
            SharedSecret::from([0u8; SHARED_SECRET_SIZE]),
            SharedSecret::from([1u8; SHARED_SECRET_SIZE])
        )
    }

    // NOTE(brycx): PublicNewtype generic tests aren't run for Encapsulation keys
    // because their parsing logic depends on valid ML-KEM768 keys
    // which isn't compatible with test framework.

    #[test]
    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    fn test_encapsulation_key() {
        use crate::hazardous::kem::mlkem768;

        let seed = mlkem768::Seed::from([21u8; mlkem768::SEED_SIZE]);
        let kp = mlkem768::KeyPair::new(seed).unwrap();

        let mut xwing_public_bytes = [0u8; EK_SIZE];
        crate::util::secure_rand_bytes(&mut xwing_public_bytes).unwrap();

        // Length mismatch
        assert!(EncapsulationKey::try_from(&xwing_public_bytes[..EK_SIZE - 1]).is_err());
        // With invalid/random ML-KEM-768 public part, X-Wing fails.
        assert!(EncapsulationKey::try_from(&xwing_public_bytes).is_err());
        // With valid ML-KEM-768 and completely random X25519, which is not parsed, X-Wing succeeds.
        xwing_public_bytes[..mlkem768::EK_SIZE].copy_from_slice(kp.public().as_ref());
        assert!(EncapsulationKey::try_from(&xwing_public_bytes).is_ok());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_encapsulation_key_serialization() {
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_serialization::<EK_SIZE, XWingEncapKey>();
    }

    #[test]
    fn test_ciphertext() {
        use crate::test_framework::newtypes::public::PublicNewtype;
        PublicNewtype::test_no_generate::<CIPHERTEXT_SIZE, CIPHERTEXT_SIZE, XWingCiphertext>();

        // Test of From<[u8; N]>
        assert_ne!(
            Ciphertext::from([0u8; CIPHERTEXT_SIZE]),
            Ciphertext::from([1u8; CIPHERTEXT_SIZE])
        );

        #[cfg(feature = "serde")]
        PublicNewtype::test_serialization::<CIPHERTEXT_SIZE, XWingCiphertext>();
    }

    #[cfg(feature = "safe_api")]
    use crate::test_framework::kem_interface::{KemTester, TestableKem};

    #[cfg(feature = "safe_api")]
    impl TestableKem<SharedSecret, Ciphertext> for KeyPair {
        fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = KeyPair::try_from(&DecapsulationKey::try_from(seed)?)?;

            Ok((
                kp.public.as_ref().to_vec(),
                kp.private.unprotected_as_ref().to_vec(),
            ))
        }

        fn ciphertext_from_bytes(b: &[u8]) -> Result<Ciphertext, UnknownCryptoError> {
            Ciphertext::try_from(b)
        }

        fn encap(ek: &[u8]) -> Result<(SharedSecret, Ciphertext), UnknownCryptoError> {
            let ek = EncapsulationKey::try_from(ek)?;
            ek.encap()
        }

        fn decap(dk: &[u8], c: &Ciphertext) -> Result<SharedSecret, UnknownCryptoError> {
            let dk = DecapsulationKey::try_from(dk)?;
            let kp = KeyPair::try_from(&dk)?;
            assert_eq!(dk.decap(c).unwrap(), kp.decap(c).unwrap());

            dk.decap(c)
        }
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn run_basic_kem_tests() {
        // Tests were designed with ML-KEM notation in mind, but with X-Wing the seed and decapsulation key
        // should be the same.
        let seed = DecapsulationKey::generate().unwrap();
        KemTester::<KeyPair, SharedSecret, Ciphertext>::run_all_tests(seed.unprotected_as_ref());
    }

    #[test]
    /// Basic no_std-compatible test.
    fn basic_roundtrip() {
        let dk = DecapsulationKey::try_from(&[127u8; DK_SIZE]).unwrap();
        let kp = KeyPair::try_from(&dk).unwrap();

        let (k, c) = kp.public().encap_deterministic(&[255u8; 64]).unwrap();
        let k_prime = kp.private().decap(&c).unwrap();

        assert_eq!(k, k_prime);
    }

    #[test]
    fn get_decapskey_as_bytes_is_seed() {
        let seed = DecapsulationKey::try_from(&[127u8; DK_SIZE]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        assert_eq!(seed.unprotected_as_ref(), kp.private().unprotected_as_ref());
    }

    #[test]
    fn bad_eseed_lens() {
        let seed = DecapsulationKey::try_from(&[127u8; DK_SIZE]).unwrap();
        let kp = KeyPair::try_from(&seed).unwrap();

        assert!(kp.public().encap_deterministic(&[255u8; 64]).is_ok());
        assert!(kp.public().encap_deterministic(&[255u8; 63]).is_err());
        assert!(kp.public().encap_deterministic(&[255u8; 65]).is_err());
    }
}
