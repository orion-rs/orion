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

#[cfg(feature = "safe_api")]
use crate::Secret;
use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        hash::sha3::shake256::Shake256,
        hpke::suite::private::{HpkeAuthKem, HpkeKem},
        kem::{x25519_hkdf_sha256, xwing},
    },
};

/// HPKE version identifier <https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10>.
pub(crate) const VERSION_ID: &[u8; 7] = b"HPKE-v1";

/// `lengthPrefixed()` of <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04>.
pub(crate) fn length_prefix(input: &[u8]) -> Result<[u8; 2], UnknownCryptoError> {
    // "It is an error to call this function with an x value that is more than 65535 bytes long."
    // src: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-3
    let len: u16 = input.len().try_into().map_err(|_| UnknownCryptoError)?;

    Ok(len.to_be_bytes())
}

#[derive(Debug, Clone, Copy)]
/// `DHKEM(X25519, HKDF-SHA256)` <https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem>.
pub struct DhKemX25519HkdfSha256 {}

impl HpkeKem for DhKemX25519HkdfSha256 {
    const KEM_ID: [u8; 2] = 0x0020u16.to_be_bytes();
    const NSECRET: usize = 32;
    const NENC: usize = 32;
    const NPK: usize = 32;
    const NSK: usize = 32;

    type PrivateKey = x25519_hkdf_sha256::PrivateKey;
    type PublicKey = x25519_hkdf_sha256::PublicKey;
    type EncapsulatedKey = x25519_hkdf_sha256::PublicKey;
    type EphemeralSecret = x25519_hkdf_sha256::PrivateKey;
    type SharedSecretSpec = x25519_hkdf_sha256::DhKemSharedSecret;

    // DHKEM has no dedicated keypair type.
    // TODO(brycx): Change this?
    type KeyPair = (Self::PrivateKey, Self::PublicKey);

    fn derive_keypair(ikm: &[u8]) -> Result<Self::KeyPair, UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::derive_keypair(ikm)
    }

    #[cfg(feature = "safe_api")]
    fn encap(
        pubkey_r: &Self::PublicKey,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::encap(pubkey_r)
    }

    fn encap_deterministic(
        pubkey_r: &Self::PublicKey,
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::encap_deterministic(pubkey_r, secret_ephemeral)
    }

    fn decap(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
    ) -> Result<Secret<Self::SharedSecretSpec>, UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::decap(enc, secret_key_r)
    }
}

impl HpkeAuthKem for DhKemX25519HkdfSha256 {
    #[cfg(feature = "safe_api")]
    fn auth_encap(
        pubkey_r: &Self::PublicKey,
        secret_key_s: &Self::PrivateKey,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::auth_encap(pubkey_r, secret_key_s)
    }

    fn auth_encap_deterministic(
        pubkey_r: &Self::PublicKey,
        secret_key_s: &Self::PrivateKey,
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::auth_encap_deterministic(
            pubkey_r,
            secret_key_s,
            secret_ephemeral,
        )
    }

    fn auth_decap(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        pubkey_s: &Self::PublicKey,
    ) -> Result<Secret<Self::SharedSecretSpec>, UnknownCryptoError> {
        x25519_hkdf_sha256::DhKem::auth_decap(enc, secret_key_r, pubkey_s)
    }
}

#[derive(Debug, Clone, Copy)]
/// `MLKEM768-X25519`, which is X-Wing
/// (<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04#section-4.2>).
///
/// This does not provde `Auth`.
pub struct MlKem768X25519 {}

impl MlKem768X25519 {
    /// Label of `DeriveKeyPair()` (<https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-4>).
    const DKP_LABEL: &[u8; 13] = b"DeriveKeyPair";
}

impl HpkeKem for MlKem768X25519 {
    const KEM_ID: [u8; 2] = 0x647au16.to_be_bytes();
    const NSECRET: usize = xwing::SHARED_SECRET_SIZE;
    const NENC: usize = xwing::CIPHERTEXT_SIZE;
    const NPK: usize = xwing::EK_SIZE;
    const NSK: usize = xwing::DK_SIZE;

    type PrivateKey = xwing::DecapsulationKey;
    type PublicKey = xwing::EncapsulationKey;
    type EncapsulatedKey = xwing::Ciphertext;
    type EphemeralSecret = xwing::Eseed;
    type SharedSecretSpec = xwing::XWingSharedSecret;
    // X-Wing's `KeyPair` caches the key material that the decapsulation-key seed expands into.
    type KeyPair = xwing::KeyPair;

    /// `DeriveKeyPair()` is specified within the scope of HPKE only. NOT part of X-Wing spec. It is defined in
    /// [Section 4.3 of draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#name-hybrid-kems-with-ecdh-and-m).
    fn derive_keypair(ikm: &[u8]) -> Result<Self::KeyPair, UnknownCryptoError> {
        // "The input to this function SHOULD be at least 32 bytes long."
        if ikm.len() < Self::NSK {
            return Err(UnknownCryptoError);
        }

        // labeled_ikm: [ ikm || "HPKE-v1" || suite_id || lengthPrefixed(label) || I2OSP(L, 2) || context ],
        // where the KEM `suite_id` is [ "KEM" || KEM_ID ] and the context is empty here.
        let mut shake = Shake256::new();
        shake.absorb(ikm)?;
        shake.absorb(VERSION_ID)?;
        shake.absorb(b"KEM")?;
        shake.absorb(&Self::KEM_ID)?;
        shake.absorb(&length_prefix(Self::DKP_LABEL)?)?;
        shake.absorb(Self::DKP_LABEL)?;
        shake.absorb(&(Self::NSK as u16).to_be_bytes())?;

        let mut seed = zeroize_wrap!([0u8; xwing::DK_SIZE]);
        shake.squeeze(seed.as_mut())?;

        xwing::KeyPair::try_from(&xwing::DecapsulationKey::try_from(seed.as_ref())?)
    }

    #[cfg(feature = "safe_api")]
    fn encap(
        pubkey_r: &Self::PublicKey,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        pubkey_r.encap()
    }

    fn encap_deterministic(
        pubkey_r: &Self::PublicKey,
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError> {
        pubkey_r.encap_deterministic(&secret_ephemeral)
    }

    fn decap(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
    ) -> Result<Secret<Self::SharedSecretSpec>, UnknownCryptoError> {
        secret_key_r.decap(enc)
    }
}
