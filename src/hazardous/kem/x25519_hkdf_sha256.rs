// MIT License

// Copyright (c) 2023-2025 The orion Developers

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
//! - `public_recipient`: The public X25519 key of the recipient.
//! - `public_ephemeral`: The ephemeral X25519 key for this KEM operation.
//! - `secret_recipient`: The private X25519 of the recipient.
//! - `secret_sender`: The private X25519 of the sender.
//! - `secret_ephemeral`: Ephemeral private key for deterministic encapsulation.
//!
//! # Errors:
//! An error will be returned if:
//! - If a shared X25519 secret is all-zero.
//! - If `ikm.len() < 32` when calling [`derive_keypair()`].
//!
//! # Panics:
//! A panic will occur if:
//! - [`generate()`] panics during [`encap()`], [`auth_encap()`], [`decap()`] or [`auth_decap()`].
//!
//! # Security:
//! - The `ikm` used as input for [`derive_keypair()`] must never be reused.
//! - The `secret_ephemeral` must never be reused.
//! - This KEM is vulnerable to key-compromise impersonation attacks (KCI), meaning
//! that if the recipients private key `secret_recipient` is leaked at any point, sender authentication
//! no longer holds. See [KCI section](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1.1) of the RFC
//! on recommendations on how to mitigate this.
//! - Please refer to the RFC for a detailed description of all security properties provided: <https://www.rfc-editor.org/rfc/rfc9180.html#section-9>.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::kem::x25519_hkdf_sha256::DhKem;
//!
//! let (sender_secret, sender_public) = DhKem::generate_keypair()?;
//! let (recipient_secret, recipient_public) = DhKem::generate_keypair()?;
//!
//! let (sender_shared_secret, public_eph) =
//!     DhKem::auth_encap(&recipient_public, &sender_secret)?;
//! let recipient_shared_secret = DhKem::auth_decap(&public_eph, &recipient_secret, &sender_public)?;
//!
//! assert_eq!(sender_shared_secret, recipient_shared_secret);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`encap()`]: x25519_hkdf_sha256::DhKem::encap
//! [`decap()`]: x25519_hkdf_sha256::DhKem::decap
//! [`auth_encap()`]: x25519_hkdf_sha256::DhKem::auth_encap
//! [`auth_decap()`]: x25519_hkdf_sha256::DhKem::auth_decap
//! [`derive_keypair()`]: x25519_hkdf_sha256::DhKem::derive_keypair
//! [`generate()`]: crate::hazardous::ecc::x25519::PrivateKey::generate

use crate::errors::UnknownCryptoError;
use crate::hazardous::ecc::x25519;
use crate::hazardous::kdf::hkdf;
use zeroize::Zeroizing;

pub use crate::hazardous::ecc::x25519::PrivateKey;
pub use crate::hazardous::ecc::x25519::PublicKey;

construct_secret_key! {
    /// A type to represent the `SharedSecret` that DH-KEM(X25519, HKDF-SHA256) produces.
    ///
    /// This type simply holds bytes. Creating an instance from slices or similar,
    /// performs no checks whatsoever.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (SharedSecret, test_shared_key, 32, 32)
}

/// DHKEM(X25519, HKDF-SHA256) as specified in HPKE [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
pub struct DhKem {}

impl DhKem {
    /// ID for this DH-KEM. See <https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1>
    pub const KEM_ID: u16 = 0x0020;

    /// Version of HPKE implemented. See <https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10>.
    pub const HPKE_VERSION_ID: &'static str = "HPKE-v1";

    /// Length of bytes of a shared secret produced by this KEM. See <https://www.rfc-editor.org/rfc/rfc9180.html#section-4-1>.
    const N_SECRET: u16 = 32;

    fn labeled_extract(
        salt: &[u8],
        label: &[u8; 7],
        ikm: &[u8],
    ) -> Result<hkdf::sha256::Tag, UnknownCryptoError> {
        hkdf::sha256::extract_with_parts(
            salt,
            &[
                Self::HPKE_VERSION_ID.as_bytes(),
                b"KEM",
                &Self::KEM_ID.to_be_bytes(),
                label,
                ikm,
            ],
        )
    }

    fn labeled_expand(
        prk: &hkdf::sha256::Tag,
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let l: u16 = out.len().try_into().map_err(|_| UnknownCryptoError)?;
        hkdf::sha256::expand_with_parts(
            prk.unprotected_as_bytes(),
            Some(&[
                &l.to_be_bytes(),
                Self::HPKE_VERSION_ID.as_bytes(),
                b"KEM",
                &Self::KEM_ID.to_be_bytes(),
                label,
                info,
            ]),
            out,
        )?;

        Ok(())
    }

    fn extract_and_expand(
        dh: &[u8],
        kem_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(out.len(), Self::N_SECRET as usize);

        let eae_prk = Self::labeled_extract(b"", b"eae_prk", dh)?;
        Self::labeled_expand(&eae_prk, b"shared_secret", kem_context, out)?;

        Ok(())
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Generate random X25519 keypair.
    pub fn generate_keypair() -> Result<(PrivateKey, PublicKey), UnknownCryptoError> {
        let sk = PrivateKey::generate();
        let pk = PublicKey::try_from(&sk)?;

        Ok((sk, pk))
    }

    /// Deterministically derive a X25519 keypair from `ikm`.
    pub fn derive_keypair(ikm: &[u8]) -> Result<(PrivateKey, PublicKey), UnknownCryptoError> {
        if ikm.len() < 32 {
            return Err(UnknownCryptoError);
        }

        let dkp_prk = Self::labeled_extract(b"", b"dkp_prk", ikm)?;
        let mut sk_bytes = Zeroizing::new([0u8; x25519::PRIVATE_KEY_SIZE]);
        Self::labeled_expand(&dkp_prk, b"sk", b"", sk_bytes.as_mut_slice())?;

        let sk = PrivateKey::from_slice(sk_bytes.as_slice())?;
        let pk = PublicKey::try_from(&sk)?;

        Ok((sk, pk))
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Derive ephemeral shared secret and encapsulation thereof, which can be
    /// decapsulated by the holder of `public_recipient`.
    pub fn encap(
        public_recipient: &PublicKey,
    ) -> Result<(SharedSecret, PublicKey), UnknownCryptoError> {
        let secret_ephemeral = PrivateKey::generate();
        Self::encap_deterministic(public_recipient, secret_ephemeral)
    }

    /// Equivalent to [`Self::encap()`], but with a one-time use provided ephemeral private key.
    pub fn encap_deterministic(
        public_recipient: &PublicKey,
        secret_ephemeral: PrivateKey,
    ) -> Result<(SharedSecret, PublicKey), UnknownCryptoError> {
        let public_ephemeral = PublicKey::try_from(&secret_ephemeral)?;

        let dh = x25519::key_agreement(&secret_ephemeral, public_recipient)?;
        let mut kem_context = [0u8; 32 + 32];
        kem_context[..32].copy_from_slice(&public_ephemeral.to_bytes());
        kem_context[32..64].copy_from_slice(&public_recipient.to_bytes());

        let mut shared_secret = SharedSecret::from_slice(&[0u8; Self::N_SECRET as usize])?;
        Self::extract_and_expand(
            dh.unprotected_as_bytes(),
            &kem_context,
            &mut shared_secret.value,
        )?;

        Ok((shared_secret, public_ephemeral))
    }

    /// Decapsulate `public_ephemeral` and return the shared ephemeral secret,
    /// using `secret_recipient` private key.
    pub fn decap(
        public_ephemeral: &PublicKey,
        secret_recipient: &PrivateKey,
    ) -> Result<SharedSecret, UnknownCryptoError> {
        let dh = x25519::key_agreement(secret_recipient, public_ephemeral)?;

        let mut kem_context = [0u8; 32 + 32];
        kem_context[..32].copy_from_slice(&public_ephemeral.to_bytes());
        kem_context[32..64].copy_from_slice(&PublicKey::try_from(secret_recipient)?.to_bytes());

        let mut shared_secret = SharedSecret::from_slice(&[0u8; Self::N_SECRET as usize])?;
        Self::extract_and_expand(
            dh.unprotected_as_bytes(),
            &kem_context,
            &mut shared_secret.value,
        )?;

        Ok(shared_secret)
    }

    #[cfg(feature = "safe_api")]
    #[cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]
    /// Equivalent to [`Self::encap()`], additionally ensuring the holder of `secret_sender` was
    /// the one to generate the shared secret.
    pub fn auth_encap(
        public_recipient: &PublicKey,
        secret_sender: &PrivateKey,
    ) -> Result<(SharedSecret, PublicKey), UnknownCryptoError> {
        let secret_ephemeral = PrivateKey::generate();
        Self::auth_encap_deterministic(public_recipient, secret_sender, secret_ephemeral)
    }

    /// Equivalent to  [`Self::auth_encap()`], but with a one-time use provided ephemeral private key.
    pub fn auth_encap_deterministic(
        public_recipient: &PublicKey,
        secret_sender: &PrivateKey,
        secret_ephemeral: PrivateKey,
    ) -> Result<(SharedSecret, PublicKey), UnknownCryptoError> {
        let public_ephemeral = PublicKey::try_from(&secret_ephemeral)?;

        let mut dh = Zeroizing::new([0u8; 64]);
        dh[..32].copy_from_slice(
            x25519::key_agreement(&secret_ephemeral, public_recipient)?.unprotected_as_bytes(),
        );
        dh[32..64].copy_from_slice(
            x25519::key_agreement(secret_sender, public_recipient)?.unprotected_as_bytes(),
        );

        let mut kem_context = [0u8; 32 * 3];
        kem_context[..32].copy_from_slice(&public_ephemeral.to_bytes());
        kem_context[32..64].copy_from_slice(&public_recipient.to_bytes());
        kem_context[64..96].copy_from_slice(&PublicKey::try_from(secret_sender)?.to_bytes());

        let mut shared_secret = SharedSecret::from_slice(&[0u8; Self::N_SECRET as usize])?;
        Self::extract_and_expand(dh.as_slice(), &kem_context, &mut shared_secret.value)?;

        Ok((shared_secret, public_ephemeral))
    }

    /// Equivalent to [`Self::decap()`], additionally ensuring the holder of `secret_sender` was
    /// the one to generate the shared secret.
    pub fn auth_decap(
        public_ephemeral: &PublicKey,
        secret_recipient: &PrivateKey,
        public_sender: &PublicKey,
    ) -> Result<SharedSecret, UnknownCryptoError> {
        let mut dh = Zeroizing::new([0u8; 64]);
        dh[..32].copy_from_slice(
            x25519::key_agreement(secret_recipient, public_ephemeral)?.unprotected_as_bytes(),
        );
        dh[32..64].copy_from_slice(
            x25519::key_agreement(secret_recipient, public_sender)?.unprotected_as_bytes(),
        );

        let mut kem_context = [0u8; 32 * 3];
        kem_context[..32].copy_from_slice(&public_ephemeral.to_bytes());
        kem_context[32..64].copy_from_slice(&PublicKey::try_from(secret_recipient)?.to_bytes());
        kem_context[64..96].copy_from_slice(&public_sender.to_bytes());

        let mut shared_secret = SharedSecret::from_slice(&[0u8; Self::N_SECRET as usize])?;
        Self::extract_and_expand(dh.as_slice(), &kem_context, &mut shared_secret.value)?;

        Ok(shared_secret)
    }
}

#[cfg(test)]
mod public {
    use crate::hazardous::ecc::x25519::{PrivateKey, PublicKey};
    use crate::hazardous::kem::x25519_hkdf_sha256::*;

    #[test]
    fn error_on_short_ikm() {
        assert!(DhKem::derive_keypair(&[0u8; 31]).is_err());
        assert!(DhKem::derive_keypair(&[0u8; 32]).is_ok());
        assert!(DhKem::derive_keypair(&[0u8; 65]).is_ok());
    }

    #[test]
    fn encap_deterministic() {
        let (_secret, public) = DhKem::derive_keypair(&[123u8; 32]).unwrap();
        let (secret_eph1, _public_eph) = DhKem::derive_keypair(&[123u8; 32]).unwrap();
        let (secret_eph2, _public_eph) = DhKem::derive_keypair(&[123u8; 32]).unwrap();

        let (shared_secret1, public_eph1) =
            DhKem::encap_deterministic(&public, secret_eph1).unwrap();
        let (shared_secret2, public_eph2) =
            DhKem::encap_deterministic(&public, secret_eph2).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(public_eph1, public_eph2);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn encap_decap_roundtrip() {
        let recipient_secret = PrivateKey::generate();
        let recipient_public = PublicKey::try_from(&recipient_secret).unwrap();

        let (shared_secret_1, public_eph) = DhKem::encap(&recipient_public).unwrap();
        let shared_secret_2 = DhKem::decap(&public_eph, &recipient_secret).unwrap();

        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    #[cfg(feature = "safe_api")]
    fn auth_encap_decap_roundtrip() {
        let sender_secret = PrivateKey::generate();
        let sender_public = PublicKey::try_from(&sender_secret).unwrap();

        let recipient_secret = PrivateKey::generate();
        let recipient_public = PublicKey::try_from(&recipient_secret).unwrap();

        let (shared_secret_1, public_eph) =
            DhKem::auth_encap(&recipient_public, &sender_secret).unwrap();
        let shared_secret_2 =
            DhKem::auth_decap(&public_eph, &recipient_secret, &sender_public).unwrap();

        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
