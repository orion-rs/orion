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

use core::marker::PhantomData;
use core::mem::size_of;

use crate::errors::UnknownCryptoError;
use crate::generics::sealed::Sealed;
use crate::hazardous::hpke::VERSION_ID;
use crate::hazardous::hpke::mode::private::*;
use crate::hazardous::hpke::suite::private::*;
use crate::{Public, Secret};

/// Largest `Nk + Nn + Nh` of any suite, at time of writing. This serves as a max-value
/// buffer. Avoid unstable const generics.
const KEY_SCHEDULE_MAX: usize = 128;

/// An HPKE suite, composed of a KEM, a KDF and an AEAD.
///
/// This is not used directly. Each supported combination of primitives is exposed as its own type,
/// see [`crate::hazardous::hpke`].
pub struct HpkeSuite<Kem, Kdf, Aead>
where
    Kem: HpkeKem,
    Kdf: HpkeKdf,
    Aead: HpkeAead,
{
    pub(crate) key: Secret<Aead::Key>,
    pub(crate) base_nonce: Public<Aead::Nonce>,
    pub(crate) ctr: u64, // "sequence number"
    pub(crate) exporter_secret: Kdf::ExporterSecret,
    pub(crate) _phantom: PhantomData<(Kem, Kdf, Aead)>,
}

#[cfg(test)]
impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Clone for HpkeSuite<Kem, Kdf, Aead> {
    fn clone(&self) -> Self {
        Self {
            // SAFETY: This is a test-only unwrap()s.
            key: Secret::<Aead::Key>::try_from(self.key.unprotected_as_ref()).unwrap(),
            base_nonce: Public::<Aead::Nonce>::try_from(self.base_nonce.as_ref()).unwrap(),
            ctr: self.ctr,
            exporter_secret: self.exporter_secret.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> PartialEq<HpkeSuite<Kem, Kdf, Aead>>
    for HpkeSuite<Kem, Kdf, Aead>
{
    fn eq(&self, other: &HpkeSuite<Kem, Kdf, Aead>) -> bool {
        use subtle::ConstantTimeEq;

        (self
            .key
            .unprotected_as_ref()
            .ct_eq(other.key.unprotected_as_ref())
            & self.base_nonce.as_ref().ct_eq(other.base_nonce.as_ref())
            & self.ctr.ct_eq(&other.ctr)
            & self
                .exporter_secret
                .as_ref()
                .ct_eq(other.exporter_secret.as_ref()))
        .into()
    }
}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Eq for HpkeSuite<Kem, Kdf, Aead> {}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> core::fmt::Debug for HpkeSuite<Kem, Kdf, Aead> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HpkeSuite {{ kem_id: {:?}, kdf_id: {:?}, aead_id: {:?} }} key: {{***OMITTED***}}, base_nonce: {:?}, ctr: {:?}, exporter_secret: {{***OMITTED***}}",
            Kem::KEM_ID,
            Kdf::KDF_ID,
            Aead::AEAD_ID,
            self.base_nonce.as_ref(),
            self.ctr
        )
    }
}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Drop for HpkeSuite<Kem, Kdf, Aead> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use crate::generics::sealed::Data;
            use zeroize::Zeroize;

            self.key.data.memzero();
            self.exporter_secret.as_mut().iter_mut().zeroize();
        }
    }
}

// `Base` and `PSK` are available for all suites.
//
//
// `Auth` is not available for every KEM, e.g. X-Wing, so but if
// they are `Auth` they are also `Base` + `PSK`.
impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Base for HpkeSuite<Kem, Kdf, Aead> {}
impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Psk for HpkeSuite<Kem, Kdf, Aead> {}
impl<Kem: HpkeAuthKem, Kdf: HpkeKdf, Aead: HpkeAead> Auth for HpkeSuite<Kem, Kdf, Aead> {}
impl<Kem: HpkeAuthKem, Kdf: HpkeKdf, Aead: HpkeAead> AuthPsk for HpkeSuite<Kem, Kdf, Aead> {}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> HpkeSuite<Kem, Kdf, Aead> {
    /// Size of the HPKE suite KEM ciphertext/encapsulated key (RFC 9180 "`Nenc`").
    pub const KEM_CT_SIZE: usize = Kem::NENC;

    /// Size of the HPKE suite KEM shared secret (RFC 9180 "`Nsecret`").
    pub const KEM_SS_SIZE: usize = Kem::NSECRET;

    /// Version identifier.
    pub const VERSION_ID: &[u8; 7] = VERSION_ID;

    /// HPKE ID.
    pub const HPKE_ID: &[u8; 4] = b"HPKE";

    /// KEM ID (in BE bytes).
    pub const KEM_ID: [u8; 2] = Kem::KEM_ID;

    /// KDF ID (in BE bytes).
    pub const KDF_ID: [u8; 2] = Kdf::KDF_ID;

    /// AEAD ID (in BE bytes).
    pub const AEAD_ID: [u8; 2] = Aead::AEAD_ID;

    /// The maximum length of `export` secret that may be requested.
    pub const EXPORT_SECRET_MAXLEN: usize = (255 * Kdf::NH);

    /// Key size for this suite's AEAD (<https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3>).
    pub const NK: usize = Aead::NK;

    /// Nonce size for this suite's AEAD (<https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3>).
    pub const NN: usize = Aead::NN;

    /// Output size for this suite's KDF (<https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2>).
    pub const NH: usize = Kdf::NH;

    /// Deterministically derive this suite's KEM keypair from input keying material.
    ///
    /// This is HPKE's `DeriveKeyPair()` for the suite's KEM, which for some KEMs is part of the KEM
    /// itself, and for others is specific to using it with HPKE. The keypair is returned in the
    /// KEM's own representation, which for some KEMs is a dedicated keypair type and for others is
    /// the `(private, public)` tuple.
    ///
    /// # Errors:
    /// An error will be returned if `ikm` is less than 32 bytes.
    pub fn derive_keypair(ikm: &[u8]) -> Result<Kem::KeyPair, UnknownCryptoError> {
        Kem::derive_keypair(ikm)
    }

    /// The `suite_id` is: "HPKE" || KEM_ID || KDF_ID || AEAD_ID.
    fn suite_id() -> [u8; 10] {
        let mut suite_id = [0u8; 10];
        suite_id[..4].copy_from_slice(Self::HPKE_ID);
        suite_id[4..6].copy_from_slice(&Kem::KEM_ID);
        suite_id[6..8].copy_from_slice(&Kdf::KDF_ID);
        suite_id[8..10].copy_from_slice(&Aead::AEAD_ID);

        suite_id
    }

    fn compute_nonce(&self) -> Public<Aead::Nonce> {
        // "Implementations MAY use a sequence number that is shorter than the nonce length (padding on the left with zero),
        // but MUST raise an error if the sequence number overflows." https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
        debug_assert!(Aead::NN >= size_of::<u64>());

        let mut n = Aead::NONCE_INIT;
        n.data.as_mut()[Aead::NN - size_of::<u64>()..].copy_from_slice(&self.ctr.to_be_bytes());
        xor_slices!(self.base_nonce.as_ref(), n.data.as_mut());

        n
    }

    fn would_overflow(&self) -> bool {
        self.ctr.checked_add(1).is_none()
    }

    pub(crate) fn increment_seq(&mut self) -> Result<(), UnknownCryptoError> {
        if let Some(next_seq) = self.ctr.checked_add(1) {
            self.ctr = next_seq;
        } else {
            return Err(UnknownCryptoError);
        }

        if self.ctr as u128 >= ((1u128 << (8u128 * Aead::NN as u128)) - 1) {
            // unreachable: Internal u64 counter should have overflowed before this counter has!
            return Err(UnknownCryptoError);
        }

        Ok(())
    }

    /// Minimum length: <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4>
    /// Maximum length: <https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.1>
    fn check_psk_length(psk: &[u8], psk_id: &[u8]) -> Result<(), UnknownCryptoError> {
        if psk.len() < 32 {
            return Err(UnknownCryptoError);
        }
        Self::check_input_max_lengths(psk)?;
        Self::check_input_max_lengths(psk_id)
    }

    /// Maximum length: <https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.1>
    fn check_input_max_lengths(input: &[u8]) -> Result<(), UnknownCryptoError> {
        if input.len() > 64 {
            return Err(UnknownCryptoError);
        }

        Ok(())
    }
}

impl<Kem: HpkeKem, Kdf: HpkeKdf, Aead: HpkeAead> Suite for HpkeSuite<Kem, Kdf, Aead>
where
    HpkeSuite<Kem, Kdf, Aead>: Sealed,
{
    type PrivateKey = Kem::PrivateKey;
    type PublicKey = Kem::PublicKey;
    type EncapsulatedKey = Kem::EncapsulatedKey;
    type EphemeralSecret = Kem::EphemeralSecret;

    fn key_schedule(
        mode: &HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        mode.verify_psk_inputs(psk, psk_id)?;

        let outlen = Aead::NK + Aead::NN + Kdf::NH;
        debug_assert!(outlen <= KEY_SCHEDULE_MAX);
        if outlen > KEY_SCHEDULE_MAX {
            return Err(UnknownCryptoError);
        }

        // [ key || base_nonce || exporter_secret ]
        let mut combined = zeroize_wrap!([0u8; KEY_SCHEDULE_MAX]);
        Kdf::combine_secrets(
            &Self::suite_id(),
            mode,
            shared_secret,
            info,
            psk,
            psk_id,
            Aead::NK,
            Aead::NN,
            &mut combined[..outlen],
        )?;

        let mut key = Aead::KEY_INIT;
        let mut base_nonce = Aead::NONCE_INIT;
        let mut exporter_secret = Kdf::EXPORTER_SECRET_INIT;
        key.data.as_mut().copy_from_slice(&combined[..Aead::NK]);
        base_nonce
            .data
            .as_mut()
            .copy_from_slice(&combined[Aead::NK..Aead::NK + Aead::NN]);
        exporter_secret
            .as_mut()
            .copy_from_slice(&combined[Aead::NK + Aead::NN..outlen]);

        Ok(Self {
            key,
            base_nonce,
            ctr: 0,
            exporter_secret,
            _phantom: PhantomData,
        })
    }

    #[cfg(feature = "safe_api")]
    fn setup_base_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::encap(pubkey_r)?;
        let ctx = Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_base_sender_deterministic(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::encap_deterministic(pubkey_r, secret_ephemeral)?;
        let ctx = Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_base_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let ss = Kem::decap(enc, secret_key_r)?;
        Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_ref(), info, &[], &[])
    }

    #[cfg(feature = "safe_api")]
    fn setup_psk_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::encap(pubkey_r)?;
        let ctx = Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_ref(), info, psk, psk_id)?;

        Ok((ctx, enc))
    }

    fn setup_psk_sender_deterministic(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::encap_deterministic(pubkey_r, secret_ephemeral)?;
        let ctx = Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_ref(), info, psk, psk_id)?;

        Ok((ctx, enc))
    }

    fn setup_psk_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let ss = Kem::decap(enc, secret_key_r)?;
        Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_ref(), info, psk, psk_id)
    }

    fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        // Ensure we don't write anything to `out` if `increment_seq()` would fail.
        if self.would_overflow() {
            return Err(UnknownCryptoError);
        }

        let nonce = self.compute_nonce();
        Aead::seal(&self.key, &nonce, plaintext, aad, out)?;

        self.increment_seq()
    }

    fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        // Ensure we don't write anything to `out` if `increment_seq()` would fail.
        if self.would_overflow() {
            return Err(UnknownCryptoError);
        }

        let nonce = self.compute_nonce();
        Aead::open(&self.key, &nonce, ciphertext, aad, out)?;

        self.increment_seq()
    }

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if out.len() > Self::EXPORT_SECRET_MAXLEN {
            return Err(UnknownCryptoError);
        }

        Self::check_input_max_lengths(exporter_context)?;
        Kdf::export(
            &Self::suite_id(),
            self.exporter_secret.as_ref(),
            exporter_context,
            out,
        )
    }
}

impl<Kem: HpkeAuthKem, Kdf: HpkeKdf, Aead: HpkeAead> AuthSuite for HpkeSuite<Kem, Kdf, Aead>
where
    HpkeSuite<Kem, Kdf, Aead>: Sealed,
{
    #[cfg(feature = "safe_api")]
    fn setup_auth_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        secret_key_s: &Self::PrivateKey,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::auth_encap(pubkey_r, secret_key_s)?;
        let ctx = Self::key_schedule(&HpkeMode::Auth, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_auth_sender_deterministic(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        secret_key_s: &Self::PrivateKey,
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::auth_encap_deterministic(pubkey_r, secret_key_s, secret_ephemeral)?;
        let ctx = Self::key_schedule(&HpkeMode::Auth, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_auth_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
        pubkey_s: &Self::PublicKey,
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let ss = Kem::auth_decap(enc, secret_key_r, pubkey_s)?;
        Self::key_schedule(&HpkeMode::Auth, ss.unprotected_as_ref(), info, &[], &[])
    }

    #[cfg(feature = "safe_api")]
    fn setup_authpsk_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &Self::PrivateKey,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::auth_encap(pubkey_r, secret_key_s)?;
        let ctx = Self::key_schedule(
            &HpkeMode::AuthPsk,
            ss.unprotected_as_ref(),
            info,
            psk,
            psk_id,
        )?;

        Ok((ctx, enc))
    }

    fn setup_authpsk_sender_deterministic(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &Self::PrivateKey,
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = Kem::auth_encap_deterministic(pubkey_r, secret_key_s, secret_ephemeral)?;
        let ctx = Self::key_schedule(
            &HpkeMode::AuthPsk,
            ss.unprotected_as_ref(),
            info,
            psk,
            psk_id,
        )?;

        Ok((ctx, enc))
    }

    fn setup_authpsk_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &Self::PublicKey,
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let ss = Kem::auth_decap(enc, secret_key_r, pubkey_s)?;
        Self::key_schedule(
            &HpkeMode::AuthPsk,
            ss.unprotected_as_ref(),
            info,
            psk,
            psk_id,
        )
    }
}
