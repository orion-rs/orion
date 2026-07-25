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

use crate::errors::UnknownCryptoError;
use crate::hazardous::aead::chacha20poly1305::{self, ChaCha20Poly1305, Nonce};
use crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
use crate::hazardous::hash::sha3::shake256::Shake256;
use crate::hazardous::hpke::mode::private::*;
use crate::hazardous::hpke::suite::private::*;
use crate::hazardous::kdf::hkdf;
use crate::hazardous::kem::xwing;

#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Clone))]
/// HPKE suite: X-Wing/MLKEM768-X25519, HKDF-SHA-256 and ChaCha20Poly1305.
///
/// This suite is defined in:
/// - KEM suite: [draft-irtf-cfrg-concrete-hybrid-kems-04](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04)
/// - HPKE suite: [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)
///
/// # Note about KEM
/// The `MLKEM768-X25519` KEM is identical to X-Wing, as stated in
/// [Section 4.2 of draft-irtf-cfrg-concrete-hybrid-kems-04](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04#section-4.2):
/// "This construction is identical to the X-Wing construction in \[XWING-SPEC\]". Thus, this suite uses [`xwing`].
///
/// # Note about missing `Auth` mode
/// `X-Wing`/`MLKEM768-X25519` provides no `AuthEncap()`/`AuthDecap()` (see Table 3 in
/// [Section 6 of draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#section-6)),
/// so this suite is only available with [`ModeBase`] and [`ModePsk`]. If sender authentication is required,
/// [`ModePsk`] must be used.
///
/// # Note about serialized private keys for this suite
/// The private key of this suite is the [`xwing::DecapsulationKey`], which is a 32-byte seed
/// (`Nsk`), that is expanded into the actual ML-KEM-768 and X25519 key material on each operation.
///
/// [`ModeBase`]: crate::hazardous::hpke::ModeBase
/// [`ModePsk`]: crate::hazardous::hpke::ModePsk
/// [`xwing`]: crate::hazardous::kem::xwing
/// [`xwing::DecapsulationKey`]: crate::hazardous::kem::xwing::DecapsulationKey
/// [`xwing::KeyPair`]: crate::hazardous::kem::xwing::KeyPair
pub struct MLKEM768_X25519_SHA256_CHACHA20 {
    key: [u8; 32],
    base_nonce: [u8; 12],
    ctr: u64, // "sequence number"
    exporter_secret: [u8; 32],
}

impl PartialEq<MLKEM768_X25519_SHA256_CHACHA20> for MLKEM768_X25519_SHA256_CHACHA20 {
    fn eq(&self, other: &MLKEM768_X25519_SHA256_CHACHA20) -> bool {
        use subtle::ConstantTimeEq;

        (self.key.ct_eq(&other.key)
            & self.base_nonce.ct_eq(&other.base_nonce)
            & self.ctr.ct_eq(&other.ctr)
            & self.exporter_secret.ct_eq(&other.exporter_secret))
        .into()
    }
}

impl Eq for MLKEM768_X25519_SHA256_CHACHA20 {}

impl core::fmt::Debug for MLKEM768_X25519_SHA256_CHACHA20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} key: {{***OMITTED***}}, base_nonce: {:?}, ctr: {:?}, exporter_secret: {{***OMITTED***}}",
            stringify!(MLKEM768_X25519_SHA256_CHACHA20),
            self.base_nonce,
            self.ctr
        )
    }
}

impl Drop for MLKEM768_X25519_SHA256_CHACHA20 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.key.iter_mut().zeroize();
            self.exporter_secret.iter_mut().zeroize();
        }
    }
}

// NOTE: `Auth` not supported by X-Wing.
impl Base for MLKEM768_X25519_SHA256_CHACHA20 {}
impl Psk for MLKEM768_X25519_SHA256_CHACHA20 {}

impl MLKEM768_X25519_SHA256_CHACHA20 {
    /// Size of the HPKE suite KEM ciphertext/encapsulated key.
    pub const KEM_CT_SIZE: usize = xwing::CIPHERTEXT_SIZE;
    /// Size of the HPKE suite KEM shared secret.
    pub const KEM_SS_SIZE: usize = xwing::SHARED_SECRET_SIZE;

    /// Version identifier for this HPKE scheme.
    pub const VERSION_ID: &[u8; 7] = b"HPKE-v1";

    /// HPKE ID for this HPKE scheme.
    pub const HPKE_ID: &[u8; 4] = b"HPKE";

    /// KEM ID for this HPKE scheme's KEM (in LE bytes).
    pub const KEM_ID: [u8; 2] = 0x647au16.to_be_bytes();

    /// KDF ID for this HPKE scheme's KDF (in LE bytes).
    pub const KDF_ID: [u8; 2] = 0x0001u16.to_be_bytes();

    /// AEAD ID for this HPKE scheme's AEAD (in LE bytes).
    pub const AEAD_ID: [u8; 2] = 0x0003u16.to_be_bytes();

    /// The maximum length of `export` secret that may be requested.
    pub const EXPORT_SECRET_MAXLEN: usize = (255 * Self::NH);

    /// Nonce size for this suite's AEAD (<https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3>).
    pub const NN: usize = 12;

    /// Output size for this suite's KDF (<https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2>).
    pub const NH: usize = 32;

    /// Label of `DeriveKeyPair()` (<https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-4>).
    const DKP_LABEL: &[u8; 13] = b"DeriveKeyPair";

    /// Deterministically derive this suite's KEM keypair from input keying material.
    ///
    /// `DeriveKeyPair()` for X-Wing is defined in the scope of HPKE only:
    /// [Section 4.3 of draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#section-4.3)
    /// of which the 32 output bytes are the seed, fed into [`xwing::DecapsulationKey`].
    /// `LabeledDerive()` is defined in [Section 4 of draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#name-hybrid-kems-with-ecdh-and-m).
    ///
    /// # Errors:
    /// An error will be returned if `ikm` is less than 32 bytes.
    ///
    /// [`xwing::DecapsulationKey`]: crate::hazardous::kem::xwing::DecapsulationKey
    /// [`xwing::KeyPair`]: crate::hazardous::kem::xwing::KeyPair
    /// [`private()`]: crate::KP::private
    /// [`public()`]: crate::KP::public
    pub fn derive_keypair(ikm: &[u8]) -> Result<xwing::KeyPair, UnknownCryptoError> {
        // "The input to this function SHOULD be at least 32 bytes long."
        if ikm.len() < xwing::DK_SIZE {
            return Err(UnknownCryptoError);
        }

        // labeled_ikm: [ ikm || "HPKE-v1" || suite_id || lengthPrefixed(label) || I2OSP(L, 2) || context ],
        // where the `suite_id` is [ "KEM" || KEM_ID ] and the context is empty here.
        let mut shake = Shake256::new();
        shake.absorb(ikm)?;
        shake.absorb(Self::VERSION_ID)?;
        shake.absorb(b"KEM")?;
        shake.absorb(&Self::KEM_ID)?;
        shake.absorb(&(Self::DKP_LABEL.len() as u16).to_be_bytes())?;
        shake.absorb(Self::DKP_LABEL)?;
        shake.absorb(&(xwing::DK_SIZE as u16).to_be_bytes())?;

        let mut seed = zeroize_wrap!([0u8; xwing::DK_SIZE]);
        shake.squeeze(seed.as_mut())?;

        xwing::KeyPair::try_from(&xwing::DecapsulationKey::try_from(seed.as_ref())?)
    }

    fn compute_nonce(&self) -> Nonce {
        // "Implementations MAY use a sequence number that is shorter than the nonce length (padding on the left with zero),
        // but MUST raise an error if the sequence number overflows." https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2

        let mut n = [0u8; crate::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE];
        n[4..12].copy_from_slice(&self.ctr.to_be_bytes());
        xor_slices!(self.base_nonce, n);

        Nonce::from(n)
    }

    fn would_overflow(&self) -> bool {
        self.ctr.checked_add(1).is_none()
    }

    fn increment_seq(&mut self) -> Result<(), UnknownCryptoError> {
        if let Some(next_seq) = self.ctr.checked_add(1) {
            self.ctr = next_seq;
        } else {
            return Err(UnknownCryptoError);
        }

        if self.ctr as u128 >= ((1u128 << (8u128 * Self::NN as u128)) - 1) {
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

impl Suite for MLKEM768_X25519_SHA256_CHACHA20 {
    type PrivateKey = xwing::DecapsulationKey;
    type PublicKey = xwing::EncapsulationKey;
    type EncapsulatedKey = xwing::Ciphertext;
    type EphemeralSecret = xwing::Eseed;

    fn labeled_extract(
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(out.len(), SHA256_OUTSIZE);

        // The `suite_id` is [b"HPKE" || KEM_ID || KDF_ID || AEAD_ID].
        let prk = hkdf::sha256::extract_with_parts(
            salt,
            &[
                Self::VERSION_ID,
                b"HPKE",
                &Self::KEM_ID,
                &Self::KDF_ID,
                &Self::AEAD_ID,
                label,
                ikm,
            ],
        )?;

        out[..SHA256_OUTSIZE].copy_from_slice(prk.unprotected_as_ref());

        Ok(())
    }

    fn labeled_expand(
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let l: u16 = out.len().try_into().map_err(|_| UnknownCryptoError)?;

        // The `suite_id` is [b"HPKE" || KEM_ID || KDF_ID || AEAD_ID].
        hkdf::sha256::expand_with_parts(
            prk,
            Some(&[
                &l.to_be_bytes(),
                Self::VERSION_ID,
                b"HPKE",
                &Self::KEM_ID,
                &Self::KDF_ID,
                &Self::AEAD_ID,
                label,
                info,
            ]),
            out,
        )?;

        Ok(())
    }

    fn key_schedule(
        mode: &HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        mode.verify_psk_inputs(psk, psk_id)?;

        // NOTE: We hardcode NK here, is this an approach we want to keep?
        // key_schedule_context: [ mode || psk_id_hash || info_hash ]
        let mut key_schedule_context = zeroize_wrap!([0u8; { (32 * 2) + 1 }]);
        key_schedule_context[0] = mode.mode_id();
        Self::labeled_extract(
            b"",
            b"psk_id_hash",
            psk_id,
            &mut key_schedule_context[1..33],
        )?;
        Self::labeled_extract(b"", b"info_hash", info, &mut key_schedule_context[33..65])?;

        let mut secret = zeroize_wrap!([0u8; 32]);
        Self::labeled_extract(shared_secret, b"secret", psk, secret.as_mut())?;

        let mut key = zeroize_wrap!([0u8; 32]);

        Self::labeled_expand(
            secret.as_ref(),
            b"key",
            key_schedule_context.as_ref(),
            key.as_mut(),
        )?;

        let mut base_nonce = [0u8; 12];
        Self::labeled_expand(
            secret.as_ref(),
            b"base_nonce",
            key_schedule_context.as_ref(),
            &mut base_nonce,
        )?;

        let mut exporter_secret = zeroize_wrap!([0u8; 32]);
        Self::labeled_expand(
            secret.as_ref(),
            b"exp",
            key_schedule_context.as_ref(),
            exporter_secret.as_mut_slice(),
        )?;

        Ok(Self {
            key: key.as_ref().try_into().expect("unreachable"),
            base_nonce,
            ctr: 0,
            exporter_secret: exporter_secret.as_ref().try_into().expect("unreachable"),
        })
    }

    #[cfg(feature = "safe_api")]
    fn setup_base_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = pubkey_r.encap()?;
        let ctx = Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_base_sender_deterministic(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        secret_ephemeral: Self::EphemeralSecret,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let (ss, enc) = pubkey_r.encap_deterministic(&secret_ephemeral)?;
        let ctx = Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_ref(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_base_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let ss = secret_key_r.decap(enc)?;
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

        let (ss, enc) = pubkey_r.encap()?;
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

        let (ss, enc) = pubkey_r.encap_deterministic(&secret_ephemeral)?;
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

        let ss = secret_key_r.decap(enc)?;
        Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_ref(), info, psk, psk_id)
    }

    // NOTE: This suite's KEM provides no `AuthEncap()`/`AuthDecap()`, so `AuthSuite` is not
    // implemented for it. That, along with the missing `Auth`/`AuthPsk` mode markers, is what makes
    // `ModeAuth`/`ModeAuthPsk` unavailable with this suite.

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

        let key = chacha20poly1305::SecretKey::from(self.key);
        let nonce = self.compute_nonce();
        ChaCha20Poly1305::seal(&key, &nonce, plaintext, Some(aad), out)?;

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

        let key = chacha20poly1305::SecretKey::from(self.key);
        let nonce = self.compute_nonce();
        ChaCha20Poly1305::open(&key, &nonce, ciphertext, Some(aad), out)?;

        self.increment_seq()
    }

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if out.len() > Self::EXPORT_SECRET_MAXLEN {
            return Err(UnknownCryptoError);
        }

        Self::check_input_max_lengths(exporter_context)?;
        Self::labeled_expand(&self.exporter_secret, b"sec", exporter_context, out)
    }
}

#[cfg(feature = "safe_api")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::KP;
    use crate::hazardous::kem::xwing::*;
    use crate::{
        hazardous::hpke::*,
        test_framework::hpke_interface::{HpkeTester, TestableHpke},
    };

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_omitted_debug() {
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let ek = kp.public();
        let (ctx, _enc) =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 64]).unwrap();

        let secret_key = format!("{:?}", ctx.key);
        let secret_export = format!("{:?}", ctx.exporter_secret);

        let test_debug_contents = format!("{:?}", ctx);
        assert!(!test_debug_contents.contains(&secret_key));
        assert!(!test_debug_contents.contains(&secret_export));
    }

    #[test]
    /// `ikmR`/`skRm`/`pkRm` of <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#appendix-A.5>.
    fn test_derive_keypair() {
        let mut ikm = [0u8; 32];
        let mut expected_dk = [0u8; DK_SIZE];
        hex::decode_to_slice(
            "c8575d137deab99ac98fb0873048c83c3a1f47ef5b409f609c0ca652f58c83e0",
            &mut ikm,
        )
        .unwrap();
        hex::decode_to_slice(
            "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be",
            &mut expected_dk,
        )
        .unwrap();

        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&ikm).unwrap();
        assert_eq!(kp.private().unprotected_as_ref(), &expected_dk);
        // The derived keypair must match the one the seed alone expands into.
        assert_eq!(
            kp.public(),
            &EncapsulationKey::try_from(&DecapsulationKey::from(expected_dk)).unwrap()
        );
        // The IKM is not itself the seed.
        assert_ne!(kp.private().unprotected_as_ref(), &ikm);
    }

    #[test]
    fn test_derive_keypair_ikm_lengths() {
        assert!(MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 31]).is_err());
        assert!(MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 32]).is_ok());
        assert!(MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 64]).is_ok());
        // Distinct IKM must give distinct keypairs.
        assert_ne!(
            MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 32])
                .unwrap()
                .public(),
            MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[1u8; 32])
                .unwrap()
                .public()
        );
    }

    #[test]
    fn test_partialeq_impl() {
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let (dk, ek) = (kp.private(), kp.public());
        let (ctx_s, enc) =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 64]).unwrap();
        let ctx_r =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, dk, &[0u8; 64]).unwrap();
        assert_eq!(ctx_s, ctx_r);

        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[1u8; DK_SIZE]).unwrap();
        let ek = kp.public();
        let (ctx_s, _enc) =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 64]).unwrap();
        assert_ne!(ctx_s, ctx_r);
    }

    #[test]
    fn test_error_on_lengths_base() {
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let (dk, ek) = (kp.private(), kp.public());
        let (ctx, enc) =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 64]).unwrap();
        // Info
        assert!(MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 64]).is_ok());
        assert!(MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, &[0u8; 65]).is_err());
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, dk, &[0u8; 64]).is_ok()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, dk, &[0u8; 65]).is_err()
        );

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * MLKEM768_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_on_lengths_psk() {
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let (dk, ek) = (kp.private(), kp.public());
        // Info
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 65], &[0u8; 64], b"psk_id"
            )
            .is_err()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 64], &[0u8; 64], b"psk_id"
            )
            .is_ok()
        );

        // PSK
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 64], &[0u8; 65], b"psk_id"
            )
            .is_err()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 64], &[0u8; 31], b"psk_id"
            )
            .is_err()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 64], &[0u8; 32], b"psk_id"
            )
            .is_ok()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
                ek, &[0u8; 64], &[0u8; 64], b"psk_id"
            )
            .is_ok()
        );
        let (ctx, enc) = MLKEM768_X25519_SHA256_CHACHA20::setup_psk_sender(
            ek, &[0u8; 64], &[0u8; 64], b"psk_id",
        )
        .unwrap();
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, dk, &[0u8; 64], &[0u8; 31], b"psk_id"
            )
            .is_err()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, dk, &[0u8; 64], &[0u8; 65], b"psk_id"
            )
            .is_err()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, dk, &[0u8; 64], &[0u8; 32], b"psk_id"
            )
            .is_ok()
        );
        assert!(
            MLKEM768_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, dk, &[0u8; 64], &[0u8; 64], b"psk_id"
            )
            .is_ok()
        );

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * MLKEM768_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_if_internal_counter_overflows() {
        let info = b"info param";
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let (dk, ek) = (kp.private(), kp.public());
        let (mut ctx, enc) = MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender(ek, info).unwrap();

        ctx.ctr = u64::MAX - 1;

        let plaintext = b"msg";
        let mut dst_out = [0u8; b"msg".len() + 16];
        assert!(ctx.seal(plaintext, b"", &mut dst_out).is_ok());
        // Overflow:
        assert!(ctx.increment_seq().is_err());
        assert!(ctx.seal(plaintext, b"", &mut dst_out).is_err());

        let mut ctx =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, dk, info).unwrap();
        ctx.ctr = u64::MAX - 1;

        let ciphertext = dst_out;
        let mut dst_out = [0u8; b"msg".len()];
        assert!(ctx.open(&ciphertext, b"", &mut dst_out).is_ok());
        // Overflow:
        assert!(ctx.increment_seq().is_err());
        assert!(ctx.open(&ciphertext, b"", &mut dst_out).is_err());

        assert_eq!(&dst_out, plaintext);
    }

    #[test]
    fn test_deterministic_and_fresh_sender_equivalent() {
        let eseed = Eseed::from([37u8; ESEED_SIZE]);
        let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; DK_SIZE]).unwrap();
        let (dk, ek) = (kp.private(), kp.public());

        let (ctx_s, enc) = MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender_deterministic(
            ek,
            b"info param",
            eseed,
        )
        .unwrap();
        let ctx_r =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, dk, b"info param").unwrap();
        assert_eq!(ctx_s, ctx_r);

        let eseed = Eseed::from([37u8; ESEED_SIZE]);
        let (ctx_s_again, enc_again) =
            MLKEM768_X25519_SHA256_CHACHA20::setup_base_sender_deterministic(
                ek,
                b"info param",
                eseed,
            )
            .unwrap();
        assert_eq!(ctx_s_again, ctx_s);
        assert_eq!(enc_again, enc);
    }

    impl TestableHpke for ModeBase<MLKEM768_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            MLKEM768_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(seed)?;
            let (dk, ek) = (kp.private(), kp.public());
            Ok((dk.unprotected_as_ref().to_vec(), ek.as_ref().to_vec()))
        }

        fn setup_fresh_sender(
            pubkey_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            _secret_key_s: &[u8],
            public_ct_out: &mut [u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let pubkey_r = EncapsulationKey::try_from(pubkey_r)?;
            let (ctx, enc) =
                ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::new_sender(&pubkey_r, info)?;
            public_ct_out.copy_from_slice(enc.as_ref());

            Ok(ctx)
        }

        fn setup_fresh_recipient(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            _pubkey_s: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let enc = Ciphertext::try_from(enc)?;
            let secret_key_r = DecapsulationKey::try_from(secret_key_r)?;
            ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::new_recipient(&enc, &secret_key_r, info)
        }

        fn seal(
            &mut self,
            plaintext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self.seal(plaintext, aad, out)
        }

        fn open(
            &mut self,
            ciphertext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self.open(ciphertext, aad, out)
        }

        fn export(&self, export_context: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self.export_secret(export_context, dst)
        }

        fn oneshot_seal(
            pubkey_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            _secret_key_s: &[u8],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let pubkey_r = EncapsulationKey::try_from(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; MLKEM768_X25519_SHA256_CHACHA20::KEM_CT_SIZE];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::base_seal(
                &pubkey_r,
                info,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(enc.as_ref());

            Ok((dst_kem_out, dst_out))
        }

        fn oneshot_open(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            _pubkey_s: &[u8],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let enc = Ciphertext::try_from(enc)?;
            let secret_key_r = DecapsulationKey::try_from(secret_key_r)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::base_open(
                &enc,
                &secret_key_r,
                info,
                ciphertext,
                aad,
                &mut dst_out,
            )?;

            Ok(dst_out)
        }
    }

    impl TestableHpke for ModePsk<MLKEM768_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            MLKEM768_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(seed)?;
            let (dk, ek) = (kp.private(), kp.public());
            Ok((dk.unprotected_as_ref().to_vec(), ek.as_ref().to_vec()))
        }

        fn setup_fresh_sender(
            pubkey_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            _secret_key_s: &[u8],
            public_ct_out: &mut [u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let pubkey_r = EncapsulationKey::try_from(pubkey_r)?;
            let (ctx, enc) = ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::new_sender(
                &pubkey_r, info, psk, psk_id,
            )?;
            public_ct_out.copy_from_slice(enc.as_ref());

            Ok(ctx)
        }

        fn setup_fresh_recipient(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            _pubkey_s: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let enc = Ciphertext::try_from(enc)?;
            let secret_key_r = DecapsulationKey::try_from(secret_key_r)?;
            ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::new_recipient(
                &enc,
                &secret_key_r,
                info,
                psk,
                psk_id,
            )
        }

        fn seal(
            &mut self,
            plaintext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self.seal(plaintext, aad, out)
        }

        fn open(
            &mut self,
            ciphertext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError> {
            self.open(ciphertext, aad, out)
        }

        fn export(&self, export_context: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self.export_secret(export_context, dst)
        }

        fn oneshot_seal(
            pubkey_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            _secret_key_s: &[u8],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let pubkey_r = EncapsulationKey::try_from(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; MLKEM768_X25519_SHA256_CHACHA20::KEM_CT_SIZE];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::psk_seal(
                &pubkey_r,
                info,
                psk,
                psk_id,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(enc.as_ref());

            Ok((dst_kem_out, dst_out))
        }

        fn oneshot_open(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            _pubkey_s: &[u8],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let enc = Ciphertext::try_from(enc)?;
            let secret_key_r = DecapsulationKey::try_from(secret_key_r)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::psk_open(
                &enc,
                &secret_key_r,
                info,
                psk,
                psk_id,
                ciphertext,
                aad,
                &mut dst_out,
            )?;

            Ok(dst_out)
        }
    }

    #[test]
    fn default_consistency_tests_mode_base() {
        let seed = 123456u64.to_le_bytes();
        let mut tester_ctx = HpkeTester::<ModeBase<MLKEM768_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }

    #[test]
    fn default_consistency_tests_mode_psk() {
        let seed = 123456u64.to_le_bytes();
        let mut tester_ctx = HpkeTester::<ModePsk<MLKEM768_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }
}
