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

use crate::errors::UnknownCryptoError;
use crate::hazardous::aead::chacha20poly1305;
use crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
use crate::hazardous::hpke::mode::private::*;
use crate::hazardous::hpke::suite::private::*;
use crate::hazardous::kdf::hkdf;
use crate::hazardous::kem::x25519_hkdf_sha256;
use zeroize::Zeroizing;

#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Clone))]
/// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305.
pub struct DHKEM_X25519_SHA256_CHACHA20 {
    key: [u8; 32],
    base_nonce: [u8; 12],
    ctr: u64, // "sequence number"
    exporter_secret: [u8; 32],
}

impl PartialEq<DHKEM_X25519_SHA256_CHACHA20> for DHKEM_X25519_SHA256_CHACHA20 {
    fn eq(&self, other: &DHKEM_X25519_SHA256_CHACHA20) -> bool {
        use subtle::ConstantTimeEq;

        (self.key.ct_eq(&other.key)
            & self.base_nonce.ct_eq(&other.base_nonce)
            & self.ctr.ct_eq(&other.ctr)
            & self.exporter_secret.ct_eq(&other.exporter_secret))
        .into()
    }
}

impl Eq for DHKEM_X25519_SHA256_CHACHA20 {}

impl core::fmt::Debug for DHKEM_X25519_SHA256_CHACHA20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} key: {{***OMITTED***}}, base_nonce: {:?}, ctr: {:?}, exporter_secret: {{***OMITTED***}}", 
            stringify!(DHKEM_X25519_SHA256_CHACHA20), &self.base_nonce, self.ctr)
    }
}

impl Drop for DHKEM_X25519_SHA256_CHACHA20 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.iter_mut().zeroize();
        self.exporter_secret.iter_mut().zeroize();
    }
}

impl Base for DHKEM_X25519_SHA256_CHACHA20 {}
impl Psk for DHKEM_X25519_SHA256_CHACHA20 {}
impl Auth for DHKEM_X25519_SHA256_CHACHA20 {}
impl AuthPsk for DHKEM_X25519_SHA256_CHACHA20 {}

const fn key_schedule_ctx_size<const NK: usize>() -> usize {
    // Two hashes and one mode id
    (NK * 2) + 1
}

impl DHKEM_X25519_SHA256_CHACHA20 {
    /// Size of the HPKE suite KEM ciphertext.
    pub const KEM_CT_SIZE: usize = 32; // Equivalent to X25519 public key.

    /// Size of the HPKE suite KEM sahred secret.
    pub const KEM_SS_SIZE: usize = 32; // Equivalent to X25519 public key.

    /// Version identifier for this HPKE scheme.
    pub const VERSION_ID: &[u8; 7] = b"HPKE-v1";

    /// HPKE ID for this HPKE scheme.
    pub const HPKE_ID: &[u8; 4] = b"HPKE";

    /// KEM ID for this HPKE scheme's KEM (in LE bytes).
    pub const KEM_ID: [u8; 2] = 0x0020u16.to_be_bytes();

    /// KDF ID for this HPKE scheme's KDF (in LE bytes).
    pub const KDF_ID: [u8; 2] = 0x0001u16.to_be_bytes();

    /// AEAD ID for this HPKE scheme's AEAD (in LE bytes).
    pub const AEAD_ID: [u8; 2] = 0x0003u16.to_be_bytes();

    /// The maximum length of `export` secret that may be requested.
    pub const EXPORT_SECRET_MAXLEN: usize = (255 * DHKEM_X25519_SHA256_CHACHA20::NH);

    const NN: usize = 12;
    const NH: usize = 32;

    fn compute_nonce(&self) -> chacha20poly1305::Nonce {
        // "Implementations MAY use a sequence number that is shorter than the nonce length (padding on the left with zero),
        // but MUST raise an error if the sequence number overflows." https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2

        let mut n = [0u8; crate::hazardous::stream::chacha20::IETF_CHACHA_NONCESIZE];
        n[4..12].copy_from_slice(&self.ctr.to_be_bytes());
        xor_slices!(self.base_nonce, n);

        chacha20poly1305::Nonce::from(n)
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
            unreachable!("Internal u64 counter should have overflowed before this counter has!");
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

impl Suite for DHKEM_X25519_SHA256_CHACHA20 {
    type PrivateKey = x25519_hkdf_sha256::PrivateKey;
    type PublicKey = x25519_hkdf_sha256::PublicKey;
    type EncapsulatedKey = x25519_hkdf_sha256::PublicKey;

    #[cfg(test)]
    fn testing_base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }

    #[cfg(test)]
    fn testing_ctr(&self) -> u64 {
        self.ctr
    }

    #[cfg(test)]
    fn testing_exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }

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

        out[..SHA256_OUTSIZE].copy_from_slice(prk.unprotected_as_bytes());

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
        let mut key_schedule_context = Zeroizing::new([0u8; key_schedule_ctx_size::<32>()]);
        key_schedule_context[0] = mode.mode_id();
        Self::labeled_extract(
            b"",
            b"psk_id_hash",
            psk_id,
            &mut key_schedule_context[1..33],
        )?;
        Self::labeled_extract(b"", b"info_hash", info, &mut key_schedule_context[33..65])?;

        let mut secret = Zeroizing::new([0u8; 32]);
        Self::labeled_extract(shared_secret, b"secret", psk, secret.as_mut())?;

        let mut key = Zeroizing::new([0u8; 32]);
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

        let mut exporter_secret = [0u8; 32];
        Self::labeled_expand(
            secret.as_ref(),
            b"exp",
            key_schedule_context.as_ref(),
            &mut exporter_secret,
        )?;

        Ok(Self {
            key: key.as_ref().try_into().expect("unreachable"),
            base_nonce,
            ctr: 0,
            exporter_secret: exporter_secret.as_ref().try_into().expect("unreachable"),
        })
    }

    fn setup_base_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        if info.len() > 64 {
            return Err(UnknownCryptoError);
        }

        let pkr = pubkey_r;
        let (ss, enc) = x25519_hkdf_sha256::DhKem::encap(pkr)?;
        let ctx = Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_bytes(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_base_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        if info.len() > 64 {
            return Err(UnknownCryptoError);
        }

        let skr = secret_key_r;
        let ss = x25519_hkdf_sha256::DhKem::decap(enc, skr)?;

        Self::key_schedule(&HpkeMode::Base, ss.unprotected_as_bytes(), info, &[], &[])
    }

    fn setup_psk_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let pkr = pubkey_r;
        let (ss, enc) = x25519_hkdf_sha256::DhKem::encap(pkr)?;
        let ctx = Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_bytes(), info, psk, psk_id)?;

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

        let skr = secret_key_r;
        let ss = x25519_hkdf_sha256::DhKem::decap(enc, skr)?;
        Self::key_schedule(&HpkeMode::Psk, ss.unprotected_as_bytes(), info, psk, psk_id)
    }

    fn setup_auth_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        secrety_key_s: &Self::PrivateKey,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let pkr = pubkey_r;
        let sks = secrety_key_s;
        let (ss, enc) = x25519_hkdf_sha256::DhKem::auth_encap(pkr, sks)?;
        let ctx = Self::key_schedule(&HpkeMode::Auth, ss.unprotected_as_bytes(), info, &[], &[])?;

        Ok((ctx, enc))
    }

    fn setup_auth_recipient(
        enc: &Self::EncapsulatedKey,
        secret_key_r: &Self::PrivateKey,
        info: &[u8],
        pubkey_s: &Self::PublicKey,
    ) -> Result<Self, UnknownCryptoError> {
        Self::check_input_max_lengths(info)?;

        let pks = pubkey_s;
        let skr = secret_key_r;
        let ss = x25519_hkdf_sha256::DhKem::auth_decap(enc, skr, pks)?;

        Self::key_schedule(&HpkeMode::Auth, ss.unprotected_as_bytes(), info, &[], &[])
    }

    fn setup_authpsk_sender(
        pubkey_r: &Self::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secrety_key_s: &Self::PrivateKey,
    ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError> {
        Self::check_psk_length(psk, psk_id)?;
        Self::check_input_max_lengths(info)?;

        let pkr = pubkey_r;
        let sks = secrety_key_s;
        let (ss, enc) = x25519_hkdf_sha256::DhKem::auth_encap(pkr, sks)?;
        let ctx = Self::key_schedule(
            &HpkeMode::AuthPsk,
            ss.unprotected_as_bytes(),
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

        let pks = pubkey_s;
        let skr = secret_key_r;
        let ss = x25519_hkdf_sha256::DhKem::auth_decap(enc, skr, pks)?;

        Self::key_schedule(
            &HpkeMode::AuthPsk,
            ss.unprotected_as_bytes(),
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
        // Ensure we don't write anything to `out` if `increment_seq()` would fail.
        if self.would_overflow() {
            return Err(UnknownCryptoError);
        }

        let key = chacha20poly1305::SecretKey::from(self.key);
        let nonce = self.compute_nonce();
        chacha20poly1305::seal(&key, &nonce, plaintext, Some(aad), out)?;

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
        chacha20poly1305::open(&key, &nonce, ciphertext, Some(aad), out)?;

        self.increment_seq()
    }

    // CHECK: This interface takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. For the KDFs defined in this specification, L has a maximum value of 255*Nh.
    // max-lenght on out (L), https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3

    fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if out.len() > 255 * Self::NH {
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
    use crate::hazardous::kem::x25519_hkdf_sha256::*;
    use crate::{
        hazardous::hpke::*,
        test_framework::hpke_interface::{HpkeTester, TestableHpke},
    };

    #[test]
    fn test_error_on_lengths_base() {
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (ctx, enc) = DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 64]).unwrap();
        // Info
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 64]).is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 65]).is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, &sk, &[0u8; 64]).is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, &sk, &[0u8; 65]).is_err());

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * DHKEM_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_on_lengths_psk() {
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        // Info
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 65], &[0u8; 64], b"psk_id"
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id"
        )
        .is_ok());

        // PSK
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 64], &[0u8; 65], b"psk_id"
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 64], &[0u8; 31], b"psk_id"
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 64], &[0u8; 32], b"psk_id"
        )
        .is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id"
        )
        .is_ok());
        let (ctx, enc) =
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 64], b"psk_id")
                .unwrap();
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 31], b"psk_id"
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 65], b"psk_id"
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 32], b"psk_id"
        )
        .is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 64], b"psk_id"
        )
        .is_ok());

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * DHKEM_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_on_lengths_auth() {
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (ctx, enc) =
            DHKEM_X25519_SHA256_CHACHA20::setup_auth_sender(&pk, &[0u8; 64], &sk).unwrap();
        // Info
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_auth_sender(&pk, &[0u8; 64], &sk).is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_auth_sender(&pk, &[0u8; 65], &sk).is_err());
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_auth_recipient(&enc, &sk, &[0u8; 64], &pk).is_ok()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_auth_recipient(&enc, &sk, &[0u8; 65], &pk).is_err()
        );

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * DHKEM_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_on_lengths_authpsk() {
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        // Info
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 65], &[0u8; 64], b"psk_id", &sk
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk
        )
        .is_ok());

        // PSK
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 65], b"psk_id", &sk
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 31], b"psk_id", &sk
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 32], b"psk_id", &sk
        )
        .is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk
        )
        .is_ok());
        let (ctx, enc) = DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk,
        )
        .unwrap();
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 31], b"psk_id", &pk
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 65], b"psk_id", &pk
        )
        .is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 32], b"psk_id", &pk
        )
        .is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
            &enc, &sk, &[0u8; 64], &[0u8; 64], b"psk_id", &pk
        )
        .is_ok());

        // Export
        let mut out = [0u8; 64];
        let mut out_max = [0u8; (255 * DHKEM_X25519_SHA256_CHACHA20::NH) + 1];
        assert!(ctx.export(&[0u8; 64], &mut out).is_ok());
        assert!(ctx.export(&[0u8; 65], &mut out).is_err());
        assert!(ctx.export(&[0u8; 64], &mut out_max).is_err());
    }

    #[test]
    fn test_error_if_internal_counter_overflows() {
        let info = b"info param";
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (mut ctx, enc) = DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, info).unwrap();

        ctx.ctr = u64::MAX - 1;

        let plaintext = b"msg";
        let mut dst_out = [0u8; b"msg".len() + 16];
        assert!(ctx.seal(plaintext, b"", &mut dst_out).is_ok());
        // Overflow:
        assert!(ctx.seal(plaintext, b"", &mut dst_out).is_err());

        let mut ctx = DHKEM_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, &sk, info).unwrap();
        ctx.ctr = u64::MAX - 1;

        let ciphertext = dst_out;
        let mut dst_out = [0u8; b"msg".len()];
        assert!(ctx.open(&ciphertext, b"", &mut dst_out).is_ok());
        // Overflow:
        assert!(ctx.open(&ciphertext, b"", &mut dst_out).is_err());

        assert_eq!(&dst_out, plaintext);
    }

    impl TestableHpke for ModeBase<DHKEM_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            DHKEM_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let (sk, pk) = DhKem::derive_keypair(seed)?;
            Ok((sk.unprotected_as_bytes().to_vec(), pk.to_bytes().to_vec()))
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
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let (ctx, enc) = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pubkey_r, info)?;
            public_ct_out.copy_from_slice(&enc.to_bytes());

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
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(&enc, &secret_key_r, info)
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
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; 32];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::base_seal(
                &pubkey_r,
                info,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(&enc.to_bytes());

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
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::base_open(
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

    impl TestableHpke for ModePsk<DHKEM_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            DHKEM_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let (sk, pk) = DhKem::derive_keypair(seed)?;
            Ok((sk.unprotected_as_bytes().to_vec(), pk.to_bytes().to_vec()))
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
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let (ctx, enc) =
                ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pubkey_r, info, psk, psk_id)?;
            public_ct_out.copy_from_slice(&enc.to_bytes());

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
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
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
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; 32];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::psk_seal(
                &pubkey_r,
                info,
                psk,
                psk_id,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(&enc.to_bytes());

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
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::psk_open(
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

    impl TestableHpke for ModeAuth<DHKEM_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            DHKEM_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let (sk, pk) = DhKem::derive_keypair(seed)?;
            Ok((sk.unprotected_as_bytes().to_vec(), pk.to_bytes().to_vec()))
        }

        fn setup_fresh_sender(
            pubkey_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            secret_key_s: &[u8],
            public_ct_out: &mut [u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let secret_key_s = PrivateKey::from_slice(secret_key_s)?;
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let (ctx, enc) = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
                &pubkey_r,
                info,
                &secret_key_s,
            )?;
            public_ct_out.copy_from_slice(&enc.to_bytes());

            Ok(ctx)
        }

        fn setup_fresh_recipient(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            pubkey_s: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let pubkey_s = PublicKey::from_slice(pubkey_s)?;
            ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                &enc,
                &secret_key_r,
                info,
                &pubkey_s,
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
            _psk: &[u8],
            _psk_id: &[u8],
            secret_key_s: &[u8],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let secret_key_s = PrivateKey::from_slice(secret_key_s)?;
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; 32];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::auth_seal(
                &pubkey_r,
                info,
                &secret_key_s,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(&enc.to_bytes());

            Ok((dst_kem_out, dst_out))
        }

        fn oneshot_open(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            _psk: &[u8],
            _psk_id: &[u8],
            pubkey_s: &[u8],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let pubkey_s = PublicKey::from_slice(pubkey_s)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::auth_open(
                &enc,
                &secret_key_r,
                info,
                &pubkey_s,
                ciphertext,
                aad,
                &mut dst_out,
            )?;

            Ok(dst_out)
        }
    }

    impl TestableHpke for ModeAuthPsk<DHKEM_X25519_SHA256_CHACHA20> {
        const HPKE_MODE: u8 = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID;

        fn kem_ct_size() -> usize {
            DHKEM_X25519_SHA256_CHACHA20::KEM_CT_SIZE
        }

        fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let (sk, pk) = DhKem::derive_keypair(seed)?;
            Ok((sk.unprotected_as_bytes().to_vec(), pk.to_bytes().to_vec()))
        }

        fn setup_fresh_sender(
            pubkey_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secret_key_s: &[u8],
            public_ct_out: &mut [u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let secret_key_s = PrivateKey::from_slice(secret_key_s)?;
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let (ctx, enc) = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
                &pubkey_r,
                info,
                psk,
                psk_id,
                &secret_key_s,
            )?;
            public_ct_out.copy_from_slice(&enc.to_bytes());

            Ok(ctx)
        }

        fn setup_fresh_recipient(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            pubkey_s: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let pubkey_s = PublicKey::from_slice(pubkey_s)?;
            ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                &enc,
                &secret_key_r,
                info,
                psk,
                psk_id,
                &pubkey_s,
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
            secret_key_s: &[u8],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError> {
            let secret_key_s = PrivateKey::from_slice(secret_key_s)?;
            let pubkey_r = PublicKey::from_slice(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; 32];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::authpsk_seal(
                &pubkey_r,
                info,
                psk,
                psk_id,
                &secret_key_s,
                plaintext,
                aad,
                &mut dst_out,
            )?;
            dst_kem_out.copy_from_slice(&enc.to_bytes());

            Ok((dst_kem_out, dst_out))
        }

        fn oneshot_open(
            enc: &[u8],
            secret_key_r: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            pubkey_s: &[u8],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, UnknownCryptoError> {
            let enc = PublicKey::from_slice(enc)?;
            let secret_key_r = PrivateKey::from_slice(secret_key_r)?;
            let pubkey_s = PublicKey::from_slice(pubkey_s)?;
            let mut dst_out = vec![0u8; ciphertext.len() - 16];
            ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::authpsk_open(
                &enc,
                &secret_key_r,
                info,
                psk,
                psk_id,
                &pubkey_s,
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
        let mut tester_ctx = HpkeTester::<ModeBase<DHKEM_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }

    #[test]
    fn default_consistency_tests_mode_psk() {
        let seed = 123456u64.to_le_bytes();
        let mut tester_ctx = HpkeTester::<ModePsk<DHKEM_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }

    #[test]
    fn default_consistency_tests_mode_auth() {
        let seed = 123456u64.to_le_bytes();
        let mut tester_ctx = HpkeTester::<ModeAuth<DHKEM_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }

    #[test]
    fn default_consistency_tests_mode_authpsk() {
        let seed = 123456u64.to_le_bytes();
        let mut tester_ctx = HpkeTester::<ModeAuthPsk<DHKEM_X25519_SHA256_CHACHA20>>::new(&seed);
        tester_ctx.run_all_tests();
    }
}
