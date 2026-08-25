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

use crate::generics::sealed::Sealed;
use crate::hazardous::aead::chacha20poly1305::ChaCha20Poly1305;
use crate::hazardous::hpke::base::HpkeSuite;
use crate::hazardous::hpke::kem::DhKemX25519HkdfSha256;
use crate::hazardous::kdf::hkdf::{Hkdf, SHA256};

#[allow(non_camel_case_types)]
/// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305.
///
/// # Note about serialized private keys for this suite
/// RFC 9180 defines the format of X25519 serialized private keys as the clamped version. According to the standard,
/// (de)serializing from/to a private key requires clamping input/output. This implementation adheres to this requirement,
/// and as such, calling [`unprotected_as_ref()`] on the private key used with this suite will return its clamped version.
///
/// The original RFC 9180 test vectors for this suite do on the contrary not include this clamping, so if someone were to compare
/// or otherwise use the output of [`unprotected_as_ref()`], and expect it to be equal that of other implementations, it might not be.
/// This does not affect interoperability in any other way, meaning HPKE data encrypted with Orion will still decrypt successfully with different
/// HPKE implementations.
///
/// The test-vector issues have been reported: <https://www.rfc-editor.org/errata/eid7121>, <https://github.com/cfrg/draft-irtf-cfrg-hpke/issues/255>
///
/// [`unprotected_as_ref()`]: crate::hazardous::kem::x25519_hkdf_sha256::PrivateKey::unprotected_as_ref
pub type DHKEM_X25519_SHA256_CHACHA20 =
    HpkeSuite<DhKemX25519HkdfSha256, Hkdf<SHA256>, ChaCha20Poly1305>;

impl Sealed for DHKEM_X25519_SHA256_CHACHA20 {}

#[cfg(feature = "safe_api")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::errors::UnknownCryptoError;
    use crate::hazardous::hpke::suite::private::{AuthSuite, Suite};
    use crate::hazardous::kem::x25519_hkdf_sha256::*;
    use crate::{
        hazardous::hpke::*,
        test_framework::hpke_interface::{HpkeTester, TestableHpke},
    };

    #[test]
    fn test_derive_keypair() {
        let (sk, pk) = DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 32]).unwrap();
        let (sk_kem, pk_kem) = DhKem::derive_keypair(&[0u8; 32]).unwrap();
        assert_eq!(sk, sk_kem);
        assert_eq!(pk, pk_kem);

        assert!(DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 31]).is_err());
        assert!(DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 32]).is_ok());
        assert!(DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 63]).is_ok());
        assert_ne!(
            DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[0u8; 32])
                .unwrap()
                .1,
            DHKEM_X25519_SHA256_CHACHA20::derive_keypair(&[1u8; 32])
                .unwrap()
                .1
        );
    }

    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_omitted_debug() {
        let (_sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (ctx, _enc) = DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 64]).unwrap();

        let secret_key = format!("{:?}", ctx.key);
        let secret_export = format!("{:?}", ctx.exporter_secret);

        let test_debug_contents = format!("{:?}", ctx);
        assert!(!test_debug_contents.contains(&secret_key));
        assert!(!test_debug_contents.contains(&secret_export));
    }

    #[test]
    fn test_partialeq_impl() {
        let (sk, pk) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (ctx_s, enc) =
            DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 64]).unwrap();
        let ctx_r =
            DHKEM_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, &sk, &[0u8; 64]).unwrap();
        assert_eq!(ctx_s, ctx_r);

        let (_sk, pk) = DhKem::derive_keypair(&[1u8; 64]).unwrap();
        let (ctx_s, _enc) =
            DHKEM_X25519_SHA256_CHACHA20::setup_base_sender(&pk, &[0u8; 64]).unwrap();
        assert_ne!(ctx_s, ctx_r);
    }

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
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 65], &[0u8; 64], b"psk_id")
                .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 64], b"psk_id")
                .is_ok()
        );

        // PSK
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 65], b"psk_id")
                .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 31], b"psk_id")
                .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 32], b"psk_id")
                .is_ok()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 64], b"psk_id")
                .is_ok()
        );
        let (ctx, enc) =
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_sender(&pk, &[0u8; 64], &[0u8; 64], b"psk_id")
                .unwrap();
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 31], b"psk_id"
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 65], b"psk_id"
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 32], b"psk_id"
            )
            .is_ok()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_psk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 64], b"psk_id"
            )
            .is_ok()
        );

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
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 65], &[0u8; 64], b"psk_id", &sk
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk
            )
            .is_ok()
        );

        // PSK
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 64], &[0u8; 65], b"psk_id", &sk
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 64], &[0u8; 31], b"psk_id", &sk
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 64], &[0u8; 32], b"psk_id", &sk
            )
            .is_ok()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
                &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk
            )
            .is_ok()
        );
        let (ctx, enc) = DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_sender(
            &pk, &[0u8; 64], &[0u8; 64], b"psk_id", &sk,
        )
        .unwrap();
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 31], b"psk_id", &pk
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 65], b"psk_id", &pk
            )
            .is_err()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 32], b"psk_id", &pk
            )
            .is_ok()
        );
        assert!(
            DHKEM_X25519_SHA256_CHACHA20::setup_authpsk_recipient(
                &enc, &sk, &[0u8; 64], &[0u8; 64], b"psk_id", &pk
            )
            .is_ok()
        );

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
        assert!(ctx.increment_seq().is_err());
        assert!(ctx.seal(plaintext, b"", &mut dst_out).is_err());

        let mut ctx = DHKEM_X25519_SHA256_CHACHA20::setup_base_recipient(&enc, &sk, info).unwrap();
        ctx.ctr = u64::MAX - 1;

        let ciphertext = dst_out;
        let mut dst_out = [0u8; b"msg".len()];
        assert!(ctx.open(&ciphertext, b"", &mut dst_out).is_ok());
        // Overflow:
        assert!(ctx.increment_seq().is_err());
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
            Ok((sk.unprotected_as_ref().to_vec(), pk.as_ref().to_vec()))
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
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
            let (ctx, enc) = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pubkey_r, info)?;
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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
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
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
            let mut dst_kem_out = vec![0u8; 32];
            let mut dst_out = vec![0u8; plaintext.len() + 16];
            let enc = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::base_seal(
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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
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
            Ok((sk.unprotected_as_ref().to_vec(), pk.as_ref().to_vec()))
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
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
            let (ctx, enc) =
                ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pubkey_r, info, psk, psk_id)?;
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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
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
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
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
            Ok((sk.unprotected_as_ref().to_vec(), pk.as_ref().to_vec()))
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
            let secret_key_s = PrivateKey::try_from(secret_key_s)?;
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
            let (ctx, enc) = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
                &pubkey_r,
                info,
                &secret_key_s,
            )?;
            public_ct_out.copy_from_slice(enc.as_ref());

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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
            let pubkey_s = PublicKey::try_from(pubkey_s)?;
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
            let secret_key_s = PrivateKey::try_from(secret_key_s)?;
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
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
            dst_kem_out.copy_from_slice(enc.as_ref());

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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
            let pubkey_s = PublicKey::try_from(pubkey_s)?;
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
            Ok((sk.unprotected_as_ref().to_vec(), pk.as_ref().to_vec()))
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
            let secret_key_s = PrivateKey::try_from(secret_key_s)?;
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
            let (ctx, enc) = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
                &pubkey_r,
                info,
                psk,
                psk_id,
                &secret_key_s,
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
            pubkey_s: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized,
        {
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
            let pubkey_s = PublicKey::try_from(pubkey_s)?;
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
            let secret_key_s = PrivateKey::try_from(secret_key_s)?;
            let pubkey_r = PublicKey::try_from(pubkey_r)?;
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
            dst_kem_out.copy_from_slice(enc.as_ref());

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
            let enc = PublicKey::try_from(enc)?;
            let secret_key_r = PrivateKey::try_from(secret_key_r)?;
            let pubkey_s = PublicKey::try_from(pubkey_s)?;
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
