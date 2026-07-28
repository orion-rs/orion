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

use crate::hazardous::aead::chacha20poly1305::ChaCha20Poly1305;
use crate::hazardous::hpke::base::HpkeSuite;
use crate::hazardous::hpke::kem::MlKem768X25519;
use crate::hazardous::kdf::hkdf::HkdfSha256;

#[allow(non_camel_case_types)]
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
pub type MLKEM768_X25519_SHA256_CHACHA20 = HpkeSuite<MlKem768X25519, HkdfSha256, ChaCha20Poly1305>;

#[cfg(feature = "safe_api")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::KP;
    use crate::errors::UnknownCryptoError;
    use crate::hazardous::hpke::suite::private::Suite;
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
