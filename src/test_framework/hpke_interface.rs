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

use crate::errors::UnknownCryptoError;
use core::ops::Range;
use rand::{rngs::SmallRng, Rng, SeedableRng};

/// A testable HPKE implementation. This is implemented separately for each HPKE mode.
pub trait TestableHpke: Clone {
    const HPKE_MODE: u8;

    fn kem_ct_size() -> usize;

    fn gen_kp(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    // Both setup functions have all parameters needed for AuthPsk, and all other modes.
    // If testing a mode that doesn't require all inputs, simply omit.
    fn setup_fresh_sender(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &[u8],
        public_ct_out: &mut [u8],
    ) -> Result<Self, UnknownCryptoError>
    where
        Self: Sized;

    fn setup_fresh_recipient(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &[u8],
    ) -> Result<Self, UnknownCryptoError>
    where
        Self: Sized;

    fn oneshot_seal(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>
    where
        Self: Sized;

    #[allow(clippy::too_many_arguments)]
    fn oneshot_open(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, UnknownCryptoError>
    where
        Self: Sized;

    fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn export(&self, export_context: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError>;
}

pub struct HpkeTester<T: TestableHpke> {
    hpke_sender: T,
    hpke_recipient: T,
    rng: SmallRng,
}

impl<T: TestableHpke> HpkeTester<T> {
    fn random_vector<R: Rng>(rng: &mut R, range: Range<usize>) -> Vec<u8> {
        let mut ret = vec![0u8; rng.random_range(range)];
        rng.fill(ret.as_mut_slice());

        ret
    }

    pub fn new(seed: &[u8]) -> Self {
        // use seed to make deterministic test rng and generate random psk, psk_id, etc.
        let mut seedu64 = [0u8; 8];
        let minlen = std::cmp::min(8, seed.len());
        seedu64[..minlen].copy_from_slice(&seed[..minlen]);

        let mut rng = SmallRng::seed_from_u64(u64::from_le_bytes(seedu64));
        let info = Self::random_vector(&mut rng, 0..64);
        let psk = Self::random_vector(&mut rng, 32..64);
        let psk_id = Self::random_vector(&mut rng, 0..64);

        let kem_ikm_sender = Self::random_vector(&mut rng, 32..64);
        let kem_ikm_recipient = Self::random_vector(&mut rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let sender =
            T::setup_fresh_sender(&recipient_pub, &info, &psk, &psk_id, &sender_priv, &mut ct)
                .unwrap();
        let recipient =
            T::setup_fresh_recipient(&ct, &recipient_priv, &info, &psk, &psk_id, &sender_pub)
                .unwrap();

        Self {
            hpke_sender: sender,
            hpke_recipient: recipient,
            rng,
        }
    }

    pub fn run_all_tests(&mut self) {
        self.test_correct_internal_nonce_handling();
        self.test_replay_protection();
        Self::test_kdf_input_limits();
        self.test_generate_keypair_deterministic();
        self.test_generate_keypair_fresh();
        self.test_psk_inclusion();
        self.test_info_inclusion();
        self.test_kemct_inclusion();
        self.test_export_context_inclusion();
        self.test_modified_aead_tag();
        self.test_modified_aead_aad();
        self.test_auth_inclusion();
        self.test_oneshot_roundtrip_and_streaming_equivalent();
    }

    fn test_correct_internal_nonce_handling(&mut self) {
        let mut sender = self.hpke_sender.clone();

        let mut plaintexts: Vec<Vec<u8>> = Vec::new();
        let mut aads: Vec<Vec<u8>> = Vec::new();
        let mut ciphertexts: Vec<Vec<u8>> = Vec::new();

        for _ in 0..3 {
            let pt = Self::random_vector(&mut self.rng, 0..512);
            let aad = Self::random_vector(&mut self.rng, 0..512);
            let mut dst = vec![0u8; pt.len() + 16];

            sender.seal(&pt, &aad, &mut dst).unwrap();

            plaintexts.push(pt);
            aads.push(aad);
            ciphertexts.push(dst);
        }

        // Correct order
        let mut recipient = self.hpke_recipient.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(recipient
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);

        // open(ct0) OK => open(ct2) => ERR => open(ct1) => OK => open(ct2) => OK
        let mut recipient = self.hpke_recipient.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(recipient
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_err());
        assert!(recipient
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);

        // open(ct2) ERR => open(ct1) => ERR => open(ct0) => OK => open(ct1) => OK => open(ct2) => OK
        let mut recipient = self.hpke_recipient.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(recipient
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_err());
        assert!(recipient
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_err());
        assert!(recipient
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(recipient
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);
    }

    fn test_oneshot_roundtrip_and_streaming_equivalent(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();

        let mut recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let plaintext = Self::random_vector(&mut self.rng, 1..256);
        let aad = Self::random_vector(&mut self.rng, 1..64);

        let mut dst_plaintext = vec![0u8; plaintext.len()];
        let mut dst_ciphertext = vec![0u8; plaintext.len() + 16];
        sender.seal(&plaintext, &aad, &mut dst_ciphertext).unwrap();
        recipient
            .open(&dst_ciphertext, &aad, &mut dst_plaintext)
            .unwrap();

        assert_eq!(dst_plaintext, plaintext);

        let (kem_ct, aead_ct) = T::oneshot_seal(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &plaintext,
            &aad,
        )
        .unwrap();
        let oneshot_plaintext = T::oneshot_open(
            &kem_ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
            &aead_ct,
            &aad,
        )
        .unwrap();

        assert_eq!(oneshot_plaintext, dst_plaintext);
    }

    fn test_generate_keypair_fresh(&mut self) {
        let ikm1 = Self::random_vector(&mut self.rng, 32..64);
        let ikm2 = Self::random_vector(&mut self.rng, 32..64);

        let kp1 = T::gen_kp(&ikm1).unwrap();
        let kp2 = T::gen_kp(&ikm2).unwrap();

        assert_ne!(kp1.0, kp2.0);
        assert_ne!(kp1.1, kp2.1);
    }

    fn test_generate_keypair_deterministic(&mut self) {
        let ikm = Self::random_vector(&mut self.rng, 32..64);
        let kp1 = T::gen_kp(&ikm).unwrap();
        let kp2 = T::gen_kp(&ikm).unwrap();

        assert_eq!(kp1.0, kp2.0);
        assert_eq!(kp1.1, kp2.1);
    }

    fn test_modified_aead_tag(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();

        let mut recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient.open(&out, &[], &mut dst).is_ok());

        out[15] ^= 1;
        assert!(recipient.open(&out, &[], &mut dst).is_err());
    }

    fn test_modified_aead_aad(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();

        let mut recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", b"aad", &mut out).unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient.open(&out, &[], &mut dst).is_err());
        assert!(recipient.open(&out, b"aad", &mut dst).is_ok());
    }

    fn test_kdf_input_limits() {
        // we  use the recommended input length restriction of 64: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.1
        let valid_info = &[0u8; 64];
        let valid_psk = &[0u8; 64];
        let valid_psk_id = &[0u8; 64];
        let valid_kem_ikm_sender = &[0u8; 64];
        let valid_kem_ikm_recipient = &[0u8; 64];

        let (sender_priv, sender_pub) = T::gen_kp(valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        assert!(T::setup_fresh_sender(
            &recipient_pub,
            valid_info,
            valid_psk,
            valid_psk_id,
            &sender_priv,
            &mut ct
        )
        .is_ok());
        assert!(T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            valid_info,
            valid_psk,
            valid_psk_id,
            &sender_pub
        )
        .is_ok());

        // info (applies to all modes)
        assert!(T::setup_fresh_sender(
            &recipient_pub,
            &[0u8; 65],
            valid_psk,
            valid_psk_id,
            &sender_priv,
            &mut ct
        )
        .is_err());
        assert!(T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &[0u8; 65],
            valid_psk,
            valid_psk_id,
            &sender_pub
        )
        .is_err());

        // psk and psk_id
        if T::HPKE_MODE == 0x01u8 || T::HPKE_MODE == 0x03u8 {
            assert!(T::setup_fresh_sender(
                &recipient_pub,
                valid_info,
                &[0u8; 65],
                valid_psk_id,
                &sender_priv,
                &mut ct
            )
            .is_err());
            assert!(T::setup_fresh_recipient(
                &ct,
                &recipient_priv,
                valid_info,
                &[0u8; 65],
                valid_psk_id,
                &sender_pub
            )
            .is_err());

            assert!(T::setup_fresh_sender(
                &recipient_pub,
                valid_info,
                valid_psk,
                &[0u8; 65],
                &sender_priv,
                &mut ct
            )
            .is_err());
            assert!(T::setup_fresh_recipient(
                &ct,
                &recipient_priv,
                valid_info,
                valid_psk,
                &[0u8; 65],
                &sender_pub
            )
            .is_err());
        }

        // ikm (NOTE/TODO: we do NOT restrict this to 64 MAX, this would be breaking change)
        // assert!(T::gen_kp(&[0u8; 64]).is_err());

        let (sender_priv, sender_pub) = T::gen_kp(valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let sender = T::setup_fresh_sender(
            &recipient_pub,
            valid_info,
            valid_psk,
            valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();
        let recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            valid_info,
            valid_psk,
            valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        // exporter_context
        let mut dst = [0u8; 128];
        assert!(sender.export(&[0u8; 64], &mut dst).is_ok());
        assert!(recipient.export(&[0u8; 64], &mut dst).is_ok());
        assert!(sender.export(&[0u8; 65], &mut dst).is_err());
        assert!(recipient.export(&[0u8; 65], &mut dst).is_err());
    }

    fn test_info_inclusion(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();

        let mut bad_info = valid_info.clone();
        bad_info[0] ^= 1;
        let mut recipient_bad = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &bad_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient_bad.open(&out, &[], &mut dst).is_err());

        let mut export_sender = [0u8; 32];
        let mut export_recipient = [0u8; 32];
        sender.export(b"exp", &mut export_sender).unwrap();
        recipient_bad.export(b"exp", &mut export_recipient).unwrap();
        assert_ne!(export_sender, export_recipient);
    }

    fn test_kemct_inclusion(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut bad_ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut bad_ct,
        )
        .unwrap();

        bad_ct[0] ^= 1;
        let mut recipient_bad = T::setup_fresh_recipient(
            &bad_ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient_bad.open(&out, &[], &mut dst).is_err());

        let mut export_sender = [0u8; 32];
        let mut export_recipient = [0u8; 32];
        sender.export(b"exp", &mut export_sender).unwrap();
        recipient_bad.export(b"exp", &mut export_recipient).unwrap();
        assert_ne!(export_sender, export_recipient);
    }

    fn test_psk_inclusion(&mut self) {
        // only for Psk or AuthPsk modes
        if T::HPKE_MODE != 0x01u8 && T::HPKE_MODE != 0x03u8 {
            return;
        }

        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();

        let mut bad_psk = valid_psk.clone();
        bad_psk[0] ^= 1;
        let mut recipient_bad = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &bad_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient_bad.open(&out, &[], &mut dst).is_err());

        let mut export_sender = [0u8; 32];
        let mut export_recipient = [0u8; 32];
        sender.export(b"exp", &mut export_sender).unwrap();
        recipient_bad.export(b"exp", &mut export_recipient).unwrap();
        assert_ne!(export_sender, export_recipient);

        let mut bad_psk_id = valid_psk_id.clone();
        bad_psk_id[0] ^= 1;
        let mut recipient_bad = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &bad_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut dst = [0u8; 24 - 16];
        assert!(recipient_bad.open(&out, &[], &mut dst).is_err());

        let mut export_sender = [0u8; 32];
        let mut export_recipient = [0u8; 32];
        sender.export(b"exp", &mut export_sender).unwrap();
        recipient_bad.export(b"exp", &mut export_recipient).unwrap();
        assert_ne!(export_sender, export_recipient);
    }

    fn test_export_context_inclusion(&mut self) {
        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        let mut ct = vec![0u8; T::kem_ct_size()];
        let sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();
        let recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut export_sender = [0u8; 32];
        let mut export_recipient = [0u8; 32];
        sender.export(b"exp", &mut export_sender).unwrap();
        recipient.export(b"exp", &mut export_recipient).unwrap();
        assert_eq!(export_sender, export_recipient);
        recipient.export(b"pxe", &mut export_recipient).unwrap();
        assert_ne!(export_sender, export_recipient);
    }

    fn test_auth_inclusion(&mut self) {
        // only for Auth or AuthPsk modes
        if T::HPKE_MODE != 0x02u8 && T::HPKE_MODE != 0x03u8 {
            return;
        }

        let valid_info = Self::random_vector(&mut self.rng, 1..64);
        let valid_psk = Self::random_vector(&mut self.rng, 32..64);
        let valid_psk_id = Self::random_vector(&mut self.rng, 1..64);
        let valid_kem_ikm_sender = Self::random_vector(&mut self.rng, 32..64);
        let valid_kem_ikm_recipient = Self::random_vector(&mut self.rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&valid_kem_ikm_sender).unwrap();
        let (bad_sender_priv, bad_sender_pub) =
            T::gen_kp(&Self::random_vector(&mut self.rng, 32..64)).unwrap();
        let (recipient_priv, recipient_pub) = T::gen_kp(&valid_kem_ikm_recipient).unwrap();

        // Sender uses bad priv
        let mut ct = vec![0u8; T::kem_ct_size()];
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &bad_sender_priv,
            &mut ct,
        )
        .unwrap();
        let mut recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();
        let mut dst = [0u8; 24 - 16];
        assert!(recipient.open(&out, &[], &mut dst).is_err());

        // Receiver uses bad Sender pub
        let mut sender = T::setup_fresh_sender(
            &recipient_pub,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &sender_priv,
            &mut ct,
        )
        .unwrap();
        let mut recipient = T::setup_fresh_recipient(
            &ct,
            &recipient_priv,
            &valid_info,
            &valid_psk,
            &valid_psk_id,
            &bad_sender_pub,
        )
        .unwrap();

        let mut out = [0u8; b"test msg".len() + 16];
        sender.seal(b"test msg", &[], &mut out).unwrap();
        let mut dst = [0u8; 24 - 16];
        assert!(recipient.open(&out, &[], &mut dst).is_err());
    }

    /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3>
    fn test_replay_protection(&mut self) {
        let mut sender = self.hpke_sender.clone();

        let pt = Self::random_vector(&mut self.rng, 0..512);
        let aad = Self::random_vector(&mut self.rng, 0..512);
        let mut ciphertexts = vec![0u8; pt.len() + 16];

        sender.seal(&pt, &aad, &mut ciphertexts).unwrap();

        let mut recipient = self.hpke_recipient.clone();
        let mut out_pt = vec![0u8; ciphertexts.len() - 16];
        assert!(recipient.open(&ciphertexts, &aad, &mut out_pt).is_ok());
        assert!(recipient.open(&ciphertexts, &aad, &mut out_pt).is_err());
        assert!(recipient.open(&ciphertexts, &aad, &mut out_pt).is_err());
    }
}
