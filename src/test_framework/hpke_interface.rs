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
use core::ops::Range;
use rand::{rngs::SmallRng, Rng, SeedableRng};

/// A testable HPKE implementation. This is implemented separately for each HPKE mode.
pub trait TestableHpke: Clone {
    const HPKE_MODE: u8;

    fn kem_ct_size() -> usize;

    fn gen_kp(seed: &[u8]) -> (Vec<u8>, Vec<u8>);

    // Both steup functions have all parameters needed for AuthPsk, and all other modes.
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

    fn setup_fresh_receiver(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &[u8],
    ) -> Result<Self, UnknownCryptoError>
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
    hpke_receiver: T,
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
        let psk = Self::random_vector(&mut rng, 0..64);
        let psk_id = Self::random_vector(&mut rng, 0..64);

        let kem_ikm_sender = Self::random_vector(&mut rng, 32..64);
        let kem_ikm_receiver = Self::random_vector(&mut rng, 32..64);

        let (sender_priv, sender_pub) = T::gen_kp(&kem_ikm_sender);
        let (receiver_priv, receiver_pub) = T::gen_kp(&kem_ikm_receiver);

        let mut ct = vec![0u8; T::kem_ct_size()];
        let sender =
            T::setup_fresh_sender(&receiver_pub, &info, &psk, &psk_id, &sender_priv, &mut ct)
                .unwrap();
        let receiver =
            T::setup_fresh_receiver(&ct, &receiver_priv, &info, &psk, &psk_id, &sender_pub)
                .unwrap();

        Self {
            hpke_sender: sender,
            hpke_receiver: receiver,
            rng,
        }
    }

    pub fn run_all_tests(&mut self, seed: &[u8]) {
        self.test_correct_internal_nonce_handling();
        self.test_replay_protection();
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
        let mut receiver = self.hpke_receiver.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(receiver
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);

        // open(ct0) OK => open(ct2) => ERR => open(ct1) => OK => open(ct2) => OK
        let mut receiver = self.hpke_receiver.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(receiver
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_err());
        assert!(receiver
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);

        // open(ct2) ERR => open(ct1) => ERR => open(ct0) => OK => open(ct1) => OK => open(ct2) => OK
        let mut receiver = self.hpke_receiver.clone();
        let mut out_ct0 = vec![0u8; ciphertexts[0].len() - 16];
        let mut out_ct1 = vec![0u8; ciphertexts[1].len() - 16];
        let mut out_ct2 = vec![0u8; ciphertexts[2].len() - 16];

        assert!(receiver
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_err());
        assert!(receiver
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_err());
        assert!(receiver
            .open(&ciphertexts[0], &aads[0], &mut out_ct0)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[1], &aads[1], &mut out_ct1)
            .is_ok());
        assert!(receiver
            .open(&ciphertexts[2], &aads[2], &mut out_ct2)
            .is_ok());
        assert_eq!(out_ct0, plaintexts[0]);
        assert_eq!(out_ct1, plaintexts[1]);
        assert_eq!(out_ct2, plaintexts[2]);
    }

    fn test_oneshot_roundtrip() {
        todo!();
    }

    fn test_generate_keypair_fresh() {
        todo!();
    }

    fn test_generate_keypair_deterministic() {
        todo!();
    }

    fn test_modified_aead_tag() {
        todo!();
    }

    fn test_modified_aead_aad() {
        todo!();
    }

    fn test_kdf_input_limits() {
        todo!();
    }

    fn test_psk_inclusion() {
        // only for Psk or AuthPsk modes

        todo!();
    }

    fn test_psk_minlen() {
        // only for Psk or AuthPsk modes

        todo!();
    }

    fn test_auth_inclusion() {
        // only for Auth or AuthPsk modes

        todo!();
    }

    fn test_auth_psk_inclusion() {
        // only for AuthPsk modes

        todo!();
    }

    /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3>
    fn test_replay_protection(&mut self) {
        let mut sender = self.hpke_sender.clone();

        let pt = Self::random_vector(&mut self.rng, 0..512);
        let aad = Self::random_vector(&mut self.rng, 0..512);
        let mut ciphertexts = vec![0u8; pt.len() + 16];

        sender.seal(&pt, &aad, &mut ciphertexts).unwrap();

        let mut receiver = self.hpke_receiver.clone();
        let mut out_pt = vec![0u8; ciphertexts.len() - 16];
        assert!(receiver.open(&ciphertexts, &aad, &mut out_pt).is_ok());
        assert!(receiver.open(&ciphertexts, &aad, &mut out_pt).is_err());
        assert!(receiver.open(&ciphertexts, &aad, &mut out_pt).is_err());
    }
}
