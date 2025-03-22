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

/// A testable HPKE implementation. This is implemented separately for each HPKE mode.
pub trait TestableHpke {
    fn setup_fresh_sender(
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError>
    where
        Self: Sized;

    fn setup_fresh_receiver(
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_pk: &[u8],
    ) -> Result<Self, UnknownCryptoError>
    where
        Self: Sized;

    fn seal(
        &mut self,
        aad: &[u8],
        pt: &[u8],
        nonce: &[u8],
        dst: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn open(
        &mut self,
        aad: &[u8],
        ct: &[u8],
        nonce: &[u8],
        dst: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn export(&self, export_context: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError>;
}

pub struct HpkeTester<T: TestableHpke> {
    hpke_sender: T,
    hpke_receiver: T,
}

impl<T: TestableHpke> HpkeTester<T> {
    pub fn run_all_tests(seed: &[u8]) {
        // use seed to make deterministic test rng and generate random psk, psk_id, etc.
    }

    fn test_correct_internal_nonce_handling() {
        todo!();
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

    fn test_kdf_input_limits() {
        todo!();
    }

    fn test_psk_inclusion() {
        todo!();
    }

    fn test_psk_minlen() {
        todo!();
    }

    fn test_auth_inclusion() {
        todo!();
    }

    fn test_auth_psk_inclusion() {
        todo!();
    }

    fn test_replay_protection() {
        todo!();
    }
}
