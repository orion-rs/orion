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

use crate::{
    errors::UnknownCryptoError,
    hazardous::{
        aead::chacha20poly1305::{self, ChaCha20Poly1305},
        hpke::suite::private::HpkeAead,
        stream::chacha20,
    },
};

impl HpkeAead for ChaCha20Poly1305 {
    const AEAD_ID: [u8; 2] = 0x0003u16.to_be_bytes();
    const NK: usize = chacha20::CHACHA_KEYSIZE;
    const NN: usize = chacha20::IETF_CHACHA_NONCESIZE;

    type Key = [u8; chacha20::CHACHA_KEYSIZE];
    type Nonce = [u8; chacha20::IETF_CHACHA_NONCESIZE];

    const KEY_INIT: Self::Key = [0u8; chacha20::CHACHA_KEYSIZE];
    const NONCE_INIT: Self::Nonce = [0u8; chacha20::IETF_CHACHA_NONCESIZE];

    fn seal(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let key = chacha20poly1305::SecretKey::from(*key);
        let nonce = chacha20poly1305::Nonce::from(*nonce);

        ChaCha20Poly1305::seal(&key, &nonce, plaintext, Some(aad), out)
    }

    fn open(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let key = chacha20poly1305::SecretKey::from(*key);
        let nonce = chacha20poly1305::Nonce::from(*nonce);

        ChaCha20Poly1305::open(&key, &nonce, ciphertext, Some(aad), out)
    }
}
