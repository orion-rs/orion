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
    Public, Secret,
    errors::UnknownCryptoError,
    hazardous::{
        aead::chacha20poly1305::ChaCha20Poly1305,
        hpke::suite::private::HpkeAead,
        stream::chacha20::{self, ChaCha20Key, ChaCha20Nonce},
    },
};

impl HpkeAead for ChaCha20Poly1305 {
    const AEAD_ID: [u8; 2] = 0x0003u16.to_be_bytes();
    const NK: usize = chacha20::CHACHA_KEYSIZE;
    const NN: usize = chacha20::IETF_CHACHA_NONCESIZE;

    type Key = ChaCha20Key;
    type Nonce = ChaCha20Nonce;

    const KEY_INIT: Secret<Self::Key> = Self::Key::zero();
    const NONCE_INIT: Public<Self::Nonce> = Self::Nonce::zero();

    fn seal(
        key: &Secret<Self::Key>,
        nonce: &Public<Self::Nonce>,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        ChaCha20Poly1305::seal(&key, &nonce, plaintext, Some(aad), out)
    }

    fn open(
        key: &Secret<Self::Key>,
        nonce: &Public<Self::Nonce>,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        ChaCha20Poly1305::open(&key, &nonce, ciphertext, Some(aad), out)
    }
}
