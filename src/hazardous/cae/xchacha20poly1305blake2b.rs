// MIT License

// Copyright (c) 2023 The orion Developers

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

pub use crate::hazardous::cae::chacha20poly1305blake2b::TAG_SIZE;
use crate::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use crate::hazardous::stream::xchacha20::subkey_and_nonce;
pub use crate::hazardous::stream::{chacha20::SecretKey, xchacha20::Nonce};
use crate::{errors::UnknownCryptoError, hazardous::aead::chacha20poly1305};

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// CTX XChaCha20Poly1305 with BLAKE2b-256.
pub fn seal(
    secret_key: &SecretKey,
    nonce: &Nonce,
    plaintext: &[u8],
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    let (subkey, ietf_nonce) = subkey_and_nonce(secret_key, nonce);
    chacha20poly1305::seal(&subkey, &ietf_nonce, plaintext, ad, dst_out)?;

    let mut blake2b = Blake2b::new(32)?;
    blake2b.update(secret_key.unprotected_as_bytes())?;
    blake2b.update(nonce.as_ref())?;
    blake2b.update(ad)?;
    blake2b.update(dst_out[plaintext.len()..plaintext.len() + POLY1305_OUTSIZE])?;
    dst_out[plaintext.len()..plaintext.len() + TAG_SIZE]
        .copy_from_slice(blake2b.finalize().as_ref());

    Ok(())
}
