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

use private::HpkeEncapKey;
use private::HpkePrivateKey;
use private::HpkePublicKey;

mod base;
mod mlkem768x25519_sha256_chacha20poly1305;
mod mlkem768x25519_shake256_chacha20poly1305;
mod mode;
mod suite;
mod x25519_sha256_chacha20poly1305;

mod aead;
mod kdf;
mod kem;

pub(crate) use kem::{VERSION_ID, length_prefix};

pub use mlkem768x25519_sha256_chacha20poly1305::MLKEM768_X25519_SHA256_CHACHA20;
pub use mlkem768x25519_shake256_chacha20poly1305::MLKEM768_X25519_SHAKE256_CHACHA20;
pub use mode::ModeAuth;
pub use mode::ModeAuthPsk;
pub use mode::ModeBase;
pub use mode::ModePsk;
pub use x25519_sha256_chacha20poly1305::DHKEM_X25519_SHA256_CHACHA20;

pub(crate) mod private {

    /// Marker trait for a public key, for a corresponding HPKE private key.
    pub trait HpkePublicKey {}

    /// Marker trait for an encapsulated key, that is generated with HPKE.
    pub trait HpkeEncapKey {}

    /// Marker trait for a private key, that can be used with HPKE.
    pub trait HpkePrivateKey {}
}

impl HpkePrivateKey for crate::hazardous::kem::x25519_hkdf_sha256::PrivateKey {}
impl HpkePublicKey for crate::hazardous::kem::x25519_hkdf_sha256::PublicKey {}
impl HpkeEncapKey for crate::hazardous::kem::x25519_hkdf_sha256::PublicKey {}

impl HpkePrivateKey for crate::hazardous::kem::xwing::DecapsulationKey {}
impl HpkePrivateKey for crate::hazardous::kem::xwing::Eseed {}
impl HpkePublicKey for crate::hazardous::kem::xwing::EncapsulationKey {}
impl HpkeEncapKey for crate::hazardous::kem::xwing::Ciphertext {}

#[derive(Clone, Debug, PartialEq)]
/// The role for an instance of HPKE mode.
pub enum Role {
    /// HPKE instance for encrypting data.
    Sender,
    /// HPKE instance for decrypting data.
    Recipient,
}
