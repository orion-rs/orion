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

mod mode;
mod suite;
mod x25519_sha256_chacha20poly1305;

pub use mode::ModeAuth;
pub use mode::ModeAuthPsk;
pub use mode::ModeBase;
pub use mode::ModePsk;
use private::HpkeEncapKey;
use private::HpkePrivateKey;
use private::HpkePublicKey;

pub use x25519_sha256_chacha20poly1305::DHKEM_X25519_SHA256_CHACHA20;

pub(crate) mod private {

    /// Marker trait for a public key, for an HPKE private key `S`, that can be uses with HPKE.
    pub trait HpkePublicKey {
        /// View as byte-slice.
        fn _as_bytes(&self) -> &[u8];
    }

    /// Marker trait for a "encapsulated" key, for an HPKE private, that is generated with HPKE.
    pub trait HpkeEncapKey {
        /// View as byte-slice.
        fn _as_bytes(&self) -> &[u8];
    }

    /// Marker trait for a private key, that can be uses with HPKE.
    pub trait HpkePrivateKey {
        /// View as byte-slice.
        fn _as_bytes(&self) -> &[u8];
    }
}

impl HpkePrivateKey for crate::hazardous::kem::x25519_hkdf_sha256::PrivateKey {
    fn _as_bytes(&self) -> &[u8] {
        self.unprotected_as_bytes()
    }
}

impl HpkePublicKey for crate::hazardous::kem::x25519_hkdf_sha256::PublicKey {
    fn _as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl HpkeEncapKey for crate::hazardous::kem::x25519_hkdf_sha256::PublicKey {
    fn _as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}
