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
use crate::hazardous::hpke::suite::private::*;
use private::*;

pub(crate) mod private {
    use crate::errors::UnknownCryptoError;

    /// Marker trait for intended for a suite `S` that implements this HPKE mode.
    pub trait Base {}

    /// Marker trait for intended for a suite `S` that implements this HPKE mode.
    pub trait Psk {}

    /// Marker trait for intended for a suite `S` that implements this HPKE mode.
    pub trait Auth {}

    /// Marker trait for intended for a suite `S` that implements this HPKE mode.
    pub trait AuthPsk {}

    #[repr(u8)]
    /// HPKE modes utility.
    pub enum HpkeMode {
        /// Base mode.
        Base = 0x00u8,
        /// PSK mode.
        Psk = 0x01u8,
        /// Auth mode.
        Auth = 0x02u8,
        /// Auth+PSK mode.
        AuthPsk = 0x03u8,
    }

    impl TryFrom<u8> for HpkeMode {
        type Error = UnknownCryptoError;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                0x00 => Ok(Self::Base),
                0x01 => Ok(Self::Psk),
                0x02 => Ok(Self::Auth),
                0x03 => Ok(Self::AuthPsk),
                _ => Err(UnknownCryptoError),
            }
        }
    }

    impl HpkeMode {
        pub(crate) fn verify_psk_inputs(
            &self,
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<(), UnknownCryptoError> {
            match *self {
                HpkeMode::Base | HpkeMode::Auth => {
                    // "default" is just empty string
                    match (psk.is_empty(), psk_id.is_empty()) {
                        (true, true) => Ok(()),
                        (_, _) => Err(UnknownCryptoError), // not PSK or AuthPSK mode
                    }
                }
                HpkeMode::Psk | HpkeMode::AuthPsk => {
                    // "default" is just empty string
                    match (psk.is_empty(), psk_id.is_empty()) {
                        (false, false) => Ok(()),          // require consistent input if provided
                        (_, _) => Err(UnknownCryptoError), // not PSK or AuthPSK mode
                    }
                }
            }
        }

        /// Returns the `mode_id` for this HPKE mode.
        pub fn mode_id(&self) -> u8 {
            match self {
                Self::Base => 0x00u8,
                Self::Psk => 0x01u8,
                Self::Auth => 0x02u8,
                Self::AuthPsk => 0x03u8,
            }
        }
    }
}

#[derive(Clone)]
/// HPKE Base mode.
/// # Parameters:
/// - TODO
///
/// # Errors:
/// An error will be returned if:
/// - TODo
///
/// # Panics:
/// A panic will occur if:
/// - TODO
///
/// # Security:
/// - TODO
///
/// # Example:
/// ```rust
/// # #[cfg(feature = "safe_api")] {
/// use orion::hazardous::hpke::{ModeBase, DHKEM_X25519_SHA256_CHACHA20};
/// use orion::hazardous::kem::x25519_hkdf_sha256::DhKem;
///
/// let (sender_secret, sender_public) = DhKem::generate_keypair()?;
/// let (recipient_secret, recipient_public) = DhKem::generate_keypair()?;
///
///
/// // Streaming-based API
/// let mut kem_ct_out = [0u8; DHKEM_X25519_SHA256_CHACHA20::KEM_CT_SIZE];
/// let mut aead_ct_out0 = [0u8; 32];
/// let mut aead_ct_out1 = [0u8; 32];
/// let mut aead_ct_out2 = [0u8; 32];
///
/// let mut hpke_sender = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&recipient_public.to_bytes(), b"info parameter", &mut kem_ct_out)?;
/// hpke_sender.seal(&[0u8; 16], b"aad parameter 0", &mut aead_ct_out0)?;
/// hpke_sender.seal(&[1u8; 16], b"aad parameter 1", &mut aead_ct_out1)?;
/// hpke_sender.seal(&[2u8; 16], b"aad parameter 2", &mut aead_ct_out2)?;
///
/// let mut hpke_receiver = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_receiver(&kem_ct_out, recipient_secret.unprotected_as_bytes(), b"info parameter")?;
/// let mut aead_pt_out0 = [0u8; 16];
/// let mut aead_pt_out1 = [0u8; 16];
/// let mut aead_pt_out2 = [0u8; 16];
/// hpke_receiver.open(&aead_ct_out0, b"aad parameter 0", &mut aead_pt_out0)?;
/// hpke_receiver.open(&aead_ct_out1, b"aad parameter 1", &mut aead_pt_out1)?;
/// hpke_receiver.open(&aead_ct_out2, b"aad parameter 2", &mut aead_pt_out2)?;
///
/// assert_eq!(&aead_pt_out0, &[0u8; 16]);
/// assert_eq!(&aead_pt_out1, &[1u8; 16]);
/// assert_eq!(&aead_pt_out2, &[2u8; 16]);
///
/// // One-shot API TODO
/// # }
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
pub struct ModeBase<S> {
    suite: S,
}

impl<S> ModeBase<S> {
    /// HPKE Base mode ID.
    pub const MODE_ID: u8 = 0x00u8;
}

impl<S: Suite + Base> ModeBase<S> {
    /// HPKE Base mode sender.
    pub fn new_sender(
        pubkey_r: &[u8],
        info: &[u8],
        public_ct_out: &mut [u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_base_sender(pubkey_r, info, public_ct_out)?,
        })
    }

    /// HPKE Base mode receiver.
    pub fn new_receiver(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_base_receiver(enc, secret_key_r, info)?,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware sealing operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Base mode `seal()` operation.
    pub fn base_seal(
        pubkey_r: &[u8],
        info: &[u8],
        public_ct_out: &mut [u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_sender(pubkey_r, info, public_ct_out)?;
        ctx.seal(plaintext, aad, out)
    }

    /// One-shot API for HPKE Base mode `seal()` operation.
    pub fn base_open(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_receiver(enc, secret_key_r, info)?;
        ctx.open(ciphertext, aad, out)
    }

    /// Export secret.
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.export(exporter_context, out)
    }
}

#[derive(Clone)]
/// HPKE Psk mode.
pub struct ModePsk<S> {
    suite: S,
}

impl<S> ModePsk<S> {
    /// HPKE Psk mode ID.
    pub const MODE_ID: u8 = 0x01u8;
}

impl<S: Suite + Psk> ModePsk<S> {
    /// HPKE Psk mode sender.
    pub fn new_sender(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        public_ct_out: &mut [u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_psk_sender(pubkey_r, info, psk, psk_id, public_ct_out)?,
        })
    }

    /// HPKE Psk mode receiver.
    pub fn new_receiver(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_psk_receiver(enc, secret_key_r, info, psk, psk_id)?,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware sealing operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Psk mode `seal()` operation.
    pub fn psk_seal(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        public_ct_out: &mut [u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_sender(pubkey_r, info, psk, psk_id, public_ct_out)?;
        ctx.seal(plaintext, aad, out)
    }

    /// One-shot API for HPKE Psk mode `open()` operation.
    pub fn psk_open(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_receiver(enc, secret_key_r, info, psk, psk_id)?;
        ctx.open(ciphertext, aad, out)
    }

    /// Export secret.
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.export(exporter_context, out)
    }
}

#[derive(Clone)]
/// HPKE Auth mode.
pub struct ModeAuth<S> {
    suite: S,
}

impl<S> ModeAuth<S> {
    /// HPKE Auth mode ID.
    pub const MODE_ID: u8 = 0x02u8;
}

impl<S: Suite + Auth> ModeAuth<S> {
    /// HPKE Auth mode sender.
    pub fn new_sender(
        pubkey_r: &[u8],
        info: &[u8],
        secret_key_s: &[u8],
        public_ct_out: &mut [u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_auth_sender(pubkey_r, info, secret_key_s, public_ct_out)?,
        })
    }

    /// HPKE Auth mode receiver.
    pub fn new_receiver(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        pubkey_s: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_auth_receiver(enc, secret_key_r, info, pubkey_s)?,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware sealing operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Auth mode `seal()` operation.
    pub fn auth_seal(
        pubkey_r: &[u8],
        info: &[u8],
        secrety_key_s: &[u8],
        public_ct_out: &mut [u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_sender(pubkey_r, info, secrety_key_s, public_ct_out)?;
        ctx.seal(plaintext, aad, out)
    }

    /// One-shot API for HPKE Auth mode `open()` operation.
    pub fn auth_open(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        pubkey_s: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_receiver(enc, secret_key_r, info, pubkey_s)?;
        ctx.open(ciphertext, aad, out)
    }

    /// Export secret.
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.export(exporter_context, out)
    }
}

#[derive(Clone)]
/// HPKE AuthPsk mode.
pub struct ModeAuthPsk<S> {
    suite: S,
}

impl<S> ModeAuthPsk<S> {
    /// HPKE AuthPsk mode ID.
    pub const MODE_ID: u8 = 0x03u8;
}

impl<S: Suite + AuthPsk> ModeAuthPsk<S> {
    /// HPKE AuthPsk mode sender.
    pub fn new_sender(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &[u8],
        public_ct_out: &mut [u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_authpsk_sender(
                pubkey_r,
                info,
                psk,
                psk_id,
                secret_key_s,
                public_ct_out,
            )?,
        })
    }

    /// HPKE AuthPsk mode receiver.
    pub fn new_receiver(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_authpsk_receiver(enc, secret_key_r, info, psk, psk_id, pubkey_s)?,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware sealing operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE AuthPsk mode `seal()` operation.
    pub fn authpsk_seal(
        pubkey_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secrety_key_s: &[u8],
        public_ct_out: &mut [u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_sender(pubkey_r, info, psk, psk_id, secrety_key_s, public_ct_out)?;
        ctx.seal(plaintext, aad, out)
    }

    /// One-shot API for HPKE AuthPsk mode `open()` operation.
    pub fn authpsk_open(
        enc: &[u8],
        secret_key_r: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_receiver(enc, secret_key_r, info, psk, psk_id, pubkey_s)?;
        ctx.open(ciphertext, aad, out)
    }

    /// Export secret.
    pub fn export_secret(
        &self,
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        self.suite.export(exporter_context, out)
    }
}
