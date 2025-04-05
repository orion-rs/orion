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
use crate::hazardous::hpke::Role;
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

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq)]
/// HPKE Base mode. Encrypt data to a public key, without sender authentication.
/// # Parameters:
/// - TODO
///
/// # Errors:
/// An error will be returned if:
/// - `info` is longer than 64 bytes
/// - `out` buffer is longer than `S::EXPORT_SECRET_MAXLEN` when exporting secrets with `Mode.export()`
/// - `exporter_context` is longer than 64 bytes
/// - The internal counter reaches `u64::MAX` and a call to `seal()`/`open()` is made
/// - Calling `seal()` when the role is `Role::Recipient`
/// - Calling `open()` when the role is `Role::Sender`
/// - TODO: Do we want to restrict `ikm` for `derive_keypair` to 64 bytes as recommended but make this a breaking change? Or just save it for an upcoming breaking release?
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
/// let mut aead_ct_out0 = [0u8; 32];
/// let mut aead_ct_out1 = [0u8; 32];
/// let mut aead_ct_out2 = [0u8; 32];
///
/// let (mut hpke_sender, kem_ct) = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&recipient_public, b"info parameter")?;
/// hpke_sender.seal(&[0u8; 16], b"aad parameter 0", &mut aead_ct_out0)?;
/// hpke_sender.seal(&[1u8; 16], b"aad parameter 1", &mut aead_ct_out1)?;
/// hpke_sender.seal(&[2u8; 16], b"aad parameter 2", &mut aead_ct_out2)?;
///
/// let mut hpke_recipient = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(&kem_ct, &recipient_secret, b"info parameter")?;
/// let mut aead_pt_out0 = [0u8; 16];
/// let mut aead_pt_out1 = [0u8; 16];
/// let mut aead_pt_out2 = [0u8; 16];
/// hpke_recipient.open(&aead_ct_out0, b"aad parameter 0", &mut aead_pt_out0)?;
/// hpke_recipient.open(&aead_ct_out1, b"aad parameter 1", &mut aead_pt_out1)?;
/// hpke_recipient.open(&aead_ct_out2, b"aad parameter 2", &mut aead_pt_out2)?;
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
    role: Role,
}

impl<S> ModeBase<S> {
    /// HPKE Base mode ID.
    pub const MODE_ID: u8 = 0x00u8;
}

impl<S: Suite + Base> ModeBase<S> {
    /// HPKE Base mode sender.
    pub fn new_sender(
        pubkey_r: &S::PublicKey,
        info: &[u8],
    ) -> Result<(Self, S::EncapsulatedKey), UnknownCryptoError> {
        let (suite, ek) = S::setup_base_sender(pubkey_r, info)?;

        Ok((
            (Self {
                suite,
                role: Role::Sender,
            }),
            ek,
        ))
    }

    /// HPKE Base mode recipient.
    pub fn new_recipient(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_base_recipient(enc, secret_key_r, info)?,
            role: Role::Recipient,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Sender {
            return Err(UnknownCryptoError);
        }

        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware opening operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Recipient {
            return Err(UnknownCryptoError);
        }

        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Base mode `seal()` operation.
    pub fn base_seal(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<S::EncapsulatedKey, UnknownCryptoError> {
        let (mut ctx, ek) = Self::new_sender(pubkey_r, info)?;
        ctx.seal(plaintext, aad, out)?;

        Ok(ek)
    }

    /// One-shot API for HPKE Base mode `seal()` operation.
    pub fn base_open(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_recipient(enc, secret_key_r, info)?;
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

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq)]
/// HPKE Psk mode. Encrypt data to a public key, using a preshared-key providing sender authentication.
/// # Parameters:
/// - TODO
///
/// # Errors:
/// An error will be returned if:
/// - `info` is longer than 64 bytes
/// - `out` buffer is longer than `S::EXPORT_SECRET_MAXLEN` when exporting secrets with `Mode.export()`
/// - `exporter_context` is longer than 64 bytes
/// - The internal counter reaches `u64::MAX` and a call to `seal()`/`open()` is made
/// - Calling `seal()` when the role is `Role::Recipient`
/// - Calling `open()` when the role is `Role::Sender`
/// - `psk` or `psk_id` are empty
/// - `psk` is less than 32 bytes or more than 64 bytes
/// - `psk_id` is more than 64 bytes
/// - TODO: Do we want to restrict `ikm` for `derive_keypair` to 64 bytes as recommended but make this a breaking change? Or just save it for an upcoming breaking release?
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
///
///
/// // One-shot API TODO
/// # }
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
pub struct ModePsk<S> {
    suite: S,
    role: Role,
}

impl<S> ModePsk<S> {
    /// HPKE Psk mode ID.
    pub const MODE_ID: u8 = 0x01u8;
}

impl<S: Suite + Psk> ModePsk<S> {
    /// HPKE Psk mode sender.
    pub fn new_sender(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Self, S::EncapsulatedKey), UnknownCryptoError> {
        let (suite, ek) = S::setup_psk_sender(pubkey_r, info, psk, psk_id)?;

        Ok((
            (Self {
                suite,
                role: Role::Sender,
            }),
            ek,
        ))
    }

    /// HPKE Psk mode recipient.
    pub fn new_recipient(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_psk_recipient(enc, secret_key_r, info, psk, psk_id)?,
            role: Role::Recipient,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Sender {
            return Err(UnknownCryptoError);
        }

        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware opening operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Recipient {
            return Err(UnknownCryptoError);
        }

        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Psk mode `seal()` operation.
    pub fn psk_seal(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<S::EncapsulatedKey, UnknownCryptoError> {
        let (mut ctx, ek) = Self::new_sender(pubkey_r, info, psk, psk_id)?;
        ctx.seal(plaintext, aad, out)?;

        Ok(ek)
    }

    /// One-shot API for HPKE Psk mode `open()` operation.
    pub fn psk_open(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_recipient(enc, secret_key_r, info, psk, psk_id)?;
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

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq)]
/// HPKE Auth mode. Encrypt data to a public key with sender authentication.
/// # Parameters:
/// - TODO
///
/// # Errors:
/// An error will be returned if:
/// - `info` is longer than 64 bytes
/// - `out` buffer is longer than `S::EXPORT_SECRET_MAXLEN` when exporting secrets with `Mode.export()`
/// - `exporter_context` is longer than 64 bytes
/// - The internal counter reaches `u64::MAX` and a call to `seal()`/`open()` is made
/// - Calling `seal()` when the role is `Role::Recipient`
/// - Calling `open()` when the role is `Role::Sender`
/// - TODO: Do we want to restrict `ikm` for `derive_keypair` to 64 bytes as recommended but make this a breaking change? Or just save it for an upcoming breaking release?
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
///
///
/// // One-shot API TODO
/// # }
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
pub struct ModeAuth<S> {
    suite: S,
    role: Role,
}

impl<S> ModeAuth<S> {
    /// HPKE Auth mode ID.
    pub const MODE_ID: u8 = 0x02u8;
}

impl<S: Suite + Auth> ModeAuth<S> {
    /// HPKE Auth mode sender.
    pub fn new_sender(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        secret_key_s: &S::PrivateKey,
    ) -> Result<(Self, S::EncapsulatedKey), UnknownCryptoError> {
        let (suite, ek) = S::setup_auth_sender(pubkey_r, info, secret_key_s)?;

        Ok((
            (Self {
                suite,
                role: Role::Sender,
            }),
            ek,
        ))
    }

    /// HPKE Auth mode recipient.
    pub fn new_recipient(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        pubkey_s: &S::PublicKey,
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_auth_recipient(enc, secret_key_r, info, pubkey_s)?,
            role: Role::Recipient,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Sender {
            return Err(UnknownCryptoError);
        }

        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware opening operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Recipient {
            return Err(UnknownCryptoError);
        }

        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE Auth mode `seal()` operation.
    pub fn auth_seal(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        secrety_key_s: &S::PrivateKey,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<S::EncapsulatedKey, UnknownCryptoError> {
        let (mut ctx, ek) = Self::new_sender(pubkey_r, info, secrety_key_s)?;
        ctx.seal(plaintext, aad, out)?;

        Ok(ek)
    }

    /// One-shot API for HPKE Auth mode `open()` operation.
    pub fn auth_open(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        pubkey_s: &S::PublicKey,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_recipient(enc, secret_key_r, info, pubkey_s)?;
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

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq)]
/// HPKE AuthPsk mode. Encrypt data to a public key, with sender authentication and an additional preshared-key.
/// # Parameters:
/// - TODO
///
/// # Errors:
/// An error will be returned if:
/// - `info` is longer than 64 bytes
/// - `out` buffer is longer than `S::EXPORT_SECRET_MAXLEN` when exporting secrets with `Mode.export()`
/// - `exporter_context` is longer than 64 bytes
/// - The internal counter reaches `u64::MAX` and a call to `seal()`/`open()` is made
/// - Calling `seal()` when the role is `Role::Recipient`
/// - Calling `open()` when the role is `Role::Sender`
/// - `psk` or `psk_id` are empty
/// - `psk` is less than 32 bytes or more than 64 bytes
/// - `psk_id` is more than 64 bytes
/// - TODO: Do we want to restrict `ikm` for `derive_keypair` to 64 bytes as recommended but make this a breaking change? Or just save it for an upcoming breaking release?
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
///
///
/// // One-shot API TODO
/// # }
/// # Ok::<(), orion::errors::UnknownCryptoError>(())
/// ```
pub struct ModeAuthPsk<S> {
    suite: S,
    role: Role,
}

impl<S> ModeAuthPsk<S> {
    /// HPKE AuthPsk mode ID.
    pub const MODE_ID: u8 = 0x03u8;
}

impl<S: Suite + AuthPsk> ModeAuthPsk<S> {
    /// HPKE AuthPsk mode sender.
    pub fn new_sender(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secret_key_s: &S::PrivateKey,
    ) -> Result<(Self, S::EncapsulatedKey), UnknownCryptoError> {
        let (suite, ek) = S::setup_authpsk_sender(pubkey_r, info, psk, psk_id, secret_key_s)?;

        Ok((
            (Self {
                suite,
                role: Role::Sender,
            }),
            ek,
        ))
    }

    /// HPKE AuthPsk mode recipient.
    pub fn new_recipient(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &S::PublicKey,
    ) -> Result<Self, UnknownCryptoError> {
        Ok(Self {
            suite: S::setup_authpsk_recipient(enc, secret_key_r, info, psk, psk_id, pubkey_s)?,
            role: Role::Recipient,
        })
    }

    /// Context-aware sealing operations.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Sender {
            return Err(UnknownCryptoError);
        }

        self.suite.seal(plaintext, aad, out)
    }

    /// Context-aware opening operations.
    pub fn open(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        if self.role != Role::Recipient {
            return Err(UnknownCryptoError);
        }

        self.suite.open(ciphertext, aad, out)
    }

    /// One-shot API for HPKE AuthPsk mode `seal()` operation.
    pub fn authpsk_seal(
        pubkey_r: &S::PublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        secrety_key_s: &S::PrivateKey,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<S::EncapsulatedKey, UnknownCryptoError> {
        let (mut ctx, ek) = Self::new_sender(pubkey_r, info, psk, psk_id, secrety_key_s)?;
        ctx.seal(plaintext, aad, out)?;

        Ok(ek)
    }

    /// One-shot API for HPKE AuthPsk mode `open()` operation.
    pub fn authpsk_open(
        enc: &S::EncapsulatedKey,
        secret_key_r: &S::PrivateKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        pubkey_s: &S::PublicKey,
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let mut ctx = Self::new_recipient(enc, secret_key_r, info, psk, psk_id, pubkey_s)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::hazardous::{hpke::DHKEM_X25519_SHA256_CHACHA20, kem::x25519_hkdf_sha256::DhKem};

    #[test]
    fn test_error_on_mismatched_role() {
        let (sk_s, pk_s) = DhKem::derive_keypair(&[0u8; 64]).unwrap();
        let (sk_r, pk_r) = DhKem::derive_keypair(&[255u8; 64]).unwrap();

        let mut pt = [1u8; 32];
        let mut out_ct = [0u8; 32 + 16];

        // ModeBase
        let (mut ctx_s, enc) =
            ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pk_r, &[0u8; 64]).unwrap();
        let mut ctx_r =
            ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(&enc, &sk_r, &[0u8; 64])
                .unwrap();

        assert!(ctx_r.seal(&pt, b"", &mut out_ct).is_err());
        ctx_s.seal(&pt, b"", &mut out_ct).unwrap();
        assert!(ctx_s.open(&out_ct, b"", &mut pt).is_err());
        ctx_r.open(&out_ct, b"", &mut pt).unwrap();
        assert_eq!(&pt, &[1u8; 32]);
        // Both can export and they should match
        let mut export_s = [0u8; 64];
        let mut export_r = [0u8; 64];
        ctx_s.export_secret(b"some context", &mut export_s).unwrap();
        ctx_r.export_secret(b"some context", &mut export_r).unwrap();
        assert_eq!(export_s, export_r);

        // ModePsk
        let (mut ctx_s, enc) = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
            &pk_r, &[0u8; 64], &[1u8; 32], b"psk_id",
        )
        .unwrap();
        let mut ctx_r = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
            &enc, &sk_r, &[0u8; 64], &[1u8; 32], b"psk_id",
        )
        .unwrap();

        assert!(ctx_r.seal(&pt, b"", &mut out_ct).is_err());
        ctx_s.seal(&pt, b"", &mut out_ct).unwrap();
        assert!(ctx_s.open(&out_ct, b"", &mut pt).is_err());
        ctx_r.open(&out_ct, b"", &mut pt).unwrap();
        assert_eq!(&pt, &[1u8; 32]);
        // Both can export and they should match
        let mut export_s = [0u8; 64];
        let mut export_r = [0u8; 64];
        ctx_s.export_secret(b"some context", &mut export_s).unwrap();
        ctx_r.export_secret(b"some context", &mut export_r).unwrap();
        assert_eq!(export_s, export_r);

        // ModeAuth
        let (mut ctx_s, enc) =
            ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(&pk_r, &[0u8; 64], &sk_s).unwrap();
        let mut ctx_r =
            ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(&enc, &sk_r, &[0u8; 64], &pk_s)
                .unwrap();

        assert!(ctx_r.seal(&pt, b"", &mut out_ct).is_err());
        ctx_s.seal(&pt, b"", &mut out_ct).unwrap();
        assert!(ctx_s.open(&out_ct, b"", &mut pt).is_err());
        ctx_r.open(&out_ct, b"", &mut pt).unwrap();
        assert_eq!(&pt, &[1u8; 32]);
        // Both can export and they should match
        let mut export_s = [0u8; 64];
        let mut export_r = [0u8; 64];
        ctx_s.export_secret(b"some context", &mut export_s).unwrap();
        ctx_r.export_secret(b"some context", &mut export_r).unwrap();
        assert_eq!(export_s, export_r);

        // ModeAuthPsk
        let (mut ctx_s, enc) = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
            &pk_r, &[0u8; 64], &[1u8; 32], b"psk_id", &sk_s,
        )
        .unwrap();
        let mut ctx_r = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
            &enc, &sk_r, &[0u8; 64], &[1u8; 32], b"psk_id", &pk_s,
        )
        .unwrap();

        assert!(ctx_r.seal(&pt, b"", &mut out_ct).is_err());
        ctx_s.seal(&pt, b"", &mut out_ct).unwrap();
        assert!(ctx_s.open(&out_ct, b"", &mut pt).is_err());
        ctx_r.open(&out_ct, b"", &mut pt).unwrap();
        assert_eq!(&pt, &[1u8; 32]);
        // Both can export and they should match
        let mut export_s = [0u8; 64];
        let mut export_r = [0u8; 64];
        ctx_s.export_secret(b"some context", &mut export_s).unwrap();
        ctx_r.export_secret(b"some context", &mut export_r).unwrap();
        assert_eq!(export_s, export_r);
    }
}
