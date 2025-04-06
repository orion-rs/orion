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

pub(crate) mod private {
    use crate::errors::UnknownCryptoError;
    use crate::hazardous::hpke::mode::private::HpkeMode;
    use crate::hazardous::hpke::private::{HpkeEncapKey, HpkePrivateKey, HpkePublicKey};

    /// Common trait for HPKE suite.
    pub trait Suite {
        /// The private key used for this suite.
        type PrivateKey: HpkePrivateKey;
        /// The public key used for this suite.
        type PublicKey: HpkePublicKey;
        /// The KEM ciphertext, i.e. the "encapsulated" key (in HPKE-terms) used for this suite.
        type EncapsulatedKey: HpkeEncapKey;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con>
        fn key_schedule(
            mode: &HpkeMode,
            shared_secret: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies>
        fn labeled_extract(
            salt: &[u8],
            label: &[u8],
            ikm: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies>
        fn labeled_expand(
            prk: &[u8],
            label: &[u8],
            info: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key>
        fn setup_base_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        fn setup_base_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secret_ephemeral: Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key>
        fn setup_base_recipient(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
            info: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre->
        fn setup_psk_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        fn setup_psk_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secret_ephemeral: Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre->
        fn setup_psk_recipient(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy>
        fn setup_auth_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secrety_key_s: &Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        fn setup_auth_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secrety_key_s: &Self::PrivateKey,
            secret_ephemeral: Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy>
        fn setup_auth_recipient(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
            info: &[u8],
            pubkey_s: &Self::PublicKey,
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4>
        fn setup_authpsk_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secrety_key_s: &Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        fn setup_authpsk_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secrety_key_s: &Self::PrivateKey,
            secret_ephemeral: Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4>
        fn setup_authpsk_recipient(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            pubkey_s: &Self::PublicKey,
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2>
        fn seal(
            &mut self,
            plaintext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2>
        fn open(
            &mut self,
            ciphertext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export>
        fn export(&self, exporter_context: &[u8], out: &mut [u8])
            -> Result<(), UnknownCryptoError>;

        #[cfg(test)]
        fn testing_base_nonce(&self) -> &[u8];

        #[cfg(test)]
        fn testing_ctr(&self) -> u64;

        #[cfg(test)]
        fn testing_exporter_secret(&self) -> &[u8];
    }
}
