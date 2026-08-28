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

pub(crate) mod private {
    use crate::Public;
    use crate::errors::UnknownCryptoError;
    use crate::generics::{Secret, TypeSpec, sealed};
    use crate::hazardous::hpke::mode::private::HpkeMode;
    use crate::hazardous::hpke::private::{HpkeEncapKey, HpkePrivateKey, HpkePublicKey};

    /// Trait for a KEM usable with HPKE.
    pub trait HpkeKem: sealed::Sealed {
        /// KEM identifier <https://www.rfc-editor.org/rfc/rfc9180.html#section-7>.
        const KEM_ID: [u8; 2];

        /// RFC9180 "`Nsecret`": The length in bytes of a KEM shared secret produced by this KEM.
        const NSECRET: usize;

        /// RFC9180 "`Nenc`": The length in bytes of an encapsulated key produced by this KEM.
        /// Also known as KEM "ciphertext".
        const NENC: usize;

        /// RFC9180 "`Npk`": The length in bytes of an encoded public key for this KEM.
        const NPK: usize;

        /// RFC9180 "`Nsk`": The length in bytes of an encoded private key for this KEM.
        const NSK: usize;

        /// The private key of this KEM.
        type PrivateKey: HpkePrivateKey;

        /// The public key of this KEM.
        type PublicKey: HpkePublicKey;

        /// The KEM ciphertext, i.e. the "encapsulated" key in HPKE-terms.
        type EncapsulatedKey: HpkeEncapKey;

        /// The secret ephemeral randomness this KEM consumes during deterministic encapsulation.
        type EphemeralSecret: HpkePrivateKey;

        /// The shared secret this KEM produces.
        type SharedSecretSpec: TypeSpec;

        /// KEM keypair produced by [`Self::derive_keypair()`].
        type KeyPair;

        /// HPKE `DeriveKeyPair()` for this KEM.
        fn derive_keypair(ikm: &[u8]) -> Result<Self::KeyPair, UnknownCryptoError>;

        #[cfg(feature = "safe_api")]
        /// HPKE `Encap()`.
        fn encap(
            pubkey_r: &Self::PublicKey,
        ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError>;

        /// HPKE `Encap()` with explicit randomness.
        fn encap_deterministic(
            pubkey_r: &Self::PublicKey,
            secret_ephemeral: Self::EphemeralSecret,
        ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError>;

        /// HPKE `Decap()`.
        fn decap(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
        ) -> Result<Secret<Self::SharedSecretSpec>, UnknownCryptoError>;
    }

    /// Trait for a HPKE KEM that supports `Auth` mode.
    pub trait HpkeAuthKem: HpkeKem {
        #[cfg(feature = "safe_api")]
        /// HPKE `AuthEncap()`.
        fn auth_encap(
            pubkey_r: &Self::PublicKey,
            secret_key_s: &Self::PrivateKey,
        ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError>;

        /// HPKE `Encap()` with explicit randomness.
        fn auth_encap_deterministic(
            pubkey_r: &Self::PublicKey,
            secret_key_s: &Self::PrivateKey,
            secret_ephemeral: Self::EphemeralSecret,
        ) -> Result<(Secret<Self::SharedSecretSpec>, Self::EncapsulatedKey), UnknownCryptoError>;

        /// HPKE `AuthDecap()`.
        fn auth_decap(
            enc: &Self::EncapsulatedKey,
            secret_key_r: &Self::PrivateKey,
            pubkey_s: &Self::PublicKey,
        ) -> Result<Secret<Self::SharedSecretSpec>, UnknownCryptoError>;
    }

    /// Trait for a KDF usable with HPKE.
    pub trait HpkeKdf: sealed::Sealed {
        /// KDF identifier <https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2>.
        const KDF_ID: [u8; 2];

        /// RFC9180 "`Nh`": The output size of this KDF's extract function, in bytes.
        const NH: usize;

        #[cfg(test)]
        /// The exporter secret this KDF produces, which is `Nh` bytes.
        type ExporterSecret: AsRef<[u8]> + AsMut<[u8]> + Clone;

        #[cfg(not(test))]
        /// The exporter secret this KDF produces, which is `Nh` bytes.
        type ExporterSecret: AsRef<[u8]> + AsMut<[u8]>;

        /// An all-zero [`Self::ExporterSecret`], to be filled by [`Self::combine_secrets()`].
        const EXPORTER_SECRET_INIT: Self::ExporterSecret;

        /// HPKE `CombineSecrets()`, filling `out` with [ `key` || `base_nonce` || `exporter_secret` ].
        ///
        /// `out` is `nk + nn + Self::NH` bytes long. `suite_id` is [ "HPKE" || `kem_id` || `kdf_id` || `aead_id` ].
        #[allow(clippy::too_many_arguments)]
        fn combine_secrets(
            suite_id: &[u8; 10],
            mode: &HpkeMode,
            shared_secret: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            nk: usize,
            nn: usize,
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// HPKE `Context.Export()`.
        fn export(
            suite_id: &[u8; 10],
            exporter_secret: &[u8],
            exporter_context: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;
    }

    /// Trait for an AEAD usable with HPKE.
    pub trait HpkeAead: sealed::Sealed {
        /// AEAD identifier <https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3>.
        const AEAD_ID: [u8; 2];

        /// RFC9180 "`Nk`": The length of a key for this AEAD, in bytes.
        const NK: usize;

        /// RFC9180 "`Nn`": The length of a nonce for this AEAD, in bytes.
        const NN: usize;

        /// RFC9180 "`Nt`": The length of a authentication tag for this AEAD, in bytes.
        const NT: usize;

        #[cfg(test)]
        /// The key of this AEAD, which is `Nk` bytes.
        type Key: TypeSpec + Clone;

        #[cfg(not(test))]
        /// The key of this AEAD, which is `Nk` bytes.
        type Key: TypeSpec;

        #[cfg(test)]
        /// The nonce of this AEAD, which is `Nn` bytes.
        type Nonce: TypeSpec + Clone;

        #[cfg(not(test))]
        /// The nonce of this AEAD, which is `Nn` bytes.
        type Nonce: TypeSpec;

        /// An all-zero [`Self::Key`], buffer used by [`HpkeKdf::combine_secrets()`].
        const KEY_INIT: Secret<Self::Key>;

        /// An all-zero [`Self::Nonce`], buffer used by [`HpkeKdf::combine_secrets()`].
        const NONCE_INIT: Public<Self::Nonce>;

        /// AEAD `Seal()`.
        fn seal(
            key: &Secret<Self::Key>,
            nonce: &Public<Self::Nonce>,
            plaintext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;

        /// AEAD `Open()`.
        fn open(
            key: &Secret<Self::Key>,
            nonce: &Public<Self::Nonce>,
            ciphertext: &[u8],
            aad: &[u8],
            out: &mut [u8],
        ) -> Result<(), UnknownCryptoError>;
    }

    /// Common trait for HPKE suite.
    pub trait Suite: sealed::Sealed {
        /// The private key used for this suite.
        type PrivateKey: HpkePrivateKey;

        /// The public key used for this suite.
        type PublicKey: HpkePublicKey;

        /// The KEM ciphertext, i.e. the "encapsulated" key (in HPKE-terms) used for this suite.
        type EncapsulatedKey: HpkeEncapKey;

        /// The secret explicit randomness this suite's KEM consumes during deterministic
        /// encapsulation.
        type EphemeralSecret: HpkePrivateKey;

        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con>
        ///
        /// This is what creates the key schedule for HPKE context. Previously we only had
        /// two-stage HKDF based routines, both with newer PQ/T construct and upcoming updates
        /// to obsoleting draft-RFC, we can have one-stage KDF (XOFs) so we generalize this one
        /// as well.
        /// <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-5.1>
        fn key_schedule(
            mode: &HpkeMode,
            shared_secret: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<Self, UnknownCryptoError>
        where
            Self: Sized;

        #[cfg(feature = "safe_api")]
        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key>
        fn setup_base_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// Deterministic setup of base-mode sender.
        fn setup_base_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secret_ephemeral: Self::EphemeralSecret,
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

        #[cfg(feature = "safe_api")]
        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre->
        fn setup_psk_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// Deterministic setup of psk-mode sender.
        fn setup_psk_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secret_ephemeral: Self::EphemeralSecret,
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
    }

    /// Trait for an HPKE suite, whose KEM impls [`HpkeAuthKem`].
    pub trait AuthSuite: Suite {
        #[cfg(feature = "safe_api")]
        /// <https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy>
        fn setup_auth_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secret_key_s: &Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// Deterministic setup of auth-mode sender.
        fn setup_auth_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            secret_key_s: &Self::PrivateKey,
            secret_ephemeral: Self::EphemeralSecret,
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

        #[cfg(feature = "safe_api")]
        /// <https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4>
        fn setup_authpsk_sender(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secret_key_s: &Self::PrivateKey,
        ) -> Result<(Self, Self::EncapsulatedKey), UnknownCryptoError>
        where
            Self: Sized;

        /// Deterministic setup of authpsk-mode sender.
        fn setup_authpsk_sender_deterministic(
            pubkey_r: &Self::PublicKey,
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            secret_key_s: &Self::PrivateKey,
            secret_ephemeral: Self::EphemeralSecret,
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
    }
}
