// MIT License

// Copyright (c) 2021 The orion Developers

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

//! Ephemeral key exchange.
//!
//! # Use case:
//! `orion::kex` can be used to establish a pair of shared keys between two parties.
//!
//! # About:
//! - Both [`EphemeralClientSession`] and [`EphemeralServerSession`] consume `slef` when shared keys
//! are being established. You can therefore never use the same private key for more than a single
//! key exchange.
//!
//! This implementation is based on and compatible with the
//! [key exchange API](https://doc.libsodium.org/key_exchange) of libsodium.
//!
//! # Parameters:
//! - `server_public_key`: The server's public key used to establish the client's shared session keys.
//! - `client_public_key`: The client's public key used to establish the server's shared session keys.
//!
//! # Errors:
//! An error will be returned if:
//! - If the key exchange results in an all-zero output.
//!
//! # Panics:
//! A panic will occur if:
//! - Failure to generate random bytes securely.
//!
//! # Security:
//! - __**Avoid using**__ `unprotected_private_key()` unless strictly needed. The API is designed to be
//! ephemeral and a [`PrivateKey`] should not be used more than once.
//!
//! # Example:
//! ```rust
//! use orion::kex::*;
//!
//! /// The server initializes their ephemeral session keys
//! let session_server = EphemeralServerSession::new()?;
//! let server_public_key = session_server.get_public();
//!
//! /// The client initializes their ephemeral session keys
//! let session_client = EphemeralClientSession::new()?;
//! let client_public_key = session_client.get_public();
//!
//! let client_keys = session_client
//!     .establish_with_server(&server_public_key)?;
//!
//! let server_keys = session_server
//!     .establish_with_client(&client_public_key)?;
//!
//! assert_eq!(client_keys.get_receiving(), server_keys.get_transport());
//! assert_eq!(client_keys.get_transport(), server_keys.get_receiving());
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```

pub use crate::hazardous::ecc::x25519::PrivateKey;
pub use crate::hazardous::ecc::x25519::PublicKey;
pub use crate::hazardous::ecc::x25519::SharedKey;

use crate::errors::UnknownCryptoError;
use crate::hazardous::ecc::x25519;
use crate::hazardous::hash::blake2b::{Blake2b, Digest};
use core::convert::TryFrom;

#[derive(Debug, PartialEq)]
/// A key pair used to establish shared keys for a single session.
pub struct EphemeralClientSession {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl EphemeralClientSession {
    /// Generate a new random key pair.
    pub fn new() -> Result<Self, UnknownCryptoError> {
        let privkey = x25519::PrivateKey::generate();
        let pubkey: PublicKey = PublicKey::try_from(&privkey)?;

        Ok(Self {
            private_key: privkey,
            public_key: pubkey,
        })
    }

    /// Get copy of the public key.
    pub fn get_public(&self) -> PublicKey {
        self.public_key.clone()
    }

    /// Get reference to the private key.
    pub fn unprotected_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Establish session keys with a server. This moves `self` to ensure that the keys
    /// generated with [`Self::new()`] are only used for this key exchange, thus remaining ephemeral.
    pub fn establish_with_server(
        self,
        server_public_key: &PublicKey,
    ) -> Result<SessionKeys, UnknownCryptoError> {
        let q = x25519::key_agreement(&self.private_key, server_public_key)?;
        let keys = establish_session_keys(&q, &self.public_key, server_public_key)?;

        Ok(SessionKeys {
            rx: SharedKey::from_slice(&keys.as_ref()[..32])?,
            tx: SharedKey::from_slice(&keys.as_ref()[32..])?,
        })
    }
}

#[derive(Debug, PartialEq)]
/// A key pair used to establish shared keys for a single session.
pub struct EphemeralServerSession {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl EphemeralServerSession {
    /// Generate a new random key pair.
    pub fn new() -> Result<Self, UnknownCryptoError> {
        let privkey = x25519::PrivateKey::generate();
        let pubkey: PublicKey = PublicKey::try_from(&privkey)?;

        Ok(Self {
            private_key: privkey,
            public_key: pubkey,
        })
    }

    /// Get copy of the public key.
    pub fn get_public(&self) -> PublicKey {
        self.public_key.clone()
    }

    /// Get reference to the private key.
    pub fn unprotected_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Establish session keys with a client. This moves `self` to ensure that the keys
    /// generated with [`Self::new()`] are only used for this key exchange, thus remaining ephemeral.
    pub fn establish_with_client(
        self,
        client_public_key: &PublicKey,
    ) -> Result<SessionKeys, UnknownCryptoError> {
        let q = x25519::key_agreement(&self.private_key, client_public_key)?;
        let keys = establish_session_keys(&q, client_public_key, &self.public_key)?;

        Ok(SessionKeys {
            rx: SharedKey::from_slice(&keys.as_ref()[32..])?,
            tx: SharedKey::from_slice(&keys.as_ref()[..32])?,
        })
    }
}

#[derive(Debug, PartialEq)]
/// A set of shared secrets for either transmitting to this entity or send to another party.
pub struct SessionKeys {
    rx: SharedKey,
    tx: SharedKey,
}

impl SessionKeys {
    /// Get the shared secret intended to be used for receiving data from the other party.
    pub fn get_receiving(&self) -> &SharedKey {
        &self.rx
    }

    /// Get the shared secret intended to be used for transporting data to the other party.
    pub fn get_transport(&self) -> &SharedKey {
        &self.tx
    }
}

/// Using BLAKE2b, derive two shared secret from a scalarmult computation.
fn establish_session_keys(
    shared_secret: &SharedKey,
    client_pk: &PublicKey,
    server_pk: &PublicKey,
) -> Result<Digest, UnknownCryptoError> {
    let mut ctx = Blake2b::new(None, 64)?;
    ctx.update(shared_secret.unprotected_as_bytes())?;
    ctx.update(&client_pk.to_bytes())?;
    ctx.update(&server_pk.to_bytes())?;
    ctx.finalize()
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[test]
    fn test_basic_key_exchange() {
        let session_server = EphemeralServerSession::new().unwrap();
        let server_public_key = session_server.get_public();

        let session_client = EphemeralClientSession::new().unwrap();
        let client_public_key = session_client.get_public();

        assert_ne!(
            session_client.unprotected_private_key(),
            session_server.unprotected_private_key()
        );

        let client = session_client
            .establish_with_server(&server_public_key)
            .unwrap();
        let server = session_server
            .establish_with_client(&client_public_key)
            .unwrap();

        assert_eq!(client.get_receiving(), server.get_transport());
        assert_eq!(client.get_transport(), server.get_receiving());

        assert_ne!(client.get_receiving(), server.get_receiving());
        assert_ne!(client.get_transport(), server.get_transport());
    }

    #[test]
    fn test_error_on_low_order_public() {
        // Taken from: https://github.com/jedisct1/libsodium/blob/master/test/default/kx.c
        let low_order_public: [u8; 32] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let server_low_order_pk = PublicKey::from_slice(&low_order_public).unwrap();

        let session_client = EphemeralClientSession::new().unwrap();
        assert!(session_client
            .establish_with_server(&server_low_order_pk)
            .is_err());
    }

    // The following are tests generated with sodiumoxide to test basic compatability with libsodium API.
    #[test]
    fn libsodium_compat_test_1() {
        let client_pk = "299283d8713b7d430376cb257e13cd5ad1a6e5ebe6135417f4bb3b45bf42f31a";
        let client_sk = "e026533c3efa096ce9c4d77ad7c3d6948af2f9ef628b88430228ca0465ec35b9";
        let server_pk = "1716d0c006e5f3c2240b2ccec9357dbd04030f51d3e584923e70823cd6fcab1c";
        let server_sk = "55a94da5003d7807850938e84a5082d3deba8e5bbf5c50f814e8160270c165b4";
        let client_rx = "37830d33c5de06fbe246db5803ed70284fe9ab78bc6b896a3db3a9b8db50418b";
        let client_tx = "201d1bb45d4b9164f269d59cc00ba1a49c1924c27485bb6e5cc77ea4cc38ec7e";
        let server_rx = "201d1bb45d4b9164f269d59cc00ba1a49c1924c27485bb6e5cc77ea4cc38ec7e";
        let server_tx = "37830d33c5de06fbe246db5803ed70284fe9ab78bc6b896a3db3a9b8db50418b";

        let client_public = PublicKey::from_slice(&hex::decode(client_pk).unwrap()).unwrap();
        let client_secret = PrivateKey::from_slice(&hex::decode(client_sk).unwrap()).unwrap();
        let server_public = PublicKey::from_slice(&hex::decode(server_pk).unwrap()).unwrap();
        let server_secret = PrivateKey::from_slice(&hex::decode(server_sk).unwrap()).unwrap();

        let client_recv = SharedKey::from_slice(&hex::decode(client_rx).unwrap()).unwrap();
        let client_trans = SharedKey::from_slice(&hex::decode(client_tx).unwrap()).unwrap();
        let server_recv = SharedKey::from_slice(&hex::decode(server_rx).unwrap()).unwrap();
        let server_trans = SharedKey::from_slice(&hex::decode(server_tx).unwrap()).unwrap();

        let session_client = EphemeralClientSession {
            private_key: client_secret,
            public_key: client_public.clone(),
        };

        let session_server = EphemeralServerSession {
            private_key: server_secret,
            public_key: server_public.clone(),
        };

        let expected_client_shared = SessionKeys {
            rx: client_recv,
            tx: client_trans,
        };

        let expected_server_shared = SessionKeys {
            rx: server_recv,
            tx: server_trans,
        };

        assert_eq!(
            session_client
                .establish_with_server(&server_public)
                .unwrap(),
            expected_client_shared
        );
        assert_eq!(
            session_server
                .establish_with_client(&client_public)
                .unwrap(),
            expected_server_shared
        );
    }

    #[test]
    fn libsodium_compat_test_2() {
        let client_pk = "31f8eed74832d31b106702ecdf464a54e9fb9514d241473c5b51deb0d126893a";
        let client_sk = "dcb760f46480ea5c2647e8dcbdc30fff8da6811712b4d5c7144aca1b72d6adb7";
        let server_pk = "ccf7a7d5d2973f517a2276f0ca6c15da3c90a85db12e3ec171c4441c2b48f15d";
        let server_sk = "e73ebfde3907296e5452e1f22ea1a85d4f3cdbf3ff9f099d45a0853d3b87d64f";
        let client_rx = "25789992d2eac8bc0e1c3322d9b8e26050064ea3cead77ca2cf36966dea54186";
        let client_tx = "f69cf60f763fb2a9c47dc1b3237983ef79cecd26205c68f9c16e91db6c8f3f18";
        let server_rx = "f69cf60f763fb2a9c47dc1b3237983ef79cecd26205c68f9c16e91db6c8f3f18";
        let server_tx = "25789992d2eac8bc0e1c3322d9b8e26050064ea3cead77ca2cf36966dea54186";

        let client_public = PublicKey::from_slice(&hex::decode(client_pk).unwrap()).unwrap();
        let client_secret = PrivateKey::from_slice(&hex::decode(client_sk).unwrap()).unwrap();
        let server_public = PublicKey::from_slice(&hex::decode(server_pk).unwrap()).unwrap();
        let server_secret = PrivateKey::from_slice(&hex::decode(server_sk).unwrap()).unwrap();

        let client_recv = SharedKey::from_slice(&hex::decode(client_rx).unwrap()).unwrap();
        let client_trans = SharedKey::from_slice(&hex::decode(client_tx).unwrap()).unwrap();
        let server_recv = SharedKey::from_slice(&hex::decode(server_rx).unwrap()).unwrap();
        let server_trans = SharedKey::from_slice(&hex::decode(server_tx).unwrap()).unwrap();

        let session_client = EphemeralClientSession {
            private_key: client_secret,
            public_key: client_public.clone(),
        };

        let session_server = EphemeralServerSession {
            private_key: server_secret,
            public_key: server_public.clone(),
        };

        let expected_client_shared = SessionKeys {
            rx: client_recv,
            tx: client_trans,
        };

        let expected_server_shared = SessionKeys {
            rx: server_recv,
            tx: server_trans,
        };

        assert_eq!(
            session_client
                .establish_with_server(&server_public)
                .unwrap(),
            expected_client_shared
        );
        assert_eq!(
            session_server
                .establish_with_client(&client_public)
                .unwrap(),
            expected_server_shared
        );
    }

    #[test]
    fn libsodium_compat_test_3() {
        let client_pk = "57f57eda618289c8f55dee0a8069405d9874684282b8380878b180719055333a";
        let client_sk = "7d613b91a1cf6a34787362229cfaf6d50613e276a20ef59eea7f02d9236cd9f7";
        let server_pk = "997f12b2ef5ba2c639c4dc39f159ce5169b60b9a3b65365f958cfb822e37b513";
        let server_sk = "c3156f11e0cc31ffb92dfd5e780738011cfe80cc4184f5a3f190892528a9bac3";
        let client_rx = "89f90402d56d5e184b1682c21583e695560e0ab54459d09a51a596a8d33293da";
        let client_tx = "547c1f1be7abe8d10bf92fb19f79edd2139441b4faa54976b5db90a50b7244c4";
        let server_rx = "547c1f1be7abe8d10bf92fb19f79edd2139441b4faa54976b5db90a50b7244c4";
        let server_tx = "89f90402d56d5e184b1682c21583e695560e0ab54459d09a51a596a8d33293da";

        let client_public = PublicKey::from_slice(&hex::decode(client_pk).unwrap()).unwrap();
        let client_secret = PrivateKey::from_slice(&hex::decode(client_sk).unwrap()).unwrap();
        let server_public = PublicKey::from_slice(&hex::decode(server_pk).unwrap()).unwrap();
        let server_secret = PrivateKey::from_slice(&hex::decode(server_sk).unwrap()).unwrap();

        let client_recv = SharedKey::from_slice(&hex::decode(client_rx).unwrap()).unwrap();
        let client_trans = SharedKey::from_slice(&hex::decode(client_tx).unwrap()).unwrap();
        let server_recv = SharedKey::from_slice(&hex::decode(server_rx).unwrap()).unwrap();
        let server_trans = SharedKey::from_slice(&hex::decode(server_tx).unwrap()).unwrap();

        let session_client = EphemeralClientSession {
            private_key: client_secret,
            public_key: client_public.clone(),
        };

        let session_server = EphemeralServerSession {
            private_key: server_secret,
            public_key: server_public.clone(),
        };

        let expected_client_shared = SessionKeys {
            rx: client_recv,
            tx: client_trans,
        };

        let expected_server_shared = SessionKeys {
            rx: server_recv,
            tx: server_trans,
        };

        assert_eq!(
            session_client
                .establish_with_server(&server_public)
                .unwrap(),
            expected_client_shared
        );
        assert_eq!(
            session_server
                .establish_with_client(&client_public)
                .unwrap(),
            expected_server_shared
        );
    }

    #[test]
    fn libsodium_compat_test_4() {
        let client_pk = "2df30ccfd5eb6cb1ae5428dd06129a22fe8eac2b8b0cfcc1876bbaeb2b515703";
        let client_sk = "52b73937f462130c82c427d68b26b689d3c020169909fea3043882654fa8e1a3";
        let server_pk = "ef09a7379139627b2a13d0376f7fea1e4e2c27859757b74282b4368d2701de1c";
        let server_sk = "384de0b04d358ef0a99cec457507b83a9fcff0c9a2875d1fc771c1b203eb90f5";
        let client_rx = "738d3ff37e8b5d58daf888111359693042508617ef088c2048c0d87bc002ca38";
        let client_tx = "fd1ab19e5c6ac0c5508ba129ded170a25c04f6f1ab9ccc3e66cd73988ade8471";
        let server_rx = "fd1ab19e5c6ac0c5508ba129ded170a25c04f6f1ab9ccc3e66cd73988ade8471";
        let server_tx = "738d3ff37e8b5d58daf888111359693042508617ef088c2048c0d87bc002ca38";

        let client_public = PublicKey::from_slice(&hex::decode(client_pk).unwrap()).unwrap();
        let client_secret = PrivateKey::from_slice(&hex::decode(client_sk).unwrap()).unwrap();
        let server_public = PublicKey::from_slice(&hex::decode(server_pk).unwrap()).unwrap();
        let server_secret = PrivateKey::from_slice(&hex::decode(server_sk).unwrap()).unwrap();

        let client_recv = SharedKey::from_slice(&hex::decode(client_rx).unwrap()).unwrap();
        let client_trans = SharedKey::from_slice(&hex::decode(client_tx).unwrap()).unwrap();
        let server_recv = SharedKey::from_slice(&hex::decode(server_rx).unwrap()).unwrap();
        let server_trans = SharedKey::from_slice(&hex::decode(server_tx).unwrap()).unwrap();

        let session_client = EphemeralClientSession {
            private_key: client_secret,
            public_key: client_public.clone(),
        };

        let session_server = EphemeralServerSession {
            private_key: server_secret,
            public_key: server_public.clone(),
        };

        let expected_client_shared = SessionKeys {
            rx: client_recv,
            tx: client_trans,
        };

        let expected_server_shared = SessionKeys {
            rx: server_recv,
            tx: server_trans,
        };

        assert_eq!(
            session_client
                .establish_with_server(&server_public)
                .unwrap(),
            expected_client_shared
        );
        assert_eq!(
            session_server
                .establish_with_client(&client_public)
                .unwrap(),
            expected_server_shared
        );
    }

    #[test]
    fn libsodium_compat_test_5() {
        let client_pk = "c4be3dfb50430e57313b6eeafc40e9b432120c4dd3d34ca6dedae1391b898c43";
        let client_sk = "23702adbbab5918b682b2a1b2b27c634865b3dcf51ed81e287da30edd4f7ef39";
        let server_pk = "a241a5a8c16e3731ddc8d3e5e5890f85b9de2c87095be3239379b3c62f73f949";
        let server_sk = "530493dddf346371ce562557d5b0ff40ddbff038cf6a20187c16510ce57cc93f";
        let client_rx = "8fa8dfc483108262b058b60b11e2f9b5b47287061bde785827afafb102a09ec7";
        let client_tx = "a01332e4cb85b2bfac65f86936f27058b339889442c13eee06414bfb2d68c58b";
        let server_rx = "a01332e4cb85b2bfac65f86936f27058b339889442c13eee06414bfb2d68c58b";
        let server_tx = "8fa8dfc483108262b058b60b11e2f9b5b47287061bde785827afafb102a09ec7";

        let client_public = PublicKey::from_slice(&hex::decode(client_pk).unwrap()).unwrap();
        let client_secret = PrivateKey::from_slice(&hex::decode(client_sk).unwrap()).unwrap();
        let server_public = PublicKey::from_slice(&hex::decode(server_pk).unwrap()).unwrap();
        let server_secret = PrivateKey::from_slice(&hex::decode(server_sk).unwrap()).unwrap();

        let client_recv = SharedKey::from_slice(&hex::decode(client_rx).unwrap()).unwrap();
        let client_trans = SharedKey::from_slice(&hex::decode(client_tx).unwrap()).unwrap();
        let server_recv = SharedKey::from_slice(&hex::decode(server_rx).unwrap()).unwrap();
        let server_trans = SharedKey::from_slice(&hex::decode(server_tx).unwrap()).unwrap();

        let session_client = EphemeralClientSession {
            private_key: client_secret,
            public_key: client_public.clone(),
        };

        let session_server = EphemeralServerSession {
            private_key: server_secret,
            public_key: server_public.clone(),
        };

        let expected_client_shared = SessionKeys {
            rx: client_recv,
            tx: client_trans,
        };

        let expected_server_shared = SessionKeys {
            rx: server_recv,
            tx: server_trans,
        };

        assert_eq!(
            session_client
                .establish_with_server(&server_public)
                .unwrap(),
            expected_client_shared
        );
        assert_eq!(
            session_server
                .establish_with_client(&client_public)
                .unwrap(),
            expected_server_shared
        );
    }
}
