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

//! Key exchange.
//!
//! # Use case:
//! `orion::kex` can be used to establish a pair of shared keys between two parties.
//!
//! TODO
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
//! -
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
//! - TODO
//!
//! # Example:
//! ```rust
//! use orion::kex::*;
//!
//! /// The server initializes their ephemeral session keys
//! let session_server = EphemeralServerSession::new().unwrap();
//! let server_public_key = session_server.get_public();
//!
//! /// The client initializes their ephemeral session keys
//! let session_client = EphemeralClientSession::new().unwrap();
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

pub use crate::hazardous::ecc::x25519::PublicKey;
pub use crate::hazardous::ecc::x25519::SharedKey;

use crate::errors::UnknownCryptoError;
use crate::hazardous::ecc::x25519;
use crate::hazardous::hash::blake2b::{Blake2b, Digest};
use core::convert::TryFrom;

#[derive(Debug, PartialEq)]
/// A key pair used to establish shared keys for a single session.
pub struct EphemeralClientSession {
    private_key: x25519::PrivateKey,
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
    private_key: x25519::PrivateKey,
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

#[test]
fn test_ephemeral() {
    let session_server = EphemeralServerSession::new().unwrap();
    let server_public_key = session_server.get_public();

    let session_client = EphemeralClientSession::new().unwrap();
    let client_public_key = session_client.get_public();

    let client = session_client
        .establish_with_server(&server_public_key)
        .unwrap();
    let server = session_server
        .establish_with_client(&client_public_key)
        .unwrap();

    assert_eq!(client.get_receiving(), server.get_transport());
    assert_eq!(client.get_transport(), server.get_receiving());
}
