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

//! Key Encapsulation Mechanism.
//!
//! # Use case:
//! `orion::kem` can be used to establish a pair of shared keys between two parties.
//!
//! # About:
//! - In general, it is highly recommended to use the [`KeyPair`] type to deal with decapsulating operations, or decapsulation keys in general.
//!   [`KeyPair`] internally caches the [`EncapsulationKey`]s used during decapsulation, making it more efficient when used to decapsulate multiple
//!   KEM ciphertext with a given private [`DecapsulationKey`].
//!
//! # Parameters:
//! - `ek`: The public encapsulation key, for which a shared secret and ciphertext is generated.
//! - `dk`: The secret decapsulation key, for which a ciphertext is used to derive a shared secret.
//! - `c`: The public ciphertext, sent to the decapsulating party.
//! - `eseed`: Explicit randomness used for encapsulation [`Eseed`].
//!
//! # Errors:
//! An error will be returned if:
//! - [`getrandom::fill()`] fails during [`EncapsulationKey::encap()`].
//! - [`getrandom::fill()`] fails during [`DecapsulationKey::generate()`]/[`KeyPair::generate()`]/[`Eseed::generate()`].
//!
//! # Security:
//! - It is critical that both the seed and explicit randomness `eseed`, used for key generation and encapsulation
//!   are generated using a strong CSPRNG.
//! - Users should always prefer encapsulation without specifying explicit randomness, if possible.
//!   [`EncapsulationKey::encap_deterministic()`] exists mainly for `no_std` usage.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::kem::*;
//!
//! let kp = KeyPair::generate()?;
//!
//! let ek = EncapsulationKey::try_from(kp.public().as_ref())?;
//! let (sender_shared_secret, sender_ciphertext) = ek.encap()?;
//! let recipient_shared_secret = kp.decap(&sender_ciphertext)?;
//!
//! assert_eq!(sender_shared_secret, recipient_shared_secret);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`getrandom::fill()`]: getrandom::fill
//! [`DecapsulationKey::generate()`]:  crate::hazardous::kem::xwing::DecapsulationKey::generate
//! [`KeyPair::generate()`]:  crate::hazardous::kem::xwing::KeyPair::generate
//! [`Eseed::generate()`]:  crate::hazardous::kem::xwing::Eseed::generate
//! [`EncapsulationKey::encap()`]: crate::hazardous::kem::xwing::EncapsulationKey::encap
//! [`EncapsulationKey::encap_deterministic()`]:  crate::hazardous::kem::xwing::EncapsulationKey::encap_deterministic
//! [`KeyPair`]:  crate::hazardous::kem::xwing::KeyPair
//! [`DecapsulationKey`]:  crate::hazardous::kem::xwing::DecapsulationKey
//! [`EncapsulationKey`]:  crate::hazardous::kem::xwing::EncapsulationKey
//! [`Eseed`]:  crate::hazardous::kem::xwing::Eseed

#![cfg_attr(docsrs, doc(cfg(feature = "safe_api")))]

pub use crate::KP;
pub use crate::hazardous::kem::xwing::CIPHERTEXT_SIZE;
pub use crate::hazardous::kem::xwing::Ciphertext;
pub use crate::hazardous::kem::xwing::DK_SIZE;
pub use crate::hazardous::kem::xwing::EK_SIZE;
pub use crate::hazardous::kem::xwing::ESEED_SIZE;
pub use crate::hazardous::kem::xwing::EncapsulationKey;
pub use crate::hazardous::kem::xwing::KeyPair;
pub use crate::hazardous::kem::xwing::SHARED_SECRET_SIZE;
pub use crate::hazardous::kem::xwing::SharedSecret;
