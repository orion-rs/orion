// MIT License

// Copyright (c) 2018-2024 The orion Developers

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

//! A usable pure-Rust cryptography library.
//!
//! ## Authenticated secret-key encryption
//! [`orion::aead`] offers authenticated secret-key encryption using
//! XChaCha20Poly1305.
//!
//! ## Password hashing and verification
//! [`orion::pwhash`] offers password hashing and verification using Argon2i.
//!
//! ## Key derivation
//! [`orion::kdf`] offers key derivation using Argon2i.
//!
//! ## Message authentication
//! [`orion::auth`] offers message authentication and verification using BLAKE2b.
//!
//! ## Hashing
//! [`orion::hash`] offers hashing using BLAKE2b.
//!
//! ## Key exchange
//! [`orion::kex`] offers ephemeral key exchange using X25519 and BLAKE2b.
//!
//! ### A note on `no_std`:
//! When Orion is used in a `no_std` context, the high-level API is not available, since it relies on access to the systems random number generator.
//!
//! More information about Orion is available in the [wiki].
//!
//! [`orion::aead`]: crate::aead
//! [`orion::pwhash`]: crate::pwhash
//! [`orion::kdf`]: crate::kdf
//! [`orion::auth`]: crate::auth
//! [`orion::hash`]: crate::hash
//! [`orion::kex`]: crate::kex
//! [wiki]: https://github.com/orion-rs/orion/wiki

#![cfg_attr(not(feature = "safe_api"), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications,
    overflowing_literals
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(test)]
#[cfg(feature = "safe_api")]
extern crate quickcheck;
#[cfg(test)]
#[cfg(feature = "safe_api")]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(feature = "alloc")]
#[cfg_attr(feature = "alloc", macro_use)]
extern crate alloc;

#[macro_use]
mod typedefs;

#[macro_use]
/// Utilities such as constant-time comparison.
pub mod util;

/// Errors for Orion's cryptographic operations.
pub mod errors;

/// \[__**Caution**__\] Low-level API.
pub mod hazardous;

#[cfg(feature = "safe_api")]
mod high_level;

#[cfg(feature = "safe_api")]
pub use high_level::hash;

#[cfg(feature = "safe_api")]
pub use high_level::aead;

#[cfg(feature = "safe_api")]
pub use high_level::auth;

#[cfg(feature = "safe_api")]
pub use high_level::pwhash;

#[cfg(feature = "safe_api")]
pub use high_level::kdf;

#[cfg(feature = "safe_api")]
pub use high_level::kex;

#[doc(hidden)]
/// Testing framework.
pub mod test_framework;
