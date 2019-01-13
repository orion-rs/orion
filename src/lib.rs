// MIT License

// Copyright (c) 2018-2019 The orion Developers

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
//! `orion::aead` offers authenticated secret-key encryption using
//! XChaCha20Poly1305.
//!
//! ## Password hashing and verification
//! `orion::pwhash` offers password hashing and verification using PBKDF2.
//!
//! ## Key derivation
//! `orion::kdf` offers key derivation using PBKDF2.
//!
//! ## Message authentication
//! `orion::auth` offers message authentication and verification using HMAC.
//!
//!
//! ### A note on `no_std`:
//! When orion is used in a `no_std` context, access to nearly all functionality
//! outside of `hazardous`, is not available.
//!
//!
//! More information about orion is available in the [wiki](https://github.com/brycx/orion/wiki).

#![cfg_attr(not(feature = "safe_api"), no_std)]
#![forbid(unsafe_code)]
#![deny(overflowing_literals)]
#![deny(missing_docs)]
#![deny(warnings)]

extern crate byteorder;
extern crate clear_on_drop;
#[cfg(feature = "safe_api")]
extern crate rand_os;
extern crate subtle;
extern crate tiny_keccak;

#[macro_use]
mod typedefs;

/// Utilities such as constant-time comparison.
pub mod util;

/// Errors for orion's cryptographic operations.
pub mod errors;

/// [__**Caution**__] Low-level API.
pub mod hazardous;

#[cfg(feature = "safe_api")]
pub mod hash;

#[cfg(feature = "safe_api")]
pub mod aead;

#[cfg(feature = "safe_api")]
pub mod auth;

#[cfg(feature = "safe_api")]
pub mod pwhash;

#[cfg(feature = "safe_api")]
pub mod kdf;

#[cfg(feature = "safe_api")]
mod hltypes;
