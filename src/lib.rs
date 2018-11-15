// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! orion - A usable pure-Rust cryptography library.
//!
//! Most functionality that you would need access to should be available through orion's `default`
//! API. This API includes authenticated secret-key encryption, password hashing and more.
//!
//! Usage of the `hazardous` module is only intended for advanced users.
//!
//! You can read more about orion in the project [wiki](https://github.com/brycx/orion/wiki).
//!
//!
//! # Common use cases
//! The following are some common use cases for a cryptography library and how these might
//! be solved using orion.
//!
//! ## Encrypting data
//! The `default::aead` API's `seal` and `open` functions let you encrypt and authenticate data easily
//! using the XChaCha20Poly1305 AEAD construct.
//!
//! ## Hashing a password for storage and verifying it
//! Using the `default::pwhash` API's `password_hash` you can easily hash a password using PBKDF2, store it
//! in a database and later use `password_hash_verify` to verify the password.
//!
//! ## Deriving multiple keys from a single key (key derivation)
//! Using the `default::hkdf` API's `hkdf` function, you can easily derive multiple keys from a single starting key.
//!
//! ## Authenticating a message
//! Using the `default::mac` API's `hmac` function, you can authenitcate a message and use `hmac_verify`
//! to verify such MACs.

#![cfg_attr(not(feature = "safe_api"), no_std)]
#![forbid(unsafe_code)]
#![deny(overflowing_literals)]
#![deny(missing_docs)]
//#![deny(warnings)]

extern crate byteorder;
#[cfg(feature = "safe_api")]
extern crate rand;
extern crate seckey;
extern crate sha2;
extern crate subtle;
extern crate tiny_keccak;

#[macro_use]
mod typedefs;

/// Utilities such as constant-time comparison.
pub mod util;

/// Errors for orion's cryptographic operations.
pub mod errors;

#[cfg(feature = "safe_api")]
/// High-level API for common use cases. Not available in a `no_std` context.
pub mod default;

/// Low-level API.
pub mod hazardous;
