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

//! # About:
//! Argon2id version 1.3. This implementation is available with features `safe_api` and `alloc`.
//!
//! # Note:
//! This implementation only supports a single thread/lane, so modifying the parallelism degree beyond `1`
//! will simply make them run sequentially.
//!
//! # Parameters:
//! - `expected`: The expected derived key.
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `iterations`: Iteration count.
//! - `memory`: Memory size in kibibytes (KiB).
//! - `parallelism:` Degree of parallelism.
//! - `secret`: Optional secret value used for hashing.
//! - `ad`: Optional associated data used for hashing.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dst_out`.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of the `password` is greater than [`MAX_PASSWORD_LEN`].
//! - The length of the `salt` is greater than [`MAX_SALT_LEN`].
//! - The length of the `secret` is greater than [`MAX_SECRET_LEN`].
//! - The length of the `ad` is greater than [`MAX_AD_LEN`].
//! - The length of `dst_out` is greater than [`u32::MAX`] or less than `4`.
//! - `iterations` is less than [`MIN_ITERATIONS_T`].
//! - `memory` is less than `8*parallelism`.
//! - `parallelism` is less then [`MIN_PARALLELISM_P`] or greater than [`MAX_PARALLELISM_P`].
//! - The hashed password does not match the expected when verifying.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - The minimum recommended length for a salt is `16` bytes.
//! - The minimum recommended length for a hashed password is `16` bytes.
//! - The minimum recommended iteration count is `3`.
//! - Password hashes should always be compared in constant-time.
//! - Please note that when verifying, a copy of the computed password hash is placed into
//! `dst_out`. If the derived hash is considered sensitive and you want to provide defense
//! in depth against an attacker reading your application's private memory, then you as
//! the user are responsible for zeroing out this buffer (see the [`zeroize` crate]).
//!
//! The cost parameters were the recommended values at time of writing. Please be sure to also check
//! [OWASP] for the latest recommended values.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::argon2i, util};
//!
//! let mut salt = [0u8; 16];
//! util::secure_rand_bytes(&mut salt)?;
//! let password = b"Secret password";
//! let mut dst_out = [0u8; 64];
//!
//! argon2i::derive_key(password, &salt, 3, 1<<16, None, None, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(argon2i::verify(
//!     &expected_dk,
//!     password,
//!     &salt,
//!     3,
//!     1<<16,
//!     None,
//!     None,
//!     &mut dst_out
//! )
//! .is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes
//! [`zeroize` crate]: https://crates.io/crates/zeroize
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

use super::*;
use crate::errors::UnknownCryptoError;
use crate::util;

pub use super::ARGON2_I_VARIANT;
pub use super::ARGON2_VERSION_19;
pub use super::MAX_AD_LEN;
pub use super::MAX_ITERATIONS_T;
pub use super::MAX_MEMORY_M;
pub use super::MAX_PARALLELISM_P;
pub use super::MAX_PASSWORD_LEN;
pub use super::MAX_SALT_LEN;
pub use super::MAX_SECRET_LEN;
pub use super::MIN_ITERATIONS_T;
pub use super::MIN_PARALLELISM_P;

#[allow(clippy::too_many_arguments)]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Argon2id password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory: u32,
    parallelism: u32,
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    argon2_derive_key(
        ARGON2_VERSION_19,
        ARGON2_ID_VARIANT,
        password,
        salt,
        iterations,
        memory,
        parallelism,
        secret,
        ad,
        dst_out,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Verify Argon2id derived key in constant time.
pub fn verify(
    expected: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory: u32,
    parallelism: u32,
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    derive_key(
        password,
        salt,
        iterations,
        memory,
        parallelism,
        secret,
        ad,
        dst_out,
    )?;
    util::secure_cmp(dst_out, expected)
}
