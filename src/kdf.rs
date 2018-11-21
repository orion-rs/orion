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

//! Key derivation.
//!
//! # Use case:
//! `orion::kdf` can be used to derive higher-entropy keys from low-entropy keys.
//!
//! An example of this could be deriving a key from a user-submitted password and using this derived key
//! for disk encryption.
//!
//! # About:
//! - Uses PBKDF2-HMAC-SHA512.
//!
//! # Parameters:
//! - `password`: The low-entropy input key to be used in key derivation.
//! - `expected`: The expected derived key.
//! - `salt`: The salt used for the key derivation.
//! - `iterations`: The number of iterations performed by PBKDF2, i.e. the cost parameter.
//! - `length`: The desired length of the derived key.
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `iterations` is 0.
//! - The `OsRng` fails to initialize or read from its source.
//! - The `expected` does not match the derived key.
//!
//!
//! # Security:
//! - The iteration count should be set as high as feasible. The recommended minimum is 100000.
//! - The salt should always be generated using a CSPRNG. `Salt::generate()` can be used for
//! this, it will generate a `Salt` of 64 bytes.
//!
//! # Example:
//! ```
//! use orion::kdf;
//!
//! let user_password = "User password that needs strethcing".as_bytes();
//! let salt = kdf::Salt::generate();
//!
//! let derived_key = kdf::derive_key(user_password, &salt, 100000, 64).unwrap();
//!
//! assert!(kdf::derive_key_verify(&derived_key, &salt, user_password, 100000).unwrap());
//! ```

use clear_on_drop::clear::Clear;
use errors::{UnknownCryptoError, ValidationCryptoError};
use hazardous::kdf::pbkdf2;
pub use hazardous::kdf::pbkdf2::Password;

construct_secret_key_variable_size! {
    /// A type to represent the `DerivedKey` that PBKDF2 returns when used in key derivation.
    ///
    /// # Exceptions:
    /// An exception will be thrown if:
    /// - `slice` is empty.
    (DerivedKey)
}

construct_salt_variable_size! {
    /// A type to represent the `Salt` that PBKDF2 uses to stretch the key.
    ///
    /// # Exceptions:
    /// An exception will be thrown if:
    /// - `slice` is empty.
    (Salt)
}

#[must_use]
/// Derive a key using PBKDF2-HMAC-SHA512.
pub fn derive_key(
    password: &Password,
    salt: &Salt,
    iterations: usize,
    length: usize,
) -> Result<DerivedKey, UnknownCryptoError> {
    let mut buffer = vec![0u8; length];

    pbkdf2::derive_key(password, &salt.as_bytes(), iterations, &mut buffer).unwrap();

    let dk = DerivedKey::from_slice(&buffer).unwrap();
    Clear::clear(&mut buffer);

    Ok(dk)
}

#[must_use]
/// Derive and verify a key using PBKDF2-HMAC-SHA512.
pub fn derive_key_verify(
    expected: &DerivedKey,
    password: &Password,
    salt: &Salt,
    iterations: usize,
) -> Result<bool, ValidationCryptoError> {
    let mut buffer = vec![0u8; expected.get_length()];

    let is_good = pbkdf2::verify(
        &expected.unprotected_as_bytes(),
        password,
        &salt.as_bytes(),
        iterations,
        &mut buffer,
    ).unwrap();

    Clear::clear(&mut buffer);

    Ok(is_good)
}
