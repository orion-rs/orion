// MIT License

// Copyright (c) 2018-2020 The orion Developers

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

/// These are the different types used by the high-level interface. They are not
/// used in `hazardous`.
use crate::errors::UnknownCryptoError;

construct_secret_key_variable_size! {
    /// A type to represent a secret key.
    ///
    /// As default it will randomly generate a `SecretKey` of 32 bytes.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `length` is 0.
    /// - `length` is not less than `u32::MAX`.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (SecretKey, test_secret_key, 32)
}

construct_salt_variable_size! {
    /// A type to represent the `Salt` that Argon2i uses during key derivation.
    ///
    /// As default it will randomly generate a `Salt` of 16 bytes.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `length` is 0.
    /// - `length` is not less than `u32::MAX`.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (Salt, test_salt, 16)
}

construct_tag! {
    /// A type to represent the `Tag` output by BLAKE2b-256 in keyed mode.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    (Tag, test_tag, 32, 32)
}

impl_from_trait!(Tag, 32);

construct_secret_key_variable_size! {
    /// A type to represent the `Password` that Argon2i hashes and uses for key derivation.
    ///
    /// As default it will randomly generate a `Password` of 32 bytes.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is empty.
    /// - `length` is 0.
    /// - `length` is not less than `u32::MAX`.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (Password, test_password, 32)
}
