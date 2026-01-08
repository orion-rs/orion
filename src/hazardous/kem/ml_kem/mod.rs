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

use crate::errors::UnknownCryptoError;

/// Internal implementation logic for ML-KEM.
pub mod internal;

/// ML-KEM-512 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem512;

/// ML-KEM-768 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem768;

/// ML-KEM-1024 as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
pub mod mlkem1024;

construct_secret_key! {
    /// A type to represent the `d||z` seed used by ML-KEM to produce
    /// a decapsulation key and its corresponding encapsulation key.
    ///
    /// It it crucial for the security of ML-KEM that these be generated
    /// using a CSPRNG.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 64 bytes.
    (Seed, test_ml_kem_seed, 64, 64, 64)
}
