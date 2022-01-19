// MIT License

// Copyright (c) 2018-2022 The orion Developers

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

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub mod hkdf;

/// PBKDF2(Password-Based Key Derivation Function 2) as specified in the [RFC 8018](https://tools.ietf.org/html/rfc8018).
pub mod pbkdf2;

#[cfg(any(feature = "safe_api", feature = "alloc"))]
/// Argon2i password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub mod argon2i;
