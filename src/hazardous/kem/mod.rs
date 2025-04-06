// MIT License

// Copyright (c) 2023-2025 The orion Developers

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

/// DHKEM(X25519, HKDF-SHA256) as specified in HPKE [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
pub mod x25519_hkdf_sha256;

/// ML-KEM as specified in [FIPS-203](https://doi.org/10.6028/NIST.FIPS.203).
mod ml_kem;

pub use ml_kem::mlkem1024;
pub use ml_kem::mlkem512;
pub use ml_kem::mlkem768;

/// X-Wing hybrid KEM as specified in [draft-connolly-cfrg-xwing-kem-06](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html).
pub mod xwing;
