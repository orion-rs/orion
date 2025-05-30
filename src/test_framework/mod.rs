// MIT License

// Copyright (c) 2019-2025 The orion Developers

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

/// Tests for a streaming context that offers incremental processing.
pub mod incremental_interface;

/// Tests for an eXtendable Output Function.
pub mod xof_interface;

/// Tests for AEAD interfaces such as `chacha20poly1305`.
pub mod aead_interface;

/// Tests for stream ciphers such as `chacha20`.
pub mod streamcipher_interface;

#[cfg(feature = "safe_api")]
/// Tests for KEMs such as `mlkem`.
pub mod kem_interface;

#[cfg(all(test, feature = "safe_api"))]
/// Tests for HPKE.
pub mod hpke_interface;
