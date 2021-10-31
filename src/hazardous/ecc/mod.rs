// MIT License

// Copyright (c) 2021 The orion Developers

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

#[allow(
    dead_code,
    non_camel_case_types,
    clippy::unnecessary_cast,
    clippy::unused_unit,
    rustdoc::broken_intra_doc_links
)]
/// Formally verified  Curve25519 field arithmetic from: <https://github.com/mit-plv/fiat-crypto>
/// Last taken at commit: <https://github.com/mit-plv/fiat-crypto/commit/626203aec9fcf5617631fb687d719e5e78dac09f>
mod fiat_curve25519_u64;

/// Diffie-Hellman key exchange over Curve25519 as specified in the [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
pub mod x25519;
