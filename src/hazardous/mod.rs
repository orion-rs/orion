// MIT License

// Copyright (c) 2018 brycx

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

//! ### **Caution**:
//! Usage of the `hazardous` module is __**only intended for advanced users**__.
//! `hazardous` contains implementations with a much higher degree of control.
//! It is also much easier to misuse those implementations. Only use `hazardous`
//! if absolutely necessary.

/// AEADs (Authenticated Encryption with Associated Data).
pub mod aead;

/// Cryptographic hash functions.
pub mod hash;

/// MACs (Message Authentication Code).
pub mod mac;

/// KDFs (Key Derivation Function) and PBKDF (Password-Based Key Derivation
/// Function).
pub mod kdf;

/// XOFs (Extendable Output Function).
pub mod xof;

/// Constant values and types.
pub mod constants;

/// Stream ciphers.
pub mod stream;
