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

#[derive(Debug, PartialEq, Clone)]
/// FIPS-204 HashML-DSA supported pre-hashes.
pub enum PreHash {
    /// SHA-256.
    SHA256,
    /// SHA-384,
    SHA384,
    /// SHA-512.
    SHA512,
    /// SHA3-224.
    SHA3_224,
    /// SHA3-256.
    SHA3_256,
    /// SHA3-384.
    SHA3_384,
    /// SHA3-512.
    SHA3_512,
    /// SHAKE-128.
    SHAKE128,
    /// SHAKE-256.
    SHAKE256,
}

impl PreHash {
    /// Return the DER-encoded OID for each variant.
    pub fn oid(&self) -> &[u8] {
        match self {
            // 2.16.840.1.101.3.4.2.1
            PreHash::SHA256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            // 2.16.840.1.101.3.4.2.2
            PreHash::SHA384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            // 2.16.840.1.101.3.4.2.3
            PreHash::SHA512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            // 2.16.840.1.101.3.4.2.7
            PreHash::SHA3_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
            ],
            // 2.16.840.1.101.3.4.2.8
            PreHash::SHA3_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            // 2.16.840.1.101.3.4.2.9
            PreHash::SHA3_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            // 2.16.840.1.101.3.4.2.10
            PreHash::SHA3_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
            ],
            // 2.16.840.1.101.3.4.2.11
            PreHash::SHAKE128 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
            ],
            // 2.16.840.1.101.3.4.2.12
            PreHash::SHAKE256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
            ],
        }
    }
}
