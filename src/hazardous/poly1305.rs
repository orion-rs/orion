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

//! # Parameters:
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - The length of the `one_time_key` is not 32 bytes
//!
//! # Security:
//!
//! # Example:
//! ```
//! ```

use byteorder::{LittleEndian, ByteOrder};
use hazardous::constants::POLY1305_BLOCKSIZE;
use utilities::{errors::*, util};
use seckey::zero;

pub struct Poly1305 {
    a: [u32; 5],
    r: [u32; 5],
    s: [u32; 4],
    is_finalized: bool,
}


impl Drop for Poly1305 {
    fn drop(&mut self) {
        zero(&mut self.a);
        zero(&mut self.r);
        zero(&mut self.s)
    }
}

impl Poly1305 {
    #[inline(never)]
    fn mul_mod_r() {}

    #[inline(always)]
    /// The Poly1305 function to clamp `r`.
    fn clamp(&mut self, key: &[u8]) -> Result<(), UnknownCryptoError> {
        if key.len() != 32 {
            return Err(UnknownCryptoError);
        }

        // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.r[0] = (LittleEndian::read_u32(&key[0..4])) & 0x3ffffff;
        self.r[1] = (LittleEndian::read_u32(&key[3..7]) >> 2) & 0x3ffff03;
        self.r[2] = (LittleEndian::read_u32(&key[6..10]) >> 4) & 0x3ffc0ff;
        self.r[3] = (LittleEndian::read_u32(&key[9..13]) >> 6) & 0x3f03fff;
        self.r[4] = (LittleEndian::read_u32(&key[12..16]) >> 8) & 0x00fffff;
    }
    #[inline(always)]
    /// Read `s` from a given key.
    fn read_s(&mut self, key: &[u8]) -> Result<(), UnknownCryptoError> {
        if key.len() != 32 {
            return Err(UnknownCryptoError);
        }

        LittleEndian::read_u32_into(&key[16..20], self.s[0]);
        LittleEndian::read_u32_into(&key[20..24], self.s[1]);
        LittleEndian::read_u32_into(&key[24..28], self.s[2]);
        LittleEndian::read_u32_into(&key[28..32], self.s[3]);
    }

    pub fn update() {}

    pub fn finalize() {}

}


pub fn init(one_time_key: &[u8]) -> Result<Poly1305, UnknownCryptoError> {
    if one_time_key.len() != 32 {
        return Err(UnknownCryptoError);
    }

    let mut poly_1305 = Poly1305 {
        a: [0u32; 5],
        r: [0u32; 5],
        s: [0u32; 4],
        is_finalized: false,
    };

    poly_1305.clamp(one_time_key).unwrap();
    poly_1305.read_s(one_time_key).unwrap();

    Ok(poly_1305)
}

pub fn verify() {}
