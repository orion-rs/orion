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

use clear_on_drop::clear::Clear;
use core::options::CShakeVariantOption;
use byte_tools::write_u64_le;
use byte_tools::write_u64_be;
use core::errors::*;
use sha3;
use sha3::Digest;

/// cSHAKE as specified in the NIST SP 800-185.
///
/// Fields `` and `` are zeroed out on drop.
pub struct CShake {
    pub input: Vec<u8>,
    pub length: usize,
    pub n: Vec<u8>,
    pub s: Vec<u8>,
    pub cshake: CShakeVariantOption,
}

impl Drop for CShake {
    fn drop(&mut self) {
        Clear::clear(&mut self.input);
        Clear::clear(&mut self.n);
        Clear::clear(&mut self.s)
    }
}

/// cSHAKE (Hash-based Message Authentication Code) as specified in the LINK HERE
///
/// # Parameters:
/// - `input`:  The main input bit string
/// - `length`: Output length in bytes
/// - `n`: Function-name bit string
/// - `s`: Customization bit string
/// - `cshake`: cSHAKE variant to be used
///
/// See LINK HERE for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The specified length is less than 8
/// - The specified length is not a multiple of 8
/// - `n` is empty
/// - `s` is empty
///
/// The reason that `n` and `s` cannot be empty is because, if they could be set to empty strings
/// the result of using cSHAKE would be equivalent to a SHAKE call (See specification).
///
/// # Security:
///
/// # Example:
/// ```
/// ```

impl CShake {

    fn return_rate(&self) -> u64 {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => 168_u64,
            CShakeVariantOption::CSHAKE256 => 136_u64,
        }
    }

    fn return_keccak(&self, data: &[u8]) -> Vec<u8> {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => {
                let mut hash = sha3::Keccak256::default();
                hash.input(data);
                hash.result().to_vec()
            },
            CShakeVariantOption::CSHAKE256 => {
                let mut hash = sha3::Keccak512::default();
                hash.input(data);
                hash.result().to_vec()
            }
        }
    }

    pub fn finalize(&self) -> Result<Vec<u8>, UnknownCryptoError> {
        // "When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent to SHAKE as
        // defined in FIPS 202"
        if (self.n.is_empty()) && (self.s.is_empty()) {
            return Err(UnknownCryptoError);
        }

        let mut concat_ns_pad = encode_string(&self.n);
        concat_ns_pad.extend_from_slice(&encode_string(&self.n));
        concat_ns_pad = bytepad(&concat_ns_pad, self.return_rate());
        concat_ns_pad.extend_from_slice(&self.input);
        concat_ns_pad.push(0u8);
        concat_ns_pad.push(0u8);

        Ok(self.return_keccak(&concat_ns_pad))

    }

}


/// The enc_8 function as specified in the NIST SP 800-185.
pub fn enc_8(i: u64) -> [u8; 8] {
    // In range of 0..255
    assert!(i < 256);

    let mut buf_encoded = [0u8; 8];
    write_u64_le(&mut buf_encoded, i);

    buf_encoded
}

/// The left_encode function as specified in the NIST SP 800-185.
pub fn left_encode(x: u64) -> Vec<u8> {
    // https://github.com/gvanas/KeccakCodePackage/blob/master/lib/high/Keccak/SP800-185/SP800-185.c
    // https://gist.github.com/mimoo/7e815318e54d5c07c3330149ddf439c5

    let mut input = vec![0u8; 9];

    let mut offset: usize = 0;

    if x == 0 {
        offset = 8;
    } else {
        write_u64_be(&mut input[1..], x);
        for idx in &input {
            offset += 1;
            if *idx != 0_u8 {
                continue;
            }
        }
    }

    input[offset - 1] = 9 - offset as u8;
    input[offset - 1..].to_vec()
}

/*
/// The right_encode function as specified in the NIST SP 800-185.
pub fn right_encode(x: u32) -> Vec<u8> {

    vec![0x00; 0]
}
*/
/// The encode_string function as specified in the NIST SP 800-185.
pub fn encode_string(s: &[u8]) -> Vec<u8> {

    let mut enc_final = left_encode(s.len() as u64);
    enc_final.extend_from_slice(s);

    enc_final
}

/// The bytepad function as specified in the NIST SP 800-185.

/// NEEDS TO BE LOOKED THROUGH
pub fn bytepad(x: &[u8], w: u64) -> Vec<u8> {
    assert!(w > 0);

    let mut z: Vec<u8> = Vec::new();
    z.extend_from_slice(&left_encode(w));
    z.extend_from_slice(x);

    while z.len().checked_rem(8) != None {
        z.push(0u8);
    }
    while (z.len().checked_div(8).unwrap()).checked_rem(w as usize) != None {
        z.extend_from_slice(&[0u8; 8]);
    }

    z
}


#[test]
fn test_encode_string() {
    // Example test case from NIST SP 800-185
    let res = encode_string("".as_bytes());
    // Empty string should yield: 10000000 00000000.
    assert_eq!(res[0].count_ones(), 1);
    assert_eq!(res[0].count_zeros(), 7);

    assert_eq!(res[1].count_ones(), 0);
    assert_eq!(res[1].count_zeros(), 8);
}

#[test]
#[should_panic]
fn test_bytepad_zero_panic() {
    bytepad(&[0u8; 1], 0);
}
