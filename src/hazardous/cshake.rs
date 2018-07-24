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
//use sha3;
//use sha3::Digest;
use tiny_keccak::Keccak;

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

// https://groups.google.com/forum/#!topic/golang-codereviews/0t_cXN1u5ro

impl CShake {

    fn rate(&self) -> u64 {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => 168_u64,
            CShakeVariantOption::CSHAKE256 => 136_u64,
        }
    }

    fn keccak_init(&self) -> Keccak {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => {
                let mut hash = Keccak::new(168, 0x04);
                hash
            },
            CShakeVariantOption::CSHAKE256 => {
                let mut hash = Keccak::new(136, 0x04);
                hash
            }
        }
    }

    fn keccak_finalize(&self, state: Keccak) -> Vec<u8> {
        let mut hash = vec![0u8; self.length];
        state.finalize(&mut hash);
        hash
    }

    pub fn finalize(&self) -> Result<Vec<u8>, UnknownCryptoError> {
        // "When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent to SHAKE as
        // defined in FIPS 202"
        if (self.n.is_empty()) && (self.s.is_empty()) {
            // INSERT SHAKE CALLL HERE
            return Err(UnknownCryptoError);
        }

        let mut cshake_pad = Vec::new();

        cshake_pad.extend_from_slice(&left_encode(self.n.len() as u64 * 8));
        cshake_pad.extend_from_slice(&self.n);

        cshake_pad.extend_from_slice(&left_encode(self.s.len() as u64 * 8));
        cshake_pad.extend_from_slice(&self.s);

        cshake_pad = bytepad(&cshake_pad, self.rate());
        cshake_pad.extend_from_slice(&self.input);

        let mut state = self.keccak_init();
        state.absorb(&cshake_pad);
        state.fill_block();
        let fin = self.keccak_finalize(state);

        Ok(fin)
    }
}

pub fn bytepad(x: &[u8], w: u64) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    res.extend_from_slice(&left_encode(w));
    res.extend_from_slice(x);
    let padlen = w - (x.len() as u64 % w);

    res.extend_from_slice(&vec![0u8; padlen as usize]);

    res
}

/// The enc_8 function as specified in the NIST SP 800-185.
pub fn enc_8(i: u64) -> [u8; 9] {
    // In range of 0..255
    assert!(i < 256);

    let mut buf_encoded = [0u8; 9];
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
        write_u64_be(&mut input[1..], x.to_le());
        for idx in &input {
            if *idx != 0 {
                break;
            }
            offset += 1;
        }
    }

    input[offset - 1] = (9 - offset) as u8;
    input[(offset - 1)..].to_vec()
}

/// The encode_string function as specified in the NIST SP 800-185.
pub fn encode_string(s: &[u8]) -> Vec<u8> {

    let mut enc_final = left_encode(s.len() as u64 * 8);
    enc_final.extend_from_slice(s);

    enc_final
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
fn test_left_encode() {
    //let test_1 = left_encode(32);
    let test_2 = left_encode(255);
    let test_3 = left_encode(0);
    let test_4 = left_encode(64);
    let test_5 = left_encode(u64::max_value());

    //assert_eq!(&test_1, &[1, 32]);
    assert_eq!(&test_2, &[1, 255]);
    assert_eq!(&test_3, &[1, 0]);
    assert_eq!(&test_4, &[1, 64]);
    assert_eq!(&test_5, &[8, 255, 255, 255, 255, 255, 255, 255, 255]);


}
