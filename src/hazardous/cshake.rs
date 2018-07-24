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

use byte_tools::write_u64_be;
use clear_on_drop::clear::Clear;
use core::errors::UnknownCryptoError;
use core::options::CShakeVariantOption;
use tiny_keccak::Keccak;

/// cSHAKE as specified in the [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).
///
/// Fields `input`, `name` and `custom` are zeroed out on drop.
pub struct CShake {
    pub input: Vec<u8>,
    pub length: usize,
    pub name: Vec<u8>,
    pub custom: Vec<u8>,
    pub cshake: CShakeVariantOption,
}

impl Drop for CShake {
    fn drop(&mut self) {
        Clear::clear(&mut self.input);
        Clear::clear(&mut self.name);
        Clear::clear(&mut self.custom)
    }
}

/// cSHAKE as specified in the [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).
///
/// # Parameters:
/// - `input`:  The main input bit string
/// - `length`: Output length in bytes
/// - `name`: Function-name bit string
/// - `custom`: Customization bit string
/// - `cshake`: cSHAKE variant to be used
///
/// See [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - Both `name` and `custom` are empty
///
/// The reason that `name` and `custom` cannot both be empty is because, if they could be set to
/// empty strings the result of using cSHAKE would be equivalent to a SHAKE call.
///
/// # Security:
///
/// # Example:

impl CShake {
    /// Return the rate in bytes of the respective Keccak sponge function.
    fn rate(&self) -> u64 {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => 168_u64,
            CShakeVariantOption::CSHAKE256 => 136_u64,
        }
    }

    /// Initialize a Keccak hasher.
    fn keccak_init(&self) -> Keccak {
        match &self.cshake {
            CShakeVariantOption::CSHAKE128 => {
                Keccak::new(self.rate() as usize, 0x04)
            }
            CShakeVariantOption::CSHAKE256 => {
                Keccak::new(self.rate() as usize, 0x04)
            }
        }
    }

    /// Return a Keccak hash.
    fn keccak_finalize(&self, mut state: Keccak) -> Vec<u8> {
        let mut hash = vec![0u8; self.length];
        state.absorb(&self.input);
        state.finalize(&mut hash);
        hash
    }

    /// Return a cSHAKE.
    pub fn finalize(&self) -> Result<Vec<u8>, UnknownCryptoError> {
        // "When N and S are both empty strings, cSHAKE(X, L, N, S) is equivalent to SHAKE as
        // defined in FIPS 202"
        if (self.name.is_empty()) && (self.custom.is_empty()) {
            return Err(UnknownCryptoError);
        }

        let mut cshake_pad = self.keccak_init();
        cshake_pad.update(&left_encode(self.rate()));
        cshake_pad.update(&encode_string(&self.name));
        cshake_pad.update(&encode_string(&self.custom));
        cshake_pad.fill_block();

        Ok(self.keccak_finalize(cshake_pad))
    }
}

/// The encode_string function as specified in the NIST SP 800-185.
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut encoded = left_encode(s.len() as u64 * 8);
    encoded.extend_from_slice(s);

    encoded
}

/// The left_encode function as specified in the NIST SP 800-185.
fn left_encode(x: u64) -> Vec<u8> {

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

#[cfg(test)]
mod test {

    use hazardous::cshake::*;

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
        let test_1 = left_encode(32);
        let test_2 = left_encode(255);
        let test_3 = left_encode(0);
        let test_4 = left_encode(64);
        let test_5 = left_encode(u64::max_value());

        assert_eq!(&test_1, &[1, 32]);
        assert_eq!(&test_2, &[1, 255]);
        assert_eq!(&test_3, &[1, 0]);
        assert_eq!(&test_4, &[1, 64]);
        assert_eq!(&test_5, &[8, 255, 255, 255, 255, 255, 255, 255, 255]);
    }

}
