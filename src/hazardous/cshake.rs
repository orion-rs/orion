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
use core::errors::*;
use core::options::CShakeVariantOption;
use core::util;
use tiny_keccak::Keccak;

/// cSHAKE as specified in the [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).
///
/// Fields `input`, `name` and `custom` are zeroed out on drop.
pub struct CShake {
    pub input: Vec<u8>,
    pub name: Vec<u8>,
    pub custom: Vec<u8>,
    pub length: usize,
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
/// - The specified length is zero
/// - The specified length is greater than 65536
/// - If the length of either `name` or `custom` is greater than 65536
///
/// The reason that `name` and `custom` cannot both be empty is because, if they could be set to
/// empty strings the result of using cSHAKE would be equivalent to a SHAKE call.
///
/// # Security:
/// cSHAKE128 has a security strength of 128 bits, whereas cSHAKE256 has a security strength of
/// 256 bits. The recommended output length for cSHAKE128 is 32 and 64 for cSHAKE256.
///
/// # Example:
/// ```
/// use orion::hazardous::cshake::CShake;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::CShakeVariantOption;
///
/// let key = gen_rand_key(32).unwrap();
///
/// let cshake = CShake {
///     input: key,
///     name: "".as_bytes().to_vec(),
///     custom: "Email signature".as_bytes().to_vec(),
///     length: 32,
///     cshake: CShakeVariantOption::CSHAKE128,
/// };
///
/// let result = cshake.finalize().unwrap();
/// assert_eq!(cshake.verify(&result).unwrap(), true);
/// ```

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
            CShakeVariantOption::CSHAKE128 => Keccak::new(self.rate() as usize, 0x04),
            CShakeVariantOption::CSHAKE256 => Keccak::new(self.rate() as usize, 0x04),
        }
    }

    /// Return a Keccak hash.
    fn keccak_finalize(&self, mut state: Keccak) -> Vec<u8> {
        let mut hash = vec![0u8; self.length];
        state.update(&self.input);
        // finalize() will call pad(), then keccakf() and finally squeeze()
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
        if self.length == 0 || self.length > 65536 {
            return Err(UnknownCryptoError);
        }
        if self.name.len() > 65536 || self.custom.len() > 65536 {
            return Err(UnknownCryptoError);
        }

        let mut cshake_pad: Keccak = self.keccak_init();
        // Only append the left encoded rate, not the rate itself as with `name` and `custom`
        cshake_pad.update(&left_encode(self.rate()));
        cshake_pad.update(&encode_string(&self.name));
        cshake_pad.update(&encode_string(&self.custom));
        // Pad with zeroes before calling pad() in finalize()
        cshake_pad.fill_block();

        Ok(self.keccak_finalize(cshake_pad))
    }

    /// Verify a cSHAKE hash by comparing one from the current struct fields to the input hash
    /// passed to the function. Comparison is done in constant time. Both hashes must be
    /// of equal length.
    pub fn verify(&self, input: &[u8]) -> Result<bool, ValidationCryptoError> {
        let own_hash = self.finalize().unwrap();

        if util::compare_ct(&own_hash, input).is_err() {
            Err(ValidationCryptoError)
        } else {
            Ok(true)
        }
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

    #[test]
    fn err_on_empty_n_c() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: b"".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_err());
    }

    #[test]
    fn empty_custom_ok() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: b"Email signature".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_ok());
    }

    #[test]
    fn empty_input_ok() {
        let cshake = CShake {
            input: b"".to_vec(),
            length: 32,
            name: b"Email signature".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_ok());
    }

    #[test]
    fn err_on_zero_length() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 0,
            name: b"Email signature".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_err());
    }

    #[test]
    fn err_on_above_max_length() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 65537,
            name: b"Email signature".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_err());
    }

    #[test]
    fn err_on_name_max_length() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: vec![0u8; 65537],
            custom: b"Email signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_err());
    }

    #[test]
    fn err_on_custom_max_length() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: b"Email signature".to_vec(),
            custom: vec![0u8; 65537],
            cshake: CShakeVariantOption::CSHAKE128,
        };

        assert!(cshake.finalize().is_err());
    }

    #[test]
    fn non_8_div_len() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 17,
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        let expected = b"\xC1\xC3\x69\x25\xB6\x40\x9A\x04\xF1\xB5\x04\xFC\xBC\xA9\xD8\x2B\x40\x17\
                        \x27\x7C\xB5\xED\x2B\x20\x65\xFC\x1D\x38\x14\xD5\xAA\xF5"
            .to_vec();

        assert_eq!(expected[..17].len(), cshake.finalize().unwrap().len());
        assert_eq!(cshake.finalize().unwrap(), &expected[..17]);
    }

    #[test]
    fn verify_ok() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            length: 32,
            cshake: CShakeVariantOption::CSHAKE128,
        };

        let expected = b"\xC1\xC3\x69\x25\xB6\x40\x9A\x04\xF1\xB5\x04\xFC\xBC\xA9\xD8\x2B\x40\x17\
                        \x27\x7C\xB5\xED\x2B\x20\x65\xFC\x1D\x38\x14\xD5\xAA\xF5"
            .to_vec();

        assert_eq!(cshake.verify(&expected).unwrap(), true);
    }

    #[test]
    fn verify_err() {
        // `name` and `custom` values have been switched here compared to the previous one
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: b"Email signature".to_vec(),
            custom: b"".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        let expected = b"\xC1\xC3\x69\x25\xB6\x40\x9A\x04\xF1\xB5\x04\xFC\xBC\xA9\xD8\x2B\x40\x17\
                        \x27\x7C\xB5\xED\x2B\x20\x65\xFC\x1D\x38\x14\xD5\xAA\xF5"
            .to_vec();

        assert!(cshake.verify(&expected).is_err());
    }
}
