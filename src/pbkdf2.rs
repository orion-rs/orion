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
use hmac::Hmac;
use core::options::ShaVariantOption;
use byte_tools::write_u32_be;
use core::errors;
use core::util;

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).

pub struct Pbkdf2 {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: usize,
    pub length: usize,
    pub hmac: ShaVariantOption,
}

impl Drop for Pbkdf2 {
    fn drop(&mut self) {
        Clear::clear(&mut self.password);
        Clear::clear(&mut self.salt)
    }
}

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The specified length is less than 1
/// - The specified length is greater than (2^32 - 1) * hLen
/// - The specified iteration count is less than 1
///
/// # Usage examples:
/// ### Generating derived key:
/// ```
/// use orion::pbkdf2::Pbkdf2;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let password = gen_rand_key(16).unwrap();
/// let salt = gen_rand_key(16).unwrap();
///
/// let dk = Pbkdf2 {
///     password: password,
///     salt: salt,
///     iterations: 10000,
///     length: 64,
///     hmac: ShaVariantOption::SHA512
/// };
///
/// dk.pbkdf2_compute().unwrap();
/// ```
/// ### Verifying derived key:
/// ```
/// use orion::pbkdf2::Pbkdf2;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let password = gen_rand_key(16).unwrap();
/// let salt = gen_rand_key(16).unwrap();
///
/// let dk = Pbkdf2 {
///     password: password,
///     salt: salt,
///     iterations: 10000,
///     length: 64,
///     hmac: ShaVariantOption::SHA512
/// };
///
/// let derived_key = dk.pbkdf2_compute().unwrap();
/// assert_eq!(dk.pbkdf2_compare(&derived_key).unwrap(), true);
/// ```


impl Pbkdf2 {

    /// Return the maximum derived keyu length.
    fn max_dklen(&self) -> usize {
        match self.hmac.output_size() {
            // These values have been calculated from the constraint given in RFC by:
            // (2^32 - 1) * hLen
            256 => 137438953440,
            384 => 206158430160,
            512 => 274877906880,
            _ => panic!("Maximum DK lenght not found.")
        }
    }

    /// Returns a PRF value from HMAC and selected Sha2 variant from Pbkdf2 struct.
    fn return_prf(&self, ipad: &[u8], opad: &[u8], message: Vec<u8>) -> Vec<u8> {

        // Secret value and message aren't needed in this case
        let fast_hmac = Hmac {
            secret_key: vec![0x00; 0],
            message: vec![0x00; 0],
            sha2: self.hmac
        };

        fast_hmac.pbkdf2_hmac(ipad.to_vec(), opad.to_vec(), message)
    }

    /// Function F as described in the RFC.
    pub fn function_f(&self, index: u32, ipad: &[u8], opad: &[u8]) -> Vec<u8> {

        let mut salt_extended = self.salt.clone();
        let mut index_buffer = [0u8; 4];
        write_u32_be(&mut index_buffer, index);
        salt_extended.extend_from_slice(&index_buffer);

        let mut f_result: Vec<u8> = Vec::new();
        // First iteration
        // u_step here will be equal to U_1 in RFC
        //let mut u_step = self.return_prf(padded_password, salt_extended);
        let mut u_step = self.return_prf(ipad, opad, salt_extended);
        // Push directly into the final buffer, as this is the first iteration
        f_result.extend_from_slice(&u_step);
        // Second iteration
        // u_step here will be equal to U_2 in RFC
        if self.iterations > 1 {
            u_step = self.return_prf(ipad, opad, u_step);
            // The length of f_result and u_step will always be the same due to HMAC
            for c in 0..f_result.len() {
                f_result[c] ^= u_step[c];
            }
            // Remainder of iterations
            if self.iterations > 2 {
                for _x in 2..self.iterations {
                    u_step = self.return_prf(ipad, opad, u_step);

                    for c in 0..f_result.len() {
                        f_result[c] ^= u_step[c];
                    }
                }
            }
        }

        f_result
    }

    /// PBKDF2 function. Return a derived key.
    pub fn pbkdf2_compute(&self) -> Result<Vec<u8>, errors::UnknownCryptoError> {

        if self.iterations < 1 {
            return Err(errors::UnknownCryptoError);
        }
        // Check that the selected key length is within the limit
        if self.length > self.max_dklen() {
            return Err(errors::UnknownCryptoError);
        } else if self.length < 1 {
            return Err(errors::UnknownCryptoError);
        }

        // Corresponds to l in RFC
        let hlen_blocks = 1 + ((self.length - 1) / (self.hmac.output_size() / 8)) as usize;

        // Make inner and outer paddings for a faster HMAC
        let pad_const = Hmac {secret_key: vec![0x00; 0], message: vec![0x00; 0], sha2: self.hmac};
        let (ipad, opad) = pad_const.pad_key_blocks(&self.password);

        let mut pbkdf2_dk: Vec<u8> = Vec::new();

        for index in 1..hlen_blocks+1 {
            pbkdf2_dk.extend_from_slice(&self.function_f(index as u32, &ipad, &opad));
        }

        pbkdf2_dk.truncate(self.length);

        Ok(pbkdf2_dk)
    }

    /// Check derived key validity by computing one from the current struct fields and comparing this
    /// to the passed derived key. Comparison is done in constant time.
    pub fn pbkdf2_compare(&self, received_dk: &[u8]) -> Result<bool, errors::UnknownCryptoError> {

        if received_dk.len() != self.length {
            return Err(errors::UnknownCryptoError);
        }

        let own_dk = self.pbkdf2_compute().unwrap();

        util::compare_ct(received_dk, &own_dk)
    }
}



#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use pbkdf2::Pbkdf2;
    use core::options::ShaVariantOption;

    #[test]
    fn length_too_high() {

        // Take 64 as this is the highest, since HMAC-SHA512
        let too_long = ((2_u64.pow(32) - 1) * 64 as u64) as usize + 1;

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: too_long,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(pbkdf2_dk_256.pbkdf2_compute().is_err());
    }

    #[test]
    fn zero_iterations_panic() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 0,
            length: 15,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(pbkdf2_dk_256.pbkdf2_compute().is_err());
    }

    #[test]
    fn zero_length_panic() {
        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 0,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(pbkdf2_dk_256.pbkdf2_compute().is_err());
    }

    #[test]
    fn pbkdf2_compare_true() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert_eq!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512).unwrap(), true);
    }

    #[test]
    fn pbkdf2_compare_false() {

        // Salt value differs between this and the previous test case

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512).is_err());

    }

    #[test]
    fn pbkdf2_compare_diff_length_panic() {

        // Different length than expected dk

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "".as_bytes().to_vec(),
            iterations: 4096,
            length: 32,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512).is_err());

    }
}
