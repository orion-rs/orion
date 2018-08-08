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

use byte_tools::write_u32_be;
use clear_on_drop::clear::Clear;
use core::options::ShaVariantOption;
use core::{errors::*, util};
use hazardous::hmac::*;

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
///
/// Fields `password` and `salt` are zeroed out on drop.
pub struct Pbkdf2 {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: usize,
    pub dklen: usize,
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
/// # Parameters:
/// - `password`: Password
/// - `salt`: Salt value
/// - `iterations`: Iteration count
/// - `dklen`: Length of the derived key
/// - `hmac`: Pseudorandom function
///
/// See [RFC](https://tools.ietf.org/html/rfc8018#section-5.2) for more information.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The specified dklen is less than 1
/// - The specified dklen is greater than (2^32 - 1) * hLen
/// - The specified iteration count is less than 1
///
/// # Security:
/// Salts should always be generated using a CSPRNG. The `gen_rand_key` function
/// in `util` can be used for this. The recommended length for a salt is 16 bytes as a minimum.
/// The iteration count should be set as high as feasible.
/// # Example:
/// ### Generating derived key:
/// ```
/// use orion::hazardous::pbkdf2::Pbkdf2;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let password = gen_rand_key(32).unwrap();
/// let salt = gen_rand_key(32).unwrap();
///
/// let dk = Pbkdf2 {
///     password: password,
///     salt: salt,
///     iterations: 10000,
///     dklen: 64,
///     hmac: ShaVariantOption::SHA256
/// };
///
/// dk.derive_key().unwrap();
/// ```
/// ### Verifying derived key:
/// ```
/// use orion::hazardous::pbkdf2::Pbkdf2;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let password = gen_rand_key(32).unwrap();
/// let salt = gen_rand_key(32).unwrap();
///
/// let dk = Pbkdf2 {
///     password: password,
///     salt: salt,
///     iterations: 10000,
///     dklen: 64,
///     hmac: ShaVariantOption::SHA256
/// };
///
/// let derived_key = dk.derive_key().unwrap();
/// assert_eq!(dk.verify(&derived_key).unwrap(), true);
/// ```

impl Pbkdf2 {
    /// Return the maximum derived key dklen ((2^32 - 1) * hLen).
    fn max_dklen(&self) -> usize {
        match self.hmac.output_size() {
            32 => 137_438_953_440,
            48 => 206_158_430_160,
            64 => 274_877_906_880,
            _ => panic!(UnknownCryptoError),
        }
    }

    /// Returns a PRK using HMAC as the PRF. The parameters `ipad` and `opad` are constructed
    /// in the `derive_key`. They are used to speed up HMAC calls.
    fn prf(&self, ipad: &[u8], opad: &[u8], data: &[u8]) -> Vec<u8> {
        pbkdf2_hmac(ipad, opad, data, self.hmac)
    }

    /// Function F as described in the RFC.
    fn function_f(&self, index: u32, ipad: &[u8], opad: &[u8], salt_ext: &mut [u8]) -> Vec<u8> {

        let pos = salt_ext.len() - 4;
        write_u32_be(&mut salt_ext[pos..], index);

        // First iteration
        let mut f_result: Vec<u8> = self.prf(ipad, opad, &salt_ext);

        // Remaining iterations
        if self.iterations > 1 {

            let mut u_step = Vec::new();
            u_step.extend_from_slice(&f_result);

            for _ in 1..self.iterations {
                u_step = self.prf(ipad, opad, &u_step);

                for index in 0..f_result.len() {
                    f_result[index] ^= u_step[index];
                }
            }
        }

        f_result
    }

    /// Main PBKDF2 function. Returns a derived key.
    pub fn derive_key(&self) -> Result<Vec<u8>, UnknownCryptoError> {
        if self.iterations < 1 {
            return Err(UnknownCryptoError);
        }
        if self.dklen > self.max_dklen() {
            return Err(UnknownCryptoError);
        }
        if self.dklen < 1 {
            return Err(UnknownCryptoError);
        }

        let hlen_blocks: usize = 1 + ((self.dklen - 1) / self.hmac.output_size());

        let pad_const = Hmac {
            secret_key: Vec::new(),
            data: Vec::new(),
            sha2: self.hmac,
        };
        let (mut ipad, mut opad) = pad_const.pad_key(&self.password);
        let mut salt_ext = self.salt.clone();
        // We need 4 bytes of space for the index value
        salt_ext.extend_from_slice(&[0u8; 4]);
        let mut derived_key: Vec<u8> = Vec::new();

        for index in 1..hlen_blocks + 1 {
            derived_key.extend_from_slice(&self.function_f(index as u32, &ipad, &opad, &mut salt_ext));
            // Given that hlen_blocks is rounded correctly, then the `index as u32`
            // should not be able to overflow. If the maximum dklen is selected,
            // along with the highest output size, then hlen_blocks will equal
            // exactly `u32::max_value()`
        }

        Clear::clear(&mut ipad);
        Clear::clear(&mut opad);

        derived_key.truncate(self.dklen);

        Ok(derived_key)
    }

    /// Verify a derived key by comparing one from the current struct fields with the derived key
    /// passed to the function. Comparison is done in constant time. Both derived keys must be
    /// of equal length.
    pub fn verify(&self, expected_dk: &[u8]) -> Result<bool, ValidationCryptoError> {
        let own_dk = self.derive_key().unwrap();

        if util::compare_ct(&own_dk, expected_dk).is_err() {
            Err(ValidationCryptoError)
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod test {

    extern crate hex;
    use self::hex::decode;
    use core::options::ShaVariantOption;
    use hazardous::pbkdf2::Pbkdf2;

    #[test]
    fn dklen_too_high_sha256() {
        let too_long = ((2_u64.pow(32) - 1) * 32 as u64) as usize + 1;

        let dk = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            dklen: too_long,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(dk.derive_key().is_err());
    }

    #[test]
    fn dklen_too_high_sha384() {
        let too_long = ((2_u64.pow(32) - 1) * 48 as u64) as usize + 1;

        let dk = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            dklen: too_long,
            hmac: ShaVariantOption::SHA384,
        };

        assert!(dk.derive_key().is_err());
    }

    #[test]
    fn dklen_too_high_sha512() {
        let too_long = ((2_u64.pow(32) - 1) * 64 as u64) as usize + 1;

        let dk = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            dklen: too_long,
            hmac: ShaVariantOption::SHA512,
        };

        assert!(dk.derive_key().is_err());
    }

    #[test]
    fn zero_iterations_err() {
        let dk = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 0,
            dklen: 15,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(dk.derive_key().is_err());
    }

    #[test]
    fn zero_dklen_err() {
        let dk = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            dklen: 0,
            hmac: ShaVariantOption::SHA256,
        };

        assert!(dk.derive_key().is_err());
    }

    #[test]
    fn verify_true() {
        let dk = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            dklen: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert_eq!(dk.verify(&expected_dk).unwrap(), true);
    }

    #[test]
    fn verify_false_wrong_salt() {
        // Salt value differs between this and the previous test case
        let dk = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "".as_bytes().to_vec(),
            iterations: 4096,
            dklen: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(dk.verify(&expected_dk).is_err());
    }

    #[test]
    fn verify_false_wrong_password() {
        let dk = Pbkdf2 {
            password: "none".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            dklen: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(dk.verify(&expected_dk).is_err());
    }

    #[test]
    fn verify_diff_dklen_error() {
        // Different dklen than expected dk
        let dk = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            dklen: 32,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(dk.verify(&expected_dk).is_err());
    }

    #[test]
    fn verify_diff_iter_error() {
        let dk = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 800,
            dklen: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        assert!(dk.verify(&expected_dk).is_err());
    }
}
