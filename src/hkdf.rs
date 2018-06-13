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





use hmac::Hmac;
use clear_on_drop::clear::Clear;
use core::options::ShaVariantOption;
use core::{util, errors::UnknownCryptoError};

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).

pub struct Hkdf {
    pub salt: Vec<u8>,
    pub ikm: Vec<u8>,
    pub info: Vec<u8>,
    pub length: usize,
    pub hmac: ShaVariantOption,
}

impl Drop for Hkdf {
    fn drop(&mut self) {
        Clear::clear(&mut self.salt);
        Clear::clear(&mut self.ikm);
        Clear::clear(&mut self.info)

    }
}

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The specified length is less than 1
/// - The specified length is greater than 255 * hash_output_size_in_bytes
///
/// # Usage examples:
/// ### Generating derived key:
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let key = gen_rand_key(16).unwrap();
/// let salt = gen_rand_key(16).unwrap();
/// let info = gen_rand_key(16).unwrap();
///
/// let dk = Hkdf {
///     salt: salt,
///     ikm: key,
///     info: info,
///     length: 50,
///     hmac: ShaVariantOption::SHA256,
/// };
///
/// let dk_final = dk.derive_key().unwrap();
/// ```
/// ### Verifying derived key:
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::core::util::gen_rand_key;
/// use orion::core::options::ShaVariantOption;
///
/// let key = gen_rand_key(16).unwrap();
/// let salt = gen_rand_key(16).unwrap();
/// let info = gen_rand_key(16).unwrap();
///
/// let dk = Hkdf {
///     salt: salt,
///     ikm: key,
///     info: info,
///     length: 50,
///     hmac: ShaVariantOption::SHA256,
/// };
///
/// let dk_final = dk.derive_key().unwrap();
///
/// assert_eq!(dk.verify(&dk_final).unwrap(), true);
/// ```

impl Hkdf {

    /// Return the maximum okm length (255 * hLen).
    fn max_okmlen(&self) -> usize {
        match self.hmac.output_size() {
            32 => 8160,
            48 => 12240,
            64 => 16320,
            _ => panic!(UnknownCryptoError)
        }
    }

    /// The HKDF Etract step.
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {

        let hmac_res = Hmac {
            secret_key: salt.to_vec(),
            data: ikm.to_vec(),
            sha2: self.hmac
        };

        hmac_res.finalize()
    }

    /// The HKDF Expand step.
    pub fn expand(&self, prk: &[u8]) -> Result<Vec<u8>, UnknownCryptoError> {
        if self.length > self.max_okmlen() {
            return Err(UnknownCryptoError);
        }
        if self.length < 1 {
            return Err(UnknownCryptoError);
        }

        let n_iter: usize = 1 + ((self.length - 1) / self.hmac.output_size());

        // con_step will hold the intermediate state of "T_n | info | 0x0n" as described in the RFC
        let mut con_step: Vec<u8> = Vec::new();
        let mut okm: Vec<u8> = Vec::new();

        for index in 1..n_iter+1 {
                con_step.extend_from_slice(&self.info);
                con_step.push(index as u8);
                // Calling extract as it yields the same result as an HMAC call
                con_step = self.extract(prk, &con_step);
                okm.extend_from_slice(&con_step);
        }

        okm.truncate(self.length);

        Ok(okm)
    }

    /// Combine extract and expand to return a derived key.
    pub fn derive_key(&self) -> Result<Vec<u8>, UnknownCryptoError> {

        let prk = self.extract(&self.salt, &self.ikm);

        self.expand(&prk)
    }

    /// Verify a derived key by comparing one from the current struct fields and the derived key
    /// passed to the function. Comparison is done in constant time. Both derived keys must be
    /// of equal length.
    pub fn verify(&self, expected_dk: &[u8]) -> Result<bool, UnknownCryptoError> {

        let own_dk = self.derive_key().unwrap();

        util::compare_ct(expected_dk, &own_dk)
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hkdf::Hkdf;
    use core::options::ShaVariantOption;

    #[test]
    fn hkdf_maximum_length_256() {

        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            // Max allowed length here is 8160
            length: 9000,
            hmac: ShaVariantOption::SHA256,
        };

        let hkdf_256_extract = hkdf_256.extract(&hkdf_256.ikm, &hkdf_256.salt);

        assert!(hkdf_256.expand(&hkdf_256_extract).is_err());
        assert!(hkdf_256.derive_key().is_err());

    }

    #[test]
    fn hkdf_maximum_length_384() {

        let hkdf_384 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            // Max allowed length here is 12240
            length: 13000,
            hmac: ShaVariantOption::SHA384,
        };

        let hkdf_384_extract = hkdf_384.extract(&hkdf_384.ikm, &hkdf_384.salt);

        assert!(hkdf_384.expand(&hkdf_384_extract).is_err());
        assert!(hkdf_384.derive_key().is_err());

    }

    #[test]
    fn hkdf_maximum_length_512() {

        let hkdf_512 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            // Max allowed length here is 16320
            length: 17000,
            hmac: ShaVariantOption::SHA512,
        };

        let hkdf_512_extract = hkdf_512.extract(&hkdf_512.ikm, &hkdf_512.salt);

        assert!(hkdf_512.expand(&hkdf_512_extract).is_err());
        assert!(hkdf_512.derive_key().is_err());

    }

    #[test]
    fn hkdf_zero_length() {

        let hkdf_512 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            length: 0,
            hmac: ShaVariantOption::SHA512,
        };

        let hkdf_512_extract = hkdf_512.extract(&hkdf_512.ikm, &hkdf_512.salt);

        assert!(hkdf_512.expand(&hkdf_512_extract).is_err());
        assert!(hkdf_512.derive_key().is_err());

    }

    #[test]
    fn hkdf_verify_true() {

        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            length: 42,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert_eq!(hkdf_256.verify(&expected_okm_256).unwrap(), true);
    }

    #[test]
    fn hkdf_verify_false() {

        // Salt value differs between this and the previous test case

        let hkdf_256 = Hkdf {
            salt: "salt".as_bytes().to_vec(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            length: 42,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert!(hkdf_256.verify(&expected_okm_256).is_err());
    }

    #[test]
    fn verify_diff_length_panic() {

        // Different length than expected okm

        let hkdf_256 = Hkdf {
            salt: "salt".as_bytes().to_vec(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            length: 75,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert!(hkdf_256.verify(&expected_okm_256).is_err());
    }
}
