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
use options::ShaVariantOption;
use constant_time_eq::constant_time_eq;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).

pub struct Hkdf {
    pub salt: Vec<u8>,
    pub ikm: Vec<u8>,
    pub info: Vec<u8>,
    pub hmac: ShaVariantOption,
    pub length: usize,
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
/// # Usage examples:
/// ### Generating derived key:
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::util::gen_rand_key;
/// use orion::options::ShaVariantOption;
///
/// let key = gen_rand_key(16);
/// let salt = gen_rand_key(16);
/// let info = gen_rand_key(16);
///
/// let dk = Hkdf { 
///     salt: salt, 
///     ikm: key, 
///     info: info, 
///     hmac: ShaVariantOption::SHA256,
///     length: 50
/// };
/// 
/// let dk_extract = dk.hkdf_extract(&dk.ikm, &dk.salt);
/// dk.hkdf_expand(&dk_extract);
/// ```
/// ### Verifying derived key:
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::util::gen_rand_key;
/// use orion::options::ShaVariantOption;
///
/// let key = gen_rand_key(16);
/// let salt = gen_rand_key(16);
/// let info = gen_rand_key(16);
///
/// let dk = Hkdf { 
///     salt: salt, 
///     ikm: key, 
///     info: info, 
///     hmac: ShaVariantOption::SHA256,
///     length: 50
/// };
/// 
/// let dk_extract = dk.hkdf_extract(&dk.ikm, &dk.salt);
/// let expanded_dk = dk.hkdf_expand(&dk_extract);
/// 
/// assert_eq!(dk.hkdf_compare(&expanded_dk), true);
/// ```

impl Hkdf {
    
    /// Return HMAC matching argument passsed to Hkdf.
    pub fn hkdf_extract(&self, ikm: &[u8], salt: &[u8]) -> Vec<u8> {
        
        let hmac_res = Hmac {
            secret_key: salt.to_vec(),
            message: ikm.to_vec(),
            sha2: self.hmac
        };

        hmac_res.hmac_compute()
    }

    /// The HKDF Expand step. Returns an HKDF.
    pub fn hkdf_expand(&self, prk: &[u8]) -> Vec<u8> {
        // Check that the selected key length is within the limit.
        if self.length > (255 * self.hmac.output_size() / 8) {
            panic!("Derived key length above max. 255 * (HMAC OUTPUT LENGTH IN BYTES)");
        }

        let n_iter = 1 + ((self.length - 1) / (self.hmac.output_size() / 8)) as usize;

        // con_step will hold the intermediate state of "T_n | info | 0x0n" as described in the RFC
        let mut con_step: Vec<u8> = vec![];
        let mut hmac_hash_step: Vec<u8> = vec![];
        let mut okm: Vec<u8> = vec![];

        for index in 1..n_iter+1 {
                con_step.append(&mut hmac_hash_step);
                con_step.extend_from_slice(&self.info);
                con_step.push(index as u8);
                // We call extract here as it has the same functionality as a simple HMAC call
                hmac_hash_step.extend_from_slice(&self.hkdf_extract(&con_step, prk));
                con_step.clear();

                okm.extend_from_slice(&hmac_hash_step);
        }

        okm.truncate(self.length);

        okm
    }

    /// Check HKDF validity by computing one from the current struct fields and comparing this
    /// to the passed HKDF. Comparison is done in constant time.
    pub fn hkdf_compare(&self, received_hkdf: &[u8]) -> bool {

        if received_hkdf.len() != self.length {
            panic!("Cannot compare two HKDF's that are not the same length.");
        }

        let own_extract = self.hkdf_extract(&self.ikm, &self.salt);
        let own_expand = self.hkdf_expand(&own_extract);

        constant_time_eq(received_hkdf, &own_expand)
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hkdf::Hkdf;
    use options::ShaVariantOption;

    #[test]
    #[should_panic]
    fn hkdf_maximum_length_256() {

        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA256,
            // Max allowed length here is 8160
            length: 9000,
        };

        let hkdf_256_extract = hkdf_256.hkdf_extract(&hkdf_256.ikm, &hkdf_256.salt);

        hkdf_256.hkdf_expand(&hkdf_256_extract);
    }

    #[test]
    #[should_panic]
    fn hkdf_maximum_length_384() {

        let hkdf_384 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA384,
            // Max allowed length here is 12240
            length: 13000,
        };

        let hkdf_384_extract = hkdf_384.hkdf_extract(&hkdf_384.ikm, &hkdf_384.salt);

        hkdf_384.hkdf_expand(&hkdf_384_extract);
    }

    #[test]
    #[should_panic]
    fn hkdf_maximum_length_512() {

        let hkdf_512 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA512,
            // Max allowed length here is 16320
            length: 17000,
        };

        let hkdf_512_extract = hkdf_512.hkdf_extract(&hkdf_512.ikm, &hkdf_512.salt);

        hkdf_512.hkdf_expand(&hkdf_512_extract);
    }

    #[test]
    fn hkdf_compare_true() {
        
        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA256,
            length: 42,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert_eq!(hkdf_256.hkdf_compare(&expected_okm_256), true);
    }

    #[test]
    fn hkdf_compare_false() {

        // Salt value differs between this and the previous test case
        
        let hkdf_256 = Hkdf {
            salt: "salt".as_bytes().to_vec(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA256,
            length: 42,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert_eq!(hkdf_256.hkdf_compare(&expected_okm_256), false);
    }
    
    #[test]
    #[should_panic]
    fn hkdf_compare_diff_length_panic() {

        // Different length than expected okm

        let hkdf_256 = Hkdf {
            salt: "salt".as_bytes().to_vec(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: ShaVariantOption::SHA256,
            length: 75,
        };

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();


        assert_eq!(hkdf_256.hkdf_compare(&expected_okm_256), false);
    }
}
