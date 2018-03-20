use hmac::Hmac;
use clear_on_drop::clear;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).

pub struct Hkdf {
    pub salt: Vec<u8>,
    pub data: Vec<u8>,
    pub info: Vec<u8>,
    pub hmac: usize,
    pub length: usize,
}

impl Drop for Hkdf {
    fn drop(&mut self) {
        //println!("DROPPING");
        self.salt.clear();
        self.data.clear();
        self.info.clear()
    }
}

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).
///
/// # Usage examples:
///
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::util::gen_rand_key;
///
/// let key = gen_rand_key(10);
/// let salt = gen_rand_key(10);
/// let info = gen_rand_key(10);
///
/// let dk = Hkdf { salt: salt, data: key, info: info, hmac: 256, length: 50 };
/// dk.hkdf_compute();
/// ```

impl Hkdf {
    /// Return HMAC matching argument passsed to Hkdf.
    pub fn hkdf_extract(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let hmac_res = Hmac {
            secret_key: salt.to_vec(),
            message: data.to_vec(),
            sha2: self.hmac
        };

        hmac_res.hmac_compute()
    }

    /// The HKDF Expand step. Returns an HKDF.
    pub fn hkdf_compute(&self) -> Vec<u8> {
        // Check that the selected key length is within the limit.
        if self.length as f32 > 255_f32 * (self.hmac / 8) as f32 {
            panic!("Derived key length above max. 255 * (HMAC OUTPUT LENGTH IN BYTES)");
        }

        let n_iter = (self.length as f32 / (self.hmac / 8) as f32).ceil() as usize;

        let mut con_step: Vec<u8> = vec![];
        let mut t_step: Vec<u8> = vec![];
        let mut hkdf_final: Vec<u8> = vec![];

        for x in 1..n_iter+1 {
                con_step.append(&mut t_step);
                con_step.extend_from_slice(&self.info);
                con_step.push(x as u8);
                t_step.extend_from_slice(&self.hkdf_extract(
                    &con_step,
                    &self.hkdf_extract(&self.data, &self.salt))
                );
                con_step.clear();

                hkdf_final.extend_from_slice(&t_step);
        }

        hkdf_final.truncate(self.length);

        hkdf_final
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hkdf::Hkdf;

    #[test]
    // Testing against provided test vectors in RFC 5869
    fn hkdf_result_test_case_1() {

        let hkdf_256 = Hkdf {
            salt: decode("000102030405060708090a0b0c").unwrap(),
            data: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
            hmac: 256,
            length: 42,
        };

        let expected_prk_256 = decode(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();

        let expected_okm_256 = decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
            34007208d5b887185865").unwrap();

        assert_eq!(hkdf_256.hkdf_extract(&hkdf_256.data, &hkdf_256.salt), expected_prk_256);
        assert_eq!(hkdf_256.hkdf_compute(), expected_okm_256);
    }

    #[test]
    // Testing against provided test vectors in RFC 5869
    fn hkdf_result_test_case_2() {

        let hkdf_256 = Hkdf {
            salt: decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap(),
            data: decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                404142434445464748494a4b4c4d4e4f").unwrap(),
            info: decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap(),
            hmac: 256,
            length: 82,
        };

        let expected_prk_256 = decode(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();

        let expected_okm_256 = decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
            59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
            cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();

        assert_eq!(hkdf_256.hkdf_extract(&hkdf_256.data, &hkdf_256.salt), expected_prk_256);
        assert_eq!(hkdf_256.hkdf_compute(), expected_okm_256);
    }

    #[test]
    // Testing against provided test vectors in RFC 5869
    fn hkdf_result_test_case_3() {

        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            data: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            hmac: 256,
            length: 42,
        };

        let expected_prk_256 = decode(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();

        let expected_okm_256 = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();

        assert_eq!(hkdf_256.hkdf_extract(&hkdf_256.data, &hkdf_256.salt), expected_prk_256);
        assert_eq!(hkdf_256.hkdf_compute(), expected_okm_256);
    }
}
