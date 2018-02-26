use hmac::Hmac;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).
pub enum Hkdf {
    hmac_SHA1,
    hmac_SHA256,
    hmac_SHA384,
    hmac_SHA512,
}

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) as specified in the
/// [RFC 5869](https://tools.ietf.org/html/rfc5869).
///
/// # Usage examples:
///
/// ```
/// use orion::hkdf::Hkdf;
/// use orion::functions;
///
/// let key = functions::gen_rand_key(10);
/// let salt = functions::gen_rand_key(10);
/// let info = functions::gen_rand_key(10);
///
/// let prk = Hkdf::hmac_SHA512.hkdf_extract(&salt, &key);
/// let d_key = Hkdf::hmac_SHA512.hkdf_expand(&prk, &info, 50);
/// ```

impl Hkdf {
    /// Return the used hash function output size in bytes.
    fn hash_return_size(&self) -> usize {
        match *self {
            Hkdf::hmac_SHA1 => 20,
            Hkdf::hmac_SHA256 => 32,
            Hkdf::hmac_SHA384 => 48,
            Hkdf::hmac_SHA512 => 64,
        }
    }

    /// Return HMAC matching argument passsed to Hkdf.
    fn hmac_return_variant(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let hmac = match *self {
            Hkdf::hmac_SHA1 => Hmac::SHA1,
            Hkdf::hmac_SHA256 => Hmac::SHA256,
            Hkdf::hmac_SHA384 => Hmac::SHA384,
            Hkdf::hmac_SHA512 => Hmac::SHA512,
        };
        hmac.hmac_compute(data, salt)
    }

    /// The HKDF Extract step. Returns an PRK (HMAC) from passed salt and IKM.
    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hmac_return_variant(salt, ikm)
    }

    /// The HKDF Expand step. Returns an HKDF.
    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
        // Check that the selected key length is within the limit.
        if okm_len as f32 > 255_f32 * self.hash_return_size() as f32 {
            panic!("Derived key length above max. Max derived key length is: {:?}",
                    255_f32 * self.hash_return_size() as f32);
        }

        let n_iter = (okm_len as f32 / self.hash_return_size() as f32).ceil() as usize;

        let mut con_step: Vec<u8> = vec![];
        let mut t_step: Vec<u8> = vec![];
        let mut hkdf_final: Vec<u8> = vec![];

        for x in 1..n_iter+1 {
                con_step.append(&mut t_step);
                con_step.extend_from_slice(info);
                con_step.push(x as u8);
                t_step.extend_from_slice(&self.hmac_return_variant(prk, &con_step));
                con_step.clear();

                hkdf_final.extend_from_slice(&t_step);
        }

        hkdf_final.truncate(okm_len);

        hkdf_final
    }
}

#[cfg(test)]
mod test {
    use ring::test;
    use hkdf::Hkdf;

    // All expected results have been computed with the python cryptography package at:
    // https://cryptography.io
    // Test that expected results are returned
    #[test]
    fn test_hkdf_return() {
        let ikm = vec![0x61; 5];
        let salt = vec![0x61; 5];
        let info = vec![0x61; 5];
        let length: usize = 50;

        let prk1 = Hkdf::hmac_SHA1.hkdf_extract(&salt, &ikm);
        let prk256 = Hkdf::hmac_SHA256.hkdf_extract(&salt, &ikm);
        let prk384 = Hkdf::hmac_SHA384.hkdf_extract(&salt, &ikm);
        let prk512 = Hkdf::hmac_SHA512.hkdf_extract(&salt, &ikm);

        let actual1 = Hkdf::hmac_SHA1.hkdf_expand(&prk1, &info, length);
        let actual256 = Hkdf::hmac_SHA256.hkdf_expand(&prk256, &info, length);
        let actual384 = Hkdf::hmac_SHA384.hkdf_expand(&prk384, &info, length);
        let actual512 = Hkdf::hmac_SHA512.hkdf_expand(&prk512, &info, length);

        let expected1 = test::from_hex("224e74d59e061324a629b274181cec75bb823bcd494b88f6ce83a815fec14030c9727fc59827e06e76f735169559b46ddf11").unwrap();
        let expected256 = test::from_hex("f64478d1e58b2070933a13aca0ab75859a41c61283ed985023c964d6287c4b5f653efe8df22a4a82b9e87fc2a8627e3d0063").unwrap();
        let expected384 = test::from_hex("74686470b67e49954926a71a5ca5e4fd4286a94c020aa7eeba16550db868dc5992ca6c2a13a2bfde7d7cc86c5fdf2bcd8ed1").unwrap();
        let expected512 = test::from_hex("73b276604fa533dac12af682d7cf9a56150d75efddd2ffbcd3f83d847282df718eeb3ff9d303c0fd54c1177ab00b3fb5f618").unwrap();

        assert_eq!(actual1, expected1);
        assert_eq!(actual256, expected256);
        assert_eq!(actual384, expected384);
        assert_eq!(actual512, expected512);
    }

    #[test]
    #[should_panic]
    // Test that hkdf_expand() panics when a length that is greater than the boundary
    // is selected.
    fn test_length_panic_return() {
        let salt = vec![0x61; 5];
        let secret = vec![0x67; 5];
        let info = "10".as_bytes();
        let len = Hkdf::hmac_SHA256.hash_return_size() * 256;
        let prk = Hkdf::hmac_SHA256.hkdf_extract(&salt, &secret);
        let actual = Hkdf::hmac_SHA256.hkdf_expand(&prk, &info, len as usize);
    }

}
