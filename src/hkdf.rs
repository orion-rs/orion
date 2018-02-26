use hmac::Hmac;
use functions;

pub enum Hkdf {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl Hkdf {

    /// Return the used hash function output size in octets
    fn hash_return_size(&self) -> usize {
        match *self {
            Hkdf::SHA1 => 20,
            Hkdf::SHA256 => 32,
            Hkdf::SHA384 => 48,
            Hkdf::SHA512 => 64,
        }
    }

    /// Return HMAC function matching passed SHA variant, 256/512
    fn hmac_return_variant(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let hmac = match *self {
            Hkdf::SHA1 => Hmac::SHA1,
            Hkdf::SHA256 => Hmac::SHA256,
            Hkdf::SHA384 => Hmac::SHA384,
            Hkdf::SHA512 => Hmac::SHA512,
        };
        hmac.hmac_compute(data, salt)
    }

    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hmac_return_variant(salt, ikm)
    }

    /// Return HKDF, take hkdf_extract as prk argument

    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {

        if okm_len as f32 > 255_f32 * self.hash_return_size() as f32 {
            panic!("Length is too high.");
        }

        // add one at last to have it run all iterations
        let border = (okm_len as f32 / self.hash_return_size() as f32).ceil(); //+ 1_f32
        let n = border as usize;

        let mut it_vec: Vec<u8> = vec![];
        let mut t_vec: Vec<u8> = vec![];
        let mut f_vec: Vec<u8> = vec![];

        for x in 1..n+1 {
                it_vec.append(&mut t_vec);
                it_vec.extend_from_slice(info); // Append info
                it_vec.push(x as u8); // Append octet count
                t_vec.extend_from_slice(&self.hmac_return_variant(prk, &it_vec)); // Append T step to final
                it_vec.clear();
                f_vec.extend_from_slice(&t_vec);
        }

        f_vec.truncate(okm_len);
        f_vec
    }
}

#[cfg(test)]
mod test {
    use hmac::Hmac;
    use ring::test;
    use functions;
    use hkdf::Hkdf;

    // All expected results have been computed with the python cryptography package at:
    // https://cryptography.io
    #[test]
    fn test_hkdf_return() {
        let ikm = vec![0x61; 5];
        let salt = vec![0x61; 5];
        let info = vec![0x61; 5];
        let length: usize = 50;

        let prk1 = Hkdf::SHA1.hkdf_extract(&salt, &ikm);
        let prk256 = Hkdf::SHA256.hkdf_extract(&salt, &ikm);
        let prk384 = Hkdf::SHA384.hkdf_extract(&salt, &ikm);
        let prk512 = Hkdf::SHA512.hkdf_extract(&salt, &ikm);

        let actual1 = Hkdf::SHA1.hkdf_expand(&prk1, &info, length);
        let actual256 = Hkdf::SHA256.hkdf_expand(&prk256, &info, length);
        let actual384 = Hkdf::SHA384.hkdf_expand(&prk384, &info, length);
        let actual512 = Hkdf::SHA512.hkdf_expand(&prk512, &info, length);

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
        let len = Hkdf::SHA256.hash_return_size() * 256;
        let prk = Hkdf::SHA256.hkdf_extract(&salt, &secret);
        let actual = Hkdf::SHA256.hkdf_expand(&prk, &info, len as usize);
    }

}
