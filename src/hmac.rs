use ring::digest;

enum Hmac {
    SHA256,
    SHA512,
}

impl Hmac {

    fn blocksize(&self) -> usize {
        match *self {
            Hmac::SHA256 => 64,
            Hmac::SHA512 => 128,
        }
    }
    /// Return either a SHA256 or SHA512 digest of byte vector
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let method = match *self {
            Hmac::SHA256 => &digest::SHA256,
            Hmac::SHA512 => &digest::SHA512,
        };
        digest::digest(method, data).as_ref().to_vec()
    }
    /// Return a padded key such that it fits the blocksize
    fn pad_key(&self, key: &[u8]) -> Vec<u8> {
        let mut resized_key = key.to_vec();

        if resized_key.len() > self.blocksize() {
            resized_key = self.hash(key);
        }
        if resized_key.len() < self.blocksize() {
            resized_key.resize(self.blocksize(), 0x00);
        }
        resized_key
    }

    /// Returns an HMAC from key and message
    pub fn hmac(&self, key: &[u8], message: &[u8]) -> Vec<u8> {

        let make_padded_key = |byte: u8| {
            let mut pad = self.pad_key(key);
            for i in &mut pad { *i ^= byte };
            pad
        };

        let mut ipad = make_padded_key(0x36);
        let mut opad = make_padded_key(0x5C);

        ipad.extend_from_slice(message);
        ipad = self.hash(&ipad);
        opad.extend_from_slice(&ipad);
        self.hash(&opad)
    }
}

#[cfg(test)]
mod test {
    use hmac::Hmac;
    use ring::test;
    use functions;

    #[test]
    // Test that the function key_deriv() returns a padded key K
    // with size of correct BLOCKSIZE, both for SHA256 and SHA512
    fn test_key_deriv() {
        let rand_k: Vec<u8> = functions::gen_rand_key(64);
        let rand_k2: Vec<u8> = functions::gen_rand_key(128);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);
        assert_eq!(Hmac::SHA256.pad_key(&rand_k).len(), Hmac::SHA256.blocksize());
        assert_eq!(Hmac::SHA512.pad_key(&rand_k).len(), Hmac::SHA512.blocksize());
        assert_eq!(Hmac::SHA256.pad_key(&rand_k2).len(), Hmac::SHA256.blocksize());
        assert_eq!(Hmac::SHA512.pad_key(&rand_k2).len(), Hmac::SHA512.blocksize());
        assert_eq!(Hmac::SHA256.pad_key(&rand_k3).len(), Hmac::SHA256.blocksize());
        assert_eq!(Hmac::SHA512.pad_key(&rand_k3).len(), Hmac::SHA512.blocksize());
    }

    #[test]
    // Test that hmac() returns expected HMAC digests
    fn test_hmac_digest_result() {
        let k_256 = vec![0x61; Hmac::SHA256.blocksize()];
        let m_256 = vec![0x62; Hmac::SHA256.blocksize()];
        let actual_256 = Hmac::SHA256.hmac(&k_256, &m_256);

        let k_512 = vec![0x63; Hmac::SHA256.blocksize()];
        let m_512 = vec![0x64; Hmac::SHA256.blocksize()];
        let actual_512 = Hmac::SHA512.hmac(&k_512, &m_512);

        // Expected values from: https://www.freeformatter.com/hmac-generator.html#ad-output
        let expected_256 = test::from_hex("f6cbb37b326d36f2f27d294ac3bb46a6aac29c1c9936b985576041bfb338ae70").unwrap();
        let expected_512 = test::from_hex("ffbd423817836ae58b801fc1e70386f09a6cc0e72daa215ac8505993721f0f6d67ce30118d7effe451310abad984d105fbd847ae37a88f042a3a79e26f307606").unwrap();
        assert_eq!(actual_256, expected_256);
        assert_eq!(actual_512, expected_512);
    }
}
