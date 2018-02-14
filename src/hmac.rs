use ring::digest;
use std::borrow::Cow;

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

    /// Return a ring::digest:Digest of a given byte slice
    fn hash(&self, data: &[u8]) -> digest::Digest {
        let method = match *self {
            Hmac::SHA256 => &digest::SHA256,
            Hmac::SHA512 => &digest::SHA512,
        };
        digest::digest(method, data)
    }

    /// Return a padded key if the key is less than or greater than the blocksize
    fn pad_key<'a>(&self, key: &'a [u8]) -> Cow<'a, [u8]> {
        let mut key = Cow::from(key);

        if key.len() > self.blocksize() {
            key = self.hash(&key).as_ref().to_vec().into();
        }
        if key.len() < self.blocksize() {
            let mut resized_key = key.into_owned();
            resized_key.resize(self.blocksize(), 0x00);
            key = resized_key.into();
        }
        key
    }

    /// Returns an HMAC from a given key and message
    pub fn hmac_compute(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let key = self.pad_key(key);

        let make_padded_key = |byte: u8| {
            let mut pad = key.to_vec();
            for i in &mut pad { *i ^= byte };
            pad
        };

        let mut ipad = make_padded_key(0x36);
        let mut opad = make_padded_key(0x5C);

        ipad.extend_from_slice(message);
        opad.extend_from_slice(self.hash(&ipad).as_ref());
        self.hash(&opad).as_ref().to_vec()
    }

    /// Check HMAC validity by computing one from message and key, then comparing this to the
    /// HMAC that has been passed to the function. Return true if the HMAC matches, return false
    /// if not.
    pub fn hmac_validate(&self, key: &[u8], message: &[u8], hmac: &Vec<u8>) -> bool {

        let check = self.hmac_compute(&key, &message);

        if &check == hmac {
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use hmac::Hmac;
    use ring::test;
    use functions;

    #[test]
    // Test that the function pad_key() returns a padded key
    // with size of correct blocksize, both for SHA256 and SHA512
    fn test_pad_key() {
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
        let actual_256 = Hmac::SHA256.hmac_compute(&k_256, &m_256);

        let k_512 = vec![0x63; Hmac::SHA256.blocksize()];
        let m_512 = vec![0x64; Hmac::SHA256.blocksize()];
        let actual_512 = Hmac::SHA512.hmac_compute(&k_512, &m_512);

        // Expected values from: https://www.freeformatter.com/hmac-generator.html#ad-output
        let expected_256 = test::from_hex("f6cbb37b326d36f2f27d294ac3bb46a6aac29c1c9936b985576041bfb338ae70").unwrap();
        let expected_512 = test::from_hex("ffbd423817836ae58b801fc1e70386f09a6cc0e72daa215ac8505993721f0f6d67ce30118d7effe451310abad984d105fbd847ae37a88f042a3a79e26f307606").unwrap();
        assert_eq!(actual_256, expected_256);
        assert_eq!(actual_512, expected_512);
    }

    #[test]
    // Test that hmac() returns expected HMAC digests
    fn test_hmac_validate() {
        let k_256 = vec![0x61; Hmac::SHA256.blocksize()];
        let m_256 = vec![0x62; Hmac::SHA256.blocksize()];
        let wrong_k_256 = vec![0x67; Hmac::SHA256.blocksize()];

        let recieved = Hmac::SHA256.hmac_compute(&k_256, &m_256);
        let expected = Hmac::SHA256.hmac_compute(&k_256, &m_256);
        let expected_wrong = Hmac::SHA256.hmac_compute(&wrong_k_256, &m_256);
        assert_eq!(recieved, expected);
        assert_ne!(recieved, expected_wrong);
    }
}
