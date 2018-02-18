use ring::digest;
use std::borrow::Cow;

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub enum Hmac {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
///
/// All available SHA variants are provided by [ring](https://github.com/briansmith/ring).
/// # Usage examples:
/// ### Generating HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::functions;
///
/// let key = functions::gen_rand_key(10);
/// let message = functions::gen_rand_key(10);
///
/// let sig = Hmac::SHA256.hmac_compute(&key, &message);
/// ```
/// ### Verifying HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::functions;
///
/// let key = functions::gen_rand_key(10);
/// let message = functions::gen_rand_key(10);
///
/// let sig = Hmac::SHA256.hmac_compute(&key, &message);
/// assert_eq!(Hmac::SHA256.hmac_validate(&key, &message, &sig), true);
/// ```
impl Hmac {
    /// Return blocksize matching SHA variant.
    fn blocksize(&self) -> usize {
        match *self {
            Hmac::SHA1 => 64,
            Hmac::SHA256 => 64,
            Hmac::SHA384 => 128,
            Hmac::SHA512 => 128,
        }
    }
    /// Return a ring::digest:Digest of a given byte slice.
    fn hash(&self, data: &[u8]) -> digest::Digest {
        let method = match *self {
            Hmac::SHA1 => &digest::SHA1,
            Hmac::SHA256 => &digest::SHA256,
            Hmac::SHA384 => &digest::SHA384,
            Hmac::SHA512 => &digest::SHA512,
        };
        digest::digest(method, data)
    }

    /// Return a padded key if the key is less than or greater than the blocksize.
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

    /// Returns HMAC from a given key and message.
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

    /// Check HMAC validity by computing one from key and message, then comparing this to the
    /// HMAC that has been passed to the function.
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
    // Test that the function pad_key() returns a padded key K
    // with size of correct BLOCKSIZE for SHA1
    fn test_pad_key_sha1() {
        let rand_k: Vec<u8> = functions::gen_rand_key(67);
        let rand_k2: Vec<u8> = functions::gen_rand_key(130);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);
        assert_eq!(Hmac::SHA1.pad_key(&rand_k).len(), Hmac::SHA1.blocksize());
        assert_eq!(Hmac::SHA1.pad_key(&rand_k2).len(), Hmac::SHA1.blocksize());
        assert_eq!(Hmac::SHA1.pad_key(&rand_k3).len(), Hmac::SHA1.blocksize());
    }

    #[test]
    // Test that the function pad_key() returns a padded key K
    // with size of correct BLOCKSIZE for SHA256
    fn test_pad_key_sha256() {
        let rand_k: Vec<u8> = functions::gen_rand_key(67);
        let rand_k2: Vec<u8> = functions::gen_rand_key(130);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);
        assert_eq!(Hmac::SHA256.pad_key(&rand_k).len(), Hmac::SHA256.blocksize());
        assert_eq!(Hmac::SHA256.pad_key(&rand_k).len(), Hmac::SHA256.blocksize());
        assert_eq!(Hmac::SHA256.pad_key(&rand_k2).len(), Hmac::SHA256.blocksize());
    }

    #[test]
    // Test that the function pad_key() returns a padded key K
    // with size of correct BLOCKSIZE for SHA384
    fn test_pad_key_sha384() {
        let rand_k: Vec<u8> = functions::gen_rand_key(67);
        let rand_k2: Vec<u8> = functions::gen_rand_key(130);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);
        assert_eq!(Hmac::SHA384.pad_key(&rand_k).len(), Hmac::SHA384.blocksize());
        assert_eq!(Hmac::SHA384.pad_key(&rand_k2).len(), Hmac::SHA384.blocksize());
        assert_eq!(Hmac::SHA384.pad_key(&rand_k3).len(), Hmac::SHA384.blocksize());
    }

    #[test]
    // Test that the function pad_key() returns a padded key K
    // with size of correct BLOCKSIZE for SHA512
    fn test_pad_key_sha512() {
        let rand_k: Vec<u8> = functions::gen_rand_key(67);
        let rand_k2: Vec<u8> = functions::gen_rand_key(130);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);
        assert_eq!(Hmac::SHA512.pad_key(&rand_k).len(), Hmac::SHA512.blocksize());
        assert_eq!(Hmac::SHA512.pad_key(&rand_k2).len(), Hmac::SHA512.blocksize());
        assert_eq!(Hmac::SHA512.pad_key(&rand_k3).len(), Hmac::SHA512.blocksize());
    }

    #[test]
    // Test that hmac_compute() returns expected HMAC digests
    fn test_hmac_computet_result() {
        let key = vec![0x61; 5];
        let message = vec![0x61; 5];

        let actual_sha1 = Hmac::SHA1.hmac_compute(&key, &message);
        let actual_sha256 = Hmac::SHA256.hmac_compute(&key, &message);
        let actual_sha384 = Hmac::SHA384.hmac_compute(&key, &message);
        let actual_sha512 = Hmac::SHA512.hmac_compute(&key, &message);

        // Expected values from: https://www.freeformatter.com/hmac-generator.html#ad-output
        let expected_sha1 = test::from_hex("40a50a7b74cf6099ee7082e3b4e2fd51f002f29d").unwrap();
        let expected_sha256 = test::from_hex("c960dd5485480f51044c1afa312fecc5ab58548f9f108a5062a3bc229fd02359").unwrap();
        let expected_sha384 = test::from_hex("6b0d10e1f341c5d9d9c3fb59431ee2ba155b5fa75e25a73bcd418d8a8a45c9562741a1214537fc33b08db20a1d52e037").unwrap();
        let expected_sha512 = test::from_hex("aaffe2e33265ab09d1f971dc8ee821a996e57264658a805317caabeb5b93321e4e4dacb366670fb34867a4d0359b07f5e9ee7e681c650c7301cc9bf89f4a1adf").unwrap();
        assert_eq!(actual_sha1, expected_sha1);
        assert_eq!(actual_sha256, expected_sha256);
        assert_eq!(actual_sha384, expected_sha384);
        assert_eq!(actual_sha512, expected_sha512);
    }

    #[test]
    // Test that hmac_validate() returns true if signatures match and false if not
    fn test_hmac_validate() {
        let key = vec![0x61; 5];
        let message = vec![0x62; 5];
        let wrong_key = vec![0x67; 5];

        let recieved_sha1 = Hmac::SHA1.hmac_compute(&key, &message);
        let recieved_sha256 = Hmac::SHA256.hmac_compute(&key, &message);
        let recieved_sha384 = Hmac::SHA384.hmac_compute(&key, &message);
        let recieved_sha512 = Hmac::SHA512.hmac_compute(&key, &message);


        assert_eq!(Hmac::SHA1.hmac_validate(&key, &message, &recieved_sha1), true);
        assert_eq!(Hmac::SHA1.hmac_validate(&wrong_key, &message, &recieved_sha1), false);

        assert_eq!(Hmac::SHA256.hmac_validate(&key, &message, &recieved_sha256), true);
        assert_eq!(Hmac::SHA256.hmac_validate(&wrong_key, &message, &recieved_sha256), false);

        assert_eq!(Hmac::SHA384.hmac_validate(&key, &message, &recieved_sha384), true);
        assert_eq!(Hmac::SHA384.hmac_validate(&wrong_key, &message, &recieved_sha384), false);

        assert_eq!(Hmac::SHA512.hmac_validate(&key, &message, &recieved_sha512), true);
        assert_eq!(Hmac::SHA512.hmac_validate(&wrong_key, &message, &recieved_sha512), false);
    }
}
