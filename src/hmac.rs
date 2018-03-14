use std::borrow::Cow;
use sha1::Digest;
use sha1;
use sha2;

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
pub enum Hmac {
    SHA1,
    SHA2_256,
    SHA2_384,
    SHA2_512,
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
/// let sig = Hmac::SHA2_256.hmac_compute(&key, &message);
/// ```
/// ### Verifying HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::functions;
///
/// let key = functions::gen_rand_key(10);
/// let message = functions::gen_rand_key(10);
///
/// let sig = Hmac::SHA2_256.hmac_compute(&key, &message);
/// assert_eq!(Hmac::SHA2_256.hmac_validate(&key, &message, &sig), true);
/// ```
impl Hmac {
    /// Return blocksize matching SHA variant.
    fn blocksize(&self) -> usize {
        match *self {
            Hmac::SHA1 => 64,
            Hmac::SHA2_256 => 64,
            Hmac::SHA2_384 => 128,
            Hmac::SHA2_512 => 128,
        }
    }
    /// Return a ring::digest:Digest of a given byte slice.
    fn hash(&self, data: &[u8]) -> Vec<u8> {

        match *self {
            Hmac::SHA1 => {
                let mut fun = sha1::Sha1::default();
                fun.input(data);
                fun.result().to_vec()
            },
            Hmac::SHA2_256 => {
                let mut fun = sha2::Sha256::default();
                fun.input(data);
                fun.result().to_vec()
            },
            Hmac::SHA2_384 => {
                let mut fun = sha2::Sha384::default();
                fun.input(data);
                fun.result().to_vec()
            },
            Hmac::SHA2_512 => {
                let mut fun = sha2::Sha512::default();
                fun.input(data);
                fun.result().to_vec()
            },
        }
    }

    /// Return a padded key if the key is less than or greater than the blocksize.
    fn pad_key<'a>(&self, key: &'a [u8]) -> Cow<'a, [u8]> {
        let mut key = Cow::from(key);

        if key.len() > self.blocksize() {
            key = self.hash(&key).into();

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
        self.hash(&opad).to_vec()

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
    extern crate hex;

    use hmac::Hmac;
    use self::hex::decode;
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
    // with size of correct BLOCKSIZE for SHA2
    fn test_pad_key_sha2() {
        let rand_k: Vec<u8> = functions::gen_rand_key(67);
        let rand_k2: Vec<u8> = functions::gen_rand_key(130);
        let rand_k3: Vec<u8> = functions::gen_rand_key(34);

        assert_eq!(Hmac::SHA2_256.pad_key(&rand_k).len(), Hmac::SHA2_256.blocksize());
        assert_eq!(Hmac::SHA2_256.pad_key(&rand_k2).len(), Hmac::SHA2_256.blocksize());
        assert_eq!(Hmac::SHA2_256.pad_key(&rand_k3).len(), Hmac::SHA2_256.blocksize());

        assert_eq!(Hmac::SHA2_384.pad_key(&rand_k).len(), Hmac::SHA2_384.blocksize());
        assert_eq!(Hmac::SHA2_384.pad_key(&rand_k2).len(), Hmac::SHA2_384.blocksize());
        assert_eq!(Hmac::SHA2_384.pad_key(&rand_k3).len(), Hmac::SHA2_384.blocksize());

        assert_eq!(Hmac::SHA2_512.pad_key(&rand_k).len(), Hmac::SHA2_512.blocksize());
        assert_eq!(Hmac::SHA2_512.pad_key(&rand_k2).len(), Hmac::SHA2_512.blocksize());
        assert_eq!(Hmac::SHA2_512.pad_key(&rand_k3).len(), Hmac::SHA2_512.blocksize());
    }

    #[test]
    // Test that hmac_compute() returns expected HMAC digests
    fn test_hmac_computet_result() {
        let key = vec![0x61; 5];
        let message = vec![0x61; 5];

        let actual_sha1 = Hmac::SHA1.hmac_compute(&key, &message);

        let actual_sha2_256 = Hmac::SHA2_256.hmac_compute(&key, &message);
        let actual_sha2_384 = Hmac::SHA2_384.hmac_compute(&key, &message);
        let actual_sha2_512 = Hmac::SHA2_512.hmac_compute(&key, &message);

        // Expected values from: https://www.liavaag.org/English/SHA-Generator/HMAC/
        let expected_sha1 = decode("40a50a7b74cf6099ee7082e3b4e2fd51f002f29d");
        // SHA2
        let expected_sha2_256 = decode("c960dd5485480f51044c1afa312fecc5ab58548f9f108a5062a3bc229fd02359");
        let expected_sha2_384 = decode("6b0d10e1f341c5d9d9c3fb59431ee2ba155b5fa75e25a73bcd418d8a8a45c9562741a1214537fc33b08db20a1d52e037");
        let expected_sha2_512 = decode("aaffe2e33265ab09d1f971dc8ee821a996e57264658a805317caabeb5b93321e4e4dacb366670fb34867a4d0359b07f5e9ee7e681c650c7301cc9bf89f4a1adf");

        assert_eq!(Ok(actual_sha1), expected_sha1);

        assert_eq!(Ok(actual_sha2_256), expected_sha2_256);
        assert_eq!(Ok(actual_sha2_384), expected_sha2_384);
        assert_eq!(Ok(actual_sha2_512), expected_sha2_512);
    }

    #[test]
    // Test that hmac_validate() returns true if signatures match and false if not
    fn test_hmac_validate() {
        let key = vec![0x61; 5];
        let message = vec![0x62; 5];
        let wrong_key = vec![0x67; 5];

        let recieved_sha1 = Hmac::SHA1.hmac_compute(&key, &message);

        let recieved_sha2_256 = Hmac::SHA2_256.hmac_compute(&key, &message);
        let recieved_sha2_384 = Hmac::SHA2_384.hmac_compute(&key, &message);
        let recieved_sha2_512 = Hmac::SHA2_512.hmac_compute(&key, &message);

        assert_eq!(Hmac::SHA1.hmac_validate(&key, &message, &recieved_sha1), true);
        assert_eq!(Hmac::SHA1.hmac_validate(&wrong_key, &message, &recieved_sha1), false);

        assert_eq!(Hmac::SHA2_256.hmac_validate(&key, &message, &recieved_sha2_256), true);
        assert_eq!(Hmac::SHA2_256.hmac_validate(&wrong_key, &message, &recieved_sha2_256), false);

        assert_eq!(Hmac::SHA2_384.hmac_validate(&key, &message, &recieved_sha2_384), true);
        assert_eq!(Hmac::SHA2_384.hmac_validate(&wrong_key, &message, &recieved_sha2_384), false);

        assert_eq!(Hmac::SHA2_512.hmac_validate(&key, &message, &recieved_sha2_512), true);
        assert_eq!(Hmac::SHA2_512.hmac_validate(&wrong_key, &message, &recieved_sha2_512), false);

    }
}
