use std::borrow::Cow;
use sha2::Digest;
use sha2;
use clear_on_drop::clear;
use util;


/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).

pub struct Hmac {
    pub secret_key: Vec<u8>,
    pub message: Vec<u8>,
    pub sha2: usize,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        //println!("DROPING");
        self.secret_key.clear();
        self.message.clear()
    }
}

/// HMAC (Hash-based Message Authentication Code) as specified in the
/// [RFC 2104](https://tools.ietf.org/html/rfc2104).
///
/// # Usage examples:
/// ### Generating HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::util::gen_rand_key;
///
/// let key = gen_rand_key(10);
/// let message = gen_rand_key(10);
///
/// let hmac_sha256 = Hmac { secret_key: key, message: message, sha2: 256 };
///
/// hmac_sha256.hmac_compute();
/// ```
/// ### Verifying HMAC:
/// ```
/// use orion::hmac::Hmac;
/// use orion::util::gen_rand_key;
///
/// let key = "Some key.";
/// let msg = "Some message.";
///
/// let hmac_sha256 = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     message: msg.as_bytes().to_vec(),
///     sha2: 256
/// };
/// let received_hmac = Hmac {
///     secret_key: key.as_bytes().to_vec(),
///     message: msg.as_bytes().to_vec(),
///     sha2: 256
/// };
/// assert_eq!(hmac_sha256.hmac_validate(&received_hmac.hmac_compute()), true);
/// ```

impl Hmac {
    /// Return blocksize matching SHA variant.
    fn blocksize(&self) -> usize {
        match self.sha2 {
            256 => 64,
            384 => 128,
            512 => 128,
            _ => panic!("Blocksize not found for {:?}", self.sha2)
        }
    }

    /// Return a byte vector of a given byte slice.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self.sha2 {
            256 => {
                let mut hash = sha2::Sha256::default();
                hash.input(data);
                hash.result().to_vec()
            },
            384 => {
                let mut hash = sha2::Sha384::default();
                hash.input(data);
                hash.result().to_vec()
            },
            512 => {
                let mut hash = sha2::Sha512::default();
                hash.input(data);
                hash.result().to_vec()
            },
            _ => panic!("Unkown option {:?}", self.sha2)
        }
    }

    /// Return a padded key if the key is less than or greater than the blocksize.
    fn pad_key<'a>(&self, secret_key: &'a [u8]) -> Cow<'a, [u8]> {
        let mut key = Cow::from(secret_key);

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
    pub fn hmac_compute(&self) -> Vec<u8> {
        let key = self.pad_key(&self.secret_key);

        let make_padded_key = |byte: u8| {
            let mut pad = key.to_vec();
            for i in &mut pad { *i ^= byte };
            pad
        };

        let mut ipad = make_padded_key(0x36);
        let mut opad = make_padded_key(0x5C);

        ipad.extend_from_slice(&self.message);
        opad.extend_from_slice(self.hash(&ipad).as_ref());
        self.hash(&opad).to_vec()
    }

    /// Check HMAC validity by computing one from the current struct fields and comparing this
    /// to the passed HMAC.
    pub fn hmac_validate(&self, received_hmac: &[u8]) -> bool {

        let own_hmac = self.hmac_compute();
        let rand_key = util::gen_rand_key(64);

        let nd_round_own = Hmac {
            secret_key: rand_key.clone(),
            message: own_hmac,
            sha2: self.sha2
        };

        let nd_round_received = Hmac {
            secret_key: rand_key.clone(),
            message: received_hmac.to_vec(),
            sha2: self.sha2
        };

        util::compare_ct(
            &nd_round_own.hmac_compute(),
            &nd_round_received.hmac_compute(),
            (self.sha2 / 8)
        )
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hmac::Hmac;

    #[test]
    fn test_hmac_return_result() {

        let hmac_256 = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x61; 5],
            sha2: 256
        };
        let hmac_384 = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x61; 5],
            sha2: 384
        };
        let hmac_512 = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x61; 5],
            sha2: 512
        };

        // Expected values from: https://www.liavaag.org/English/SHA-Generator/HMAC/
        let expected_hmac_256 = decode(
            "c960dd5485480f51044c1afa312fecc5ab58548f9f108a5062a3bc229fd02359");
        let expected_hmac_384 = decode(
            "6b0d10e1f341c5d9d9c3fb59431ee2ba155b5fa75e25a73bcd418d8a8a45c956\
            2741a1214537fc33b08db20a1d52e037");
        let expected_hmac_512 = decode(
            "aaffe2e33265ab09d1f971dc8ee821a996e57264658a805317caabeb5b93321e\
            4e4dacb366670fb34867a4d0359b07f5e9ee7e681c650c7301cc9bf89f4a1adf");

        assert_eq!(Ok(hmac_256.hmac_compute()), expected_hmac_256);
        assert_eq!(Ok(hmac_384.hmac_compute()), expected_hmac_384);
        assert_eq!(Ok(hmac_512.hmac_compute()), expected_hmac_512);
    }


    #[test]
    // Test that hmac_validate() returns true if signatures match and false if not
    fn test_hmac_validate() {

        let own_hmac = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x61; 5],
            sha2: 256
        };
        let recieved_hmac = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x61; 5],
            sha2: 256
        };
        let false_hmac = Hmac {
            secret_key: vec![0x61; 5],
            message: vec![0x67; 5],
            sha2: 256
        };

        assert_eq!(own_hmac.hmac_validate(&recieved_hmac.hmac_compute()), true);
        assert_eq!(own_hmac.hmac_validate(&false_hmac.hmac_compute()), false);
    }
}
