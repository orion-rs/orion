use std::borrow::Cow;
use sha2::Digest;
use sha2;
use clear_on_drop::clear;
use util::compare_ct;


#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct Hmac {
    secret_key: Vec<u8>,
    message: Vec<u8>,
    sha2: u32,
}

impl Drop for Hmac {
    fn drop(&mut self) {
        //println!("DROP: {:?}", self.secret_key);
        self.secret_key.clear();
        self.message.clear()
    }
}


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

    fn outputsize(&self) -> usize {
        match self.sha2 {
            256 => 32,
            384 => 48,
            512 => 64,
            _ => panic!("Outputsize not found for {:?}", self.sha2)
        }
    }

    /// Return a byte vector of a given byte slice.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self.sha2 {
            256 => {
                let mut hash = sha2::Sha512::default();
                hash.input(data);
                hash.result().to_vec()
            },
            384 => {
                let mut hash = sha2::Sha512::default();
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

    /// Check HMAC validity by computing one from key and message, then comparing this to the
    /// HMAC that has been passed to the function. Assumes the key, data and SHA2 variant used,
    /// are those belonging to the initialized struct.
    pub fn hmac_validate(&self, received_hmac: &Vec<u8>) -> bool {

        let own_hmac = self.hmac_compute();

        compare_ct(&own_hmac, received_hmac, self.outputsize())
    }
}

#[cfg(test)]
mod test {
    extern crate hex;
    use self::hex::decode;
    use hmac::HmacR;

    #[test]
    fn test_run_new() {
        let key = vec![0x61; 5];
        let message = vec![0x61; 5];

        let maccer = HmacR { secret_key: key, message: message, sha2: 512 };
        let summ = maccer.hmac_compute();
        let expected_sha2_512 = decode("aaffe2e33265ab09d1f971dc8ee821a996e57264658a805317caabeb5b93321e4e4dacb366670fb34867a4d0359b07f5e9ee7e681c650c7301cc9bf89f4a1adf");


        //assert_eq!(HmacR::hmac_validate(&key, &message, &actual_sha2_512), true);
        assert_eq!(Ok(summ), expected_sha2_512);

    }
}
