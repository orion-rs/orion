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
        let hmac_res = Hmac { secret_key: salt.to_vec(), message: data.to_vec(), sha2: self.hmac };

        hmac_res.hmac_compute()
    }

    /// The HKDF Expand step. Returns an HKDF.
    pub fn hkdf_compute(&self) -> Vec<u8> {
        // Check that the selected key length is within the limit.
        if self.length as f32 > 255_f32 * (self.hmac / 8) as f32 {
            panic!("Derived key length above max. Max derived key length is: {:?}",
                    255_f32 * (self.hmac / 8) as f32);
        }

        let n_iter = (self.length as f32 / (self.hmac / 8) as f32).ceil() as usize;

        let mut con_step: Vec<u8> = vec![];
        let mut t_step: Vec<u8> = vec![];
        let mut hkdf_final: Vec<u8> = vec![];

        for x in 1..n_iter+1 {
                con_step.append(&mut t_step);
                con_step.extend_from_slice(&self.info);
                con_step.push(x as u8);
                t_step.extend_from_slice(&self.hkdf_extract(&con_step, &self.hkdf_extract(&self.salt, &self.data)));
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
    fn test_hkdf_return_result() {
        let ikm = vec![0x61; 5];
        let salt_1 = vec![0x61; 5];
        let info_1 = vec![0x61; 5];
        //let length: usize = 50;

        let actual256 = Hkdf { salt: salt_1.clone(), data: ikm.clone(), info: info_1.clone(), hmac: 256, length: 50 };
        let actual384 = Hkdf { salt: salt_1.clone(), data: ikm.clone(), info: info_1.clone(), hmac: 384, length: 50 };
        let actual512 = Hkdf { salt: salt_1.clone(), data: ikm.clone(), info: info_1.clone(), hmac: 512, length: 50 };


        let expected256 = decode(
            "f64478d1e58b2070933a13aca0ab75859a41c61283ed985023c964d6287c4b5f65\
            3efe8df22a4a82b9e87fc2a8627e3d0063");

        let expected384 = decode(
            "74686470b67e49954926a71a5ca5e4fd4286a94c020aa7eeba16550db868dc5992c\
            a6c2a13a2bfde7d7cc86c5fdf2bcd8ed1");
        let expected512 = decode(
            "73b276604fa533dac12af682d7cf9a56150d75efddd2ffbcd3f83d847282df718ee\
            b3ff9d303c0fd54c1177ab00b3fb5f618");

        assert_eq!(Ok(actual256.hkdf_compute()), expected256);
        assert_eq!(Ok(actual384.hkdf_compute()), expected384);
        assert_eq!(Ok(actual512.hkdf_compute()), expected512);
    }
}
