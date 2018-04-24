use clear_on_drop::clear;
use util;
use hmac::Hmac;
use options::ShaVariantOption;
use byte_tools::write_u32_be;

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).

pub struct Pbkdf2 {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub iterations: usize,
    pub length: usize,
    pub hmac: ShaVariantOption,
}

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
///
/// # Usage examples:
/// ### Generating HMAC:
/// ```
/// use orion::pbkdf2::Pbkdf2;
/// use orion::util::gen_rand_key;
/// use orion::options::ShaVariantOption;
///
/// let password = gen_rand_key(16);
/// let salt = gen_rand_key(16);
///
/// let dk = Pbkdf2 {
///     password: password,
///     salt: salt,
///     iterations: 10000,
///     length: 64,
///     hmac: ShaVariantOption::SHA512
/// };
///
/// dk.pbkdf2_compute();
/// ```

impl Drop for Pbkdf2 {
    fn drop(&mut self) {
        //println!("DROPPING");
        self.password.clear();
        self.salt.clear()
    }
}

impl Pbkdf2 {

    /// XOR two equal length bytes vectors.
    fn fixed_xor(&self, buffer_1: &[u8], buffer_2: &[u8]) -> Vec<u8> {
        assert_eq!(buffer_1.len(), buffer_2.len());

        let mut result: Vec<u8> = Vec::new();

        for i in 0..buffer_1.len() {
            result.push(buffer_1[i] ^ buffer_2[i]);
        }

        result
    }

    /// Returns a PRF value from HMAC and selected Sha2 variant from Pbkdf2 struct.
    fn return_prf(&self, key: &[u8], data: &[u8]) -> Vec<u8> {

        let prf_res = Hmac {
            secret_key: key.to_vec(),
            message: data.to_vec(),
            sha2: self.hmac
        };

        prf_res.hmac_compute()
    }

    /// Function F as described in the RFC.
    fn function_f(&self, i: u32) -> Vec<u8> {

        let mut u_step: Vec<u8> = Vec::new();
        let mut f_iter_final: Vec<u8> = Vec::new();

        let mut salt_extended = self.salt.clone();
        let mut i_buffer = [0u8; 4];
        write_u32_be(&mut i_buffer, i);
        salt_extended.extend_from_slice(&i_buffer);

        // First iteration
        // u_step here will be equal to U_1 in RFC
        u_step = self.return_prf(&self.password, &salt_extended);
        // Push directly into the final buffer, as this is the first iteration
        f_iter_final.extend_from_slice(&u_step);

        // Second iteration
        // u_step here will be equal to U_2 in RFC
        if self.iterations > 1 {
            u_step = self.return_prf(&self.password, &u_step);
            f_iter_final = self.fixed_xor(&f_iter_final, &u_step);
        }

        // Remainder of iterations
        if self.iterations > 2 {
            for _x in 2..self.iterations {
                u_step = self.return_prf(&self.password, &u_step);
                f_iter_final = self.fixed_xor(&f_iter_final, &u_step);
            }
        }

        f_iter_final
    }

    /// PBKDF2 function. Return a derived key.
    pub fn pbkdf2_compute(&self) -> Vec<u8> {
        // Check that the selected key length is within the limit.
        if self.length > ((2_u64.pow(32) - 1) * (self.hmac.return_value() / 8) as u64) as usize {
            panic!("Derived key length above max. 255 * (HMAC OUTPUT LENGTH IN BYTES)");
        }

        // Corresponds to l in RFC
        let hlen_blocks = (self.length as f32 / (self.hmac.return_value() / 8) as f32).ceil() as usize;
        // Corresponds to r in RFC
        let r_last_block: usize = self.length - ((hlen_blocks - 1) * (self.hmac.return_value() / 8));

        let mut pbkdf2_res: Vec<u8> = Vec::new();
        let mut iter_count: u32 = 0;

        println!("hlen block {}", hlen_blocks);

        for _x in 0..hlen_blocks {
            iter_count += 1;
            pbkdf2_res.extend_from_slice(&self.function_f(iter_count));
        }

        pbkdf2_res.truncate(self.length);

        pbkdf2_res
    }
}



#[cfg(test)]
mod test {

    use pbkdf2::Pbkdf2;
    use options::ShaVariantOption;
    extern crate hex;
    use self::hex::decode;

    // These test vectors have been generated with the cryptography.io Python package.
    // This package passes the original test vectors from the [RFC 6070](https://tools.ietf.org/html/rfc6070.html).
    // The script that has been used to generate the expected test vectors can be found
    // in the pbkdf2-test-vectors folder.
    #[test]
    fn gen_test_case_1() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: 32,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn gen_test_case_2() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 32,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn gen_test_case_3() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 4096,
            length: 32,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    // Commented out because it takes about 10 minues to complete
    /*
    #[test]
    fn gen_test_case_4() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 16777216,
            length: 32,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());

    }
    */

    #[test]
    fn gen_test_case_5() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "passwordPASSWORDpassword".as_bytes().to_vec(),
            salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_vec(),
            iterations: 4096,
            length: 40,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn gen_test_case_6() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "89b69d0516f829893c696226650a8687"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    #[should_panic]
    fn length_too_high() {

        // Take 64 as this is the highest, since HMAC-SHA512
        let too_long = ((2_u64.pow(32) - 1) * 64 as u64) as usize + 1;

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: too_long,
            hmac: ShaVariantOption::SHA256,
        };

        pbkdf2_dk_256.pbkdf2_compute();
    }
}
