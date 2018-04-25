use clear_on_drop::clear;
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

impl Drop for Pbkdf2 {
    fn drop(&mut self) {
        //println!("DROPPING");
        self.password.clear();
        self.salt.clear()
    }
}

/// PBKDF2 (Password-Based Key Derivation Function 2) as specified in the
/// [RFC 8018](https://tools.ietf.org/html/rfc8018).
///
/// # Usage examples:
/// ### Generating derived key:
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
    fn function_f(&self, index_i: u32) -> Vec<u8> {

        let mut u_step: Vec<u8> = Vec::new();
        let mut f_result: Vec<u8> = Vec::new();

        let mut salt_extended = self.salt.clone();
        let mut index_buffer = [0u8; 4];
        write_u32_be(&mut index_buffer, index_i);
        salt_extended.extend_from_slice(&index_buffer);

        // First iteration
        // u_step here will be equal to U_1 in RFC
        u_step = self.return_prf(&self.password, &salt_extended);
        salt_extended.clear();
        // Push directly into the final buffer, as this is the first iteration
        f_result.extend_from_slice(&u_step);
        // Second iteration
        // u_step here will be equal to U_2 in RFC
        if self.iterations > 1 {
            u_step = self.return_prf(&self.password, &u_step);
            f_result = self.fixed_xor(&f_result, &u_step);
        }
        // Remainder of iterations
        if self.iterations > 2 {
            for _x in 2..self.iterations {
                u_step = self.return_prf(&self.password, &u_step);
                f_result = self.fixed_xor(&f_result, &u_step);
            }
        }

        f_result
    }

    /// PBKDF2 function. Return a derived key.
    pub fn pbkdf2_compute(&self) -> Vec<u8> {

        if self.iterations < 1 {
            panic!("0 iterations are not possible");
        }
        // Check that the selected key length is within the limit.
        if self.length > ((2_u64.pow(32) - 1) * (self.hmac.return_value() / 8) as u64) as usize {
            panic!("Derived key length above max.");
        } else if self.length == 0 {
            panic!("A derived key length of zero is not allowed.");
        }

        // Corresponds to l in RFC
        let hlen_blocks = (self.length as f32 / (self.hmac.return_value() / 8) as f32).ceil() as usize;

        let mut pbkdf2_res: Vec<u8> = Vec::new();
        let mut index_i: u32 = 0;

        for _x in 0..hlen_blocks {
            index_i += 1;
            pbkdf2_res.extend_from_slice(&self.function_f(index_i));
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
    fn sha256_test_case_1() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: 20,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "120fb6cffcf8b32c43e7225256c4f837a86548c9"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn sha256_test_case_2() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 20,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn sha256_test_case_3() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 4096,
            length: 20,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "c5e478d59288c841aa530db6845c4c8d962893a0"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    // Commented out because it takes about 10 minues to complete
    /*
    #[test]
    fn sha256_test_case_4() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 16777216,
            length: 20,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e8"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());

    }
    */

    #[test]
    fn sha256_test_case_5() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "passwordPASSWORDpassword".as_bytes().to_vec(),
            salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_vec(),
            iterations: 4096,
            length: 25,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn sha256_test_case_6() {

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
    fn sha384_test_case_1() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: 20,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "c0e14f06e49e32d73f9f52ddf1d0c5c719160923"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());
    }

    #[test]
    fn sha384_test_case_2() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 20,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "54f775c6d790f21930459162fc535dbf04a93918"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());
    }

    #[test]
    fn sha384_test_case_3() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 4096,
            length: 20,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "559726be38db125bc85ed7895f6e3cf574c7a01c"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());
    }

    // Commented out because it takes about 10 minues to complete
    /*
    #[test]
    fn sha384_test_case_4() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 16777216,
            length: 20,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "a7fdb349ba2bfa6bf647bb0161bae1320df27e64"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());

    }
    */

    #[test]
    fn sha384_test_case_5() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "passwordPASSWORDpassword".as_bytes().to_vec(),
            salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_vec(),
            iterations: 4096,
            length: 25,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());
    }

    #[test]
    fn sha384_test_case_6() {

        let pbkdf2_dk_384 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA384,
        };

        let expected_pbkdf2_dk_384 = decode(
            "a3f00ac8657e095f8e0823d232fc60b3"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_384, pbkdf2_dk_384.pbkdf2_compute());
    }

    #[test]
    fn sha512_test_case_1() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: 20,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a6"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());
    }

    #[test]
    fn sha512_test_case_2() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 20,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());
    }

    #[test]
    fn sha512_test_case_3() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 4096,
            length: 20,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());
    }

    // Commented out because it takes about 10 minues to complete
    /*
    #[test]
    fn sha512_test_case_4() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 16777216,
            length: 20,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "6180a3ceabab45cc3964112c811e0131bca93a35"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());

    }
    */

    #[test]
    fn sha512_test_case_5() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "passwordPASSWORDpassword".as_bytes().to_vec(),
            salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_vec(),
            iterations: 4096,
            length: 25,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());
    }

    #[test]
    fn sha512_test_case_6() {

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "sa\0lt".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_512, pbkdf2_dk_512.pbkdf2_compute());
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

    #[test]
    #[should_panic]
    fn zero_iterations_panic() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 0,
            length: 15,
            hmac: ShaVariantOption::SHA256,
        };

        pbkdf2_dk_256.pbkdf2_compute();
    }

    #[test]
    #[should_panic]
    fn zero_length_panic() {
        let pbkdf2_dk_256 = Pbkdf2 {
            password: "password".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 2,
            length: 0,
            hmac: ShaVariantOption::SHA256,
        };

        pbkdf2_dk_256.pbkdf2_compute();
    }
}
