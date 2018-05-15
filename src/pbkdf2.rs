use clear_on_drop::clear::Clear;
use hmac::Hmac;
use options::ShaVariantOption;
use byte_tools::write_u32_be;
use util;

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
        Clear::clear(&mut self.password);
        Clear::clear(&mut self.salt)
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
/// ### Verifying derived key:
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
/// let derived_key = dk.pbkdf2_compute();
/// assert_eq!(dk.pbkdf2_compare(&derived_key), true);
/// ```


impl Pbkdf2 {

    /// Return the maximum derived keyu length.
    fn max_dklen(&self) -> usize {
        match self.hmac.return_value() {
            // These values have been calculated from the constraint given in RFC by:
            // (2^32 - 1) * hLen
            256 => 137438953440,
            384 => 206158430160,
            512 => 274877906880,
            _ => panic!("Blocksize not found for {:?}", self.hmac.return_value())
        }
    }

    /// Returns a PRF value from HMAC and selected Sha2 variant from Pbkdf2 struct.
    fn return_prf(&self, ipad: &[u8], opad: &[u8], message: Vec<u8>) -> Vec<u8> {

        // Secret value and message aren't needed in this case
        let fast_hmac = Hmac {
            secret_key: vec![0x00; 0],
            message: vec![0x00; 0],
            sha2: self.hmac
        };

        fast_hmac.pbkdf2_hmac(ipad.to_vec(), opad.to_vec(), message)
    }

    /// Function F as described in the RFC.
    fn function_f(&self, index_i: u32, ipad: &[u8], opad: &[u8]) -> Vec<u8> {

        let mut salt_extended = self.salt.clone();
        let mut index_buffer = [0u8; 4];
        write_u32_be(&mut index_buffer, index_i);
        salt_extended.extend_from_slice(&index_buffer);

        let mut f_result: Vec<u8> = Vec::new();
        // First iteration
        // u_step here will be equal to U_1 in RFC
        //let mut u_step = self.return_prf(padded_password, salt_extended);
        let mut u_step = self.return_prf(ipad, opad, salt_extended);
        // Push directly into the final buffer, as this is the first iteration
        f_result.extend_from_slice(&u_step);
        // Second iteration
        // u_step here will be equal to U_2 in RFC
        if self.iterations > 1 {
            u_step = self.return_prf(ipad, opad, u_step);
            // The length of f_result and u_step will always be the same due to HMAC
            for c in 0..f_result.len() {
                f_result[c] ^= u_step[c];
            }
            // Remainder of iterations
            if self.iterations > 2 {
                for _x in 2..self.iterations {
                    u_step = self.return_prf(ipad, opad, u_step);

                    for c in 0..f_result.len() {
                        f_result[c] ^= u_step[c];
                    }
                }
            }
        }

        f_result
    }

    /// PBKDF2 function. Return a derived key.
    pub fn pbkdf2_compute(&self) -> Vec<u8> {

        if self.iterations < 1 {
            panic!("0 iterations are not possible");
        }
        // Check that the selected key length is within the limit
        if self.length > self.max_dklen() {
            panic!("Derived key length above max.");
        } else if self.length == 0 {
            panic!("A derived key length of zero is not allowed.");
        }

        // Corresponds to l in RFC
        let hlen_blocks = (self.length as f32 / (self.hmac.return_value() / 8) as f32).ceil() as usize;

        // Make inner and outer paddings for a faster HMAC
        let pad_const = Hmac {secret_key: vec![0x00; 0], message: vec![0x00; 0], sha2: self.hmac};
        let (ipad, opad) = pad_const.make_pads(&self.password);

        let mut pbkdf2_dk: Vec<u8> = Vec::new();
        let mut index_i: u32 = 0;

        for _x in 0..hlen_blocks {
            index_i += 1;
            pbkdf2_dk.extend_from_slice(&self.function_f(index_i, &ipad, &opad));
        }

        pbkdf2_dk.truncate(self.length);

        pbkdf2_dk
    }

    /// Check derived key validity by computing one from the current struct fields and comparing this
    /// to the passed derived key. Comparison is done in constant time.
    pub fn pbkdf2_compare(&self, received_dk: &[u8]) -> bool {

        if received_dk.len() != self.length {
            panic!("Cannot compare two DK's that are not the same length.");
        }

        let own_dk = self.pbkdf2_compute();

        util::compare_ct(received_dk, &own_dk)
    }
}



#[cfg(test)]
mod test {

    use pbkdf2::Pbkdf2;
    use options::ShaVariantOption;
    extern crate hex;
    use self::hex::decode;

    #[test]
    fn rfc7914_test_case_1() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "passwd".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            length: 64,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
            49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    #[test]
    fn rfc7914_test_case_2() {

        let pbkdf2_dk_256 = Pbkdf2 {
            password: "Password".as_bytes().to_vec(),
            salt: "NaCl".as_bytes().to_vec(),
            iterations: 80000,
            length: 64,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_pbkdf2_dk_256 = decode(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
            a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        ).unwrap();

        assert_eq!(expected_pbkdf2_dk_256, pbkdf2_dk_256.pbkdf2_compute());
    }

    // These test vectors have been generated with the cryptography.io Python package.
    // More information here: https://github.com/brycx/PBKDF2-HMAC-SHA2-Test-Vectors
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

    #[test]
    fn pbkdf2_compare_true() {

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

        assert_eq!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512), true);
    }

    #[test]
    fn pbkdf2_compare_false() {

        // Salt value differs between this and the previous test case

        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "".as_bytes().to_vec(),
            iterations: 4096,
            length: 16,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert_eq!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512), false);
        
    }

    #[test]
    #[should_panic]
    fn pbkdf2_compare_diff_length_panic() {

        // Different length than expected dk
        
        let pbkdf2_dk_512 = Pbkdf2 {
            password: "pass\0word".as_bytes().to_vec(),
            salt: "".as_bytes().to_vec(),
            iterations: 4096,
            length: 32,
            hmac: ShaVariantOption::SHA512,
        };

        let expected_pbkdf2_dk_512 = decode(
            "9d9e9c4cd21fe4be24d5b8244c759665"
        ).unwrap();

        assert_eq!(pbkdf2_dk_512.pbkdf2_compare(&expected_pbkdf2_dk_512), false);
        
    }
}
