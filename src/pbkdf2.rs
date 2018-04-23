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
///
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

    // function_f() is the function F described in the RFC.
    fn function_f(&self, i: u32) -> Vec<u8> {

        let mut u_int_step: Vec<u8> = Vec::new();
        let mut f_iter_final: Vec<u8> = Vec::new();

        let mut salt_extended = self.salt.clone();
        let mut i_buffer = [0u8; 4];
        write_u32_be(&mut i_buffer, i);
        salt_extended.extend_from_slice(&i_buffer);

        //salt_extended.push(i as u8);
        // u_first will be the same as U_1
        let u_first = self.return_prf(&self.password, &salt_extended);
        // u_step here will be same as U_2
        let mut u_step: Vec<u8> = self.return_prf(&self.password, &u_first);
        f_iter_final.extend_from_slice(&self.fixed_xor(&u_first, &u_step));

        for x in 2..self.iterations+1 {
            u_int_step = self.return_prf(&self.password, &u_step);
            u_step = self.return_prf(&self.password, &u_int_step);
            f_iter_final.extend_from_slice(&self.fixed_xor(&u_step, &u_int_step));
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
        let mut pbkdf2_final: Vec<u8> = Vec::new();
        let mut iter_count: u32 = 0;

        for x in 0..hlen_blocks {
            iter_count.checked_add(1).expect("Overflow on iteration count.");
            if x != hlen_blocks {
                pbkdf2_final.extend_from_slice(&self.function_f(iter_count));
            } else {
                pbkdf2_final.extend_from_slice(&self.function_f(iter_count)[..r_last_block-1]);
            }
        }

        pbkdf2_final.truncate(self.length);
        pbkdf2_final

    }
}



#[cfg(test)]
mod test {

    use pbkdf2::Pbkdf2;
    use options::ShaVariantOption;
    extern crate hex;
    use self::hex::decode;

    // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

    #[test]
    fn rfc6070_test_case_1() {

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
    fn rfc6070_test_case_2() {


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
    fn rfc6070_test_case_3() {

    }

    #[test]
    fn rfc6070_test_case_4() {

    }

    #[test]
    fn rfc6070_test_case_5() {

    }

    #[test]
    fn rfc6070_test_case_6() {

    }

    #[test]
    fn rfc6070_test_case_7() {

    }

}
