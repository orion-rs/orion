// Testing against RFC 7914 test vectors.

#[cfg(test)]
mod rfc7914 {
    
    extern crate hex;
    use self::hex::decode;
    use pbkdf2::Pbkdf2;
    use options::ShaVariantOption;

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
}