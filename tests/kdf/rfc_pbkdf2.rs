// Testing against RFC-7914 test vectors.
// Only has two PBKDF2-HMAC-SHA256 test vector.

#[cfg(test)]
mod rfc7914_test_vectors {

    use hex::decode;
    use orion::hazardous::kdf::pbkdf2::*;

    #[test]
    fn test_case_1() {
        let password_256 = sha256::Password::from_slice("passwd".as_bytes()).unwrap();
        let salt = "salt".as_bytes();
        let iter = 1;
        let mut dk_out = [0u8; 64];

        let expected_dk_256 = decode("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783").unwrap();

        // verify() also runs derive_key()
        assert!(sha256::verify(&expected_dk_256, &password_256, &salt, iter, &mut dk_out).is_ok());
    }

    #[test]
    fn test_case_2() {
        let password_256 = sha256::Password::from_slice("Password".as_bytes()).unwrap();
        let salt = "NaCl".as_bytes();
        let iter = 80000;
        let mut dk_out = [0u8; 64];

        let expected_dk_256 = decode("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d").unwrap();

        // verify() also runs derive_key()
        assert!(sha256::verify(&expected_dk_256, &password_256, &salt, iter, &mut dk_out).is_ok());
    }
}
