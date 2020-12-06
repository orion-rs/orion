// Testing against OpenSSL test vectors.
// https://github.com/openssl/openssl/blob/2d0b44126763f989a4cbffbffe9d0c7518158bb7/test/evptests.txt
// Taken at commit: 9257959

#[cfg(test)]
mod openssl_test_vectors {

    use super::super::blake2b_test_runner;
    use hex::decode;

    #[test]
    fn openssl_test_case_0() {
        let input = decode("").unwrap();
        let expected_output = decode("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_1() {
        let input = decode("61").unwrap();
        let expected_output = decode("333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_2() {
        let input = decode("616263").unwrap();
        let expected_output = decode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_3() {
        let input = decode("6d65737361676520646967657374").unwrap();
        let expected_output = decode("3c26ce487b1c0f062363afa3c675ebdbf5f4ef9bdc022cfbef91e3111cdc283840d8331fc30a8a0906cff4bcdbcd230c61aaec60fdfad457ed96b709a382359a").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_4() {
        let input = decode("6162636465666768696a6b6c6d6e6f707172737475767778797a").unwrap();
        let expected_output = decode("c68ede143e416eb7b4aaae0d8e48e55dd529eafed10b1df1a61416953a2b0a5666c761e7d412e6709e31ffe221b7a7a73908cb95a4d120b8b090a87d1fbedb4c").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_5() {
        let input = decode("4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839").unwrap();
        let expected_output = decode("99964802e5c25e703722905d3fb80046b6bca698ca9e2cc7e49b4fe1fa087c2edf0312dfbb275cf250a1e542fd5dc2edd313f9c491127c2e8c0c9b24168e2d50").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }

    #[test]
    fn openssl_test_case_6() {
        let input = decode("3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930").unwrap();
        let expected_output = decode("686f41ec5afff6e87e1f076f542aa466466ff5fbde162c48481ba48a748d842799f5b30f5b67fc684771b33b994206d05cc310f31914edd7b97e41860d77d282").unwrap();

        // Using empty keys since that is the same as None in test_runner
        blake2b_test_runner(&input, &[0u8; 0], &expected_output);
    }
}
