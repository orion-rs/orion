// Testing against test vectors generated with Monocypher.

#[cfg(test)]
mod other_argon2i {

    extern crate hex;
    extern crate orion;

    use self::{hex::decode, orion::hazardous::kdf::argon2i};

    #[test]
    fn test_case_0() {
        let mem: u32 = 508;
        let passes: u32 = 3;
        let password = decode("e4e4c4054fe35a75d9c0f679ad8770d8").unwrap();
        let salt = decode("227e68e4c1e68ce67ee88e6be251a207").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("01533c77ae625c68ccce382f1cbaf210b9ece67a407f85f85e49eb84d45b62e9").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_1() {
        let mem: u32 = 509;
        let passes: u32 = 3;
        let password = decode("48b3753cff3a6d990163e6b60da1e4e5").unwrap();
        let salt = decode("d6a2df78c16c96a52d4fb01ea4ecf70e").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("49091f6fe0d5973221fbccd59f2bc793a026a983727af769ee34ec6467e7bea1").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_2() {
        let mem: u32 = 510;
        let passes: u32 = 3;
        let password = decode("81ac001b08d6577bd91ce991c4c45c46").unwrap();
        let salt = decode("bc84d5465fc9139bf17042ae7313181f").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("d095882c151136a7efedc4714f284891acd4ee3f4d67b11536a9631237b7d6f8").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_3() {
        let mem: u32 = 511;
        let passes: u32 = 3;
        let password = decode("7afb217bd1eceeac1e133aaa9edb441f").unwrap();
        let salt = decode("a88ea3ae0eaa06cb9911b6d218570f92").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("da720b54fe04d734cd4a86627229f997268a52c29e9aec1038d3ca559efe7410").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_4() {
        let mem: u32 = 512;
        let passes: u32 = 3;
        let password = decode("4a70a7e992b43e0b18578e892e954c40").unwrap();
        let salt = decode("a51abdb5a85d300c32f391c45d6ef4db").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("c32b94affb74b9f6d173960730ddb20f7fee4d40e4db238f401bc9a5dc24a9cb").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_5() {
        let mem: u32 = 513;
        let passes: u32 = 3;
        let password = decode("043ddcf4214f24ea6ef6b181071f299a").unwrap();
        let salt = decode("a254a4606ab6a058e0c6fb5598218db7").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("d14d64ab70468337bc887fc9a15412238def84e90ec95660e592d3d27c4315d8").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_6() {
        let mem: u32 = 514;
        let passes: u32 = 3;
        let password = decode("1deb473f7d04c152e7e857736715dc7b").unwrap();
        let salt = decode("788aca39a3c96a878019e8999c815c57").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("6b541a3d30ab6595d541316c8fffa46532ea4148771d90737846a00779c3394e").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_7() {
        let mem: u32 = 515;
        let passes: u32 = 3;
        let password = decode("23dbfbde05e6c71f118afc0dedb5b9f8").unwrap();
        let salt = decode("dea398b2d764bca68dfc023a9821939d").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("0d28aa5e502bbe04bb9996c192f32374bac9c939e8ef3eb65ace9626f269a371").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_8() {
        let mem: u32 = 8;
        let passes: u32 = 3;
        let password = decode("389e38a072cf1b413bb1517c3fe83abe").unwrap();
        let salt = decode("bb1cdf3a218abb1b0c01da64c24f59ee").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash = decode("74dc318303ec45c8d84ac60c21528a9dc18d53105b973f269947d229d1c802138c11a6806a0d1d3345eb85e26ce43251f4e410f258728f4444eb3285f0c92e").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_9() {
        let mem: u32 = 8;
        let passes: u32 = 3;
        let password = decode("d19cfb8cb3940aba546f0be57895e2cc").unwrap();
        let salt = decode("869fe55aab069c5abcf9e7ba6444a846").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash = decode("67790a697ca614867c58ce9f995059b213a2851e80aa4ca31d903d5023a2509a0417fb3598ead6d184e99653c5b2db3bd9cefa0e3f293fe7d795502fb77f8a91").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_10() {
        let mem: u32 = 8;
        let passes: u32 = 3;
        let password = decode("e5d73f1c8c5376c1220ff3d9d53eeb65").unwrap();
        let salt = decode("cc53599f40d6c8348c353b0017265523").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("1aff2fe51d6c5da28cd633617adccf86b1a70715bf20270df78f4ec8d3799c0b").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_11() {
        let mem: u32 = 8;
        let passes: u32 = 4;
        let password = decode("6cddcd1879ca1f04b35f91adab70b81f").unwrap();
        let salt = decode("504035fc169964a5ae985e6c11b0b7bb").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("0dd5929051d8dc103c6e93548b1b0ce35b2a09eda7b263f5226de1e2faf058ae").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_12() {
        let mem: u32 = 8;
        let passes: u32 = 5;
        let password = decode("18a51fd77fbffd722aa220efdd8947ca").unwrap();
        let salt = decode("5a5c7fb1c2ebdb9ad1f603801ff22e80").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
            decode("6904f9d2fa76d9d5efca8616c6cd0d6a8d4a4bc9301fb7429129d23550f8ca26").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_13() {
        let mem: u32 = 7604;
        let passes: u32 = 3;
        let password = decode("314f716af9c22022fa159dbb4b4d3153").unwrap();
        let salt = decode("f999b20ab4769eb1d01c057c5295ed04").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
			decode("ccc31784ebeae41d4c46c24dd67ef384b9764ff5ac487d760cf6ca86e6019b792fdfcd4b44599f7d0bb8dc3e48ed870198c76abdad9bc234b7192072e98f6862b9a60c92d72154f04cff3b0206fe57ac124eb1b86a711ae1f10b13c6b985").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }

    #[test]
    fn test_case_14() {
        let mem: u32 = 7604;
        let passes: u32 = 3;
        let password = decode("2b4536561dce32478b113adb5b605cac").unwrap();
        let salt = decode("75bcfcacb5e3e811b78e72e398fdd118").unwrap();
        let secret_value = &[0u8; 0];
        let associated_data = &[0u8; 0];
        let expected_hash =
			decode("9f555315bd086935c5a3830f907a02faf3e423f3cb8591b6a83c52ba20717ec5000eb3f2aeade0cd881443aa6292f4eedbc36d27e914ae1befe26820b6f9ceb3e71cbc8a58d8825511076d89d33054b8356aa063e499fd89557b75c68d7224c199").unwrap();

        let mut actual_hash = vec![0u8; expected_hash.len()];

        argon2i::derive_key(
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash,
        )
        .unwrap();
        assert_eq!(expected_hash, actual_hash);
        assert!(argon2i::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            Some(secret_value),
            Some(associated_data),
            &mut actual_hash
        )
        .is_ok());
    }
}
