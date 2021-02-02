// Testing against custom test vectors.
// These test vectors have been generated with the cryptography.io Python
// package. More information here: https://github.com/brycx/Test-Vector-Generation/

#[cfg(test)]
mod custom_hkdf {

    use crate::kdf;
    use hex::decode;

    #[test]
    fn test_case_1() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = decode("000102030405060708090a0b0c").unwrap();
        let info = decode("").unwrap();
        let expected_okm_256 =
            decode("b2a3d45126d31fb6828ef00d76c6d54e9c2bd4785e49c6ad86e327d89d0de940").unwrap();
        let expected_okm_384 =
            decode("0a8c436c47640798993780b9e4ef9044fe307889e84bdd401a33a7abdb6d5c36").unwrap();
        let expected_okm_512 =
            decode("f81b87481a18b664936daeb222f58cba0ebc55f5c85996b9f1cb396c327b70bb").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }

    #[test]
    fn test_case_2() {
        let ikm = decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2\
             02122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849\
             4a4b4c4d4e4f",
        )
        .unwrap();
        let salt = "salt".as_bytes();
        let info = "random InF\0".as_bytes();
        let expected_okm_256 =
            decode("ce6878ed2512bdb79282ff9795f091a78ba3434363ec7f7f4a2eb64265c8d6bc57deb3fcae070034ccdf25f8ac2da166c45822053c5de630c5aa76e7529e9ce728ab6d09bbb1af359d38f073da4da0c409028db6d310abf706121c37f386d1c7eb961feaf921449dc36214dc2e2b6f280170d8d2a7c5228d500c22aab56fda62").unwrap();
        let expected_okm_384 =
            decode("1dbf9c75566141f6824f637f6e57bddc465de04cce5809f081edd6b240b36f39d58590bc1354a7aa0286cce31d2cd8c26b88ede6a7f4466a7f5984667fe2c17a1cd1e38fabf3849424982f93730bfacb6a9812efe1ba0b67c399f0b06f4917ad5eb98545fa8c8b5d3472c5c6b0d72e9e546af07b1c7d7be7a231ffb11f2f1b34").unwrap();
        let expected_okm_512 =
            decode("a246ef99f6a0f783fc004682508e6f288f036469788f004fcbac9414caa889fa175e746ee663914d678c155d510fa536f7d49b1054e85e7751d9745ea02079a78608eec9aacdd82fa9421d6223c158c71b76bcf9008b50e8aac027a73f98643eb3947106b65c0bc9a2983404fd4d0fce0735d639379b1934709c8b2999b5989e").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }

    #[test]
    fn test_case_3() {
        let ikm = "password".as_bytes();
        let salt = decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7\
             f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a\
             8a9aaabacadaeaf",
        )
        .unwrap();
        let info = decode("").unwrap();
        let expected_okm_256 =
            decode("debf25481a437e4b11c7fb01ea15b33c6a024ad61e6e1d7d70d12ed9aa0fb8d769e222d8545dc1a635b7ff3a910f9d6faaf67c233804a261c2eaed1c583c3d3cf65070d74e853bb0c1c18434f41479feb54e14e0188d48c4e9ac26a96a8aa5ee1c76273adbb4b29ece749f5ebb8ffa6b14eccb3649a22022e63db73f349eed72b9ac05b2f281c8fa3b94411bdf0b30c0bc0a2dbe8957fe9ca63f4721d789bd5b2ac22ddab78dd5d73c06071cec56c71b0d8d289f0b96aa8742b8a0a0d4f2e832dc5e5b20671877937f48268302ef781bbdda741fd7d5eb4f6777b0b5e786e851df0abbb3313919de33a399c333c969473a597827c21fc431094566847621feda").unwrap();
        let expected_okm_384 =
            decode("85734e6f8fb715523d077f8b25cd43cadb10cd67fb2af78fc18fcfe4361ccd0b720f8a96a467dc560447aec8ed12ca1df800b70f2811cb9499028c689223174643555901299af45a29be532a6a92a76b0c2e42adfec56f5dcf1455ef1d6ee05a4c8a3ee7e302b06d68998c64aa662cebeeca087bc563586aeb62d9c720d9b1a4a7ea21f59452a304d5532030ed7d5be1729697212104f110a66b156a1d3a1e8d3a914bdd19ac56b041e3acf5051abf8c93e3aa2e07c69e56f1408e90f321e85e8d3cc7320e9a30f20fde504746b96424cc4931e8bbec1fcb0a95ff68e1ad2d7563987ed6e6b4a95dbee37fa0b67923adad53ee0a8cf3641a29ac2cbf555d825e").unwrap();
        let expected_okm_512 =
            decode("245d63179146a61ca1a25f92c38391d406bb52da4b773714fb0e43ce9084ce430f43e1980a8817cf0af320fb684776d81f674d2b187449d62200d3e39cb51ab7a444f7964944895ad36b37432fb400fdca0181a9ebda41f9d124d58f8a696dde9bd104a93fbbe3c93b94dd06a2254894b489822ab08daa791f8962a492a6a7379e8710b46fe85c8bf9d64a957641164577d5b5afdaf8fad1fb3879a3c8bc8425b9f265462b59785e7cf7855e6c571353c38907a8d9b0a01c228bb3a1792039e8728ea01c9391601f1626da771f65f2322116ddc4e192d98da81b0402fd664ef89801a4905d9557be5c7f01bf8381fae7d325c3dc7a5795dc760b9668eb63f8ee").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }

    #[test]
    fn test_case_4() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = "s$#$#%$#SBGHWE@#W#lt".as_bytes();
        let info = "random InF\0".as_bytes();
        let expected_okm_256 =
            decode("dae56c32147f77c16acfbf7924d862f6a665b2bdb261c6f24f28c9d29749f0ddf1304ba32275a404e26bdae66c223f6c6c55ac7bb0bc6f95dec0840313cc4b2d525387ff7b2b765b745fbce9dcb5aae3ce3b8b6cff224c34fa1fb246361bcba9a621eb07b9317e116e2c2a5504d2d406c89777f9f8bdffca591fca43ecf517b93c49471003128495e985ec88c8b61a7560c503db1365e491b1a6132e56605eea7809dffff7f13052a0b6c9044dc64ec289a3b8169304e74fa623e0902f94d546cca95884c02ebcfd507fb8229c091cbb7d4b76f26048dd2b33e0b131bbd34af8c7722bcce9be5b47e2401adf7f451e65913f370d005d710236e29dcce3d1edd5").unwrap();
        let expected_okm_384 =
            decode("636668c99a9ffb025ae1201f3c429f8d2e0f69f57990cc9d92c34505a3b9af4c4bcc84bf7dbfd2bc08fe2d0c8f7a412909a200cccbd3515d93d26aaa9cc393aeaf9d49c891ca9af6be5e755d225d4cffd8469d13d8cc8a86998a7a56f4e30ddcff345f9412eb9900bf452cd8de8b557a4d82c7d92863e0b2ce879775fdd60e57349e0b1d6ec08aa22b67bb5d68b2a946247d8cf4bc26b5b4ba5502fb7e880bc863ca9f60710b9f279cb9b4c37c336b319e26c7d9466d12fb4cd461974c606d6bf6db948551f15b8847d0bcf712c6f592a2c4b901bb95b6c1a2394b8b7e16412695a35754c3fb82aefadb1bf35dfedc73b31ae5f08af9fb5f68683df8664c340c").unwrap();
        let expected_okm_512 =
            decode("e93182a8af74a1e70a6202075759bbbceb1926a18aa9f9ee317965570b507cea7ef11f94d83760bb6f8a2f6031edb581c1ae43f45ead820223d34c6ffadab43d3cfaf9cd782b8aa7bd2ebab8663b51d4e40b9a659a7e262630581fee55ac986770e88f580c8d8b82deba4d1c28bce4dc7a579456ed30a94a1782cab84699a4302ef8d24f23e9122ef2daaba4fd3d84c812c4b3a8d4788397fd38ddccf59d60a8330000cb04e5aa2d3e16e56dbccd8ca68020abcb3bc097788d38dfd2e241ba7772ba188c29d7f4d010b421875c9e7165ed2ebcf338b81071eca62300c9ca9840b6f1fc9403752536b3eca147e9fbf127ff88d33b984582ced74fa029b50f441e").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }

    #[test]
    fn test_case_5() {
        let ikm = "passwordPASSWORDpassword".as_bytes();
        let salt = "salt".as_bytes();
        let info = decode("").unwrap();
        let expected_okm_256 =
            decode("573b98885355e49f23dacdcaf549f0edfdf366a32444485b28153c7f464c8f46").unwrap();
        let expected_okm_384 =
            decode("3c58b0271ffd73b3b4347e5ebd3220083296bad2ac3294f72b14fe1b52754b27").unwrap();
        let expected_okm_512 =
            decode("1ef9dccc02d5786f0d7133da824afe212547f2d8c97e9299345db86814dcb9b8").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }

    #[test]
    fn test_case_6() {
        let ikm = "pass\0word".as_bytes();
        let salt = "saltSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALTSALT".as_bytes();
        let info = decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbccc\
             dcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f\
             3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let expected_okm_256 = decode("71505363b1096f544ec9e40e361963dd").unwrap();
        let expected_okm_384 = decode("851ff840cd77e4549736a7ec0ed8869f").unwrap();
        let expected_okm_512 = decode("8ae15623215eaaa156bad552f411c4ad").unwrap();

        kdf::hkdf256_test_runner(
            None,
            &expected_okm_256,
            &salt,
            &ikm,
            &info,
            expected_okm_256.len(),
            true,
        );
        kdf::hkdf384_test_runner(
            None,
            &expected_okm_384,
            &salt,
            &ikm,
            &info,
            expected_okm_384.len(),
            true,
        );
        kdf::hkdf512_test_runner(
            None,
            &expected_okm_512,
            &salt,
            &ikm,
            &info,
            expected_okm_512.len(),
            true,
        );
    }
}
