// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Testing against custom test vectors.
// These test vectors have been generated with the cryptography.io Python package.
// More information here: https://github.com/brycx/Test-Vector-Generation/

#[cfg(test)]
mod custom_hkdf {

    extern crate hex;
    use self::hex::decode;

    use kdf::hkdf_test_runner;

    #[test]
    fn test_case_1() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = decode("000102030405060708090a0b0c").unwrap();
        let info = decode("").unwrap();
        let mut okm = [0u8; 32];

        let expected_okm =
            decode("f81b87481a18b664936daeb222f58cba0ebc55f5c85996b9f1cb396c327b70bb").unwrap();

        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
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
        let mut okm = [0u8; 128];

        let expected_okm = decode(
            "a246ef99f6a0f783fc004682508e6f288f036469788f004fcbac9414caa889fa175e746ee663914d\
             678c155d510fa536f7d49b1054e85e7751d9745ea02079a78608eec9aacdd82fa9421d6223c158c71\
             b76bcf9008b50e8aac027a73f98643eb3947106b65c0bc9a2983404fd4d0fce0735d639379b193470\
             9c8b2999b5989e",
        )
        .unwrap();

        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
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
        let mut okm = [0u8; 256];

        let expected_okm = decode(
            "245d63179146a61ca1a25f92c38391d406bb52da4b773714fb0e43ce90\
             84ce430f43e1980a8817cf0af320fb684776d81f674d2b187449d62200d3e39cb51ab7a444f7964944895\
             ad36b37432fb400fdca0181a9ebda41f9d124d58f8a696dde9bd104a93fbbe3c93b94dd06a2254894b489\
             822ab08daa791f8962a492a6a7379e8710b46fe85c8bf9d64a957641164577d5b5afdaf8fad1fb3879a3c\
             8bc8425b9f265462b59785e7cf7855e6c571353c38907a8d9b0a01c228bb3a1792039e8728ea01c939160\
             1f1626da771f65f2322116ddc4e192d98da81b0402fd664ef89801a4905d9557be5c7f01bf8381fae7d32\
             5c3dc7a5795dc760b9668eb63f8ee",
        )
        .unwrap();

        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }

    #[test]
    fn test_case_4() {
        let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = "s$#$#%$#SBGHWE@#W#lt".as_bytes();
        let info = "random InF\0".as_bytes();
        let mut okm = [0u8; 256];

        let expected_okm = decode(
            "e93182a8af74a1e70a6202075759bbbceb1926a18aa9f9ee31796557\
             0b507cea7ef11f94d83760bb6f8a2f6031edb581c1ae43f45ead820223d34c6ffadab43d3cfaf9cd782\
             b8aa7bd2ebab8663b51d4e40b9a659a7e262630581fee55ac986770e88f580c8d8b82deba4d1c28bce4\
             dc7a579456ed30a94a1782cab84699a4302ef8d24f23e9122ef2daaba4fd3d84c812c4b3a8d4788397f\
             d38ddccf59d60a8330000cb04e5aa2d3e16e56dbccd8ca68020abcb3bc097788d38dfd2e241ba7772ba\
             188c29d7f4d010b421875c9e7165ed2ebcf338b81071eca62300c9ca9840b6f1fc9403752536b3eca14\
             7e9fbf127ff88d33b984582ced74fa029b50f441e",
        )
        .unwrap();
        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }

    #[test]
    fn test_case_5() {
        let ikm = "passwordPASSWORDpassword".as_bytes();
        let salt = "salt".as_bytes();
        let info = decode("").unwrap();
        let mut okm = [0u8; 32];

        let expected_okm =
            decode("1ef9dccc02d5786f0d7133da824afe212547f2d8c97e9299345db86814dcb9b8").unwrap();

        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
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
        let mut okm = [0u8; 16];

        let expected_okm = decode("8ae15623215eaaa156bad552f411c4ad").unwrap();

        assert!(hkdf_test_runner(
            None,
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }
}
