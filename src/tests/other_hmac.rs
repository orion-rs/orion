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

// Testing against [IETF Draft](https://tools.ietf.org/html/draft-ietf-ipsec-ciph-sha-256-01) test vectors
#[cfg(test)]
mod ietf_draft {

    extern crate hex;
    use self::hex::decode;
    use core::options::ShaVariantOption;
    use hazardous::hmac::*;

    fn hmac_test_runner(
        secret_key: &[u8],
        data: &[u8],
        sha2: ShaVariantOption,
        expected: &[u8],
        trunc: Option<usize>,
        should_be: bool,
    ) -> bool {
        let mac = Hmac {
            secret_key: secret_key.to_vec(),
            data: data.to_vec(),
            sha2,
        };

        let (ipad, opad) = mac.pad_key(&mac.secret_key);

        let mut def_hmac = mac.finalize();
        let mut pbkdf2_hmac = pbkdf2_hmac(&ipad, &opad, &mac.data, mac.sha2);

        match trunc {
            Some(ref length) => {
                def_hmac.truncate(*length);
                pbkdf2_hmac.truncate(*length);
            }
            None => (),
        };

        // If the MACs are modified, then they should not be equal to the expected
        assert_ne!(&def_hmac[..def_hmac.len() - 1], expected);
        assert_ne!(&pbkdf2_hmac[..pbkdf2_hmac.len() - 1], expected);

        should_be == ((pbkdf2_hmac == expected) == (def_hmac == expected))
    }

    #[test]
    fn test_case_1() {
        let secret_key = decode(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1\
             c1d1e1f20",
        ).unwrap();
        let data = "abc".as_bytes().to_vec();

        let expected_hmac_256 =
            decode("a21b1f5d4cf4f73a4dd939750f7a066a7f98cc131cb16a6692759021cfab8181").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_2() {
        let secret_key = decode(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1\
             c1d1e1f20",
        ).unwrap();
        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("104fdc1257328f08184ba73131c53caee698e36119421149ea8c712456697d30").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_3() {
        let secret_key = decode(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1\
             c1d1e1f20",
        ).unwrap();
        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdef\
                    defgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("470305fc7e40fe34d3eeb3e773d95aab73acf0fd060447a5eb4595bf33a9d1a3").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_4() {
        let secret_key = decode(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
             0b0b0b0b0b0b",
        ).unwrap();
        let data = "Hi There".as_bytes().to_vec();

        let expected_hmac_256 =
            decode("198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_5() {
        let secret_key = "Jefe".as_bytes().to_vec();
        let data = "what do ya want for nothing?".as_bytes().to_vec();

        let expected_hmac_256 =
            decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_6() {
        let secret_key = decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaa",
        ).unwrap();
        let data = "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
                    ddddddddddddddddddddddddddddddddd"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_7() {
        let secret_key = decode(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\
                2122232425",
        ).unwrap();
        let data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("d4633c17f6fb8d744c66dee0f8f074556ec4af55ef07998541468eb49bd2e917").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_8() {
        let secret_key = decode(
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0\
             c0c0c0c0c0c0c",
        ).unwrap();
        let data = "Test With Truncation".as_bytes().to_vec();

        let expected_hmac_256 =
            decode("7546af01841fc09b1ab9c3749a5f1c17d4f589668a587b2700a9c97c1193cf42").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_9() {
        let secret_key = decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ).unwrap();
        let data = "Test Using Larger Than Block-Size Key - Hash Key First"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }

    #[test]
    fn test_case_10() {
        let secret_key = decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ).unwrap();
        let data = "Test Using Larger Than Block-Size Key and Larger Than One \
                    Block-Size Data"
            .as_bytes()
            .to_vec();

        let expected_hmac_256 =
            decode("6355ac22e890d0a3c8481a5ca4825bc884d3e7a1ff98a2fc2ac7d8e064c3b2e6").unwrap();

        assert!(hmac_test_runner(
            &secret_key,
            &data,
            ShaVariantOption::SHA256,
            &expected_hmac_256,
            None,
            true
        ));
    }
}
