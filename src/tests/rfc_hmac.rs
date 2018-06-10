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





// Testing against RFC 4231 test vectors.

#[cfg(test)]
mod rfc4231 {

    extern crate hex;
    use self::hex::decode;
    use core::options::ShaVariantOption;
    use hmac::Hmac;

    fn hmac_test_runner(hmac: Hmac, expected: &[u8], trunc: Option<usize>, should_be: bool) -> bool {

        let (ipad, opad) = hmac.pad_key(&hmac.secret_key);

        let mut def_hmac = hmac.hmac_compute();
        let mut pbkdf2_hmac = hmac.pbkdf2_hmac(ipad, opad, &hmac.message);

        match trunc {
            Some(ref length) => {
                def_hmac.truncate(*length);
                pbkdf2_hmac.truncate(*length);
            }
            None => (),
        };

        // If the MACs are modified, this should panic
        assert_ne!(&def_hmac[..def_hmac.len()-1], expected);
        assert_ne!(&pbkdf2_hmac[..pbkdf2_hmac.len()-1], expected);

        should_be == ( (pbkdf2_hmac == expected) == (def_hmac == expected) )
    }

    #[test]
    fn test_case_1() {

        let hmac_256 = Hmac {
            secret_key: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            message: "Hi There".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            message: "Hi There".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            message: "Hi There".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
        let expected_hmac_384 = decode(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
            faea9ea9076ede7f4af152e8b2fa9cb6").unwrap();
        let expected_hmac_512 = decode(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
            daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }

    #[test]
    fn test_case_2() {

        let hmac_256 = Hmac {
            secret_key: "Jefe".as_bytes().to_vec(),
            message: "what do ya want for nothing?".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: "Jefe".as_bytes().to_vec(),
            message: "what do ya want for nothing?".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: "Jefe".as_bytes().to_vec(),
            message: "what do ya want for nothing?".as_bytes().to_vec(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();
        let expected_hmac_384 = decode(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
            8e2240ca5e69e2c78b3239ecfab21649").unwrap();
        let expected_hmac_512 = decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
            9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }

    #[test]
    fn test_case_3() {

        let hmac_256 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            message: decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
                  dddddddddddddddddddddddddddddddddddd").unwrap(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            message: decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
                  dddddddddddddddddddddddddddddddddddd").unwrap(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            message: decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
                  dddddddddddddddddddddddddddddddddddd").unwrap(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").unwrap();
        let expected_hmac_384 = decode(
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
            2a5ab39dc13814b94e3ab6e101a34f27").unwrap();
        let expected_hmac_512 = decode(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
            bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }

    #[test]
    fn test_case_4() {

        let hmac_256 = Hmac {
            secret_key: decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
            message: decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                  cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
            message: decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                  cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
            message: decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                  cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b").unwrap();
        let expected_hmac_384 = decode(
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
            6801dd23c4a7d679ccf8a386c674cffb").unwrap();
        let expected_hmac_512 = decode(
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
            a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }

    #[test]
    fn test_case_5() {

        let hmac_256 = Hmac {
            secret_key: decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
            message: decode("546573742057697468205472756e636174696f6e").unwrap(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
            message: decode("546573742057697468205472756e636174696f6e").unwrap(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
            message: decode("546573742057697468205472756e636174696f6e").unwrap(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "a3b6167473100ee06e0c796c2955552b").unwrap();
        let expected_hmac_384 = decode(
            "3abf34c3503b2a23a46efc619baef897").unwrap();
        let expected_hmac_512 = decode(
            "415fad6271580a531d4179bc891d87a6").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, Some(16), true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, Some(16), true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, Some(16), true));
    }

    #[test]
    fn test_case_6() {

        let hmac_256 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
                  65204b6579202d2048617368204b6579204669727374").unwrap(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
                  65204b6579202d2048617368204b6579204669727374").unwrap(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
                  65204b6579202d2048617368204b6579204669727374").unwrap(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54").unwrap();
        let expected_hmac_384 = decode(
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
            0c2ef6ab4030fe8296248df163f44952").unwrap();
        let expected_hmac_512 = decode(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
            6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }


    #[test]
    fn test_case_7() {

        let hmac_256 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("5468697320697320612074657374207573696e672061206c6172676572207468\
                  616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
                  68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
                  647320746f20626520686173686564206265666f7265206265696e6720757365\
                  642062792074686520484d414320616c676f726974686d2e").unwrap(),
            sha2: ShaVariantOption::SHA256
        };
        let hmac_384 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("5468697320697320612074657374207573696e672061206c6172676572207468\
                  616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
                  68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
                  647320746f20626520686173686564206265666f7265206265696e6720757365\
                  642062792074686520484d414320616c676f726974686d2e").unwrap(),
            sha2: ShaVariantOption::SHA384
        };
        let hmac_512 = Hmac {
            secret_key: decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa").unwrap(),
            message: decode("5468697320697320612074657374207573696e672061206c6172676572207468\
                  616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
                  68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
                  647320746f20626520686173686564206265666f7265206265696e6720757365\
                  642062792074686520484d414320616c676f726974686d2e").unwrap(),
            sha2: ShaVariantOption::SHA512
        };

        let expected_hmac_256 = decode(
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2").unwrap();
        let expected_hmac_384 = decode(
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
            a678cc31e799176d3860e6110c46523e").unwrap();
        let expected_hmac_512 = decode(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
            b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58").unwrap();

        assert!(hmac_test_runner(hmac_256, &expected_hmac_256, None, true));
        assert!(hmac_test_runner(hmac_384, &expected_hmac_384, None, true));
        assert!(hmac_test_runner(hmac_512, &expected_hmac_512, None, true));
    }
}
