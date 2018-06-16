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





// Testing against RFC 5869 test vectors.

#[cfg(test)]
mod rfc5869 {

    extern crate hex;
    use self::hex::decode;
    use hkdf::Hkdf;
    use core::options::ShaVariantOption;

    #[test]
    fn test_case_1() {

        let hkdf_256 = Hkdf {
            salt: decode("000102030405060708090a0b0c").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
            length: 42,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_prk = decode(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();

        let expected_okm = decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
            34007208d5b887185865").unwrap();

        let actual_prk = hkdf_256.extract(&hkdf_256.salt, &hkdf_256.ikm);

        assert_eq!(actual_prk, expected_prk);
        assert_eq!(hkdf_256.expand(&actual_prk).unwrap(), expected_okm);
        assert_eq!(hkdf_256.derive_key().unwrap(), expected_okm);
    }

    #[test]
    fn test_case_2() {

        let hkdf_256 = Hkdf {
            salt: decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap(),
            ikm: decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                404142434445464748494a4b4c4d4e4f").unwrap(),
            info: decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap(),
            length: 82,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_prk = decode(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();

        let expected_okm = decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
            59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
            cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();

        let actual_prk = hkdf_256.extract(&hkdf_256.salt, &hkdf_256.ikm);

        assert_eq!(actual_prk, expected_prk);
        assert_eq!(hkdf_256.expand(&actual_prk).unwrap(), expected_okm);
        assert_eq!(hkdf_256.derive_key().unwrap(), expected_okm);
    }

    #[test]
    fn test_case_3() {

        let hkdf_256 = Hkdf {
            salt: decode("").unwrap(),
            ikm: decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            info: decode("").unwrap(),
            length: 42,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_prk = decode(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();

        let expected_okm = decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
            9d201395faa4b61a96c8").unwrap();

        let actual_prk = hkdf_256.extract(&hkdf_256.salt, &hkdf_256.ikm);

        assert_eq!(actual_prk, expected_prk);
        assert_eq!(hkdf_256.expand(&actual_prk).unwrap(), expected_okm);
        assert_eq!(hkdf_256.derive_key().unwrap(), expected_okm);
    }
}
