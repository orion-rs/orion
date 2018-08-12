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
    use hazardous::hkdf::*;

    fn hkdf_test_runner(
        excp_okm: &[u8],
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm_out: &mut [u8],
    ) -> bool {
        let actual_prk = extract(&salt, &ikm);

        expand(&actual_prk, &info, okm_out).unwrap();

        (okm_out == excp_okm)
    }

    #[test]
    fn test_case_1() {
        let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".as_bytes();
        let salt = "000102030405060708090a0b0c".as_bytes();
        let info = decode("").unwrap();
        let mut okm = [0u8; 32];

        let expected_okm =
            decode("55f4e219c32e613b33c637e4795379e886c8babb53cfbb9b8fa201fc7fdf604a").unwrap();

        assert!(hkdf_test_runner(
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }

    #[test]
    fn test_case_2() {
        let ikm = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2\
             02122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849\
             4a4b4c4d4e4f".as_bytes();
        let salt = "salt".as_bytes();
        let info = "random InF\0".as_bytes();
        let mut okm = [0u8; 128];

        let expected_okm = decode(
            "56b03ea00ca8ef5bf639027ae10af7c0392f619a63b40cf61f305505f4e2c039df6e1baae41\
             f0f8545bba840afe297d8da514b03892233076ad0a38a5215d21c37757bb753c60cc03b2b71b\
             b4cad3fced96a9038b4b4369c9863879dd2e17d0c84d889e07f57a4502e2137b042a0e913974f\
             adbee53ff94a5bdae6aaae333766",
        ).unwrap();

        assert!(hkdf_test_runner(
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
        let salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7\
             f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a\
             8a9aaabacadaeaf".as_bytes();
        let info = decode("").unwrap();
        let mut okm = [0u8; 256];

        let expected_okm = decode(
            "b59f1a1f19a28aa1401bb5c3b8a6fded08d39ee15ae4101687585116fca3bd63ab64b9ba83f9\
             675cfe97e7012a9b7fbce263c2b9c952ab07891d7cf4110846424f74a74c15a37d2124ee5962e\
             94f5a00af64cdfdf59afc58af18dc43652860b4502770a8fd6997ed130546624ed26b75c8c7799\
             54e8ba286a324e9cdad8babaf609ef12c84f3d7351a391bce365839a20ebf59e23dc22854d73c\
             8386536c36261f67410309178097e40d46fe62bfe24d7e71c1a1bf854e62f8300d24c72137067b\
             d63e401606c5ece5fa31fba62bd3fc05d1906672c5b12605bd12ab8b2c3e216437d32973890d5\
             1f9d713cc11ddbd40ef32fda2d581c4ac3f9ba8bdc823bdbe",
        ).unwrap();

        assert!(hkdf_test_runner(
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }

    #[test]
    fn test_case_4() {
        let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".as_bytes();
        let salt = "s$#$#%$#SBGHWE@#W#lt".as_bytes();
        let info = "random InF\0".as_bytes();
        let mut okm = [0u8; 256];

        let expected_okm = decode(
            "2033ff164f1c52fff45984131a8e791da83f41b681d33f254cbd9fdc2e376f485ef07a5132a\
            461a43efa454439b75dc270177a9871b4ceccc1c4d354d89a8e22ca4362839e55576088f3a3d\
            b677b3c7c2841f1f49bd646519020a0ac868390d52d3c96497c125bcf5a7083ad10422ec0b8f\
            9a0c3f9d8eaa049173a67282d8393fdd8f24d78bb458b02eba60137c445f456c6e1922b8db02\
            706efee900f5aa4b49cf407f8ac85297a09c29e2a16ef3a02da90ce8268a150cfa1e5325926f\
            0bdefae6dabea86af6401d67c3c9a62e21db7ade26641628301d321f6d000034eae6e570321b\
            bb8eb2a36bd954b7c39dcb950b1bf55e1b3deffc06855f77513950d03"
        ).unwrap();
        assert!(hkdf_test_runner(
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
        let info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbccc\
             dcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f\
             3f4f5f6f7f8f9fafbfcfdfeff".as_bytes();
        let mut okm = [0u8; 16];

        let expected_okm = decode("ae4107effdae85d156832ec28e6e84e6").unwrap();

        assert!(hkdf_test_runner(
            &expected_okm,
            &salt,
            &ikm,
            &info,
            &mut okm
        ));
    }
}
