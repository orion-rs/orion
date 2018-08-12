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
mod custom_test_vectors {

    extern crate hex;
    use self::hex::decode;
    use hazardous::pbkdf2::*;

    #[test]
    fn sha512_test_case_1() {
        let password = "password".as_bytes();
        let salt = "salt".as_bytes();
        let iter = 1;
        let mut dk_out = [0u8; 20];

        let expected_dk = decode("867f70cf1ade02cff3752599a3a53dc4af34c7a6").unwrap();

        // verify() also runs derive_key()
        assert!(verify(&expected_dk, password, salt, iter, &mut dk_out).unwrap());
    }

    #[test]
    fn sha512_test_case_2() {
        let password = "password".as_bytes();
        let salt = "salt".as_bytes();
        let iter = 2;
        let mut dk_out = [0u8; 20];

        let expected_dk = decode("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e").unwrap();

        // verify() also runs derive_key()
        assert!(verify(&expected_dk, password, salt, iter, &mut dk_out).unwrap());
    }

    #[test]
    fn sha512_test_case_3() {
        let password = "password".as_bytes();
        let salt = "salt".as_bytes();
        let iter = 4096;
        let mut dk_out = [0u8; 20];

        let expected_dk = decode("d197b1b33db0143e018b12f3d1d1479e6cdebdcc").unwrap();

        // verify() also runs derive_key()
        assert!(verify(&expected_dk, password, salt, iter, &mut dk_out).unwrap());
    }

    #[test]
    fn sha512_test_case_4() {
        let password = "passwordPASSWORDpassword".as_bytes();
        let salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes();
        let iter = 4096;
        let mut dk_out = [0u8; 25];

        let expected_dk = decode("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868").unwrap();

        // verify() also runs derive_key()
        assert!(verify(&expected_dk, password, salt, iter, &mut dk_out).unwrap());
    }

    #[test]
    fn sha512_test_case_5() {
        let password = "pass\0word".as_bytes();
        let salt = "sa\0lt".as_bytes();
        let iter = 4096;
        let mut dk_out = [0u8; 16];

        let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

        // verify() also runs derive_key()
        assert!(verify(&expected_dk, password, salt, iter, &mut dk_out).unwrap());
    }
}
