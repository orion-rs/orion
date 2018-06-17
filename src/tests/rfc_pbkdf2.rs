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

// Testing against RFC 7914 test vectors
#[cfg(test)]
mod rfc7914 {

    extern crate hex;
    use self::hex::decode;
    use core::options::ShaVariantOption;
    use hazardous::pbkdf2::Pbkdf2;

    #[test]
    fn rfc7914_test_case_1() {
        let dk = Pbkdf2 {
            password: "passwd".as_bytes().to_vec(),
            salt: "salt".as_bytes().to_vec(),
            iterations: 1,
            dklen: 64,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_dk = decode(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ).unwrap();

        assert_eq!(expected_dk, dk.derive_key().unwrap());
    }

    #[test]
    fn rfc7914_test_case_2() {
        let dk = Pbkdf2 {
            password: "Password".as_bytes().to_vec(),
            salt: "NaCl".as_bytes().to_vec(),
            iterations: 80000,
            dklen: 64,
            hmac: ShaVariantOption::SHA256,
        };

        let expected_dk = decode(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
             a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ).unwrap();

        assert_eq!(expected_dk, dk.derive_key().unwrap());
    }
}
