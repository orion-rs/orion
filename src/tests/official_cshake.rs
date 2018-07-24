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


/// Testing against official test vectors from the [KeccakCodePackage](https://github.com/gvanas/KeccakCodePackage/blob/master/tests/UnitTests/testSP800-185.c)

#[cfg(test)]
mod kcp_test_vectors {

    use core::options::*;
    use hazardous::cshake::CShake;

    #[test]
    fn cshake128_test_case_1() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 32,
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        let expected = b"\xC1\xC3\x69\x25\xB6\x40\x9A\x04\xF1\xB5\x04\xFC\xBC\xA9\xD8\x2B\x40\x17\
                        \x27\x7C\xB5\xED\x2B\x20\x65\xFC\x1D\x38\x14\xD5\xAA\xF5"
            .to_vec();

        assert_eq!(expected.len(), cshake.finalize().unwrap().len());
        assert_eq!(cshake.finalize().unwrap(), expected);
    }

    #[test]
    fn cshake_128_test_case_2() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\
                    \x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\
                    \x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\
                    \x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\
                    \x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\
                    \x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\
                    \x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\
                    \x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\
                    \x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\
                    \xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\
                    \xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7"
                .to_vec(),
            length: 32,
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE128,
        };

        let expected = b"\xC5\x22\x1D\x50\xE4\xF8\x22\xD9\x6A\x2E\x88\x81\xA9\x61\x42\x0F\x29\x4B\
                        \x7B\x24\xFE\x3D\x20\x94\xBA\xED\x2C\x65\x24\xCC\x16\x6B"
            .to_vec();

        assert_eq!(expected.len(), cshake.finalize().unwrap().len());
        assert_eq!(cshake.finalize().unwrap(), expected);
    }

    #[test]
    fn cshake_256_test_case_1() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03".to_vec(),
            length: 64,
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE256,
        };

        let expected = b"\xD0\x08\x82\x8E\x2B\x80\xAC\x9D\x22\x18\xFF\xEE\x1D\x07\x0C\x48\xB8\
                        \xE4\xC8\x7B\xFF\x32\xC9\x69\x9D\x5B\x68\x96\xEE\xE0\xED\xD1\x64\x02\
                        \x0E\x2B\xE0\x56\x08\x58\xD9\xC0\x0C\x03\x7E\x34\xA9\x69\x37\xC5\x61\
                        \xA7\x4C\x41\x2B\xB4\xC7\x46\x46\x95\x27\x28\x1C\x8C"
            .to_vec();

        assert_eq!(expected.len(), cshake.finalize().unwrap().len());
        assert_eq!(cshake.finalize().unwrap(), expected);
    }

    #[test]
    fn cshake_256_test_case_2() {
        let cshake = CShake {
            input: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\
                    \x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\
                    \x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\
                    \x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\
                    \x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\
                    \x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\
                    \x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\
                    \x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\
                    \x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\
                    \xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\
                    \xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7"
                .to_vec(),
            length: 64,
            name: b"".to_vec(),
            custom: b"Email Signature".to_vec(),
            cshake: CShakeVariantOption::CSHAKE256,
        };

        let expected = b"\x07\xDC\x27\xB1\x1E\x51\xFB\xAC\x75\xBC\x7B\x3C\x1D\x98\x3E\x8B\x4B\x85\
                        \xFB\x1D\xEF\xAF\x21\x89\x12\xAC\x86\x43\x02\x73\x09\x17\x27\xF4\x2B\x17\
                        \xED\x1D\xF6\x3E\x8E\xC1\x18\xF0\x4B\x23\x63\x3C\x1D\xFB\x15\x74\xC8\xFB\
                        \x55\xCB\x45\xDA\x8E\x25\xAF\xB0\x92\xBB"
            .to_vec();

        assert_eq!(expected.len(), cshake.finalize().unwrap().len());
        assert_eq!(cshake.finalize().unwrap(), expected);
    }
}
