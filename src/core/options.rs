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

use sha2;
use sha2::Digest;

#[derive(Clone, Copy)]
/// SHA2 options and hashing.
pub enum ShaVariantOption {
    SHA256,
    SHA384,
    SHA512,
    SHA512Trunc256,
}

impl ShaVariantOption {
    /// Return the output size in bytes.
    pub fn output_size(self) -> usize {
        match self {
            ShaVariantOption::SHA256 => 32,
            ShaVariantOption::SHA384 => 48,
            ShaVariantOption::SHA512 => 64,
            ShaVariantOption::SHA512Trunc256 => 32,
        }
    }

    /// Return blocksize in bytes, matching SHA2 variant.
    pub fn blocksize(self) -> usize {
        match self {
            ShaVariantOption::SHA256 => 64,
            ShaVariantOption::SHA384 => 128,
            ShaVariantOption::SHA512 => 128,
            ShaVariantOption::SHA512Trunc256 => 128,
        }
    }

    /// Return a SHA2 digest of a given byte slice.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            ShaVariantOption::SHA256 => {
                let mut hash = sha2::Sha256::default();
                hash.input(data);
                hash.result().to_vec()
            }
            ShaVariantOption::SHA384 => {
                let mut hash = sha2::Sha384::default();
                hash.input(data);
                hash.result().to_vec()
            }
            ShaVariantOption::SHA512 => {
                let mut hash = sha2::Sha512::default();
                hash.input(data);
                hash.result().to_vec()
            },
            ShaVariantOption::SHA512Trunc256 => {
                let mut hash = sha2::Sha512Trunc256::default();
                hash.input(data);
                hash.result().to_vec()
            },
        }
    }
}

#[cfg(test)]
mod test {
    use core::options::ShaVariantOption;
    extern crate hex;
    use self::hex::decode;

    // These test cases are some picks from
    // the [NIST SHAVS](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs)
    #[test]
    fn shavs_256() {
        let msg = decode("889468b1").unwrap();
        let expected_md = decode(
            "855b2244b875ed9ae089fb10d84c85257f30c65ea1325c2f\
             76727a582ba4c801",
        ).unwrap();
        let actual_md = ShaVariantOption::SHA256.hash(&msg);

        assert_eq!(expected_md, actual_md);
    }

    #[test]
    fn shavs_384() {
        let msg = decode("15247149").unwrap();
        let expected_md = decode(
            "f1f2164a41471741d30ef3408be496e3f7903b2c005b57e9\
             d707cee8ab50777d4ddfc9348ad2aba7cca92fca3b7108e6",
        ).unwrap();
        let actual_md = ShaVariantOption::SHA384.hash(&msg);

        assert_eq!(expected_md, actual_md);
    }

    #[test]
    fn shavs_512() {
        let msg = decode("012c461b").unwrap();
        let expected_md = decode(
            "4a49e900d69c87a95d1a3fefabe9dc767fd0d70d866f85ef05453\
             7bb8f0a4224313590fee49fd65b76f4ea414ed457f0a12a52455570\
             717cbb051ca2af23ca20",
        ).unwrap();
        let actual_md = ShaVariantOption::SHA512.hash(&msg);

        assert_eq!(expected_md, actual_md);
    }

    #[test]
    fn shavs_512_trunc_256() {
        let msg = decode("63d8cfd72768c44920d7b015460489ad578c063be19053889cb809").unwrap();
        let expected_md = decode(
            "876e59c8a64faf9d665f7cde5d42fbb331ba818ddcd284491ac51ed50e1613be",
        ).unwrap();
        let actual_md = ShaVariantOption::SHA512Trunc256.hash(&msg);

        assert_eq!(expected_md, actual_md);
    }
}
