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


#[cfg(test)]
mod nonofficial_test_vectors {

    extern crate hex;
    use self::hex::decode;
    use hazardous::cshake::CShake;
    use core::options::*;

    #[test]
    fn test_result() {

        let cshake = CShake {
            input: "message".as_bytes().to_vec(),
            length: 32_usize,
            n: "".as_bytes().to_vec(),
            s: "custom".as_bytes().to_vec(),
            cshake: CShakeVariantOption::CSHAKE128
        };

        let expected = decode("db006103bb064f875a6695cd7f636d184d7cdabdbc61b553cade47f1d4b29ab3").unwrap();

        assert_eq!(cshake.finalize().unwrap(), expected);

    }
}
