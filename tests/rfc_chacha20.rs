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

// Testing against RFC 8439 test vectors
#[cfg(test)]
mod rfc8439_chacha20 {

    extern crate hex;
    extern crate orion;
    extern crate std;

    use self::hex::decode;
    use self::orion::hazardous::chacha20::{decrypt, encrypt};

    fn test_runner(key: &[u8], nonce: &[u8], init_block_count: u32, pt: &mut [u8], ct: &mut [u8]) {
        let original_pt = pt.to_vec();
        let original_ct = ct.to_vec();

        encrypt(&key, &nonce, init_block_count, &original_pt, ct).unwrap();
        decrypt(&key, &nonce, init_block_count, &original_ct, pt).unwrap();
        assert!(&original_pt == &pt);
        assert!(&original_ct == &ct);
    }

    #[test]
    fn chacha20_encryption_test_0() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut expected = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut plaintext =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip \
             for the future, sunscreen would be it."
                .as_bytes()
                .to_vec();

        test_runner(&key, &nonce, 1, &mut plaintext, &mut expected);
    }

    #[test]
    // From https://github.com/pyca/cryptography/blob/master/vectors/cryptography_vectors/ciphers/ChaCha20/rfc7539.txt
    fn chacha20_encryption_test_1() {
        let key =
            decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let nonce = decode("000000000000000000000000").unwrap();
        let mut plaintext = decode(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000",
        ).unwrap();
        let mut expected = decode(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d\
             7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ).unwrap();

        test_runner(&key, &nonce, 0, &mut plaintext, &mut expected);
    }

    #[test]
    // From https://github.com/pyca/cryptography/blob/master/vectors/cryptography_vectors/ciphers/ChaCha20/rfc7539.txt
    fn chacha20_encryption_test_2() {
        let key =
            decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let nonce = decode("000000000000000000000002").unwrap();
        let mut plaintext = decode(
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e64656420627920\
             74686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070\
             617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e\
             792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e2049\
             45544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e74726962\
             7574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d\
             656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e2061\
             6e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e79207469\
             6d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        ).unwrap();
        let mut expected = decode(
            "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd37229\
             15c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6\
             e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87\
             bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c91\
             39ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca32\
             8b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b0\
             4b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36f\
             f216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982\
             ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
        ).unwrap();

        test_runner(&key, &nonce, 1, &mut plaintext, &mut expected);
    }

    #[test]
    // From https://github.com/pyca/cryptography/blob/master/vectors/cryptography_vectors/ciphers/ChaCha20/rfc7539.txt
    fn chacha20_encryption_test_3() {
        let key =
            decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0").unwrap();
        let nonce = decode("000000000000000000000002").unwrap();
        let mut plaintext =
        decode("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a44696420\
        6779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d7379207765726520\
        74686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e")
        .unwrap();
        let mut expected =
        decode("62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf\
        9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532\
        055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
        ).unwrap();

        test_runner(&key, &nonce, 42, &mut plaintext, &mut expected);
    }
}
