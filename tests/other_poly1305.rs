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

// Testing against OpenSSL test vector obtained from [ring](https://github.com/briansmith/ring/blob/master/src/poly1305_test.txt).
#[cfg(test)]
mod other_poly1305 {

    extern crate hex;
    extern crate orion;
    extern crate ring;

    use self::hex::decode;
    use self::orion::hazardous::poly1305;
    use self::ring::{error, test};

    fn poly1305_test_runner(
        key: &[u8],
        input: &[u8],
        output: &[u8],
        is_ok: bool,
    ) -> Result<(), error::Unspecified> {
        let mut state = poly1305::init(key).unwrap();
        state.update(input).unwrap();

        let tag = state.finalize().unwrap();

        assert_eq!(is_ok, tag.as_ref() == output.as_ref());

        // To conform with the Result construction of compare functions
        match is_ok {
            true => {
                assert!(poly1305::verify(output, key, input).unwrap());
            }
            false => {
                assert!(poly1305::verify(output, key, input).is_err());
            }
        }

        Ok(())
    }

    #[test]
    fn openssl_from_ring() {
        test::from_file("tests/test_data/Poly1305_ring_openssl.rsp", |section, test_case| {
            assert_eq!(section, "");
            let key_value = test_case.consume_bytes("Key");
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("MAC");

            poly1305_test_runner(&key_value[..], &input[..], &output[..16], true)
        });
    }

    // Only test vectors from Monocypher where the input is not empty are tested
    // as orion does not allow empty input on .update()
    // https://github.com/LoupVaillant/Monocypher/blob/master/tests/vectors/poly1305
    #[test]
    fn monocypher_test_5() {
        let key =
            decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let expected = decode("00000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_6() {
        let key =
            decode("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e").unwrap();
        let message = decode("416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f").unwrap();
        let expected = decode("36e5f6b5c5e06070f0efca96227a863e").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_7() {
        let key =
            decode("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000").unwrap();
        let message = decode("416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f").unwrap();
        let expected = decode("f3477e7cd95417af89a6b8794c310cf0").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_8() {
        let key =
            decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0").unwrap();
        let message = decode("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e").unwrap();
        let expected = decode("4541669a7eaaee61e708dc7cbcc5eb62").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_9() {
        let key =
            decode("0200000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let expected = decode("03000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_10() {
        let key =
            decode("02000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let message = decode("02000000000000000000000000000000").unwrap();
        let expected = decode("03000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_11() {
        let key =
            decode("0100000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11000000000000000000000000000000").unwrap();
        let expected = decode("05000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_12() {
        let key =
            decode("0100000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101").unwrap();
        let expected = decode("00000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_13() {
        let key =
            decode("0200000000000000000000000000000000000000000000000000000000000000").unwrap();
        let message = decode("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        let expected = decode("FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_14() {
        let key =
            decode("0100000000000000040000000000000000000000000000000000000000000000").unwrap();
        let message = decode("E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000").unwrap();
        let expected = decode("14000000000000005500000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_15() {
        let key =
            decode("0100000000000000040000000000000000000000000000000000000000000000").unwrap();
        let message = decode("E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000").unwrap();
        let expected = decode("13000000000000000000000000000000").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }

    #[test]
    fn monocypher_test_16() {
        let key =
            decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let message =
            decode("43727970746f6772617068696320466f72756d2052657365617263682047726f7570").unwrap();
        let expected = decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();

        poly1305_test_runner(&key[..32], &message[..], &expected[..16], true).unwrap();
    }
}
