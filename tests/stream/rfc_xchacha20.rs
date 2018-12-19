// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Testing against https://github.com/bikeshedders/xchacha-rfc/blob/master/draft-arciszewski-xchacha-rfc-03.txt test vectors
// Pulled at commit: https://github.com/bikeshedders/xchacha-rfc/commit/984b586f3cb3c32ae475c2580c505755e6de97dd
#[cfg(test)]
mod draft_rfc_xchacha20 {

	extern crate hex;

	use self::hex::decode;
	use crate::stream::chacha_test_runner;

	#[test]
	fn xchacha20_encryption_test_0() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("404142434445464748494a4b4c4d4e4f5051525354555658").unwrap();
		let mut plaintext = decode(
			"5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973\
			 20616c736f206b6e6f776e2061732074686520417369617469632077696c6420\
			 646f672c2072656420646f672c20616e642077686973746c696e6720646f672e\
			 2049742069732061626f7574207468652073697a65206f662061204765726d61\
			 6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061\
			 206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c\
			 757369766520616e6420736b696c6c6564206a756d70657220697320636c6173\
			 736966696564207769746820776f6c7665732c20636f796f7465732c206a6163\
			 6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963\
			 2066616d696c792043616e696461652e",
		)
		.unwrap();
		let mut expected = decode(
			"4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9\
			 8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d\
			 4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da\
			 ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744\
			 3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240\
			 7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c\
			 09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae\
			 577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c\
			 cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663\
			 93b93111c1a55dd7421a10184974c7c5",
		)
		.unwrap();

		chacha_test_runner(&key, &nonce, 0, &mut plaintext, &mut expected);
	}
}
