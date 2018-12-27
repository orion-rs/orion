// MIT License

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

// Testing against custom test vectors.
// These test vectors have been generated with the cryptography.io Python
// package. More information here: https://github.com/brycx/Test-Vector-Generation/

#[cfg(test)]
mod custom_test_vectors {

	extern crate hex;
	extern crate orion;

	use self::{hex::decode, orion::hazardous::kdf::pbkdf2::*};

	#[test]
	fn sha512_test_case_1() {
		let password = Password::from_slice("password".as_bytes()).unwrap();
		let salt = "salt".as_bytes();
		let iter = 1;
		let mut dk_out = [0u8; 20];

		let expected_dk = decode("867f70cf1ade02cff3752599a3a53dc4af34c7a6").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_2() {
		let password = Password::from_slice("password".as_bytes()).unwrap();
		let salt = "salt".as_bytes();
		let iter = 2;
		let mut dk_out = [0u8; 20];

		let expected_dk = decode("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_3() {
		let password = Password::from_slice("password".as_bytes()).unwrap();
		let salt = "salt".as_bytes();
		let iter = 4096;
		let mut dk_out = [0u8; 20];

		let expected_dk = decode("d197b1b33db0143e018b12f3d1d1479e6cdebdcc").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_4() {
		let password = Password::from_slice("passwordPASSWORDpassword".as_bytes()).unwrap();
		let salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes();
		let iter = 4096;
		let mut dk_out = [0u8; 25];

		let expected_dk = decode("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_5() {
		let password = Password::from_slice("pass\0word".as_bytes()).unwrap();
		let salt = "sa\0lt".as_bytes();
		let iter = 4096;
		let mut dk_out = [0u8; 16];

		let expected_dk = decode("9d9e9c4cd21fe4be24d5b8244c759665").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_6() {
		let password = Password::from_slice("passwd".as_bytes()).unwrap();
		let salt = "salt".as_bytes();
		let iter = 1;
		let mut dk_out = [0u8; 128];

		let expected_dk = decode("c74319d99499fc3e9013acff597c23c5baf0a0bec5634c46b8352b793e324723d55caa76b2b25c43402dcfdc06cdcf66f95b7d0429420b39520006749c51a04ef3eb99e576617395a178ba33214793e48045132928a9e9bf2661769fdc668f31798597aaf6da70dd996a81019726084d70f152baed8aafe2227c07636c6ddece").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}

	#[test]
	fn sha512_test_case_7() {
		let password = Password::from_slice("Password".as_bytes()).unwrap();
		let salt = "NaCl".as_bytes();
		let iter = 80000;
		let mut dk_out = [0u8; 128];

		let expected_dk = decode("e6337d6fbeb645c794d4a9b5b75b7b30dac9ac50376a91df1f4460f6060d5addb2c1fd1f84409abacc67de7eb4056e6bb06c2d82c3ef4ccd1bded0f675ed97c65c33d39f81248454327aa6d03fd049fc5cbb2b5e6dac08e8ace996cdc960b1bd4530b7e754773d75f67a733fdb99baf6470e42ffcb753c15c352d4800fb6f9d6").unwrap();

		// verify() also runs derive_key()
		assert!(verify(&expected_dk, &password, &salt, iter, &mut dk_out).unwrap());
	}
}
