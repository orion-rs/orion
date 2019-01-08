// Testing against test vectors from https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
#[cfg(test)]
mod other_hkdf {

	extern crate hex;
	extern crate orion;

	use self::hex::decode;

	use crate::kdf::hkdf_test_runner;

	#[test]
	fn test_case_1() {
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = decode("000102030405060708090a0b0c").unwrap();
		let info = decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let mut okm = [0u8; 42];

		let expected_prk = decode(
                "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            ).unwrap();

		let expected_okm = decode(
			"832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
		)
		.unwrap();

		assert!(hkdf_test_runner(
			Some(&expected_prk),
			&expected_okm,
			&salt,
			&ikm,
			&info,
			&mut okm
		));
	}

	#[test]
	fn test_case_2() {
		let ikm = decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
		let salt = decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
		let info = decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
		let mut okm = [0u8; 82];

		let expected_prk = decode(
                "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
            ).unwrap();

		let expected_okm = decode(
                "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
            ).unwrap();

		assert!(hkdf_test_runner(
			Some(&expected_prk),
			&expected_okm,
			&salt,
			&ikm,
			&info,
			&mut okm
		));
	}

	#[test]
	fn test_case_3() {
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = decode("").unwrap();
		let info = decode("").unwrap();
		let mut okm = [0u8; 42];

		let expected_prk = decode(
                "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
            ).unwrap();

		let expected_okm = decode(
			"f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
		)
		.unwrap();

		assert!(hkdf_test_runner(
			Some(&expected_prk),
			&expected_okm,
			&salt,
			&ikm,
			&info,
			&mut okm
		));
	}

	#[test]
	fn test_case_4() {
		let ikm = decode("0b0b0b0b0b0b0b0b0b0b0b").unwrap();
		let salt = decode("000102030405060708090a0b0c").unwrap();
		let info = decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
		let mut okm = [0u8; 42];

		let expected_prk = decode(
                "67409c9cac28b52ee9fad91c2fda999f7ca22e3434f0ae772863836568ad6a7f10cf113bfddd560129a594a8f52385c2d661d785d29ce93a11400c920683181d",
            ).unwrap();

		let expected_okm = decode(
			"7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff53559bd5e3028b080f7c068",
		)
		.unwrap();
		assert!(hkdf_test_runner(
			Some(&expected_prk),
			&expected_okm,
			&salt,
			&ikm,
			&info,
			&mut okm
		));
	}

	#[test]
	fn test_case_5() {
		let ikm = decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap();
		let salt = decode("").unwrap();
		let info = decode("").unwrap();
		let mut okm = [0u8; 42];

		let expected_prk = decode(
                "5346b376bf3aa9f84f8f6ed5b1c4f489172e244dac303d12f68ecc766ea600aa88495e7fb605803122fa136924a840b1f0719d2d5f68e29b242299d758ed680c",
            ).unwrap();

		let expected_okm = decode(
			"1407d46013d98bc6decefcfee55f0f90b0c7f63d68eb1a80eaf07e953cfc0a3a5240a155d6e4daa965bb",
		)
		.unwrap();

		assert!(hkdf_test_runner(
			Some(&expected_prk),
			&expected_okm,
			&salt,
			&ikm,
			&info,
			&mut okm
		));
	}
}
