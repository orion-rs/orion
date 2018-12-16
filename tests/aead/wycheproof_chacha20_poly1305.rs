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

// Testing against Google Wycheproof test vectors
// Latest commit when these test vectors were pulled: https://github.com/google/wycheproof/commit/8f2cba4d3fe693aa312fed6939ef5454952d830d
#[cfg(test)]
mod wycheproof_aead_chacha20_poly1305 {

	extern crate hex;
	extern crate orion;

	use self::hex::decode;
	use crate::aead::wycheproof_test_runner as chacha20_poly1305_test_runner;

	#[test]
	fn wycheproof_test_case_1() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("070000004041424344454647").unwrap();
		let aad = decode("50515253c0c1c2c3c4c5c6c7").unwrap();
		let input = decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
		let output = decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
		let tag = decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

		// Wycheproof test case comment: rfc7539

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	// EXCLUDED: orion does not allow empty input/output with otherwise good
	// paramters. All other test cases that have empty input/output are marked by
	// Wycheproof as "invalid" and therfor tested here as #[should_panic], so they
	// can be tested correctly by orion too.
	//
	// #[test]
	// fn wycheproof_test_case_2() {
	// let key =
	// decode("80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0").
	// unwrap(); let nonce = decode("4da5bf8dfd5852c1ea12379d").unwrap();
	// let aad = decode("").unwrap();
	// let input = decode("").unwrap();
	// let output = decode("").unwrap();
	// let tag = decode("76acb342cf3166a5b63c0c0ea1383c8d").unwrap();
	//
	// Wycheproof test case comment:
	//
	// chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input,
	// &output).unwrap(); }
	//
	// #[test]
	// fn wycheproof_test_case_3() {
	// let key =
	// decode("7a4cd759172e02eb204db2c3f5c746227df584fc1345196391dbb9577a250742").
	// unwrap(); let nonce = decode("a92ef0ac991dd516a3c6f689").unwrap();
	// let aad = decode("bd506764f2d2c410").unwrap();
	// let input = decode("").unwrap();
	// let output = decode("").unwrap();
	// let tag = decode("906fa6284b52f87b7359cbaa7563c709").unwrap();
	//
	// Wycheproof test case comment:
	//
	// chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input,
	// &output).unwrap(); }
	#[test]
	fn wycheproof_test_case_4() {
		let key =
			decode("cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273").unwrap();
		let nonce = decode("99e23ec48985bccdeeab60f1").unwrap();
		let aad = decode("").unwrap();
		let input = decode("2a").unwrap();
		let output = decode("3a").unwrap();
		let tag = decode("cac27dec0968801e9f6eded69d807522").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_5() {
		let key =
			decode("46f0254965f769d52bdb4a70b443199f8ef207520d1220c55e4b70f0fda620ee").unwrap();
		let nonce = decode("ab0dca716ee051d2782f4403").unwrap();
		let aad = decode("91ca6c592cbcca53").unwrap();
		let input = decode("51").unwrap();
		let output = decode("c4").unwrap();
		let tag = decode("168310ca45b1f7c66cad4e99e43f72b9").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_6() {
		let key =
			decode("2f7f7e4f592bb389194989743507bf3ee9cbde1786b6695fe6c025fd9ba4c100").unwrap();
		let nonce = decode("461af122e9f2e0347e03f2db").unwrap();
		let aad = decode("").unwrap();
		let input = decode("5c60").unwrap();
		let output = decode("4d13").unwrap();
		let tag = decode("91e8b61efb39c122195453077b22e5e2").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_7() {
		let key =
			decode("c8833dce5ea9f248aa2030eacfe72bffe69a620caf793344e5718fe0d7ab1a58").unwrap();
		let nonce = decode("61546ba5f1720590b6040ac6").unwrap();
		let aad = decode("88364fc8060518bf").unwrap();
		let input = decode("ddf2").unwrap();
		let output = decode("b60d").unwrap();
		let tag = decode("ead0fd4697ec2e5558237719d02437a2").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_8() {
		let key =
			decode("55568158d3a6483f1f7021eab69b703f614251cadc1af5d34a374fdbfc5adac7").unwrap();
		let nonce = decode("3c4e654d663fa4596dc55bb7").unwrap();
		let aad = decode("").unwrap();
		let input = decode("ab85e9c1571731").unwrap();
		let output = decode("5dfe3440dbb3c3").unwrap();
		let tag = decode("ed7a434e2602d394281e0afa9fb7aa42").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_9() {
		let key =
			decode("e3c09e7fab1aefb516da6a33022a1dd4eb272c80d540c5da52a730f34d840d7f").unwrap();
		let nonce = decode("58389375c69ee398de948396").unwrap();
		let aad = decode("84e46be8c0919053").unwrap();
		let input = decode("4ee5cda20d4290").unwrap();
		let output = decode("4bd47212941ce3").unwrap();
		let tag = decode("185f1408ee7fbf18f5abad6e2253a1ba").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_10() {
		let key =
			decode("51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152").unwrap();
		let nonce = decode("4f07afedfdc3b6c2361823d3").unwrap();
		let aad = decode("").unwrap();
		let input = decode("be3308f72a2c6aed").unwrap();
		let output = decode("8e9439a56eeec817").unwrap();
		let tag = decode("fbe8a6ed8fabb1937539dd6c00e90021").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_11() {
		let key =
			decode("1131c1418577a054de7a4ac551950f1a053f9ae46e5b75fe4abd5608d7cddadd").unwrap();
		let nonce = decode("b4ea666ee119563366484a78").unwrap();
		let aad = decode("66c0ae70076cb14d").unwrap();
		let input = decode("a4c9c2801b71f7df").unwrap();
		let output = decode("b9b910433af052b0").unwrap();
		let tag = decode("4530f51aeee024e0a445a6328fa67a18").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_12() {
		let key =
			decode("99b62bd5afbe3fb015bde93f0abf483957a1c3eb3ca59cb50b39f7f8a9cc51be").unwrap();
		let nonce = decode("9a59fce26df0005e07538656").unwrap();
		let aad = decode("").unwrap();
		let input = decode("42baae5978feaf5c368d14e0").unwrap();
		let output = decode("ff7dc203b26c467a6b50db33").unwrap();
		let tag = decode("578c0f2758c2e14e36d4fc106dcb29b4").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_13() {
		let key =
			decode("85f35b6282cff440bc1020c8136ff27031110fa63ec16f1e825118b006b91257").unwrap();
		let nonce = decode("58dbd4ad2c4ad35dd906e9ce").unwrap();
		let aad = decode("a506e1a5c69093f9").unwrap();
		let input = decode("fdc85b94a4b2a6b759b1a0da").unwrap();
		let output = decode("9f8816de0994e938d9e53f95").unwrap();
		let tag = decode("d086fc6c9d8fa915fd8423a7cf05072f").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_14() {
		let key =
			decode("67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb").unwrap();
		let nonce = decode("68ab7fdbf61901dad461d23c").unwrap();
		let aad = decode("").unwrap();
		let input = decode("51f8c1f731ea14acdb210a6d973e07").unwrap();
		let output = decode("0b29638e1fbdd6df53970be2210042").unwrap();
		let tag = decode("2a9134087d67a46e79178d0a93f5e1d2").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_15() {
		let key =
			decode("e6f1118d41e4b43fb58221b7ed79673834e0d8ac5c4fa60bbc8bc4893a58894d").unwrap();
		let nonce = decode("d95b3243afaef714c5035b6a").unwrap();
		let aad = decode("6453a53384632212").unwrap();
		let input = decode("97469da667d6110f9cbda1d1a20673").unwrap();
		let output = decode("32db66c4a3819d81557455e5980fed").unwrap();
		let tag = decode("feae30dec94e6ad3a9eea06a0d703917").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_16() {
		let key =
			decode("59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a").unwrap();
		let nonce = decode("2fcb1b38a99e71b84740ad9b").unwrap();
		let aad = decode("").unwrap();
		let input = decode("549b365af913f3b081131ccb6b825588").unwrap();
		let output = decode("e9110e9f56ab3ca483500ceabab67a13").unwrap();
		let tag = decode("836ccabf15a6a22a51c1071cfa68fa0c").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_17() {
		let key =
			decode("b907a45075513fe8a8019edee3f2591487b2a030b03c6e1d771c862571d2ea1e").unwrap();
		let nonce = decode("118a6964c2d3e380071f5266").unwrap();
		let aad = decode("034585621af8d7ff").unwrap();
		let input = decode("55a465644f5b650928cbee7c063214d6").unwrap();
		let output = decode("e4b113cb775945f3d3a8ae9ec141c00c").unwrap();
		let tag = decode("7c43f16ce096d0dc27c95849dc383b7d").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_18() {
		let key =
			decode("3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011").unwrap();
		let nonce = decode("45aaa3e5d16d2d42dc03445d").unwrap();
		let aad = decode("").unwrap();
		let input = decode("3ff1514b1c503915918f0c0c31094a6e1f").unwrap();
		let output = decode("02cc3acb5ee1fcdd12a03bb857976474d3").unwrap();
		let tag = decode("d83b7463a2c3800fe958c28eaa290813").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_19() {
		let key =
			decode("f60c6a1b625725f76c7037b48fe3577fa7f7b87b1bd5a982176d182306ffb870").unwrap();
		let nonce = decode("f0384fb876121410633d993d").unwrap();
		let aad = decode("9aaf299eeea78f79").unwrap();
		let input = decode("63858ca3e2ce69887b578a3c167b421c9c").unwrap();
		let output = decode("35766488d2bc7c2b8d17cbbb9abfad9e6d").unwrap();
		let tag = decode("1f391e657b2738dda08448cba2811ceb").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_20() {
		let key =
			decode("0212a8de5007ed87b33f1a7090b6114f9e08cefd9607f2c276bdcfdbc5ce9cd7").unwrap();
		let nonce = decode("e6b1adf2fd58a8762c65f31b").unwrap();
		let aad = decode("").unwrap();
		let input = decode("10f1ecf9c60584665d9ae5efe279e7f7377eea6916d2b111").unwrap();
		let output = decode("42f26c56cb4be21d9d8d0c80fc99dde00d75f38074bfe764").unwrap();
		let tag = decode("54aa7e13d48fff7d7557039457040a3a").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_21() {
		let key =
			decode("c5bc09565646e7edda954f1f739223dada20b95c44ab033d0fae4b0283d18be3").unwrap();
		let nonce = decode("6b282ebecc541bcd7834ed55").unwrap();
		let aad = decode("3e8bc5ade182ff08").unwrap();
		let input = decode("9222f9018e54fd6de1200806a9ee8e4cc904d29f25cba193").unwrap();
		let output = decode("123032437b4bfd6920e8f7e7e0087ae4889ebe7a0ad0e900").unwrap();
		let tag = decode("3cf68f179550da63d3b96c2d55411865").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_22() {
		let key =
			decode("2eb51c469aa8eb9e6c54a8349bae50a20f0e382711bba1152c424f03b6671d71").unwrap();
		let nonce = decode("04a9be03508a5f31371a6fd2").unwrap();
		let aad = decode("").unwrap();
		let input =
			decode("b053999286a2824f42cc8c203ab24e2c97a685adcc2ad32662558e55a5c729").unwrap();
		let output =
			decode("45c7d6b53acad4abb68876a6e96a48fb59524d2c92c9d8a189c9fd2db91746").unwrap();
		let tag = decode("566d3ca10e311b695f3eae1551652493").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_23() {
		let key =
			decode("7f5b74c07ed1b40fd14358fe2ff2a740c116c7706510e6a437f19ea49911cec4").unwrap();
		let nonce = decode("470a339ecb3219b8b81a1f8b").unwrap();
		let aad = decode("374618a06ea98a48").unwrap();
		let input =
			decode("f45206abc25552b2abc9ab7fa243035fedaaddc3b2293956f1ea6e7156e7eb").unwrap();
		let output =
			decode("46a80c4187024720084627580080dde5a3f4a11093a7076ed6f3d326bc7b70").unwrap();
		let tag = decode("534d4aa2835a52e72d14df0e4f47f25f").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_24() {
		let key =
			decode("e1731d5854e1b70cb3ffe8b786a2b3ebf0994370954757b9dc8c7bc5354634a3").unwrap();
		let nonce = decode("72cfd90ef3026ca22b7e6e6a").unwrap();
		let aad = decode("").unwrap();
		let input =
			decode("b9c554cbc36ac18ae897df7beecac1dbeb4eafa156bb60ce2e5d48f05715e678").unwrap();
		let output =
			decode("ea29afa49d36e8760f5fe19723b9811ed5d519934a440f5081ac430b953b0e21").unwrap();
		let tag = decode("222541af46b86533c6b68d2ff108a7ea").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_25() {
		let key =
			decode("27d860631b0485a410702fea61bc873f3442260caded4abde25b786a2d97f145").unwrap();
		let nonce = decode("262880d475f3dac5340dd1b8").unwrap();
		let aad = decode("2333e5ce0f93b059").unwrap();
		let input =
			decode("6b2604996cd30c14a13a5257ed6cffd3bc5e29d6b97eb1799eb335e281ea451e").unwrap();
		let output =
			decode("6dad637897544d8bf6be9507ed4d1bb2e954bc427e5de729daf50762846ff2f4").unwrap();
		let tag = decode("7b997d93c982189d7095dc794c746232").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_26() {
		let key =
			decode("cf0d40a4644e5f51815165d5301b22631f4544c49a1878e3a0a5e8e1aae0f264").unwrap();
		let nonce = decode("e74a515e7e2102b90bef55d2").unwrap();
		let aad = decode("").unwrap();
		let input = decode("973d0c753826bae466cf9abb3493152e9de7819e2bd0c71171346b4d2cebf8041aa3cedc0dfd7b467e26228bc86c9a").unwrap();
		let output = decode("fba78ae4f9d808a62e3da40be2cb7700c3613d9eb2c529c652e76a432c658d27095f0eb8f940c324981ea935e507f9").unwrap();
		let tag = decode("8f046956db3a512908bd7afc8f2ab0a9").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_27() {
		let key =
			decode("6cbfd71c645d184cf5d23c402bdb0d25ec54898c8a0273d42eb5be109fdcb2ac").unwrap();
		let nonce = decode("d4d807341683825b31cd4d95").unwrap();
		let aad = decode("b3e4064683b02d84").unwrap();
		let input = decode("a98995504df16f748bfb7785ff91eeb3b660ea9ed3450c3d5e7b0e79ef653659a9978d75542ef91c456762215640b9").unwrap();
		let output = decode("a1ffed80761829ecce242e0e88b138049016bca018da2b6e19986b3e318cae8d806198fb4c527cc39350ebddeac573").unwrap();
		let tag = decode("c4cbf0befda0b70242c640d7cd02d7a3").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_28() {
		let key =
			decode("5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701").unwrap();
		let nonce = decode("d61040a313ed492823cc065b").unwrap();
		let aad = decode("").unwrap();
		let input = decode("d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82").unwrap();
		let output = decode("9a4ef22b181677b5755c08f747c0f8d8e8d4c18a9cc2405c12bb51bb1872c8e8b877678bec442cfcbb0ff464a64b74332cf072898c7e0eddf6232ea6e27efe50").unwrap();
		let tag = decode("9ff3427a0f32fa566d9ca0a78aefc013").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_29() {
		let key =
			decode("97d635c4f47574d9998a90875da1d3a284b755b2d39297a5725235190e10a97e").unwrap();
		let nonce = decode("d31c21aba175b70de4ebb19c").unwrap();
		let aad = decode("7193f623663321a2").unwrap();
		let input = decode("94ee166d6d6ecf8832437136b4ae805d428864359586d9193a25016293edba443c58e07e7b7195ec5bd84582a9d56c8d4a108c7d7ce34e6c6f8ea1bec0567317").unwrap();
		let output = decode("5fbbdecc34be201614f636031eeb42f1cace3c79a12cffd871ee8e73820c829749f1abb4294367849fb6c2aa56bda8a3078f723d7c1c852024b017b58973fb1e").unwrap();
		let tag = decode("09263da7b4cb921452f97dca40f580ec").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_30() {
		let key =
			decode("fe6e55bdaed1f7284ca5fc0f8c5f2b8df56dc0f49e8ca66a41995e783351f901").unwrap();
		let nonce = decode("17c86a8abbb7e003acde2799").unwrap();
		let aad = decode("").unwrap();
		let input = decode("b429eb80fb8fe8baeda0c85b9c333458e7c2992e558475069d12d45c22217564121588032297eff56783742a5fc22d7410ffb29d66098661d76f126c3c27689e43b37267cac5a3a6d3ab49e391da29cd3054a5692e2807e4c3ea46c8761d50f592").unwrap();
		let output = decode("d0102f6c258bf49742cec34cf2d0fedf23d105fb4c84cf98515e1bc9a64f8ad5be8f0721bde50645d00083c3a263a31053b760245f52ae2866a5ec83b19f61be1d30d5c5d9fecc4cbbe08fd385813a2aa39a00ff9c10f7f23702add1e4b2ffa31c").unwrap();
		let tag = decode("41865fc71de12b19612127ce49993bb0").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_31() {
		let key =
			decode("aabc063474e65c4c3e9bdc480dea97b45110c8618846ff6b15bdd2a4a5682c4e").unwrap();
		let nonce = decode("46362f45d6379e63e5229460").unwrap();
		let aad = decode("a11c40b603767330").unwrap();
		let input = decode("ceb534ce50dc23ff638ace3ef63ab2cc2973eeada80785fc165d06c2f5100ff5e8ab2882c475afcd05ccd49f2e7d8f55ef3a72e3dc51d6852b8e6b9e7aece57be6556b0b6d9413e33fc5fc24a9a205ad59574bb39d944a92dc47970d84a6ad3176").unwrap();
		let output = decode("7545391b51de01d5c53dfaca777909063e58edee4bb1227e7110ac4d2620c2aec2f848f56deeb037a8dced75afa8a6c890e2dee42f950bb33d9e2424d08a505d899563973ed38870f3de6ee2adc7fe072c366c14e2cf7ca62fb3d36bee11685461").unwrap();
		let tag = decode("b70d44ef8c66c5c7bbf10dcadd7facf6").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_32() {
		let key =
			decode("7d00b48095adfa3272050607b264185002ba99957c498be022770f2ce2f3143c").unwrap();
		let nonce = decode("87345f1055fd9e2102d50656").unwrap();
		let aad = decode("02").unwrap();
		let input = decode("e5ccaa441bc814688f8f6e8f28b500b2").unwrap();
		let output = decode("7e72f5a185af16a611921b438f749f0b").unwrap();
		let tag = decode("1242c670732334029adfe1c5001651e4").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_33() {
		let key =
			decode("6432717f1db85e41ac7836bce25185a080d5762b9e2b18444b6ec72c3bd8e4dc").unwrap();
		let nonce = decode("87a3163ec0598ad95b3aa713").unwrap();
		let aad = decode("b648").unwrap();
		let input = decode("02cde168fba3f544bbd0332f7adeada8").unwrap();
		let output = decode("85f29a719557cdd14d1f8fffab6d9e60").unwrap();
		let tag = decode("732ca32becd515a1ed353f542e999858").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_34() {
		let key =
			decode("8e34cf73d245a1082a920b86364eb896c4946467bcb3d58929fcb36690e6394f").unwrap();
		let nonce = decode("6f573aa86baa492ba46596df").unwrap();
		let aad = decode("bd4cd02fc7502bbdbdf6c9a3cbe8f0").unwrap();
		let input = decode("16ddd23ff53f3d23c06334487040eb47").unwrap();
		let output = decode("c1b295936d56fadac03e5f742bff73a1").unwrap();
		let tag = decode("39c457dbab66382babb3b55800cda5b8").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_35() {
		let key =
			decode("cb5575f5c7c45c91cf320b139fb594237560d0a3e6f865a67d4f633f2c08f016").unwrap();
		let nonce = decode("1a6518f02ede1da6809266d9").unwrap();
		let aad = decode("89cce9fb47441d07e0245a66fe8b778b").unwrap();
		let input = decode("623b7850c321e2cf0c6fbcc8dfd1aff2").unwrap();
		let output = decode("c84c9bb7c61c1bcb17772a1c500c5095").unwrap();
		let tag = decode("dbadf7a5138ca03459a2cd65831e092f").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_36() {
		let key =
			decode("a5569e729a69b24ba6e0ff15c4627897436824c941e9d00b2e93fddc4ba77657").unwrap();
		let nonce = decode("564dee49ab00d240fc1068c3").unwrap();
		let aad = decode("d19f2d989095f7ab03a5fde84416e00c0e").unwrap();
		let input = decode("87b3a4d7b26d8d3203a0de1d64ef82e3").unwrap();
		let output = decode("94bc80621ed1e71b1fd2b5c3a15e3568").unwrap();
		let tag = decode("333511861796978401598b963722f5b3").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_37() {
		let key =
			decode("56207465b4e48e6d04630f4a42f35cfc163ab289c22a2b4784f6f9290330bee0").unwrap();
		let nonce = decode("df8713e87ec3dbcfad14d53e").unwrap();
		let aad = decode("5e6470facd99c1d81e37cd44015fe19480a2a4d3352a4ff560c0640fdbda").unwrap();
		let input = decode("e601b38557797da2f8a4106a089d1da6").unwrap();
		let output = decode("299b5d3f3d03c087209a16e285143111").unwrap();
		let tag = decode("4b454ed198de117e83ec49fa8d8508d6").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_38() {
		let key =
			decode("3937986af86dafc1ba0c4672d8abc46c207062682d9c264ab06d6c5807205130").unwrap();
		let nonce = decode("8df4b15a888c33286a7b7651").unwrap();
		let aad =
			decode("ba446f6f9a0ced22450feb10737d9007fd69abc19b1d4d9049a5551e86ec2b37").unwrap();
		let input = decode("dc9e9eaf11e314182df6a4eba17aec9c").unwrap();
		let output = decode("605bbf90aeb974f6602bc778056f0dca").unwrap();
		let tag = decode("38ea23d99054b46b42ffe004129d2204").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_39() {
		let key =
			decode("36372abcdb78e0279646ac3d176b9674e9154eecf0d5469c651ec7e16b4c1199").unwrap();
		let nonce = decode("be40e5f1a11817a0a8fa8949").unwrap();
		let aad =
			decode("d41a828d5e71829247021905402ea257dccbc3b80fcd5675056b68bb59e62e8873").unwrap();
		let input = decode("81ce84ede9b35859cc8c49a8f6be7dc6").unwrap();
		let output = decode("7b7ce0d824809a70de32562ccf2c2bbd").unwrap();
		let tag = decode("15d44a00ce0d19b4231f921e22bc0a43").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_40() {
		let key =
			decode("9f1479ed097d7fe529c11f2f5add9aaff4a1ca0b68997a2cb7f79749bd90aaf4").unwrap();
		let nonce = decode("84c87dae4eee27730ec35d12").unwrap();
		let aad = decode("3f2dd49bbf09d69a78a3d80ea2566614fc379474196c1aae84583da73d7ff85c6f42ca42056a9792cc1b9fb3c7d261").unwrap();
		let input = decode("a66747c89e857af3a18e2c79500087ed").unwrap();
		let output = decode("ca82bff3e2f310ccc976672c4415e69b").unwrap();
		let tag = decode("57638c62a5d85ded774f913c813ea032").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_41() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000000000000000000000000000").unwrap();
		let input =
			decode("256d40888094178355d304846443fee8df99470303fb3b7b80e030beebd329be").unwrap();
		let output =
			decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
		let tag = decode("e6d3d7324a1cbba777bbb0ecdda37807").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_42() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000000000000000000000000000").unwrap();
		let input = decode("256d40888094178355d304846443fee8df99470303fb3b7b80e030beebd329bee3bcdb5b1edefcfe8bcda1b6a15c8c2b0869ffd2ec5e26e553b7b227fe87fdbd").unwrap();
		let output = decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
		let tag = decode("062de6795f274fd2a305d76980bc9cce").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_43() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000000000000000000000000000").unwrap();
		let input = decode("256d40888094178355d304846443fee8df99470303fb3b7b80e030beebd329bee3bcdb5b1edefcfe8bcda1b6a15c8c2b0869ffd2ec5e26e553b7b227fe87fdbd7ada44424269bffa5527f270acf68502b74c5ae2e60c0580981a4938459392c49bb2f284b646efc7f3f0b1361dc348ed77d30bc57692ed38fbac0188380488c7").unwrap();
		let output = decode("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
		let tag = decode("d8b47902baaeafb34203051529af282e").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_44() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffff").unwrap();
		let input =
			decode("da92bf777f6be87caa2cfb7b9bbc01172066b8fcfc04c4847f1fcf41142cd641").unwrap();
		let output =
			decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("b3891c849cb52c27747edfcf31213bb6").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_45() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("da92bf777f6be87caa2cfb7b9bbc01172066b8fcfc04c4847f1fcf41142cd6411c4324a4e121030174325e495ea373d4f796002d13a1d91aac484dd801780242").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("f0c12d26ef03029b62c008da27c5dc68").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_46() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("da92bf777f6be87caa2cfb7b9bbc01172066b8fcfc04c4847f1fcf41142cd6411c4324a4e121030174325e495ea373d4f796002d13a1d91aac484dd8017802428525bbbdbd964005aad80d8f53097afd48b3a51d19f3fa7f67e5b6c7ba6c6d3b644d0d7b49b910380c0f4ec9e23cb712882cf43a896d12c70453fe77c7fb7738").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("ee65783001c25691fa28d0f5f1c1d762").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_47() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000080000000800000008000000080").unwrap();
		let input =
			decode("256d40088094170355d304046443fe68df99478303fb3bfb80e0303eebd3293e").unwrap();
		let output =
			decode("0000008000000080000000800000008000000080000000800000008000000080").unwrap();
		let tag = decode("79ba7a29f5a7bb75797af87a610129a4").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_48() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000080000000800000008000000080").unwrap();
		let input = decode("256d40088094170355d304046443fe68df99478303fb3bfb80e0303eebd3293ee3bcdbdb1edefc7e8bcda136a15c8cab0869ff52ec5e266553b7b2a7fe87fd3d").unwrap();
		let output = decode("00000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080").unwrap();
		let tag = decode("36b1743819e1b9ba1551e8ed922a959a").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_49() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000080000000800000008000000080").unwrap();
		let input = decode("256d40088094170355d304046443fe68df99478303fb3bfb80e0303eebd3293ee3bcdbdb1edefc7e8bcda136a15c8cab0869ff52ec5e266553b7b2a7fe87fd3d7ada44c24269bf7a5527f2f0acf68582b74c5a62e60c0500981a49b8459392449bb2f204b646ef47f3f0b1b61dc3486d77d30b457692edb8fbac010838048847").unwrap();
		let output = decode("0000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080000000800000008000000080").unwrap();
		let tag = decode("feac4955554e806f3a1902e24432c08a").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_50() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffff7fffffff7fffffff7fffffff7f").unwrap();
		let input =
			decode("da92bff77f6be8fcaa2cfbfb9bbc01972066b87cfc04c4047f1fcfc1142cd6c1").unwrap();
		let output =
			decode("ffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7f").unwrap();
		let tag = decode("20a3798df1292c5972bf9741aec38a19").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_51() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffff7fffffff7fffffff7fffffff7f").unwrap();
		let input = decode("da92bff77f6be8fcaa2cfbfb9bbc01972066b87cfc04c4047f1fcfc1142cd6c11c432424e121038174325ec95ea37354f79600ad13a1d99aac484d58017802c2").unwrap();
		let output = decode("ffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7f").unwrap();
		let tag = decode("c03d9f67354a97b2f074f7551557e49c").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_52() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffff7fffffff7fffffff7fffffff7f").unwrap();
		let input = decode("da92bff77f6be8fcaa2cfbfb9bbc01972066b87cfc04c4047f1fcfc1142cd6c11c432424e121038174325ec95ea37354f79600ad13a1d99aac484d58017802c28525bb3dbd964085aad80d0f53097a7d48b3a59d19f3faff67e5b647ba6c6dbb644d0dfb49b910b80c0f4e49e23cb792882cf4ba896d12470453fef7c7fb77b8").unwrap();
		let output = decode("ffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7f").unwrap();
		let tag = decode("c86da8dd652286d50213d328d63e4006").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_53() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("7fffffff7fffffff7fffffff7fffffff").unwrap();
		let input =
			decode("5a92bf77ff6be87c2a2cfb7b1bbc0117a066b8fc7c04c484ff1fcf41942cd641").unwrap();
		let output =
			decode("7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff").unwrap();
		let tag = decode("bede9083ceb36ddfe5fa811f95471c67").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_54() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("7fffffff7fffffff7fffffff7fffffff").unwrap();
		let input = decode("5a92bf77ff6be87c2a2cfb7b1bbc0117a066b8fc7c04c484ff1fcf41942cd6419c4324a461210301f4325e49dea373d47796002d93a1d91a2c484dd881780242").unwrap();
		let output = decode("7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff").unwrap();
		let tag = decode("300874bb0692b689dead9ae15b067390").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_55() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("7fffffff7fffffff7fffffff7fffffff").unwrap();
		let input = decode("5a92bf77ff6be87c2a2cfb7b1bbc0117a066b8fc7c04c484ff1fcf41942cd6419c4324a461210301f4325e49dea373d47796002d93a1d91a2c484dd8817802420525bbbd3d9640052ad80d8fd3097afdc8b3a51d99f3fa7fe7e5b6c73a6c6d3be44d0d7bc9b910388c0f4ec9623cb712082cf43a096d12c78453fe7747fb7738").unwrap();
		let output = decode("7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff").unwrap();
		let tag = decode("99cad85f45ca40942d0d4d5e950ade22").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_56() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000ffffffff00000000ffffffff").unwrap();
		let input =
			decode("256d40887f6be87c55d304849bbc0117df994703fc04c48480e030be142cd641").unwrap();
		let output =
			decode("00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff").unwrap();
		let tag = decode("8bbe145272e7c2d9a1891a3ab0983d9d").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_57() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000ffffffff00000000ffffffff").unwrap();
		let input = decode("256d40887f6be87c55d304849bbc0117df994703fc04c48480e030be142cd641e3bcdb5be12103018bcda1b65ea373d40869ffd213a1d91a53b7b22701780242").unwrap();
		let output = decode("00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff").unwrap();
		let tag = decode("3b41861913a8f6de7f61e225631bc382").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_58() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("00000000ffffffff00000000ffffffff").unwrap();
		let input = decode("256d40887f6be87c55d304849bbc0117df994703fc04c48480e030be142cd641e3bcdb5be12103018bcda1b65ea373d40869ffd213a1d91a53b7b227017802427ada4442bd9640055527f27053097afdb74c5ae219f3fa7f981a4938ba6c6d3b9bb2f28449b91038f3f0b136e23cb71277d30bc5896d12c7fbac0188c7fb7738").unwrap();
		let output = decode("00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff").unwrap();
		let tag = decode("8428bcf023ec6bf31fd9efb203ff0871").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_59() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffff00000000ffffffff00000000").unwrap();
		let input =
			decode("da92bf7780941783aa2cfb7b6443fee82066b8fc03fb3b7b7f1fcf41ebd329be").unwrap();
		let output =
			decode("ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000").unwrap();
		let tag = decode("139fdf6474ea24f549b075825f2c7620").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_60() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffff00000000ffffffff00000000").unwrap();
		let input = decode("da92bf7780941783aa2cfb7b6443fee82066b8fc03fb3b7b7f1fcf41ebd329be1c4324a41edefcfe74325e49a15c8c2bf796002dec5e26e5ac484dd8fe87fdbd").unwrap();
		let output = decode("ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000").unwrap();
		let tag = decode("bbad8d863b835a8e8664fd1d4566b6b4").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_61() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000000000000000001ee3200").unwrap();
		let aad = decode("ffffffff00000000ffffffff00000000").unwrap();
		let input = decode("da92bf7780941783aa2cfb7b6443fee82066b8fc03fb3b7b7f1fcf41ebd329be1c4324a41edefcfe74325e49a15c8c2bf796002dec5e26e5ac484dd8fe87fdbd8525bbbd4269bffaaad80d8facf6850248b3a51de60c058067e5b6c7459392c4644d0d7bb646efc70c0f4ec91dc348ed882cf43a7692ed380453fe77380488c7").unwrap();
		let output = decode("ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000").unwrap();
		let tag = decode("42f2354297849a511d53e5571772f71f").unwrap();

		// Wycheproof test case comment:

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_62() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a2e3fdf9fba6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 0 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_63() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a1e3fdf9fba6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 1 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_64() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("23e3fdf9fba6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 7 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_65() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e2fdf9fba6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 8 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_66() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fd79fba6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 31 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_67() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9faa6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 32 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_68() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9f9a6861b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 33 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_69() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6869b5ad2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 63 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_70() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5bd2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 64 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_71() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5af2607f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 77 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_72() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2617f40b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 80 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_73() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f41b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 96 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_74() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f42b7f447").unwrap();

		// Wycheproof test case comment: Flipped bit 97 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_75() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f40b7f446").unwrap();

		// Wycheproof test case comment: Flipped bit 120 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_76() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f40b7f445").unwrap();

		// Wycheproof test case comment: Flipped bit 121 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_77() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f40b7f407").unwrap();

		// Wycheproof test case comment: Flipped bit 126 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_78() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6861b5ad2607f40b7f4c7").unwrap();

		// Wycheproof test case comment: Flipped bit 127 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_79() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("a3e3fdf9fba6869b5ad2607f40b7f4c7").unwrap();

		// Wycheproof test case comment: Flipped bit 63 and 127 in tag expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_80() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("00000000000000000000000000000000").unwrap();

		// Wycheproof test case comment: Tag changed to all zero expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_81() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("ffffffffffffffffffffffffffffffff").unwrap();

		// Wycheproof test case comment: tag change to all 1 expected
		// tag:a3e3fdf9fba6861b5ad2607f40b7f447

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_82() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("26da374f17b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 0 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_83() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("25da374f17b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 1 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_84() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("a7da374f17b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 7 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_85() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27db374f17b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 8 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_86() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da37cf17b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 31 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_87() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f16b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 32 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_88() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f15b7f1b23844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 33 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_89() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1323844a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 63 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_90() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23944a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 64 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_91() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23864a5490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 77 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_92() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a4490bfc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 80 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_93() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a5490afc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 96 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_94() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a54909fc4001").unwrap();

		// Wycheproof test case comment: Flipped bit 97 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_95() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a5490bfc4000").unwrap();

		// Wycheproof test case comment: Flipped bit 120 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_96() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a5490bfc4003").unwrap();

		// Wycheproof test case comment: Flipped bit 121 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_97() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a5490bfc4041").unwrap();

		// Wycheproof test case comment: Flipped bit 126 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_98() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1b23844a5490bfc4081").unwrap();

		// Wycheproof test case comment: Flipped bit 127 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_99() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("27da374f17b7f1323844a5490bfc4081").unwrap();

		// Wycheproof test case comment: Flipped bit 63 and 127 in tag expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_100() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("00000000000000000000000000000000").unwrap();

		// Wycheproof test case comment: Tag changed to all zero expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_101() {
		let key =
			decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad = decode("616164").unwrap();
		let input = decode("00000000000000000000000000000000").unwrap();
		let output = decode("2cf8ae525fc86025268a4e1d88bead19").unwrap();
		let tag = decode("ffffffffffffffffffffffffffffffff").unwrap();

		// Wycheproof test case comment: tag change to all 1 expected
		// tag:27da374f17b7f1b23844a5490bfc4001

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_102() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("30303030303030300002506e").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("d4500bf009493551c380adf52c573a69df7e8b762463330facc16a5726be7190c63c5a1c926584a096756828dcdc64acdf963d931bf1dae238f3f157224ac4b542d785b0dd84db6be3bc5a3663e84149ffbed09e54f78f16a8223b24cb019f58b21b0e551e7aa07327629551376ccbc3937671a0629bd95c9915c78555771e7a").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("0b300d8da56c2185755279553c4c82ca").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_103() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("3030303030303030000318a5").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("7de87f6729945275d0655da4c7fde4569e16f111b5eb26c22d859e3ff822eced3a6dd9a60f22957f7b7c857e8822eb9fe0b8d7022141f2d0b48f4b5612d322a88dd0fe0b4d9179324f7c6c9e990efbd80e5ed6775826498b1efe0f71a0f3ec5b29cb28c2540a7dcd51b7daaee0ff4a7f3ac1ee54c29ee4c170de408f66692194").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("c578e2aa44d309b7b6a5193bdc6118f5").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_104() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("00000000000000000007b4f0").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("1b996f9a3ccc6785de22ff5b8add9502ce03a0faf5992a09522cdd1206d220b8f8bd07d1f1f5a1bd9a71d11c7f579b855818c08d4de036393183b7f590b335aed8de5b57b13c5fede2441c3e184aa9d46e61598506b3e11c43c62cbcaceced33190875b012218b1930fb7c38ec45ac11c353d0cf938dccb9efad8fedbe46daa5").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("4b0bda8ad043830d8319ab82c50c7663").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_105() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("00000000000000000020fb66").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("86cbacae4d3f74ae01213e0551cc15160ea1be8408e3d5d74f01464995a69e6176cb9e02b2247ed299892f9182a45caf4c69405611766edfafdc285519ea30480c44f05e781eacf8fcecc7090abb28fa5fd585ac8cda7e8772e594e4ce6c883281932e0f89f877a1f04d9c32b06cf90b0e762b430c4d517c97107068f498ef7f").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("4bc98f72c494c2a43c2b15a1043f1cfa").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_106() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("00000000000000000038bb90").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("fab1cddf4fe198ef63add881d6ead6c57637bbe92018ca7c0b96fba0871e932db1fbf90761be25df8dfaf931ce5757e617b3d7a9f0bf0ffe5d591a33c143b8f53fd0b5a19609fd62e5c251a4281a200cfdc34f281710406f4e37625446ff6ef224913deb0d89af337128e3d155d16d3ec3246041432143e9ab3a6d2ccc2f4d62").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("f7e9e151b02533c74658bfc7737c680d").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_107() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("00000000000000000070484a").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("227202be7f3515e9d1c02eea2f1950b6481b048a4c91506cb40d504e6c949f82d197c25ad17dc721651125782ac7a71247feaef32f1f250ce4bb8f79acaa179d45a7b0545f0924325efa87d5e441d28478c61f2223ee67c3b41f4394535e2a24369a2e16613c459490c14fb1d755fe53fbe1ee45b1b21f7162e2fcaa742abefd").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("795bcff647c553c2e4eb6e0eafd9e04e").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_108() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("000000000000000000932f40").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("fae58345c16cb0f5cc537f2b1b3469c969463b3ea71bcf6b98d669a8e60e04fc08d5fd069c362638e3400ef4cb242e27e2245e68cb9ec583da5340b12edf423b7326ad20feeb57daca2e0467a32899b42df8e56d84e006bc8a7acc731e7c1f6becb5719f7077f0d4f4c61ab11ebac1001801ce33c4e4a77d831d3ce34e8410e1").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("1946d653960f947a74d3e8093cf48502").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_109() {
		let key =
			decode("3030303030303030303030303030303030303030303030303030303030303030").unwrap();
		let nonce = decode("000000000000000000e29335").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("ebb216ddd7ca709215f503df9ce63c5cd2194e7d9099e8a90b2afaad5eba35069925a603fdbc341aaed41505b10941fa3856a7e247b1040709746cfc2096caa631b2fff41c250506d889c1c90671ade853ee6394c19192a5cf3710d1073099e5bc946582fc0fab9f543c716ae2486a8683fdca39d2e14f23d00a582664f4ecb1").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("36c3002985dd21baf895d633573f12c0").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_110() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000000ef7d5").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("408ae6ef1c7ef0fb2c2d610816fc7849efa58f78273f5f166ea65f81b575747d035b3040fede1eb9459788669788408e00413b3e376d152d204aa2b7a83558fcd48a0ef7a26b1cd6d35d23b3f5dfe0ca77a4ce32b94abf83da2aefcaf068380879e89fb0a3829595cf44c3852ae2cc662b689f9355d9c183801f6acc313f8907").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("6514518e0a264142e0b7351f967fc2ae").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_111() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000003dfce4").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("0a0a24499bcade58cf1576c312aca984718cb4cc7e0153f5a9015810859644dfc021174e0b060a397448de8b484a8603be680a6934c0906f30dd17eae2d4c5faa777f8ca53370e08331b88c342bac959787bbb33930e3b56be86da7f2a6eb1f94089d1d181074d4302f8e0552d0de1fab306a21b42d4c3ba6e6f0cbcc81e877a").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("4c194da6a99fd65b40e9cad798f44b19").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_112() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000018486a8").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("4a0aaff8494729188691701340f3ce2b8a78eed3a0f065994b72484e7991d25c29aa075eb1fc16de93fe069058112ab284a3ed18780326d1258a47222fa633d8b29f3bd9150b239b1546c2bb9b9f410febead396000ee477701532c3d0f5fbf895d280196d2f737c5e9fec50d92bb0df5d7e513be5b8ea971310d5bf16ba7aee").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("c8ae7788cd2874abc138541e11fd0587").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_113() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875c783d35f613e6d9093d38e975c38fe3b89f7aed35cb5a2fcaa0346efb936554649cf6378171eae4396ea15dc240d1abf4472d9096524fa1b2b023b8b288222773d4d206616f9293f65b45dbbc74e7c2edfbcbbf1cfb679bb739a5862de2bcb937f74d5bf8671c5a8a5092f61d54c9aa5b").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("933a5163c7f62368327b3fbc1036c943").unwrap();

		// Wycheproof test case comment: checking for int overflows

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_114() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("85ffffffffffffffffffffffffffffffa6902fcbc883bbc180b256ae34ad7f00").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("000102030405060708090a0b0c0d0e0f").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_115() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("ffffffffffffffffffffffffffffffff247e50642a1c0a2f8f77219609dba958").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("00000000000000000000000000000000").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_116() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("7cffffffffffffffffffffffffffffffd9e72c064ac8961f3fa585e0e2abd600").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("ffffffffffffffffffffffffffffffff").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_117() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("65ffffffffffffffffffffffffffffff95af0f4d0b686eaeccca4307d596f502").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("00000080000000800000008000000080").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_118() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("ffffffffffffffffffffffffffffffff8540b464357707be3a39d55c34f8bcb3").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("ffffff7fffffff7fffffff7fffffff7f").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_119() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("4fffffffffffffffffffffffffffffff6623d990b898d830d212af2383330701").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("01000000010000000100000001000000").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_120() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("000102030405060708090a0b").unwrap();
		let aad =
			decode("83ffffffffffffffffffffffffffffff5f16d09f17787211b7d484e024f89701").unwrap();
		let input = decode("9a49c40f8b48d7c66d1db4e53f20f2dd4aaa241ddab26b5bc0e218b72c3390f2df3ebd0176704419972bcdbc6bbcb3e4e74a71528ef51263ce24e0d575e0e44d").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
		let tag = decode("ffffffff000000000000000000000000").unwrap();

		// Wycheproof test case comment: special case tag

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_121() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("005235d2a919f28d3db7664a34ae6b444d3d35f613e6d9093d38e975c38fe3b85b8b94509e2b74a36d346e33d572659ba9f6378171eae4396ea15dc240d1abf483dce9f3073efadb7d23b87ace35168c").unwrap();
		let output = decode("0039e2fd2fd312149e989880884813e7caffffffffffffffffffffffffffffff3b0e869aaa8ea49632ffff37b9e8ce00caffffffffffffffffffffffffffffff3b0e869aaa8ea49632ffff37b9e8ce00").unwrap();
		let tag = decode("a519ac1a35b4a57787510af78d8d200a").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_122() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("d39428d079351f665cd001354319875ce5da78766fa19290c031f75208506745ae7aed35cb5a2fcaa0346efb93655464496ddeb05509c6efffab75eb2df4ab09762d9096524fa1b2b023b8b2882227730149ef504b71b120ca4ff39519c2c210").unwrap();
		let output = decode("d3ffffffffffffffffffffffffffffff6218b27f83b8b46602f6e1d834207b02ceffffffffffffffffffffffffffffff2a6416cedb1cdd296ef5d7d692daff02ceffffffffffffffffffffffffffffff2a6416cedb1cdd296ef5d7d692daff02").unwrap();
		let tag = decode("302fe82ab0a09af64400d015ae83d9cc").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_123() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("e99428d079351f665cd001354319875c6df1394edc539b5b3a0957be0fb85946807aed35cb5a2fcaa0346efb93655464d1769fe806bbfeb6f590950f2eac9e0a582d9096524fa1b2b023b8b2882227739952ae0818c38979c07413711a9af713").unwrap();
		let output = decode("e9ffffffffffffffffffffffffffffffea33f347304abdadf8ce413433c84501e0ffffffffffffffffffffffffffffffb27f579688aee57064ce37329182ca01e0ffffffffffffffffffffffffffffffb27f579688aee57064ce37329182ca01").unwrap();
		let tag = decode("98a7e836e0ee4d023500d0557ec2cbe0").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_124() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875c64f90f5b2692b860d4596ff4b3402c5c00b9bb53707aa667d356fe50c7199694033561e7caca6d941dc3cd6914ad6904").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffe33bc552ca8b9e96169e797e8f30301b603ca99944df76528c9d6f54ab833d0f603ca99944df76528c9d6f54ab833d0f").unwrap();
		let tag = decode("6ab8dce2c59da4737130b0252f68a8d8").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_125() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("689428d079351f665cd001354319875cb08f25675b9bcbf6e38407de2ec75a479f7aed35cb5a2fcaa0346efb936554642d2af7cd6b080501d31ba54fb2eb7596472d9096524fa1b2b023b8b288222773650ec62d757072cee6ff233186dd1c8f").unwrap();
		let output = decode("68ffffffffffffffffffffffffffffff374def6eb782ed002143115412b74600ffffffffffffffffffffffffffffffff4e233fb3e51d1ec7424507720dc5219dffffffffffffffffffffffffffffffff4e233fb3e51d1ec7424507720dc5219d").unwrap();
		let tag = decode("044dea608880412bfdffcf35579e9b26").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_126() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("6d9428d079351f665cd001354319875ca161b5ab040900629efeff78d7d86b459f7aed35cb5a2fcaa0346efb93655464c6f8078cc8ef12a0ff657d6d08db10b8472d9096524fa1b2b023b8b2882227738edc366cd697656fca81fb133ced79a1").unwrap();
		let output = decode("6dffffffffffffffffffffffffffffff26a37fa2e81026945c39e9f2eba87702ffffffffffffffffffffffffffffffffa5f1cff246fa09666e3bdf50b7f544b3ffffffffffffffffffffffffffffffffa5f1cff246fa09666e3bdf50b7f544b3").unwrap();
		let tag = decode("1e6bea6314542e2ef9ffcf450b2e982b").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_127() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875cfc01b891e5f0f9128d7d1c579192b69863414415b69968959a7291b7a5af134860cd9ea10c29a36654e7a28e761becd8").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff7bc3729809e9dfe44fba0addade2aadf03c456df823cb8a0c5b900b3c935b8d303c456df823cb8a0c5b900b3c935b8d3").unwrap();
		let tag = decode("ed2017c8dba4775629049d786e3bceb1").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_128() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875c6b6dc9d21a819e70b577f44137d3d6bd1335f5eb44494077b26449a54b6c7c7510b92f5ffef98b847cf17a9c98d883e5").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffffecaf03dbf698b88677b0e2cb0ba3cafa73b0e72170ec9042edafd8a127f6d7ee73b0e72170ec9042edafd8a127f6d7ee").unwrap();
		let tag = decode("073f17cb6778645925049d8822cbcab6").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_129() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ffcb2b1106f8234c5e99d4db4c7048de323d35f613e6d9093d38e975c38fe3b816e9884a114f0e9266cea3885fe36b9fd6f6378171eae4396ea15dc240d1abf4cebef5e9885a80ea76d975c144a41888").unwrap();
		let output = decode("ffa0fc3e8032c3d5fdb62a11f096307db5ffffffffffffffffffffffffffffff766c9a8025eadea73905328c3379c004b5ffffffffffffffffffffffffffffff766c9a8025eadea73905328c3379c004").unwrap();
		let tag = decode("8b9bb4b4861289658c696a8340150405").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_130() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("6f9e70ed3b8baca026e46a5a0943158d213d35f613e6d9093d38e975c38fe3b80c612c5e8d89a873dbcaad5b7346429bc5f6378171eae4396ea15dc240d1abf4d43651fd149c260bcbdd7b126801318c").unwrap();
		let output = decode("6ff5a7c2bd414c3985cb9490b5a56d2ea6ffffffffffffffffffffffffffffff6ce43e94b92c784684013c5f1fdce900a6ffffffffffffffffffffffffffffff6ce43e94b92c784684013c5f1fdce900").unwrap();
		let tag = decode("8b3bbd51644459568d81ca1fa72ce404").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_131() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("412b080a3e19c10d44a1af1eabdeb4ce353d35f613e6d9093d38e975c38fe3b86b8394330921486ca11d291c3e97ee9ad1f6378171eae4396ea15dc240d1abf4b3d4e9909034c614b10aff5525d09d8d").unwrap();
		let output = decode("4140df25b8d32194e78e51d41738cc6db2ffffffffffffffffffffffffffffff0b0686f93d849859fed6b818520d4501b2ffffffffffffffffffffffffffffff0b0686f93d849859fed6b818520d4501").unwrap();
		let tag = decode("86fbab2b4a94f47aa56f0aea65d11008").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_132() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("b247a74723491aacacaad709c91e932b313d35f613e6d9093d38e975c38fe3b89ade04e75bb701d9660601b34765de98d5f6378171eae4396ea15dc240d1abf442897944c2a28fa17611d7fa5c22ad8f").unwrap();
		let output = decode("b22c7068a583fa350f8529c375f8eb88b6fffffffffffffffffffffffffffffffa5b162d6f12d1ec39cd90b72bff7503b6fffffffffffffffffffffffffffffffa5b162d6f12d1ec39cd90b72bff7503").unwrap();
		let tag = decode("a019ac2ed667e17da16f0afa19610d0d").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_133() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("740f9e49f610efa585b659ca6ed8b4992d3d35f613e6d9093d38e975c38fe3b8412d96afbe80ec3e79d451b00a2db29ac9f6378171eae4396ea15dc240d1abf4997aeb0c2795624669c387f9116ac18d").unwrap();
		let output = decode("7464496670da0f3c2699a700d23ecc3aaaffffffffffffffffffffffffffffff21a884658a253c0b261fc0b466b71901aaffffffffffffffffffffffffffffff21a884658a253c0b261fc0b466b71901").unwrap();
		let tag = decode("736e18181696a5889c3159faabab20fd").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_134() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("adba5d105bc8aa062c2336cb889ddbd5373d35f613e6d9093d38e975c38fe3b8177c5ffe2875f468f6c2965748f3599ad3f6378171eae4396ea15dc240d1abf4cf2b225db1607a10e6d5401e53b42a8d").unwrap();
		let output = decode("add18a3fdd024a9f8f0cc801347ba376b0ffffffffffffffffffffffffffffff77f94d341cd0245da90907532469f201b0ffffffffffffffffffffffffffffff77f94d341cd0245da90907532469f201").unwrap();
		let tag = decode("bad58f10a91e6a889aba32fd17d8331a").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_135() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("fe9428d079351f665cd001354319875cc001edc5da442e719bce9abe273af144b47aed35cb5a2fcaa0346efb9365546448025f41fa4e336c786957a2a7c4930a6c2d9096524fa1b2b023b8b28822277300266ea1e43644a34d8dd1dc93f2fa13").unwrap();
		let output = decode("feffffffffffffffffffffffffffffff47c327cc365d088759098c341b4aed03d4ffffffffffffffffffffffffffffff2b0b973f745b28aae937f59f18eac701d4ffffffffffffffffffffffffffffff2b0b973f745b28aae937f59f18eac701").unwrap();
		let tag = decode("d68ce174079add028dd05cf814630488").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_136() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("b513b06ab9ac14435acb8aa3a37afdb6543d35f613e6d9093d38e975c38fe3b861950193b1bf0311ff117989aed9a999b0f6378171eae4396ea15dc240d1abf4b9c27c3028aa8d69ef06afc0b59eda8e").unwrap();
		let output = decode("b57867453f66f4daf9e474691f9c8515d3ffffffffffffffffffffffffffffff01101359851ad324a0dae88dc2430202d3ffffffffffffffffffffffffffffff01101359851ad324a0dae88dc2430202").unwrap();
		let tag = decode("aa48a3887d4b059699c2fdf9c6787e0a").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_137() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875cd4f109e814cea85a08c011d850dd1dcbcf7aed35cb5a2fcaa0346efb936554645340b85a9aa08296b77a5fc3961f660f172d9096524fa1b2b023b8b2882227731b6489ba84d8f559829ed9bda2290f16").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff5333c3e1f8d78eacca0707526cad018cafffffffffffffffffffffffffffffff3049702414b599502624fdfe29313204afffffffffffffffffffffffffffffff3049702414b599502624fdfe29313204").unwrap();
		let tag = decode("b936a817f2211af129e2cf160fd42bcb").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_138() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875cdf4c62032d4119b588477e99925a56d9d67aed35cb5a2fcaa0346efb93655464fa84f0645536421b2bb9246ec219ed0b0e2d9096524fa1b2b023b8b288222773b2a0c1844b4e35d41e5da210f62f8412").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff588ea80ac1583f434a806813ae2a4a9eb6ffffffffffffffffffffffffffffff998d381adb2359ddbae786537d37b900b6ffffffffffffffffffffffffffffff998d381adb2359ddbae786537d37b900").unwrap();
		let tag = decode("9f7ac4351f6b91e63097a713115d05be").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_139() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875c13f80a006dc1bbdad639a92fc7eca655f77aed35cb5a2fcaa0346efb936554646348b8fd29bf96d563a517e27d7bfc0f2f2d9096524fa1b2b023b8b2882227732b6c891d37c7e11a5641919c494d9516").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff943ac00981d89d2c14febfa5fb9cba1297ffffffffffffffffffffffffffffff00417083a7aa8d13f2fbb5dfc255a80497ffffffffffffffffffffffffffffff00417083a7aa8d13f2fbb5dfc255a804").unwrap();
		let tag = decode("9a18a828070269f44700d009e7171cc9").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_140() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875c82e59b4582915038f933811e652dc66afc7aed35cb5a2fcaa0346efb93655464b671c8cac270c265a0ac2f535799880a242d9096524fa1b2b023b8b288222773fe55f92adc08b5aa9548a92d63afe113").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff0527514c6e8876ce3bf49794595dda2d9cffffffffffffffffffffffffffffffd57800b44c65d9a331f28d6ee8b7dc019cffffffffffffffffffffffffffffffd57800b44c65d9a331f28d6ee8b7dc01").unwrap();
		let tag = decode("b436a82b93d555f74300d0199ba718ce").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_141() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("ff9428d079351f665cd001354319875cf1d12887b7216986a12d79098b6de60fc07aed35cb5a2fcaa0346efb93655464a7c75899f3e60af1fcb6c7307d87590f182d9096524fa1b2b023b8b288222773efe36979ed9e7d3ec952414e49b13016").unwrap();
		let output = decode("ffffffffffffffffffffffffffffffff7613e28e5b384f7063ea6f83b71dfa48a0ffffffffffffffffffffffffffffffc4ce90e77df311376de8650dc2a90d04a0ffffffffffffffffffffffffffffffc4ce90e77df311376de8650dc2a90d04").unwrap();
		let tag = decode("ce54a82e1fa942fa3f00d0294f3715d3").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_142() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("cbf1da9e0ba9377374e69e1c0e600cfc343d35f613e6d9093d38e975c38fe3b8be3fa66b6ce7808aa3e45949f944649fd0f6378171eae4396ea15dc240d1abf46668dbc8f5f20ef2b3f38f00e2031788").unwrap();
		let output = decode("cb9a0db18d63d7ead7c960d6b286745fb3ffffffffffffffffffffffffffffffdebab4a1584250bffc2fc84d95decf04b3ffffffffffffffffffffffffffffffdebab4a1584250bffc2fc84d95decf04").unwrap();
		let tag = decode("2383ab0b799205699b510aa709bf31f1").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_143() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("8f278694c4e9daebd58d3e5b966e8b68423d35f613e6d9093d38e975c38fe3b80653e7a331718833acc3b9adff1c3198a6f6378171eae4396ea15dc240d1abf4de049a00a864064bbcd46fe4e45b428f").unwrap();
		let output = decode("8f4c51bb42233a7276a2c0912a88f3cbc5ffffffffffffffffffffffffffffff66d6f56905d45806f30828a993869a03c5ffffffffffffffffffffffffffffff66d6f56905d45806f30828a993869a03").unwrap();
		let tag = decode("8bfbab17a9e0b8748b510ae7d9fd2305").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_144() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("d59428d079351f665cd001354319875c9a22d70a48e24fddcdd4419de64c8f44fc7aed35cb5a2fcaa0346efb9365546477b5c907d9c9e1ea51851a204aad9f0a242d9096524fa1b2b023b8b2882227733f91f8e7c7b1962564619c5e7e9bf613").unwrap();
		let output = decode("d5ffffffffffffffffffffffffffffff1de01d03a4fb692b0f135717da3c93039cffffffffffffffffffffffffffffff14bc017957dcfa2cc0dbb81df583cb019cffffffffffffffffffffffffffffff14bc017957dcfa2cc0dbb81df583cb01").unwrap();
		let tag = decode("49bc6e9fc51c4d503036644d842773d2").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_145() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("db9428d079351f665cd001354319875c75d5643aa5af934d8cce392cc3eedb47c07aed35cb5a2fcaa0346efb93655464601b5ad2067f28066a8f3281715ba808182d9096524fa1b2b023b8b288222773283f6b3218075fc95f6bb4ff456dc111").unwrap();
		let output = decode("dbfffffffffffffffffffffffffffffff217ae3349b6b5bb4e092fa6ff9ec700a0ffffffffffffffffffffffffffffff031292ac886a33c0fbd190bcce75fc03a0ffffffffffffffffffffffffffffff031292ac886a33c0fbd190bcce75fc03").unwrap();
		let tag = decode("63da6ea251f039532c36645d38b76fd7").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn wycheproof_test_case_146() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("0000000000000000064c2d52").unwrap();
		let aad = decode("ffffffff").unwrap();
		let input = decode("939428d079351f665cd001354319875c624839604216e403ebcc6af559ec8b43977aed35cb5a2fcaa0346efb93655464d8c8c3fa1a9e474abe52d02c8187e90f4f2d9096524fa1b2b023b8b28822277390ecf21a04e630858bb65652b5b18016").unwrap();
		let output = decode("93ffffffffffffffffffffffffffffffe58af369ae0fc2f5290b7c7f659c9704f7ffffffffffffffffffffffffffffffbbc10b84948b5c8c2f0c72113ea9bd04f7ffffffffffffffffffffffffffffffbbc10b84948b5c8c2f0c72113ea9bd04").unwrap();
		let tag = decode("73eb2724b5c405f04d00d0f15840a1c1").unwrap();

		// Wycheproof test case comment: edge case intermediate sums in poly1305

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_147() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("5f5f5f5f5f5f5f5f").unwrap();
		let aad = decode("").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("").unwrap();

		// Wycheproof test case comment: invalid nonce size

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_148() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("5f5f5f5f5f5f5f5f5f5f").unwrap();
		let aad = decode("").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("").unwrap();

		// Wycheproof test case comment: invalid nonce size

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_149() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("5f5f5f5f5f5f5f5f5f5f5f").unwrap();
		let aad = decode("").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("").unwrap();

		// Wycheproof test case comment: invalid nonce size

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_150() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("5f5f5f5f5f5f5f5f5f5f5f5f5f5f").unwrap();
		let aad = decode("").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("").unwrap();

		// Wycheproof test case comment: invalid nonce size

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	#[should_panic]
	fn wycheproof_test_case_151() {
		let key =
			decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
		let nonce = decode("5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f").unwrap();
		let aad = decode("").unwrap();
		let input = decode("").unwrap();
		let output = decode("").unwrap();
		let tag = decode("").unwrap();

		// Wycheproof test case comment: invalid nonce size

		chacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}
}
