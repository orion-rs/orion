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

#[cfg(test)]
mod boringssl_aead_xchacha20_poly1305 {

	extern crate hex;
	use self::hex::decode;
	use crate::aead::aead_test_runner as xchacha20_poly1305_test_runner;

	// Testing against BoringSSL test vector from [boringssl](https://boringssl.googlesource.com/boringssl/+/master/crypto/poly1305/poly1305_tests.txt).
	// Pulled at commit (master): 0f5ecd3a854546d943104e1f7421e489b7f4d5aa
	#[test]
	fn boringssl_test_case_1() {
		let key =
			decode("eb27969c7abf9aff79348e1e77f1fcba7508ceb29a7471961b017aef9ceaf1c2").unwrap();
		let nonce = decode("990009311eab3459c1bee84b5b860bb5bdf93c7bec8767e2").unwrap();
		let aad = decode("").unwrap();
		let input = decode("e7ec3d4b9f").unwrap();
		let output = decode("66bd484861").unwrap();
		let tag = decode("07e31b4dd0f51f0819a0641c86380f32").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_2() {
		let key =
			decode("4b6d89dbd7d019c0e1683d4c2a497305c778e2089ddb0f383f2c7fa2a5a52153").unwrap();
		let nonce = decode("97525eb02a8d347fcf38c81b1be5c3ba59406241cf251ba6").unwrap();
		let aad = decode("").unwrap();
		let input = decode("074db54ef9fbc680b41a").unwrap();
		let output = decode("1221898afd6f516f770f").unwrap();
		let tag = decode("75e7182e7d715f5a32ee6733fd324539").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_3() {
		let key =
			decode("766997b1dc6c3c73b1f50e8c28c0fcb90f206258e685aff320f2d4884506c8f4").unwrap();
		let nonce = decode("30e7a9454892ef304776b6dc3d2c2f767ed97041b331c173").unwrap();
		let aad = decode("").unwrap();
		let input = decode("b8250c93ac6cf28902137b4522cc67").unwrap();
		let output = decode("e2a13eeff8831a35d9336cb3b5c5d9").unwrap();
		let tag = decode("62fdf67735cad0172f9b88603b5f3c13").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_4() {
		let key =
			decode("6585031b5649fcabd9d4971d4ac5646fc7dca22f991dfa7dac39647001004e20").unwrap();
		let nonce = decode("705ee25d03fec430e24c9c6ccaa633f5b86dd43682778278").unwrap();
		let aad = decode("").unwrap();
		let input = decode("9a4ca0633886a742e0241f132e8f90794c34dfd4").unwrap();
		let output = decode("0a8e6fd4cd1640be77c4c87dde4ae6222c887ed7").unwrap();
		let tag = decode("edc4fbc91dfa07021e74ae0d9d1c98dc").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_5() {
		let key =
			decode("dfc6f7c86a10a319ebcb6362997e585f55b67f3434f47dc4039c2d67973e3077").unwrap();
		let nonce = decode("6097f30fd75229d928454c7d59a2d2c58bfddcb14c16438e").unwrap();
		let aad = decode("").unwrap();
		let input = decode("74c946a7f0733377e852a23087506a28dccef86e101a4359c0").unwrap();
		let output = decode("6e8ea0bb4c2f1323841d8e236816c61c3295866b75cefb5c25").unwrap();
		let tag = decode("f16c0e9487ca7de5e7cb2a1b8bb370fc").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_6() {
		let key =
			decode("59b8d488773767c4804d918709cfec6c69a193371145bb94f183899851aaadac").unwrap();
		let nonce = decode("ad5bdf8f190ca2d2cc02a75bb62aa22274cb3c98fe2d25f2").unwrap();
		let aad = decode("").unwrap();
		let input = decode("066b9ed10f16d3dc132b409aae02d8cac209dd9b4fb789c4d34725ab2a1f").unwrap();
		let output =
			decode("2bbd4542489006df66ad1462a932524642b139ddcbf86b6b480e9e6d976c").unwrap();
		let tag = decode("ca4835419ba029bc57010a8cc8bca80c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_7() {
		let key =
			decode("8c0cb4633cf8dc6b4b9552d1035f85517cb1ba4c36bcbc43338a8c6c7d15ce20").unwrap();
		let nonce = decode("8418b9655a0376fadefa3cdf8805815c4f7b56f467a74a95").unwrap();
		let aad = decode("").unwrap();
		let input =
			decode("50c205a9c5d4088ba8e59a96fcd837f5170669854547678288199f1078ff2a81f0b19a")
				.unwrap();
		let output =
			decode("8b55a12df1a85dd3fb19c34ab047a85849d15a30225bb5360bad1f0a8f5f2bd49f5898")
				.unwrap();
		let tag = decode("bce13201df6e4a7e6d896262e45d969d").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_8() {
		let key =
			decode("b45386a75a5772e34bd193e1946f69ebfb90c37ae4581d39c9669d75e4584f50").unwrap();
		let nonce = decode("9fb763d0926585b5f726af9b8e3babdb331e9aa97f8d99ed").unwrap();
		let aad = decode("").unwrap();
		let input = decode(
			"64df0e341145d9e4a0d090153591a74893bc36cb9dae1e9570d8fee62e907cf004f9d8a360343483",
		)
		.unwrap();
		let output = decode(
			"3146d8a5c898edd832ec9d126e93b3a433ec97dc47dce0e1985bda88c88c6aeca46fc7d9a68e30ab",
		)
		.unwrap();
		let tag = decode("44fdb0d69abd8068442cb2ea6df8b2f2").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_9() {
		let key =
			decode("f2efbd358dd353639a162be39a957d27c0175d5ab72aeba4a266aeda434e4a58").unwrap();
		let nonce = decode("65a6f7ebe48de78beb183b518589a0afacf71b40a949fa59").unwrap();
		let aad = decode("").unwrap();
		let input = decode("f7473947996e6682a3b9c720f03cfaf26bbcdaf76c83342d2ad922435e227a5d1eacbd9bd6ea1727ec19fb0e42").unwrap();
		let output = decode("778a0fb701b9d671ccfaf1454e8928158ede9bb4395119356a8133036840c1bcbb8fe5e19922fbbcf8b18596e7").unwrap();
		let tag = decode("9d195a89fdd29ca271405d3330f996f9").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_10() {
		let key =
			decode("9dd674fb4a30a7bb85fc78050479ab0e2c3cc9f9f5b8689a7a67413aca304b21").unwrap();
		let nonce = decode("ad9e8fe15940694725f232e88f79cda7c82fe1b8aae58ba4").unwrap();
		let aad = decode("").unwrap();
		let input = decode("7272bb6609cbd1399a0b89f6ea255165f99330aeb170ac88fccdd8e226df0952407e35718fb5edc9e987faabb271cc69f7e7").unwrap();
		let output = decode("846901650cb38974463a18c367676e1579ebdaf3e96b57224e842f5d5f678f3270b9a15f01241795662befb3db0768800e25").unwrap();
		let tag = decode("900004db3613acbeb33d65d74dd437d7").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_11() {
		let key =
			decode("280cbe7380a0d8bb4d8dd4476012f2eeb388a37b8b71067969abb99f6a888007").unwrap();
		let nonce = decode("2e1854617c67002599e6b077a812c326deb22fe29d093cbb").unwrap();
		let aad = decode("").unwrap();
		let input = decode("d0901ec3d31ece2832685ff577f383bdff26c31341ea254acee7c5929a5df74fea2aa964524dc680b2f55fbd4fea900e956c304cc4ac3c").unwrap();
		let output = decode("546370726cc63068d3520d67f4f57f65d03b9ecec21c2a8c7b1133089ad28b07025a7181bddeb4a49f514fac1a44f64ee3af33d778fb98").unwrap();
		let tag = decode("39084e33e42a1b05f58da65ba487d138").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_12() {
		let key =
			decode("887564f75afa78f595cdadcea7340d20f5c5a2df169d0ad14b15fe32ce337004").unwrap();
		let nonce = decode("54c11df13d1f444da80b0964caeb59474b17b23a650a33f5").unwrap();
		let aad = decode("").unwrap();
		let input = decode("f0f008eece79ecb24b715dff8a3456dfe253924b99f98f2f1b18564cced50925fca860d1c2d4785bdf4a964c76c3079efa6b37c4ba2cacc534fb590c").unwrap();
		let output = decode("32bb077268568d569b39e8ccdeeeb447ef424eaa2ffab565209a19b16a25952f897e5405bb0d67d8c9005d1c0b32687164d17fa4d0f412b80414c025").unwrap();
		let tag = decode("0bac7c0f8dce12917fbd4ed1738ac0cc").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_13() {
		let key =
			decode("0c97b9a65ffcd80b8f7c20c3904d0d6dd8809a7f97d7f46d39a12c198a85da5d").unwrap();
		let nonce = decode("1f2c1dbc5f52fc9c8f9ca7695515d01d15904b86f703fba3").unwrap();
		let aad = decode("bd8a6f18").unwrap();
		let input = decode("ecaf65b66d").unwrap();
		let output = decode("8d1b2b0e38").unwrap();
		let tag = decode("27a7c7ac8bda627085414f0f31206a07").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_14() {
		let key =
			decode("4ab5e3595f39c4379a924e5f8ebcf3279075c08d18daff01d9ddfa40e03faf12").unwrap();
		let nonce = decode("94e6ddc294f5f1531924ec018823343ebcc220a88ea5ee33").unwrap();
		let aad = decode("c576f6ea").unwrap();
		let input = decode("c91b73abe5316c3effc6").unwrap();
		let output = decode("abe960fbc64b339c53b1").unwrap();
		let tag = decode("7ebae48a2ff10117069324f04619ad6f").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_15() {
		let key =
			decode("a1e6146c71c2ea22300e9063455f621e15bd5bf1a3762e17f845e1aba5dd5a9c").unwrap();
		let nonce = decode("82ddb6929abff8a9ad03dfb86c0bb3e7c092d45ebfa60a1b").unwrap();
		let aad = decode("5d14bc05").unwrap();
		let input = decode("f011f32ccc2955158c117f53cf7b12").unwrap();
		let output = decode("44592321c665f51e9ffea052df1fea").unwrap();
		let tag = decode("d556798b97f9b647729801419424affc").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_16() {
		let key =
			decode("7a1af30362c27fd55b8c24b7fca324d350decee1d1f8fae56b66253a9dd127dd").unwrap();
		let nonce = decode("61201d6247992002e24e1a893180d4f0c19a3ae4cc74bf0c").unwrap();
		let aad = decode("00c49210").unwrap();
		let input = decode("5c7150b6a4daa362e62f82f676fdc4c4b558df64").unwrap();
		let output = decode("27d9e2730b6809c08efbd4b0d24639c7b67486f3").unwrap();
		let tag = decode("5889fdee25379960038778e36b2cedb2").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_17() {
		let key =
			decode("0b3fd9073e545ac44a7967263ead139c9547f7a54f06228fd3c8609fa2620784").unwrap();
		let nonce = decode("6450e1097d6f9ea76eb42e8e65972d501041c3a58baf8770").unwrap();
		let aad = decode("318d292b").unwrap();
		let input = decode("d679ae442b0351e5bff9906b099d45aab4f6aea5306a7a794f").unwrap();
		let output = decode("a3f9ee45316d7b0f948a26145ee4fd0552bc6dc25e577e777a").unwrap();
		let tag = decode("0068a401a194b8417ec0e198baa81830").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_18() {
		let key =
			decode("047c7d378fe80c02ee48df6f679a859253aed534fdcdd87023eb3d2f93fcafe3").unwrap();
		let nonce = decode("ed240b0ff6f8ac585b3ea1ab2dab8080fc2f6401b010c5d0").unwrap();
		let aad = decode("e4310302").unwrap();
		let input = decode("7288afb4e0fa5c58602090a75c10d84b5f5f1c0e03498519afe457251aa7").unwrap();
		let output =
			decode("87906b14ca3e32ab01523b31ae0bb74590ce9e1df0811e743a2c7a93415a").unwrap();
		let tag = decode("3a0abeab93792b1ffe768d316da74741").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_19() {
		let key =
			decode("1ad4e42acc5dfd07eb0a2456e9103cd0e150a36c667eb2f2b73c0d1ac1089ce3").unwrap();
		let nonce = decode("48efb52387284c5d38b4940c75f0c39a3f81f60bfebb48cb").unwrap();
		let aad = decode("446be8e3").unwrap();
		let input =
			decode("da7edb5b3193b4484f09efa85fcf85600968ecdc537d3829a469c866ee67b0df677866")
				.unwrap();
		let output =
			decode("b76457ca99e95b6539b12f1d6bdac55a6d5c6469b1ff274459363ec05241f7e6e5d3ce")
				.unwrap();
		let tag = decode("06880ee508ce929da5a81f8b9de0031c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_20() {
		let key =
			decode("702a554c1b703d4dd69ad51234293ab787a01e15bdb3ce88bf89e18c01a67164").unwrap();
		let nonce = decode("ea535d9c371241b9850b8b4a596b63db79eea60bd2cd9fbb").unwrap();
		let aad = decode("ba5790e3").unwrap();
		let input = decode(
			"a97156e9b39d05c00b811552d22088d7ee090a117a7f08adac574820d592021f16207720d49fb5fd",
		)
		.unwrap();
		let output = decode(
			"8d0b2b04479c33287096f0c6276a73f6c037edc1a2b28f8d3b2b8e6d4c5f9dc5113309dd3ecb15e6",
		)
		.unwrap();
		let tag = decode("3cf303305e12924d29c223976699fb73").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_21() {
		let key =
			decode("1bb7303fefa4d8d344bb9a215901b2314324bf1f3aeb9df5d1c1532c3a55ebf1").unwrap();
		let nonce = decode("a304551e5f0dc98995ddfee6215a9995023a3696debfd302").unwrap();
		let aad = decode("901c5feb").unwrap();
		let input = decode("6cf6819ce3e7ed9d4f85f4a5699701dbcaf3161adc210c0b7825ddfd83d6d7c685db62f68b3801ccc8a786066d").unwrap();
		let output = decode("bc5ef09c111f76e54f897e6fce4aee1d25b6ed934f641ed5262d0c5eed45f610a6aea3b58b7771e34256d43a16").unwrap();
		let tag = decode("b83f73f7995ba1b243dbf48ddfeb8e3a").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_22() {
		let key =
			decode("24b294f6cbac10d87158d1c6aca83b337d596132afac7633f69a3b3e58823f11").unwrap();
		let nonce = decode("805772ff619cc6fcc5ec0e9965435d6f74a2290c055ec754").unwrap();
		let aad = decode("7ae1c561").unwrap();
		let input = decode("65e8581286868caabcec1a9814db00b805edc660b94ee3babc6ce19a3ca868bd322105484d59b4ce02ced4071bc16642a1f2").unwrap();
		let output = decode("fe1d463b1466e8e411f0b0700f90760472ee5141f3e5afef43fd729f1623dca75cd4d00576765b335f8b2b77b00527599cb3").unwrap();
		let tag = decode("111d8540fd5ec04b9ba16ed810133026").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_23() {
		let key =
			decode("38e63e8b6402ac3f6d1641a1e3b74d2074be0fe41129975a3ff62b74ca52af05").unwrap();
		let nonce = decode("228d671b036710cbdaa72e9bf1d9ed6982b0bb3428a69fd6").unwrap();
		let aad = decode("e9e6ac73").unwrap();
		let input = decode("20a8d18878924d09aac32853c10e73dbd741134b7050ae6999839f2dbc727cb0052b5497c4bbd2a89e716278f15c81b871953614a49693").unwrap();
		let output = decode("80e0fe8eb26e5df229c6d939c944d440a37aa3cabf76eab5b9a420095513021ea4241ab367f6f44a20817b14631549ae6c96aa963970e1").unwrap();
		let tag = decode("1e80fbafcc7168e0494fce4cd76d692c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_24() {
		let key =
			decode("4325dd8406fdb8431a81f1b5db3603995256de36121019724cca2190c87a6e83").unwrap();
		let nonce = decode("dcbf3077b36d5d678d668fd2d0c99284c780b55c4658ea75").unwrap();
		let aad = decode("6fa0d757").unwrap();
		let input = decode("4f599ad04f79be9add10fdc649b8be53e1062ea5e9c2bed22265dc6fb30d5ab4fd4425b38ff14d8e68013405bec1eff8c9ef3069902e492aac73dcd9").unwrap();
		let output = decode("7decbdc7043495c59ecc64e720436bb0708b586a46f8745f74391477f5a2520905dfcebc3765a330999013d309dfaa997bf70bab6a0b8f4f2a2a3cdf").unwrap();
		let tag = decode("051ec4ecce208d9be0cd17f434e13be3").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_25() {
		let key =
			decode("09ec4e79a02db53b19b54dd2d3592afc92c74ef57d1e0f51f3726a6631b1b73f").unwrap();
		let nonce = decode("2907ced16e0777fedb1e2de30df11b3fd712af41dd714a4b").unwrap();
		let aad = decode("b5488e9b7f339b7b").unwrap();
		let input = decode("b6e50cd4ea").unwrap();
		let output = decode("0163e75330").unwrap();
		let tag = decode("e29401c6d756adcc516580ae656852aa").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_26() {
		let key =
			decode("9d5ac25a417b8a57b85332979e8a7cbad23617bb27772bbccc2acb0acae7b755").unwrap();
		let nonce = decode("ff152421688dd6af7fef87817b508493a32d97a06fbda4f3").unwrap();
		let aad = decode("892b793f7a6e0727").unwrap();
		let input = decode("92f4b9bc809be77e6a0d").unwrap();
		let output = decode("bcc594f59de8ee8c22c6").unwrap();
		let tag = decode("1a8275816c0d32a1b6cfd41fa3889558").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_27() {
		let key =
			decode("eccf80c5f744d2ecc932f95ade0d9fe9327e19795023db1846d68d04720a2401").unwrap();
		let nonce = decode("abc050fad8876589633b222d6a0f2e0bf709f73610aa23ee").unwrap();
		let aad = decode("c32c9a1ce6852046").unwrap();
		let input = decode("45a380e438405314510c166bac6840").unwrap();
		let output = decode("9fa452dc9ca04c16ff7bde9925e246").unwrap();
		let tag = decode("3d5e826162fa78de3fc043af26044a08").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_28() {
		let key =
			decode("b1912d6bc3cff47f0c3beccff85d7cd915b70ab88d0d3a8a59e994e1b0da8ac8").unwrap();
		let nonce = decode("d8756090a42eea14ff25be890e66bfe4949fad498776ea20").unwrap();
		let aad = decode("4576bb59b78032c8").unwrap();
		let input = decode("e2f85df2ebcfa6045bd521abfe8af37fc88a0be1").unwrap();
		let output = decode("5eb6324aa48e0a4f72f5cb0a4917faf93af4209c").unwrap();
		let tag = decode("774f8077f039588495045fee07950e14").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_29() {
		let key =
			decode("85162b111c9f3163f57c2cbc311a1e9aeed9dd6136b5784bc9c0b5052f8bffbd").unwrap();
		let nonce = decode("23cdb8b546bb8a5a746b24446f0ab4199f0543d915ff51f1").unwrap();
		let aad = decode("3084f3e9c4d0a15f").unwrap();
		let input = decode("dc81000077d5743beef09ac91663885d984212bbccf3dbe6f3").unwrap();
		let output = decode("692d17ae0b524ec6edc0cf49b69ac90c99bed44691f7ae63b7").unwrap();
		let tag = decode("efe72ff84b3bccb4d83a27ddc574bc21").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_30() {
		let key =
			decode("b05ca358d8ca79f51283d83e2673bfb741c379ba271a773b8dd9c6a108e758d3").unwrap();
		let nonce = decode("9a53ad79f535c6e9da011463063c896f2ec7645e6e3548fc").unwrap();
		let aad = decode("71ab5948c5e0f4c6").unwrap();
		let input = decode("44e793742c774020e7349c996418042dc0dc30ee2bfd2654008c8929a436").unwrap();
		let output =
			decode("c5eddb7aeaa175b5f3dab68cf746f2acaf56fc62b29804629e25e2d63879").unwrap();
		let tag = decode("bec3b7a8b8dad22ff3d14d26273294d2").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_31() {
		let key =
			decode("abb5136a01354c765a96e832df58bec3b088bd19dc4d6bd6674f2f02007ebdaa").unwrap();
		let nonce = decode("71267ac9f4fe5caa1d52cd85948a170a778f0141d54dbffe").unwrap();
		let aad = decode("047baa2b04748b62").unwrap();
		let input =
			decode("afb526fe41c4e2a767ce77c4145b9d054268f5f3b279237dec97f8bc46f9d158868b86")
				.unwrap();
		let output =
			decode("0032d4c1e65da2266539464c5d3c2b1618454a6af0e7f1e3cfc87845c75f2f4ae8b03f")
				.unwrap();
		let tag = decode("b526a95a33f17ab61f2cdfc1e2dd486a").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_32() {
		let key =
			decode("bb826ed38008a0d7fb34c0c1a1a1149d2cad16b691d5129cc83f5eff2b3e5748").unwrap();
		let nonce = decode("4e02fe0915d81e9d5a62e5b3551b9db882e3873c0aaa230d").unwrap();
		let aad = decode("db852a275081e29b").unwrap();
		let input = decode(
			"20270d291a8d9791b0f5e35a64387bb4237bad61169841d7e1667c994ad49869c7d5580ffa752a2d",
		)
		.unwrap();
		let output = decode(
			"d740012efb7e1bb986ce2c535134a45f658b92163c109bdecf1ce5b836879fe9e006a56be1fac8d7",
		)
		.unwrap();
		let tag = decode("21e931042e7df80695262198a06286c9").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_33() {
		let key =
			decode("938d2c59f6f3e2e7316726537932372e05e8c1b5577aae0ee870bf712ff001ab").unwrap();
		let nonce = decode("fb4d71cf7eb2f70df9759a64c76a36b75203f88bf64f4edb").unwrap();
		let aad = decode("a3fca278a63bf944").unwrap();
		let input = decode("8910415d674a93c54c8f5e4aa88e59648d9a0a5039a66837d58ab14f0665a5f6d9af9b839f9033d0fe8bc58f19").unwrap();
		let output = decode("1905c6987a702980b7f87f1ed2d3ae073abe1401b23434f3db43b5c37c979c2068ce9a92afedcdc218003848ea").unwrap();
		let tag = decode("1bd712f64777381f68be5ccc73f364a3").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_34() {
		let key =
			decode("dd0521842f498d23236692a22db0eb2f0f14fef57577e5fb194503e206b0973d").unwrap();
		let nonce = decode("519e0eee8f86c75c7a364e0905a5d10d82073e11b91083a5").unwrap();
		let aad = decode("bb5c4e5ae8f7e461").unwrap();
		let input = decode("61ff13acb99c5a7fd1921ec787c8de23c1a712ff002b08cecc644a78c47341eab78e7680380c93c7d53d5e56ef050d6ff192").unwrap();
		let output = decode("9bfdb0fd195fa5d37da3416b3b1e8f67bd2a456eb0317c02aabf9aac9d833a19bda299e6388e7b7119be235761477a34d49e").unwrap();
		let tag = decode("0f0c03b8423583cb8305a74f622fa1f9").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_35() {
		let key =
			decode("189bd84be3fb02723539b29cf76d41507c8b85b7217777ee1fb8f84a24aa7fee").unwrap();
		let nonce = decode("ef1bf39f22ba2edf86853505c24fafdf62c1a067963c63ba").unwrap();
		let aad = decode("93368a8e0900c7b6").unwrap();
		let input = decode("d5f96e240b5dd77b9fb2bf11c154fcbff312a791c3eb0717684e4fd84bf943e788050b47e76c427f42f3e5344b2636091603ba3b1d7a91").unwrap();
		let output = decode("c55a8b7f587bee4f97514582c5115582abffd6312914d76c2568be6836f62ba098789ed897c9a7508a5dc214bf8c218664f29941ccdfd6").unwrap();
		let tag = decode("78f87352dcb1143038c95dc6e7352cfd").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_36() {
		let key =
			decode("23a2dbfcd02d265805169fa86e6927c7d49c9a24d2707884e18955e32dafc542").unwrap();
		let nonce = decode("305c7851f46f23ea8d832d5ed09d266714fd14f82ba0f69c").unwrap();
		let aad = decode("0075b20502bd29b2").unwrap();
		let input = decode("224de94a938d49cad46144e657e548bd86690a1b57b81558095eace59df1c552600dea389aaa609304fbc1eadf2241f2118c8bdf04522e1898efe1d4").unwrap();
		let output = decode("8e10c59369bbb0d72958100b05788498f59588795e075b8bce21d92d320206348b04010ced9b8cd3d651e825488915ce4a6e4f1af2f4d2f77b955376").unwrap();
		let tag = decode("c39f0595ae8112dea6ef96df1c12458b").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_37() {
		let key =
			decode("d8ba98a272b5f91797b04b114311c3b92b7f2e3bb72edb7f78ed311b9f8ea2ad").unwrap();
		let nonce = decode("481de9a06eee76a501e3c2b9d7423d90596193ad9d8a6564").unwrap();
		let aad = decode("928653701f6d6c8429b08c0d").unwrap();
		let input = decode("9ee1a3134d").unwrap();
		let output = decode("459a07898f").unwrap();
		let tag = decode("9188ec8d8e3bd91dcfda48fcc76773f7").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_38() {
		let key =
			decode("ac9afd627a745df682bb003517056f07876eb94d2f8c610c61b6ac0d34ec4ec0").unwrap();
		let nonce = decode("eaae7b8704530db1e8c3dcc968a00604a333c7c27ba51b16").unwrap();
		let aad = decode("796620b367d5f041821baf69").unwrap();
		let input = decode("f7c3f6ee2e9c03394dc8").unwrap();
		let output = decode("d4a69005790cc91d8d34").unwrap();
		let tag = decode("e4c83def113afcf83a1ea8cb204a0eae").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_39() {
		let key =
			decode("ea1a07c1fd60a5421f1fb6c43b4318090e290c97aa3bfa037e6fc5ee00fd47d4").unwrap();
		let nonce = decode("37327805cce92b38a669affbca1de92e068727fcf6fbb09a").unwrap();
		let aad = decode("64e7c48fc3041eac0734737f").unwrap();
		let input = decode("7002ca765b91913ee719e7521ef5ac").unwrap();
		let output = decode("9d8857a8c52a9ab3bf44b024b191b6").unwrap();
		let tag = decode("d072c31714a7d0fe1596fd443a96e715").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_40() {
		let key =
			decode("b3beb34fe0229fc8f49b354e941025bde6a788f25017a60e8a49591ed5d7e7da").unwrap();
		let nonce = decode("dd0e9fec76de1f6efb022b12164f7e9248b8e8c01d14ac02").unwrap();
		let aad = decode("1489ca8d852f0a8547dbe8bc").unwrap();
		let input = decode("acf360d7529a42be1f132f74745a940da9e823f2").unwrap();
		let output = decode("2e8718372d6e8167213cf112dc41c80377244f5a").unwrap();
		let tag = decode("e4f31e8f84b9356999dc60989009e698").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_41() {
		let key =
			decode("9357cecd10bab8d2e42ed88c0386204827c3b76e9e51150d09fd4e3b4e0e1e6f").unwrap();
		let nonce = decode("81f2106a5379e0ed861cf76b3cf95afb17515478b5cbcae9").unwrap();
		let aad = decode("b80cb677f4b409cd1537363b").unwrap();
		let input = decode("ee51a0f25d091288b5e2b91ad11d491329e48b35a18a3a8685").unwrap();
		let output = decode("f681f19fa8de1fdea3538001a46f30fa6333b76d6439337e68").unwrap();
		let tag = decode("afad5e6d282d9df6d8119c32237b3e60").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_42() {
		let key =
			decode("9f868600fbf81e40398b7dfb201fcae35d34bba10908860b0b2bf8b942b4e8fa").unwrap();
		let nonce = decode("2ddcc13c97185614095d437900b8c0a9170e0a4a50e46ba5").unwrap();
		let aad = decode("0d61321fbee8bb1f3f5cb454").unwrap();
		let input = decode("133fa3ac176fee6df67472752e41c6834f13300c0064ff5b190f903b7ac7").unwrap();
		let output =
			decode("b93abb311ec0bf018dc300c7d511b42ade72780373186e231820b44f22f0").unwrap();
		let tag = decode("f8bd2f649a337783ff911e37966037bd").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_43() {
		let key =
			decode("05affcdfce0a28539924370db8d80a78b835254778ec41acbff52bfab092fa33").unwrap();
		let nonce = decode("3edaeb185f7273b1a7cccba54f84c5f7d6583433b49d3694").unwrap();
		let aad = decode("d7c213e9e6f4a40f3e5b662c").unwrap();
		let input =
			decode("7657581faad266cc1037962a380c8aa5306f88000427d0a05397696b503790ad2643c6")
				.unwrap();
		let output =
			decode("5eb19080aadc89f2329da4f5c41dc60568651c424c1b05d827f2bfb8dbff42c5a08224")
				.unwrap();
		let tag = decode("2da20087b5674f0b967d1baa664bbd82").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_44() {
		let key =
			decode("645ed60ec74ddfe1f02694792db4436c262d20405d8645cd9755d64876219799").unwrap();
		let nonce = decode("d83665b44c1fdf567299f2b8501e9c0e7ae2dda0bb8f2c82").unwrap();
		let aad = decode("57379f8f44191ec9cf3b1a07").unwrap();
		let input = decode(
			"ceee69d32ad4667a00909964d9611bf34fd98be41ad7f0feaaaff8169060d64cf310c13bcb9394cf",
		)
		.unwrap();
		let output = decode(
			"4496a0666f0f895ebce224b448a04502f2ae7b354d868b7c54295bf051162e82c530c767d1ffd2cc",
		)
		.unwrap();
		let tag = decode("1ffc56da4fb961ffdfabe66d82ec8f29").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_45() {
		let key =
			decode("06624c9a75bb7dbe224a3f23791281f53c40b407a14161a3f82f34924623dc02").unwrap();
		let nonce = decode("e647b8b4739bf542a81d72d695e1cd6ba348fa593987ac47").unwrap();
		let aad = decode("75536443a6c2189a57d553bb").unwrap();
		let input = decode("2658763f8d70e8c3303582d66ba3d736ce9d407e9507f6c6627e382d0144da157d73d0aee10ef034083cdd9013").unwrap();
		let output = decode("305cab5c2f9a6edccac307d6965febe3c86f2a1e31ac8c74e88924a10c2a29106bce980c803b7886985bba8ec5").unwrap();
		let tag = decode("8c12bb58c84175b9f601b704d0f8a25c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_46() {
		let key =
			decode("63aeb46083100bbcc430f4f09bcc34410df9cfd5883d629e4af8645ffabb89c2").unwrap();
		let nonce = decode("b09830874dc549195a5d6da93b9dcc12aa1ec8af201c96bd").unwrap();
		let aad = decode("7dcc05b0940198bd5c68cdf1").unwrap();
		let input = decode("1b3c9050e0a062f5a5cff7bec8706864cf8648142ec5cb1f9867ace384e9b2bba33aab8dc83e83b2d2fac70cd5189f2b5ab5").unwrap();
		let output = decode("d8b22e5d381de08a50b163c00dbbca6c07d61c80199cebd52234c7bd4f7ed0a90d47ef05617cdb8e3f782875ae629c0f0ad6").unwrap();
		let tag = decode("194077f0e6d415bf7307d171e8484a9c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_47() {
		let key =
			decode("4826c1bf8b48088fece4008922173c500ff45790f945b1027f36110da4fecc92").unwrap();
		let nonce = decode("3a78fc7397944d762303b0a75974ac92a60e250bf112600a").unwrap();
		let aad = decode("904d2cd3e50f7bfb9352f142").unwrap();
		let input = decode("d26e3a2b92120ff8056bb992660cc8a2364792589c16a518b8d232b8184aed05ba8d4fd0b2ad2b928cd873e11905a21ffece5f1e63c974").unwrap();
		let output = decode("21f4cf679662fad36f57945fc0c0753c3791261eb58d643278dfe1f14bfb585c5a01370ba96f18dc3f6b6945a2c6997330b24f12f5219a").unwrap();
		let tag = decode("95397c54428f9d069c511b5c82e0151c").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}

	#[test]
	fn boringssl_test_case_48() {
		let key =
			decode("ec526c03d8a08e8a63751112428a76399c399e8b83d98c9247c73164805ac8fe").unwrap();
		let nonce = decode("2cc1a6ae89c2a091415fa2964b44a0e5da629d40d77b77f1").unwrap();
		let aad = decode("35575b56716868b66cd21e24").unwrap();
		let input = decode("567377f5b6df5442e70bc9a31bc450bd4febfcf89d7ca611353c7e612d8b7e36e859f6365ec7e5e99e9e0e882532666dd7203d06f6e25439ed871237").unwrap();
		let output = decode("6b738274fe974438f1f5fca8ef1ee7df664f1e72bc54ccd3fb58c4a3df67ef9a73261df41ffe9c52aeafc8be4f6524baf9efb1558d4a57defec7bee3").unwrap();
		let tag = decode("92599d4b14a795e8c375ec2a8960b4dc").unwrap();

		xchacha20_poly1305_test_runner(&key, &nonce, &aad, &tag, &input, &output).unwrap();
	}
}
