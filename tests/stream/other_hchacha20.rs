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

// Testing against Monocypher-generated test vectors
// https://github.com/LoupVaillant/Monocypher/tree/master/tests/gen
// Pulled at commit: https://github.com/LoupVaillant/Monocypher/commit/39b164a5bf715d1a62689203b059144df76d98e2
#[cfg(test)]
mod monocypher_hchacha20 {

	use crate::stream::hchacha_test_runner as test_runner;

	#[test]
	fn test_case_0() {
		let key = "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207";
		let nonce = "48b3753cff3a6d990163e6b60da1e4e5";
		let expected_output = "d805447c583fd97a07a2b7ab66be621ad0fa32d63d86ac20588da90b87c1907b";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_1() {
		let key = "d6a2df78c16c96a52d4fb01ea4ecf70e81ac001b08d6577bd91ce991c4c45c46";
		let nonce = "bc84d5465fc9139bf17042ae7313181f";
		let expected_output = "66d1fd5e89a564b55ccf0c339455449c20dfbc9d17081c85fbb430a157777be9";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_2() {
		let key = "7afb217bd1eceeac1e133aaa9edb441fa88ea3ae0eaa06cb9911b6d218570f92";
		let nonce = "4a70a7e992b43e0b18578e892e954c40";
		let expected_output = "41119e28a00a9d3f24b1910495f3058f9db83cbcf12889de84a2fcd7de8dc31b";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_3() {
		let key = "a51abdb5a85d300c32f391c45d6ef4db043ddcf4214f24ea6ef6b181071f299a";
		let nonce = "a254a4606ab6a058e0c6fb5598218db7";
		let expected_output = "04c2f31fdcc7013ac7d10ec82e8d3628c9ab23b08bbf95d6d77ad2dec7e865d6";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_4() {
		let key = "1deb473f7d04c152e7e857736715dc7b788aca39a3c96a878019e8999c815c57";
		let nonce = "23dbfbde05e6c71f118afc0dedb5b9f8";
		let expected_output = "75e9a94daf28b6b8634823325c61cdcb2beeb17a8f7554cc6d5b1b1d2e3592cf";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_5() {
		let key = "dea398b2d764bca68dfc023a9821939d389e38a072cf1b413bb1517c3fe83abe";
		let nonce = "bb1cdf3a218abb1b0c01da64c24f59ee";
		let expected_output = "65a20993e8e69de41d38e94c0796cb7baccd6d80a6e4084e65d0d574fbcb7311";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_6() {
		let key = "d19cfb8cb3940aba546f0be57895e2cc869fe55aab069c5abcf9e7ba6444a846";
		let nonce = "e5d73f1c8c5376c1220ff3d9d53eeb65";
		let expected_output = "a345f5f10ec20b4a744634fbb94e94c9425699b4d57ffeab5403b8fbfb85bae7";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_7() {
		let key = "cc53599f40d6c8348c353b00172655236cddcd1879ca1f04b35f91adab70b81f";
		let nonce = "504035fc169964a5ae985e6c11b0b7bb";
		let expected_output = "11dda56dce88c92641177e2a6e21b11c5ca794912b3bceb9ccb375c87bcc7968";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_8() {
		let key = "18a51fd77fbffd722aa220efdd8947ca5a5c7fb1c2ebdb9ad1f603801ff22e80";
		let nonce = "314f716af9c22022fa159dbb4b4d3153";
		let expected_output = "14759f0e978a9f45a4696739fecb590b4ba6f06536384225333cccba074c8a68";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_9() {
		let key = "f999b20ab4769eb1d01c057c5295ed042b4536561dce32478b113adb5b605cac";
		let nonce = "75bcfcacb5e3e811b78e72e398fdd118";
		let expected_output = "564eb6b2ac2b92270af7c0b054cc7a721313e4ed3651b0970db9dfcdfda27220";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_10() {
		let key = "bf04c6a7ed0756a3533e3dca02109e1830b739210bd8bffe6a8a542980bd73e9";
		let nonce = "ca43cdd4eb7173476862df6d2458d6c7";
		let expected_output = "4f8975d01fb3525a60de55c61190471e86b95cb3e835374d58b003f55eb9819a";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_11() {
		let key = "4739a0ad2169b9c89edd74e16fbcecc748c25dc338041fc34af0f1bda20eaf3f";
		let nonce = "ff7b372aa801eb98a1298bc610280737";
		let expected_output = "06ccde41d10d6466859927bfc9a476dbc84064838ec721261cb548c18bd14c67";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_12() {
		let key = "50831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5";
		let nonce = "c9cd6f05d76b2bd4caec8d80b58235cb";
		let expected_output = "6ed040d7721395fb2c74c8afe252a169ded78e6f2f889e8fb0ec1490533a8154";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_13() {
		let key = "4268543ab0eb865a948cc5b5f6e31f05f8146bd9495acc459d6d200005ee72c3";
		let nonce = "bc3e4ae3badfd79adfe46b2ae1045f78";
		let expected_output = "19b839a6d3424cf2a52d301e70e76cb77368cf9f60945bf43ce4c657aeb1d157";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_14() {
		let key = "382e04c969df1a2d6a963a79c58401770a383248b5d70bb4adedcbe520fed634";
		let nonce = "f513b8c2ea6ab37fe633ba7302a5db6c";
		let expected_output = "fd0739819bae6c98cbde7cb50a80e8d0b359567c50cec1ca7e985745c1cedb3a";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_15() {
		let key = "2aa209e24478fa1bd6f6ffabe98555e034342cbec07364c54d1e407e282ef08e";
		let nonce = "dbfdbde936c9d42df58ae15889f5c939";
		let expected_output = "f5047baa0acf9a603415a09b64268d77712ae902c73490e9c53db593765726db";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_16() {
		let key = "a3087eaeac1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090fb607a";
		let nonce = "90c87defd622e5f55977877cec9ed883";
		let expected_output = "1d882fa80248882c6bc311a693ebd06b8c09aa2776e6e90df523d12bfeeed77a";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_17() {
		let key = "12b0411228540cd6dde6e84cd2da59b1871db119e3298e3c12fe8200a47eddf0";
		let nonce = "49c971cd99f694e3b2a5e25fa37aedf0";
		let expected_output = "69bb83ccb7bc4deaf60cfe168cb11fad4257222c3523c2d08922564ac0fb74d2";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_18() {
		let key = "1bf32e7c679a3187e22a635d301ce98ad000ca301049f2e891e403250c3358fc";
		let nonce = "2030b227bb96e93b88f419afe9f9d660";
		let expected_output = "d0ed414a875a81db1e4cff7609afdbb2ffcdd575ebc17543fb92de53c6487efb";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_19() {
		let key = "e013761228051ec5a8f0c093b33fc60e2cd7a9c845434e95d4319d79d1bdaa8f";
		let nonce = "73853fbd9958e9ffc23a0ecbb7b48dbb";
		let expected_output = "e3f6c6da6c0300103d665dd877a8b62e23b1361bf3af5bbc2310502131d69be8";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_20() {
		let key = "a63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a0015";
		let nonce = "85321bfee1714260dd6130cc768d20b1";
		let expected_output = "97e05360aca70058389d93be38d49fa26df01a4d3b4c4f10c3ec31e0ed64f08e";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_21() {
		let key = "4d3850f0eec0f8f349110e751c16cdb5ed05516df17479937d942c90eb1fb181";
		let nonce = "3062bd3f3f6b7668cd8fd3afce0cc752";
		let expected_output = "77513195542b2ab157cb2e6870c5b1ba143a8423ad276a64152ab923c6f54c06";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_22() {
		let key = "9b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99e";
		let nonce = "fa5ef6e59d3b201680f8e2d5a4ef7f23";
		let expected_output = "56a208bd87c5b486b5de50fbe4c1c476532f874147eba529cbb0cbeae8f09b94";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_23() {
		let key = "f1b6a8e102670a3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a0501";
		let nonce = "7d26e3afc3a88541f6c3f45d71f8a3cc";
		let expected_output = "a02140057f889e7ab36b4a5066e376dff248d13bd8072c384e23bd8fe4bf7047";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_24() {
		let key = "31a063ea4aad1b4d00db6f5228e9b9b1561a7f61812b8b79e6af4292580d02ea";
		let nonce = "4f6266d04244303304510272e383eaa5";
		let expected_output = "d610d44b8b3c14c7d3782f73405637fd14b7fada717665a9acbd4df6daa89adc";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_25() {
		let key = "1a8ea7099a74bafa3375b210653a0d2f40b15afd725cf5065066be1cb803dc15";
		let nonce = "8865ed8d7cca72dcf2b7c6b5d0d045bf";
		let expected_output = "f10cce296197a056bedbee166183ad6aaa56bdb21c3459296ca54c0bb78317d1";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_26() {
		let key = "32b063d3da484ba1843e071b61c49ce7f30ba18a4f7ef2730ecd785494839966";
		let nonce = "f593168e17311913753c59593fc66cb6";
		let expected_output = "f18115a9568724c25184728f563b65b737219cb0df1b3ce19a8bdcbdf7b8b2be";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_27() {
		let key = "64c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad9";
		let nonce = "2308df7e6daa8bf3efde75f80ad72a49";
		let expected_output = "06a24cb90abe94cf3ee8e429d8197bc42bc769fbe81119156274f9692aa017a2";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_28() {
		let key = "ae0794009e21ad33fa4141fe5fa79fed12f6a20f51614dc130f45598e92549b1";
		let nonce = "13ed6185724507e7fa5a7e8a75b2c7a3";
		let expected_output = "51d1aec8d64d20e448a377bfa83ccbf71a73a3ad00d062bf6b83c549a7296ef1";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_29() {
		let key = "ad700919f36a46ea0ffa680857e30188f8a03c7c4b6c11bc39aececec2668723";
		let nonce = "3682d31887277028e2fd286f2654c681";
		let expected_output = "a24610a94968df2dc9d197cd0bc55cab08c9dabd444c0efcd2a47fd37016382e";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_30() {
		let key = "efd9e7ed6b340874e897337d4dcc672811a6cf4b69086e0a57c266424dc1d10e";
		let nonce = "cbaf0c822cce9e4f17b19e0ece39c180";
		let expected_output = "6f94a0f8ed7f3fe5ebaa3b8caba016ab64373ffc3c7b1c86e6787f31b4a905ec";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_31() {
		let key = "a4c756c03c19900280ff6cdebe5174d507c6e0860c38c3537176c58965b74a56";
		let nonce = "c52b3151bb8a149cf4f82158d57c823f";
		let expected_output = "50ea3d4f6a45e4a062b2d966e63cac51e093dfb6ab9df6d16bb109bc177b0a38";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_32() {
		let key = "3a90c6b427912226ff604d9abee1fb8c8d35530a0cd5808e53e308ac580f7318";
		let nonce = "fe2ab2a4933b5d90db718aa3440fbe9b";
		let expected_output = "2b57adcc5d26060383c87ef7e055f9aca4addcb2646cbf2cff4edc3f17b72ad5";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_33() {
		let key = "a17f09716219bdffc93a189e410a6a3e6477fbb05c7c35956c3c0c5f342355fa";
		let nonce = "0850307998642501c025e3873ebac3cc";
		let expected_output = "d3a58c49e9fe1ecf2eca169f4d4131cde27279053d562d0429a08ec701aaa39e";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_34() {
		let key = "d749d8379ae6d830f785ec104897bd723d34ad20c9d36bfe371df46aebc6d459";
		let nonce = "5d490a770bee4dd0be6a5a0b5e95645c";
		let expected_output = "c278c0079bd656f1dadf3dec692f19f25339c6557542181716d2a41379740bf2";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_35() {
		let key = "7dcbc03c27010df3320fe75b0a3ecc8983ad94217e80348fd0f3f54e54b95bb5";
		let nonce = "48dc2225a264443732b41b861590358d";
		let expected_output = "b244c408c74f3dcb8bcb72f834a054c554edad0363d761847003dab003ac6848";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_36() {
		let key = "543894006b73f3d70fc04b15d0c2a5dfa650be5044fb5061811b866be7f9d623";
		let nonce = "fcb077ee19421610aeb263c57faef006";
		let expected_output = "fb20ea177cb7225c87122f285d92faf0c2033e2497575f74505255b6d3dfcb96";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_37() {
		let key = "62d424c07a7aa5005068b262251c0667a4e2e4b12f5df7f509564517887e370b";
		let nonce = "425fabab1ce9e733ab2911b42074414e";
		let expected_output = "3a5eb5552cdd267c05c1e4fe936ce8f0eaf7279ff328ed9a42d6d83f7b30416c";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_38() {
		let key = "387d7247fa5055489bbd4b7d4de256de723566c1c2d3ecee8c10e7d98233dbef";
		let nonce = "90494951ec91a843f6701f8216a7326b";
		let expected_output = "8c4bc60a1e05004ec93aef4ae162aeff43d679ea1ba048739c700d6a168bc6cc";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_39() {
		let key = "241fd57f32e09976de4054797b9aee820e0de381d02852ac13f511918267b703";
		let nonce = "7330e60ba1c5875a0275f8ccc75cbe98";
		let expected_output = "9e724c5b0321e2528278a501108f1ae8a14dffaea9b6b138eacef3bd8d4dda41";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_40() {
		let key = "7c12457eb5614f87f1fdc40118906d02c602059d48ae05ae62d3d607d6bf63c6";
		let nonce = "760b802483b0e3aaa9dd4f79c6c5e93e";
		let expected_output = "e5b86f76fbc1f488c44e4d7f304736b752ab6cfb99fcf6910668eeefa4b67c2a";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_41() {
		let key = "6b51da45018c6bde108f81f9abfa23640b83cfe3fed34bcf6640bf0baf647daf";
		let nonce = "e9bc99acee972b5a152efa3e69e50f34";
		let expected_output = "1032b5d539b1c8cd6e0be96db443a08fc759bea8988384435c03b5f00b6e485f";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_42() {
		let key = "3bc12887fec8e70db73b4b48dce564d83786aca4c6b7e224163ea928771fde37";
		let nonce = "78c453b35d98deced812fc5685843565";
		let expected_output = "2279b063dab4c73a96abe02175e694662c65d09eb5889234293c7a1f2911e13d";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_43() {
		let key = "b73d097601d3558278bd9d7327de5fdaa2b842050b370e837ef811a496169d5f";
		let nonce = "f768878766c08c45561fdc2aad6469c1";
		let expected_output = "a8e85a6ab627f08ad415649a9cf9998f4b1065030f3c844e31c8185036af7558";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_44() {
		let key = "1380c3d3f873c7233c541ea4c43824ecd8bf7e11ac8486208fb685218d46736e";
		let nonce = "51103d1fae0e8e368f25480ee7328381";
		let expected_output = "9b84e50804449b594a54240741e21d75d31050d2612f4cbc651fea2f25bd9c1f";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_45() {
		let key = "c2f8b252a18a29c44dbfbb62cbe6c3dfd4db55378734d8110b8f20f1d1ada6dd";
		let nonce = "d4da48fb09c06580eb46bbc5ca62bfab";
		let expected_output = "315c3fe1009e438762a72f27e7a68b8ccb2c0b60bf79cb6e48123db0c42d4aeb";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_46() {
		let key = "40b184271b73b710d40cb63435042c9b526d1e5c3a77bfc516a2bcb4cc27ecae";
		let nonce = "b3451318590c84e311dd1e876f527d81";
		let expected_output = "cbbde3a3412504c1f684aa273ee691159edc9f44e306360278d63d4ee2f1faa4";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_47() {
		let key = "ec81df06c7e426b729aebb02be30c846eb228490df4a0e6c688aaaa6bf05d144";
		let nonce = "28335f2652926bfdfe32dfd789173ba8";
		let expected_output = "522b522e4cf9aa1e80126a446ed7b9665af3e781a3d5afdce43a5fe0cdbd4351";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_48() {
		let key = "60fa0114802ee333d7c49ccaad8108db470c882514716592e57aba26bb75049b";
		let nonce = "75db088bd1a89c6a67fb76b96c987478";
		let expected_output = "e004cc12dfdb74268e59958385e2a1c6ff31e31664838971629f5bbf88f4ed51";
		test_runner(key, nonce, expected_output);
	}
	#[test]
	fn test_case_49() {
		let key = "bfba2449a607f3cca1c911d3b7d9cb972bcd84b0246189c7820032e031949f1e";
		let nonce = "97e8ad5eb5a75cc805900850969de48e";
		let expected_output = "19faebfbb954552fcfbf9b91f271c9397a15c641733c394a9cb731c286c68645";
		test_runner(key, nonce, expected_output);
	}
}
