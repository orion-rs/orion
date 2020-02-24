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
        let plaintext = decode(
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
        let expected = decode(
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

        chacha_test_runner(&key, &nonce, 0, &plaintext, &expected);
    }

    #[test]
    fn xchacha20_encryption_test_2() {
        let key =
            decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode("404142434445464748494a4b4c4d4e4f5051525354555658").unwrap();
        let expected = decode(
                "29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a255e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe462215cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf607cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290fa0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00b3df507ca8c924f7017b7e712d15a2eb5c50484451e54e1b4b995bd8fdd94597bb94d7af0b2c04df10ba0890899ed9293a0f55b8bafa999264035f1d4fbe7fe0aafa109a62372027e50e10cdfecca127",
        )
        .unwrap();

        chacha_test_runner(&key, &nonce, 1, &vec![0u8; expected.len()], &expected);
    }

    #[test]
    fn xchacha20_encryption_test_3() {
        let key =
            decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode("404142434445464748494a4b4c4d4e4f5051525354555658").unwrap();
        let plaintext = "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.";
        let expected = decode(
                "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee053a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd20112f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d316838a9c71f70b5b5907a66f7ea49aadc409",
        )
        .unwrap();

        chacha_test_runner(&key, &nonce, 1, plaintext.as_bytes(), &expected);
    }

    #[test]
    fn xchacha20_encryption_test_4() {
        let key =
            decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode("404142434445464748494a4b4c4d4e4f5051525354555658").unwrap();
        let expected = decode(
                "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9aadec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a255e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe462215cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf607cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290fa0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00b3df507ca8c924f7017b7e712d15a2eb",
        )
        .unwrap();

        chacha_test_runner(&key, &nonce, 0, &vec![0u8; 304], &expected);
    }

    #[test]
    fn xchacha20_encryption_test_5() {
        let key =
            decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode("404142434445464748494a4b4c4d4e4f5051525354555658").unwrap();
        let plaintext = "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.";
        let expected = decode(
                "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5",
        )
        .unwrap();

        chacha_test_runner(&key, &nonce, 0, plaintext.as_bytes(), &expected);
    }
}
