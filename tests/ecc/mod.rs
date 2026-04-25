use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey, key_agreement};

pub mod wycheproof_x25519;

fn x25519_test_runner(expected_result: &[u8; 32], k: &[u8; 32], u: &[u8; 32], valid_result: bool) {
    let private = PrivateKey::try_from(k).unwrap();
    let public = PublicKey::try_from(u).unwrap();

    if valid_result {
        let actual_result = key_agreement(&private, &public).unwrap();

        assert_eq!(&actual_result, &expected_result.as_ref());
    } else {
        assert!(key_agreement(&private, &public).is_err());
    }
}
