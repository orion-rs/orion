use orion::hazardous::ecc::x25519::{x25519_with_err, Scalar};

pub mod wycheproof_x25519;

fn x25519_test_runner(expected_result: &[u8; 32], k: &[u8; 32], u: &[u8; 32], valid_result: bool) {
    let private = Scalar::from_slice(&k);

    if valid_result {
        let actual_result = x25519_with_err(&private, &u).unwrap();

        assert_eq!(actual_result, expected_result);
    } else {
        assert!(x25519_with_err(&private, &u).is_err());
    }
}
