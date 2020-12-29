pub mod boringssl_poly1305;
pub mod nist_cavp_hmac;
pub mod other_poly1305;
pub mod rfc_hmac;
pub mod rfc_poly1305;
pub mod wycheproof_hmac_sha512;

use orion::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;
use orion::hazardous::mac::{hmac, poly1305};
use poly1305::{OneTimeKey, Tag};

fn hmac_test_runner(
    expected: &[u8],
    secret_key: &[u8],
    data: &[u8],
    len_bytes: Option<usize>,
    valid_result: bool,
) {
    let len = match len_bytes {
        Some(length) => length,
        None => SHA512_OUTSIZE,
    };

    let key = hmac::SecretKey::from_slice(secret_key).unwrap();

    // Only use verify() on SHA512_OUTSIZE length tags since this is
    // the amount that Tag requires.
    if len == SHA512_OUTSIZE {
        let expected_tag = hmac::Tag::from_slice(expected).unwrap();
        let res = hmac::Hmac::verify(&expected_tag, &key, data);
        if valid_result {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
        }
    } else {
        let mut ctx = hmac::Hmac::new(&key);
        ctx.update(data).unwrap();
        let actual = ctx.finalize().unwrap();
        if valid_result {
            assert_eq!(expected, actual.unprotected_as_bytes()[..len].as_ref());
        } else {
            assert_ne!(expected, actual.unprotected_as_bytes()[..len].as_ref());
        }
    }
}

fn poly1305_test_runner(key: &[u8], input: &[u8], output: &[u8]) {
    let sk = OneTimeKey::from_slice(key).unwrap();

    let mut state = poly1305::Poly1305::new(&sk);
    state.update(input).unwrap();
    let tag_stream = state.finalize().unwrap();

    let tag_one_shot = poly1305::Poly1305::poly1305(&sk, input).unwrap();

    assert!(tag_stream == output);
    assert!(tag_one_shot == output);
    assert!(poly1305::Poly1305::verify(&Tag::from_slice(&output).unwrap(), &sk, input).is_ok());
}
