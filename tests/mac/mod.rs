pub mod boringssl_poly1305;
pub mod nist_cavp_hmac;
pub mod other_poly1305;
//pub mod rfc_hmac;
pub mod rfc_poly1305;
pub mod wycheproof_hmac;

use orion::hazardous::hash::sha2;
use orion::hazardous::mac::{hmac, poly1305};
use poly1305::{OneTimeKey, Tag};

macro_rules! impl_hmac_test_runner (($name:ident, $hmac:ident, $hmac_tag:ident, $hmac_sk:ident, $sha2_outsize:ident) => (
    fn $name(
        expected: &[u8],
        secret_key: &[u8],
        data: &[u8],
        len_bytes: Option<usize>,
        valid_result: bool,
    ) {
        let len = match len_bytes {
            Some(length) => length,
            None => $sha2_outsize,
        };

        let key = $hmac_sk::from_slice(secret_key).unwrap();

        // Only use verify() on OUTSIZE length tags since this is
        // the amount that Tag requires.
        if len == $sha2_outsize {
            let expected_tag = $hmac_tag::from_slice(expected).unwrap();
            let res = $hmac::verify(&expected_tag, &key, data);
            if valid_result {
                assert!(res.is_ok());
            } else {
                assert!(res.is_err());
            }
        } else {
            let mut ctx =$hmac::new(&key);
            ctx.update(data).unwrap();
            let actual = ctx.finalize().unwrap();
            if valid_result {
                assert_eq!(expected, actual.unprotected_as_bytes()[..len].as_ref());
            } else {
                assert_ne!(expected, actual.unprotected_as_bytes()[..len].as_ref());
            }
        }
    }
));

use orion::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
use orion::hazardous::mac::hmac::sha256::{HmacSha256, SecretKey as SecretKey256, Tag as Tag256};

impl_hmac_test_runner!(
    hmac256_test_runner,
    HmacSha256,
    Tag256,
    SecretKey256,
    SHA256_OUTSIZE
);

use orion::hazardous::hash::sha2::sha384::SHA384_OUTSIZE;
use orion::hazardous::mac::hmac::sha384::{HmacSha384, SecretKey as SecretKey384, Tag as Tag384};

impl_hmac_test_runner!(
    hmac384_test_runner,
    HmacSha384,
    Tag384,
    SecretKey384,
    SHA384_OUTSIZE
);

use orion::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;
use orion::hazardous::mac::hmac::sha512::{HmacSha512, SecretKey as SecretKey512, Tag as Tag512};

impl_hmac_test_runner!(
    hmac512_test_runner,
    HmacSha512,
    Tag512,
    SecretKey512,
    SHA512_OUTSIZE
);

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
