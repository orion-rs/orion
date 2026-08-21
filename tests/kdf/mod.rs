#[cfg(feature = "safe_api")]
pub mod custom_argon2;
pub mod custom_hkdf;
pub mod custom_pbkdf2;
#[cfg(feature = "safe_api")]
pub mod custom_scrypt;
#[cfg(feature = "safe_api")]
pub mod other_argon2i;
pub mod other_hkdf;
#[cfg(feature = "safe_api")]
pub mod pynacl_argon2i;
#[cfg(feature = "safe_api")]
pub mod ref_argon2i;
#[cfg(feature = "safe_api")]
pub mod rfc9106_argon2;

pub mod rfc_pbkdf2;
pub mod wycheproof_hkdf;
pub mod wycheproof_pbkdf2;

use orion::hazardous::{
    kdf::{
        hkdf::{Hkdf, SHA256, SHA384, SHA512},
        pbkdf2,
    },
    mac::hmac,
};

macro_rules! impl_hkdf_test_runner (($name:ident, $hkdf:ident, $hmac_tag:ident) => (
    fn $name(
        expected_prk: Option<&[u8]>,
        expected_okm: &[u8],
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm_len: usize,
        valid_result: bool,
    ) {
        if expected_prk.is_some() {
            let actual_prk = Hkdf::<$hkdf>::extract(salt, &ikm).unwrap();
            assert_eq!(actual_prk, $hmac_tag::try_from(expected_prk.unwrap()).unwrap());
        }

        let mut okm_out = vec![0u8; okm_len];

        if valid_result {
            assert!(Hkdf::<$hkdf>::derive_key(salt, ikm, Some(&info), &mut okm_out).is_ok());
            assert_eq!(okm_out, expected_okm);
        } else {
            // If derivation call is OK, actual MUST NOT = expected
            if Hkdf::<$hkdf>::derive_key(salt, ikm, Some(&info), &mut okm_out).is_ok() {
                assert_ne!(okm_out, expected_okm);
            }
        }
    }
));

use hmac::sha256::Tag as Tag256;
use hmac::sha384::Tag as Tag384;
use hmac::sha512::Tag as Tag512;

impl_hkdf_test_runner!(hkdf256_test_runner, SHA256, Tag256);
impl_hkdf_test_runner!(hkdf384_test_runner, SHA384, Tag384);
impl_hkdf_test_runner!(hkdf512_test_runner, SHA512, Tag512);

fn pbkdf2_256_test_runner(
    expected_dk: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    dk_len: usize,
    valid_result: bool,
) {
    let mut dk_out = vec![0u8; dk_len];
    if valid_result {
        assert!(
            pbkdf2::Pbkdf2::<pbkdf2::SHA256>::derive_key(password, salt, iterations, &mut dk_out)
                .is_ok()
        );
        assert_eq!(dk_out, expected_dk);
    } else {
        unimplemented!("there aren't supposed to be these vectors")
    }
}

fn pbkdf2_384_test_runner(
    expected_dk: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    dk_len: usize,
    valid_result: bool,
) {
    let mut dk_out = vec![0u8; dk_len];
    if valid_result {
        assert!(
            pbkdf2::Pbkdf2::<pbkdf2::SHA384>::derive_key(password, salt, iterations, &mut dk_out)
                .is_ok()
        );
        assert_eq!(dk_out, expected_dk);
    } else {
        unimplemented!("there aren't supposed to be these vectors")
    }
}

fn pbkdf2_512_test_runner(
    expected_dk: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    dk_len: usize,
    valid_result: bool,
) {
    let mut dk_out = vec![0u8; dk_len];
    if valid_result {
        assert!(
            pbkdf2::Pbkdf2::<pbkdf2::SHA512>::derive_key(password, salt, iterations, &mut dk_out)
                .is_ok()
        );
        assert_eq!(dk_out, expected_dk);
    } else {
        unimplemented!("there aren't supposed to be these vectors")
    }
}
