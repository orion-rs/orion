pub mod custom_hkdf;
pub mod custom_pbkdf2;
#[cfg(feature = "safe_api")]
pub mod other_argon2i;
pub mod other_hkdf;
#[cfg(feature = "safe_api")]
pub mod pynacl_argon2i;
#[cfg(feature = "safe_api")]
pub mod ref_argon2i;
pub mod rfc_pbkdf2;
pub mod wycheproof_hkdf;
pub mod wycheproof_pbkdf2;

use orion::hazardous::{
    kdf::{hkdf, pbkdf2},
    mac::hmac,
};

macro_rules! impl_hkdf_test_runner (($name:ident, $extract:ident, $derive_key:ident, $hmac_tag:ident) => (
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
            let actual_prk = $extract(salt, &ikm).unwrap();
            assert_eq!(actual_prk, $hmac_tag::from_slice(expected_prk.unwrap()).unwrap());
        }

        let mut okm_out = vec![0u8; okm_len];

        if valid_result {
            assert!($derive_key(salt, ikm, Some(&info), &mut okm_out).is_ok());
            assert_eq!(okm_out, expected_okm);
        } else {
            // If derivation call is OK, actual MUST NOT = expected
            if $derive_key(salt, ikm, Some(&info), &mut okm_out).is_ok() {
                assert_ne!(okm_out, expected_okm);
            }
        }
    }
));

use hkdf::sha256::{derive_key as hkdf_derive_key256, extract as extract256};
use hmac::sha256::Tag as Tag256;

impl_hkdf_test_runner!(hkdf256_test_runner, extract256, hkdf_derive_key256, Tag256);

use hkdf::sha384::{derive_key as hkdf_derive_key384, extract as extract384};
use hmac::sha384::Tag as Tag384;

impl_hkdf_test_runner!(hkdf384_test_runner, extract384, hkdf_derive_key384, Tag384);

use hkdf::sha512::{derive_key as hkdf_derive_key512, extract as extract512};
use hmac::sha512::Tag as Tag512;

impl_hkdf_test_runner!(hkdf512_test_runner, extract512, hkdf_derive_key512, Tag512);

macro_rules! impl_pbkdf2_test_runner (($name:ident, $password:ident, $derive_key:ident) => (
    fn $name(
        expected_dk: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: usize,
        dk_len: usize,
        valid_result: bool,
    ) {
        let mut dk_out = vec![0u8; dk_len];
        let password = $password::from_slice(password).unwrap();

        if valid_result {
            assert!($derive_key(&password, salt, iterations, &mut dk_out).is_ok());
            assert_eq!(dk_out, expected_dk);
        } else {
            unimplemented!("there aren't supposed to be these vectors")
        }
    }
));

use pbkdf2::sha256::derive_key as pbkdf2_derive_key256;
use pbkdf2::sha256::Password as Password256;

impl_pbkdf2_test_runner!(pbkdf2_256_test_runner, Password256, pbkdf2_derive_key256);

use pbkdf2::sha384::derive_key as pbkdf2_derive_key384;
use pbkdf2::sha384::Password as Password384;

impl_pbkdf2_test_runner!(pbkdf2_384_test_runner, Password384, pbkdf2_derive_key384);

use pbkdf2::sha512::derive_key as pbkdf2_derive_key512;
use pbkdf2::sha512::Password as Password512;

impl_pbkdf2_test_runner!(pbkdf2_512_test_runner, Password512, pbkdf2_derive_key512);
