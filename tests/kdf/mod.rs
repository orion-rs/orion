pub mod custom_hkdf;
pub mod custom_pbkdf2;
pub mod rfc_pbkdf2;
#[cfg(feature = "safe_api")]
pub mod other_argon2i;
pub mod other_hkdf;
#[cfg(feature = "safe_api")]
pub mod pynacl_argon2i;
#[cfg(feature = "safe_api")]
pub mod ref_argon2i;
pub mod wycheproof_hkdf;

use orion::hazardous::{kdf::hkdf, mac::hmac};

macro_rules! impl_hkdf_test_runner (($name:ident, $extract:ident, $verify:ident, $hmac_tag:ident) => (
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
            assert!(actual_prk == $hmac_tag::from_slice(expected_prk.unwrap()).unwrap());
        }

        let mut okm_out = vec![0u8; okm_len];

        // verify() also runs derive_key()
        if valid_result {
            assert!($verify(expected_okm, salt, ikm, Some(&info), &mut okm_out).is_ok());
        } else {
            assert!($verify(expected_okm, salt, ikm, Some(&info), &mut okm_out).is_err());
        }
    }
));

use hkdf::sha256::{extract as extract256, verify as verify256};
use hmac::sha256::Tag as Tag256;

impl_hkdf_test_runner!(hkdf256_test_runner, extract256, verify256, Tag256);

use hkdf::sha384::{extract as extract384, verify as verify384};
use hmac::sha384::Tag as Tag384;

impl_hkdf_test_runner!(hkdf384_test_runner, extract384, verify384, Tag384);

use hkdf::sha512::{extract as extract512, verify as verify512};
use hmac::sha512::Tag as Tag512;

impl_hkdf_test_runner!(hkdf512_test_runner, extract512, verify512, Tag512);
