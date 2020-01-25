pub mod custom_hkdf;
pub mod custom_pbkdf2;
pub mod other_hkdf;

extern crate orion;
use self::orion::hazardous::{kdf::hkdf::*, mac::hmac};

pub fn hkdf_test_runner(
    excp_prk: Option<&[u8]>,
    excp_okm: &[u8],
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_out: &mut [u8],
) -> bool {
    if excp_prk.is_some() {
        let actual_prk = extract(salt, &ikm).unwrap();
        assert!(actual_prk == hmac::Tag::from_slice(excp_prk.unwrap()).unwrap());
    }

    // verify() also runs derive_key()
    verify(excp_okm, salt, ikm, Some(&info), &mut okm_out.to_vec()).is_ok()
}
