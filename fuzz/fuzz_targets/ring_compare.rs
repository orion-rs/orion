#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
pub mod util;

use self::util::*;
use orion::hazardous::hkdf;
use orion::hazardous::hmac;
use orion::hazardous::pbkdf2;
use ring::digest;
use ring::hkdf::extract_and_expand as ring_hkdf;
use ring::hmac as ring_hmac;
use ring::pbkdf2 as ring_pbkdf2;

fn ro_hmac(data: &[u8]) {
    let (secret_key, message) = hmac_setup(data);
    let s_key = ring_hmac::SigningKey::new(&digest::SHA512, &secret_key);
    let ring_signature = ring_hmac::sign(&s_key, &message);

    let mut orion_hmac = hmac::init(&secret_key);
    orion_hmac.update(&message).unwrap();
    let orion_signature = orion_hmac.finalize().unwrap();

    let v_key = ring_hmac::VerificationKey::new(&digest::SHA512, &secret_key);

    let mut ring_res = false;
    let mut ring_res_switch = false;

    if ring_hmac::verify(&v_key, &message, orion_signature.as_ref()).is_ok() {
        ring_res = true;
    }

    if ring_hmac::verify(&v_key, &message, ring_signature.as_ref()).is_ok() {
        ring_res_switch = true;
    }

    let orion_res_switch = hmac::verify(orion_signature.as_ref(), &secret_key, &message).unwrap();
    let orion_res = hmac::verify(ring_signature.as_ref(), &secret_key, &message).unwrap();

    assert!(orion_res);
    assert!(orion_res_switch);
    assert!(ring_res);
    assert!(ring_res_switch);
}

fn ro_hkdf(data: &[u8]) {
    let (ikm, salt, info, mut okm_out_orion) = hkdf_setup(data);
    let mut okm_out_ring = okm_out_orion.clone();

    hkdf::derive_key(&salt, &ikm, &info, &mut okm_out_orion).unwrap();

    let s_key = ring_hmac::SigningKey::new(&digest::SHA512, &salt);
    ring_hkdf(&s_key, &ikm, &info, &mut okm_out_ring);
    assert_eq!(okm_out_orion, okm_out_ring);
}

fn ro_pbkdf2(data: &[u8]) {
    let (password, salt, mut dk_out_orion, iter) = pbkdf2_setup(data);
    let mut dk_out_ring = dk_out_orion.clone();

    pbkdf2::derive_key(&password, &salt, iter, &mut dk_out_orion).unwrap();
    ring_pbkdf2::derive(
        &digest::SHA512,
        iter as u32,
        &salt,
        &password,
        &mut dk_out_ring,
    );

    assert_eq!(&dk_out_ring, &dk_out_orion);
    assert!(
        ring_pbkdf2::verify(
            &digest::SHA512,
            iter as u32,
            &salt,
            &password,
            &dk_out_orion
        ).is_ok()
    );
    assert!(pbkdf2::verify(&dk_out_ring, &password, &salt, iter, &mut dk_out_orion).unwrap());
}

fuzz_target!(|data: &[u8]| {
    ro_hmac(data);
    ro_hkdf(data);
    ro_pbkdf2(data);
});
