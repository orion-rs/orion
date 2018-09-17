#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;
extern crate ring;

use orion::hazardous::hkdf;
use orion::hazardous::hmac;
use orion::hazardous::pbkdf2;
use rand::prelude::*;
use ring::digest;
use ring::hkdf::extract_and_expand as ring_hkdf;
use ring::hmac as ring_hmac;
use ring::pbkdf2 as ring_pbkdf2;

fn return_digest() -> &'static digest::Algorithm {
    &digest::SHA512
}

fn ro_hmac(buf1: &[u8], buf2: &[u8]) {
    let key = buf1;
    let message = buf2;

    let s_key = ring_hmac::SigningKey::new(return_digest(), key);
    let ring_signature = ring_hmac::sign(&s_key, message);

    let mut orion_hmac = hmac::init(key);
    orion_hmac.update(message).unwrap();
    let orion_signature = orion_hmac.finalize().unwrap();

    let v_key = ring_hmac::VerificationKey::new(return_digest(), key);

    let mut ring_res = false;
    let mut ring_res_switch = false;

    if ring_hmac::verify(&v_key, message, orion_signature.as_ref()).is_ok() {
        ring_res = true;
    }

    if ring_hmac::verify(&v_key, message, ring_signature.as_ref()).is_ok() {
        ring_res_switch = true;
    }

    let orion_res_switch = hmac::verify(orion_signature.as_ref(), key, message).unwrap();
    let orion_res = hmac::verify(ring_signature.as_ref(), key, message).unwrap();

    assert!(orion_res);
    assert!(orion_res_switch);
    assert!(ring_res);
    assert!(ring_res_switch);
}

fn ro_hkdf(buf1: &[u8], buf2: &[u8], buf3: &[u8]) {
    let salt = buf1;
    let ikm = buf2;
    let info = buf3;

    let mut rng = thread_rng();
    let okm_len: usize = rng.gen_range(1, 8161);

    let mut out_okm = vec![0u8; okm_len];
    let mut out_okm_orion = vec![0u8; okm_len];

    hkdf::derive_key(salt, ikm, info, &mut out_okm_orion).unwrap();

    let s_key = ring_hmac::SigningKey::new(return_digest(), salt);
    ring_hkdf(&s_key, ikm, info, &mut out_okm);
    assert_eq!(out_okm_orion, out_okm);
}

fn ro_pbkdf2(buf1: &[u8], buf2: &[u8]) {
    let salt = buf1;
    let password = buf2;

    let mut rng = rand::thread_rng();
    let iter: usize = rng.gen_range(1, 10001);
    let len: usize = rng.gen_range(1, 129);

    let mut dk_out = vec![0u8; len];
    let mut dk_out_orion = vec![0u8; len];

    pbkdf2::derive_key(&password, &salt, iter, &mut dk_out_orion).unwrap();
    ring_pbkdf2::derive(return_digest(), iter as u32, &salt, &password, &mut dk_out);

    assert_eq!(&dk_out, &dk_out_orion);
    assert!(ring_pbkdf2::verify(return_digest(), iter as u32, &salt, &password, &dk_out_orion).is_ok());
    assert!(pbkdf2::verify(&dk_out, password, salt, iter, &mut dk_out_orion).unwrap());
}

fuzz_target!(|data: &[u8]| {
    ro_hmac(data, data);

    ro_hkdf(data, data, data);

    ro_pbkdf2(data, data);
});
