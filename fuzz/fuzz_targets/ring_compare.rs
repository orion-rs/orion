#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
extern crate rand;


use ring::digest;
use ring::hmac as ring_hmac;
use ring::hkdf::*;
use ring::pbkdf2 as ring_pbkdf2;
use orion::hazardous::hmac;
use orion::hazardous::hkdf;
use orion::hazardous::pbkdf2;
use orion::core::options;
use orion::core::util::*;
use rand::prelude::*;

fn return_rand_data() -> Vec<u8> {

    let mut rng = thread_rng();
    let key_len = rng.gen_range(1, 256);

    gen_rand_key(key_len).unwrap()
}

fn ro_hmac(buf1: &[u8], buf2: &[u8]) {

    let choices = [
        options::ShaVariantOption::SHA256,
        options::ShaVariantOption::SHA384,
        options::ShaVariantOption::SHA512,
        options::ShaVariantOption::SHA512Trunc256,
    ];

    let mut rng = thread_rng();
    let hmac_choice = rng.choose(&choices).unwrap();

    let ring_digest = match *hmac_choice {
            options::ShaVariantOption::SHA256 => &digest::SHA256,
            options::ShaVariantOption::SHA384 => &digest::SHA384,
            options::ShaVariantOption::SHA512 => &digest::SHA512,
            options::ShaVariantOption::SHA512Trunc256 => &digest::SHA512_256,
    };


    let key = buf1.to_vec();
    let message = buf2.to_vec();

    let s_key = ring_hmac::SigningKey::new(&ring_digest, key.as_ref());
    let ring_signature = ring_hmac::sign(&s_key, message.as_ref());

    let orion_hmac = hmac::Hmac {
        secret_key: key.to_vec(),
        data: message.to_vec(),
        sha2: *hmac_choice,
    };

    let orion_signature = orion_hmac.finalize();
    let v_key = ring_hmac::VerificationKey::new(&ring_digest, key.as_ref());


    let mut ring_res = false;
    let mut ring_res_switch = false;

    if ring_hmac::verify(&v_key, message.as_ref(), orion_signature.as_ref()).is_ok() {
        ring_res = true;
    }

    if ring_hmac::verify(&v_key, message.as_ref(), ring_signature.as_ref()).is_ok() {
        ring_res_switch = true;
    }

    let orion_res_switch = orion_hmac.verify(orion_signature.as_ref()).unwrap();
    let orion_res = orion_hmac.verify(ring_signature.as_ref()).unwrap();

    assert!(orion_res);
    assert!(orion_res_switch);
    assert!(ring_res);
    assert!(ring_res_switch);

}

fn ro_hkdf(buf1: &[u8], buf2: &[u8], buf3: &[u8]) {


    let salt = buf1.to_vec();
    let ikm = buf2.to_vec();
    let info = buf3.to_vec();

    let mut rng = thread_rng();

    let choices = [
        options::ShaVariantOption::SHA256,
        options::ShaVariantOption::SHA384,
        options::ShaVariantOption::SHA512,
        options::ShaVariantOption::SHA512Trunc256,
    ];

    let hmac_choice = rng.choose(&choices).unwrap();

    let ring_digest = match *hmac_choice {
            options::ShaVariantOption::SHA256 => &digest::SHA256,
            options::ShaVariantOption::SHA384 => &digest::SHA384,
            options::ShaVariantOption::SHA512 => &digest::SHA512,
            options::ShaVariantOption::SHA512Trunc256 => &digest::SHA512_256,
    };

    let okm_len: usize = match *hmac_choice {
            options::ShaVariantOption::SHA256 => rng.gen_range(1, 8161),
            options::ShaVariantOption::SHA384 => rng.gen_range(1, 12241),
            options::ShaVariantOption::SHA512 => rng.gen_range(1, 16321),
            options::ShaVariantOption::SHA512Trunc256 => rng.gen_range(1, 8161),
    };

    let mut out_okm = vec![0u8; okm_len];

    let orion_hkdf = hkdf::Hkdf {
        salt: salt.to_vec(),
        ikm: ikm.to_vec(),
        info: info.to_vec(),
        length: okm_len,
        hmac: *hmac_choice,
    };


    let orion_prk = orion_hkdf.extract(&orion_hkdf.salt, &orion_hkdf.ikm);
    let orion_okm = orion_hkdf.expand(&orion_prk).unwrap();
    let orion_derived = orion_hkdf.derive_key().unwrap();


    let s_key = ring_hmac::SigningKey::new(&ring_digest, salt.as_ref());
    let ring_prk = extract(&s_key, ikm.as_ref());
    expand(&ring_prk, &info, &mut out_okm);
    assert_eq!(orion_okm, out_okm);

    extract_and_expand(&s_key, ikm.as_ref(), &info, &mut out_okm);
    assert_eq!(orion_derived, out_okm);
}

fn ro_pbkdf2(buf1: &[u8], buf2: &[u8]) {

    let salt = buf1.to_vec();
    let password = buf2.to_vec();

    let mut rng = rand::thread_rng();

    let choices = [
        options::ShaVariantOption::SHA256,
        options::ShaVariantOption::SHA384,
        options::ShaVariantOption::SHA512,
        options::ShaVariantOption::SHA512Trunc256,
    ];

    let iter: usize = rng.gen_range(1, 10001);
    let hmac_choice = rng.choose(&choices).unwrap();
    let len: usize = rng.gen_range(1, 128);

    let mut dk_out = vec![0u8; len];

    let ring_digest = match *hmac_choice {
            options::ShaVariantOption::SHA256 => &digest::SHA256,
            options::ShaVariantOption::SHA384 => &digest::SHA384,
            options::ShaVariantOption::SHA512 => &digest::SHA512,
            options::ShaVariantOption::SHA512Trunc256 => &digest::SHA512_256,
    };

    let dk = pbkdf2::Pbkdf2 {
        password: password.to_vec(),
        salt: salt.to_vec(),
        iterations: iter,
        dklen: len,
        hmac: *hmac_choice
    };

    ring_pbkdf2::derive(ring_digest, iter as u32, &salt, &password, &mut dk_out);

    let orion_dk = dk.derive_key().unwrap();

    assert_eq!(dk_out, orion_dk);

    assert!(ring_pbkdf2::verify(ring_digest, iter as u32, &salt, &password, &dk_out).is_ok());
    assert!(ring_pbkdf2::verify(ring_digest, iter as u32, &salt, &password, &orion_dk).is_ok());
    assert!(dk.verify(&dk_out).is_ok());
    assert!(dk.verify(&orion_dk).is_ok());
}






fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let rand_key = return_rand_data();

    ro_hmac(data, data);
    ro_hmac(&rand_key, data);
    ro_hmac(data, &rand_key);
    ro_hmac(&rand_key, &rand_key);

    ro_hkdf(data, data, data);
    ro_hkdf(&rand_key, data, data);
    ro_hkdf(data, &rand_key, data);
    ro_hkdf(data, data, &rand_key);
    ro_hkdf(&rand_key, &rand_key, data);
    ro_hkdf(&rand_key, &rand_key, &rand_key);

    ro_pbkdf2(data, data);
    ro_pbkdf2(&rand_key, data);
    ro_pbkdf2(data, &rand_key);
    ro_pbkdf2(&rand_key, &rand_key);
});
