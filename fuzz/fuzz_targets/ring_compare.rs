#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
extern crate rand;


use ring::digest;
use ring::hmac as ring_hmac;
use orion::hazardous::hmac;
use orion::core::options;
use orion::core::util::*;
use rand::prelude::*;


fn return_rand_data() -> Vec<u8> {

    let mut rng = thread_rng();
    let key_len = rng.gen_range(1, 256);

    gen_rand_key(key_len).unwrap()
}


fn ro_hmac(buf1: &[u8], buf2: &[u8]) {


    let message = buf1.to_vec();
    let key = buf2.to_vec();

    let s_key = ring_hmac::SigningKey::new(&digest::SHA256, key.as_ref());
    let ring_signature = ring_hmac::sign(&s_key, message.as_ref());

    let orion_hmac = hmac::Hmac {
        secret_key: key.to_vec(),
        data: message.to_vec(),
        sha2: options::ShaVariantOption::SHA256,
    };

    let orion_signature = orion_hmac.finalize();
    let v_key = ring_hmac::VerificationKey::new(&digest::SHA256, key.as_ref());


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






fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let rand_key = return_rand_data();

    ro_hmac(data, data);
    ro_hmac(&rand_key, data);
    ro_hmac(data, &rand_key);
    ro_hmac(&rand_key, &rand_key);

});
