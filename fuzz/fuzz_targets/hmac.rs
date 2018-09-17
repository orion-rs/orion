#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
use orion::hazardous::hmac;

fn fuzz_hmac(secret_key: &[u8], data: &[u8]) {
    let mut mac = hmac::init(secret_key);
    mac.update(data).unwrap();

    let mac_def = mac.finalize().unwrap();
    assert_eq!(hmac::verify(&mac_def, secret_key, data).unwrap(), true);
}

fuzz_target!(|data: &[u8]| {
    fuzz_hmac(data, data);
});
