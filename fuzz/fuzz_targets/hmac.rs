#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::hmac;

fuzz_target!(|data: &[u8]| {
    let (secret_key, message) = hmac_setup(data);
    let mut mac = hmac::init(&secret_key);
    mac.update(&message).unwrap();
    let mac_def = mac.finalize().unwrap();

    assert_eq!(hmac::verify(&mac_def, &secret_key, &message).unwrap(), true);
});
