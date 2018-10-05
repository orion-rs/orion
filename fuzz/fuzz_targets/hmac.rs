#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::hmac;

fuzz_target!(|data: &[u8]| {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut secret_key = vec![0u8; input[0] as usize];
    let mut message = Vec::new();
    apply_from_input_fixed(&mut secret_key, &input, 0);
    apply_from_input_heap(&mut message, &input, secret_key.len());

    let mut mac = hmac::init(&secret_key);
    mac.update(&message).unwrap();

    let mac_def = mac.finalize().unwrap();
    assert_eq!(hmac::verify(&mac_def, &secret_key, &message).unwrap(), true);
});
