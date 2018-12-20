#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;

use orion::hazardous::hash::sha512;

fuzz_target!(|data: &[u8]| {
    let mut state = sha512::init();
    state.update(data).unwrap();
    let digest_stream = state.finalize().unwrap();

    let digest_one_shot = sha512::digest(data).unwrap();

    assert!(digest_stream.as_bytes() == digest_one_shot.as_bytes());
});
