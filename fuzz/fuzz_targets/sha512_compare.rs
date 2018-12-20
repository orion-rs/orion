#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
pub mod util;

use self::util::*;
use orion::hazardous::hash::sha512;
use ring::digest;

fuzz_target!(|data: &[u8]| {
    let digest_orion = sha512::digest(data).unwrap();
    let digest_other = digest::digest(&digest::SHA512, data);

    assert!(digest_orion.as_bytes() == digest_other.as_ref());
});
