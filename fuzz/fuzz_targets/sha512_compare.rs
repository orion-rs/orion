#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate ring;
pub mod util;

use orion::hazardous::hash::sha512;
use ring::digest;

fuzz_target!(|data: &[u8]| {
    let mut state = sha512::init();
    let mut other_data: Vec<u8> = Vec::new();

    other_data.extend_from_slice(data);
    state.update(data).unwrap();

    if data.len() > 512 {
		other_data.extend_from_slice(b"");
		state.update(b"").unwrap();
	}
	if data.len() > 1028 {
		other_data.extend_from_slice(b"Extra");
		state.update(b"Extra").unwrap();
	}
	if data.len() > 2049 {
		other_data.extend_from_slice(&[0u8; 256]);
		state.update(&[0u8; 256]).unwrap();
	}
    
    let digest_other = digest::digest(&digest::SHA512, &other_data);

    assert!(state.finalize().unwrap().as_bytes() == digest_other.as_ref());
});
