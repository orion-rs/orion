#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::hash::blake2b;

fn fuzz_blake2b_non_keyed(data: &[u8], outsize: usize) {
	let mut state = blake2b::init(None, outsize).unwrap();
	state.update(data).unwrap();

	if data.len() > 512 {
		state.update(b"").unwrap();
	}
	if data.len() > 1028 {
		state.update(b"Extra").unwrap();
	}
	if data.len() > 2049 {
		state.update(&[0u8; 256]).unwrap();
	}

	let _orion_hash = state.finalize().unwrap();
}

fn fuzz_blake2b_keyed(data: &[u8], outsize: usize) {
	let mut key = [0u8; 64];
	apply_from_input_fixed(&mut key, data, 0);
	let orion_key = blake2b::SecretKey::from_slice(&key).unwrap();

	let mut state = blake2b::init(Some(&orion_key), outsize).unwrap();
	state.update(data).unwrap();

	if data.len() > 512 {
		state.update(b"").unwrap();
	}
	if data.len() > 1028 {
		state.update(b"Extra").unwrap();
	}
	if data.len() > 2049 {
		state.update(&[0u8; 256]).unwrap();
	}

	let _orion_hash = state.finalize().unwrap();
}

fuzz_target!(|data: &[u8]| {
    for out in 1..65 {
	  fuzz_blake2b_non_keyed(data, out);
	  fuzz_blake2b_keyed(data, out);
    }
});
