#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::cshake;
use rand::prelude::*;

fn fuzz_cshake(input: &[u8], name: &[u8], custom: &[u8], len_max: usize) {
    let mut rng = rand::thread_rng();
    let len_rand = rng.gen_range(1, len_max + 1);

    // They can't both be empty
    let mut mod_custom = custom.to_vec();
    mod_custom.push(0u8);

    let mut hash_out = vec![0u8; len_rand];
    let mut cshake = cshake::init(&mod_custom, Some(name)).unwrap();
    cshake.update(input);
    cshake.finalize(&mut hash_out).unwrap();
}

fuzz_target!(|data: &[u8]| {
    fuzz_cshake(data, data, data, 65536);
    fuzz_cshake(data, &Vec::new(), data, 65536);
    fuzz_cshake(data, data, &Vec::new(), 65536);
    fuzz_cshake(&Vec::new(), data, data, 65536);
});
