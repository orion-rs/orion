#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate sp800_185;
pub mod util;

use orion::hazardous::cshake;
use sp800_185::CShake as sp_cshake;
use self::util::*;

fuzz_target!(|data: &[u8]| {
    let mut input = Vec::from(data);
    // Input data cannot be empty, because the first byte will be used to determine
    // where the input should be split
    if input.is_empty() {
        input.push(0u8);
    }

    let mut message = vec![0u8; input[0] as usize];
    apply_from_input_fixed(&mut message, &input, 0);
    let mut name = Vec::new();
    let mut custom = Vec::new();

    // If input[0] > 127 then set name to something else than an empty string
    if input[0] > 127 {
        apply_from_input_heap(&mut custom, &input, message.len());
        apply_from_input_heap(&mut name, &input, custom.len() + message.len());
    } else {
        apply_from_input_heap(&mut custom, &input, message.len());
    }

    // Max iteration count will be (255*256) + 1 = 65281
    let out_len = (input[0] as usize * 256) + 1;

    let mut hash_out_orion = vec![0u8; out_len];
    let mut hash_out_sp = vec![0u8; out_len];

    let mut cshake = cshake::init(&custom, Some(&name)).unwrap();
    cshake.update(&input).unwrap();
    cshake.finalize(&mut hash_out_orion).unwrap();

    let mut sp_cshake_hash = sp_cshake::new_cshake256(&name, &custom);
    sp_cshake_hash.update(&input);
    sp_cshake_hash.finalize(&mut hash_out_sp);

    assert_eq!(&hash_out_orion, &hash_out_orion);
});
