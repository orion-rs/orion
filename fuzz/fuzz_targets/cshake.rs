#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
pub mod util;

use self::util::*;
use orion::hazardous::cshake;

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
    let mut hash_out = vec![0u8; out_len];

    let mut cshake = cshake::init(&custom, Some(&name)).unwrap();
    cshake.update(&message).unwrap();
    cshake.finalize(&mut hash_out).unwrap();
});
