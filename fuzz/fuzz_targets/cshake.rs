#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;

use orion::hazardous::cshake::CShake;
use orion::core::options::KeccakVariantOption;
use rand::prelude::*;


fn fuzz_cshake(input: &[u8], name: &[u8], custom: &[u8], len_max: usize, keccak: KeccakVariantOption) {

    let mut rng = rand::thread_rng();
    let len_rand = rng.gen_range(1, len_max+1);

    // They can't both be empty
    let mut mod_custom = custom.to_vec();
    mod_custom.push(0u8);

    let cshake_init = CShake {
        input: input.to_vec(),
        name: name.to_vec(),
        custom: mod_custom,
        length: len_rand,
        keccak,
    };

    let hash = cshake.finalize().unwrap();

    assert_eq!(cshake.verify(&hash).unwrap(), true);

}

fuzz_target!(|data: &[u8]| {

    fuzz_cshake(data, data, data, 65536, KeccakVariantOption::KECCAK128);
    fuzz_cshake(data, &Vec::new(), data, 65536, KeccakVariantOption::KECCAK128);
    fuzz_cshake(data, data, &Vec::new(), 65536, KeccakVariantOption::KECCAK128);
    fuzz_cshake(&Vec::new(), data, data, 65536, KeccakVariantOption::KECCAK128);

    fuzz_cshake(data, data, data, 65536, KeccakVariantOption::KECCAK256);
    fuzz_cshake(data, &Vec::new(), data, 65536, KeccakVariantOption::KECCAK256);
    fuzz_cshake(data, data, &Vec::new(), 65536, KeccakVariantOption::KECCAK256);
    fuzz_cshake(&Vec::new(), data, data, 65536, KeccakVariantOption::KECCAK256);

});
