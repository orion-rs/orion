#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate orion;
extern crate rand;
extern crate sp800_185;

use orion::core::options::KeccakVariantOption;
use orion::hazardous::cshake::CShake;
use rand::prelude::*;
use sp800_185::CShake as sp_cshake;

fn fuzz_cshake(
    input: &[u8],
    name: &[u8],
    custom: &[u8],
    len_max: usize,
    keccak: KeccakVariantOption,
) {
    let mut rng = rand::thread_rng();
    let len_rand = rng.gen_range(1, len_max + 1);

    // They can't both be empty
    let mut mod_custom = custom.to_vec();
    mod_custom.push(0u8);

    let cshake = CShake {
        input: input.to_vec(),
        name: name.to_vec(),
        custom: mod_custom.to_vec(),
        length: len_rand,
        keccak,
    };

    let hash = cshake.finalize().unwrap();

    let mut sp_cshake_hash = match &keccak {
        KeccakVariantOption::KECCAK256 => sp_cshake::new_cshake128(name, &mod_custom),
        KeccakVariantOption::KECCAK512 => sp_cshake::new_cshake256(name, &mod_custom),
    };

    sp_cshake_hash.update(input);
    let mut sp_cshake_fin = vec![0u8; len_rand];
    sp_cshake_hash.finalize(&mut sp_cshake_fin);

    assert_eq!(hash.len(), sp_cshake_fin.len());
    assert_eq!(&hash, &sp_cshake_fin);
    assert_eq!(cshake.verify(&hash).unwrap(), true);
    assert_eq!(cshake.verify(&sp_cshake_fin).unwrap(), true);
}

fuzz_target!(|data: &[u8]| {
    fuzz_cshake(data, data, data, 65536, KeccakVariantOption::KECCAK256);
    fuzz_cshake(
        data,
        &Vec::new(),
        data,
        65536,
        KeccakVariantOption::KECCAK256,
    );
    fuzz_cshake(
        data,
        data,
        &Vec::new(),
        65536,
        KeccakVariantOption::KECCAK256,
    );
    fuzz_cshake(
        &Vec::new(),
        data,
        data,
        65536,
        KeccakVariantOption::KECCAK256,
    );

    fuzz_cshake(data, data, data, 65536, KeccakVariantOption::KECCAK512);
    fuzz_cshake(
        data,
        &Vec::new(),
        data,
        65536,
        KeccakVariantOption::KECCAK512,
    );
    fuzz_cshake(
        data,
        data,
        &Vec::new(),
        65536,
        KeccakVariantOption::KECCAK512,
    );
    fuzz_cshake(
        &Vec::new(),
        data,
        data,
        65536,
        KeccakVariantOption::KECCAK512,
    );
});
