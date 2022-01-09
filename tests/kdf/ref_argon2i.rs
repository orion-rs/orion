// The following test vectors were generated with the reference implementation at: https://github.com/P-H-C/phc-winner-argon2/commit/62358ba2123abd17fccf2a108a301d4b52c01a7c
// These are the only test vectors that include associated data and secret value.

use orion::hazardous::kdf::argon2i;

#[test]
fn test_case_1() {
    let memory: u32 = 32;
    let iterations: u32 = 3;
    let password =
        hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = hex::decode("02020202020202020202020202020202").unwrap();
    let secret = hex::decode("0303030303030303").unwrap();
    let ad = hex::decode("040404040404040404040404").unwrap();
    let expected_hash =
        hex::decode("1e14f98dce844e462a545ba81034494ce32ebba9a3f6a899ba83e98888e432b6").unwrap();

    let mut actual = vec![0u8; expected_hash.len()];
    assert!(argon2i::verify(
        &expected_hash,
        &password,
        &salt,
        iterations,
        memory,
        Some(&secret),
        Some(&ad),
        &mut actual
    )
    .is_ok());
}

#[test]
fn test_case_2() {
    let memory: u32 = 65356;
    let iterations: u32 = 1;
    let password =
        hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = hex::decode("02020202020202020202020202020202").unwrap();
    let secret = hex::decode("0303030303030303").unwrap();
    let ad = hex::decode("040404040404040404040404").unwrap();
    let expected_hash =
            hex::decode("4269ba4b39232080c29b9618e8860da16358ff3c228c243c280897ac524f7364fc18a59018cc3f9cc53e9dc2ad05fc5c390956adfd589e2af559cb44f63727d61c4ece8fd64444992932990c5c48f5a2c3b00563ec14151c7756f6d2243624e7058c6941d4cfa9563acaab0b5af916a8edf97f67344d85b96b4fd1b3b6badfed")
                .unwrap();

    let mut actual = vec![0u8; expected_hash.len()];
    assert!(argon2i::verify(
        &expected_hash,
        &password,
        &salt,
        iterations,
        memory,
        Some(&secret),
        Some(&ad),
        &mut actual
    )
    .is_ok());
}

#[test]
fn test_case_3() {
    let memory: u32 = 4096;
    let iterations: u32 = 3;
    let password =
        hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = hex::decode("02020202020202020202020202020202").unwrap();
    let secret = hex::decode("0303030303030303").unwrap();
    let ad = hex::decode("040404040404040404040404").unwrap();
    let expected_hash =
            hex::decode("616d7b734e0510c1067683ce07689ece72c263374d4a425f1fc36ad01049f18f0772ca42b0baa6287f8ccd897a0f9a506cadc16f77f9c1a323acbe6a4ba7fe655646f2b106c64d713f19afaea0c141fd0d44f510089a390049bbe9853c9e091cb2492ffc9a154c79eb6d0ac36e85619b14c028dcc0e79db148b23f46e5a638dd")
                .unwrap();

    let mut actual = vec![0u8; expected_hash.len()];
    assert!(argon2i::verify(
        &expected_hash,
        &password,
        &salt,
        iterations,
        memory,
        Some(&secret),
        Some(&ad),
        &mut actual
    )
    .is_ok());
}
