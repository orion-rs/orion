// src: https://www.rfc-editor.org/rfc/rfc9106.html#name-test-vectors

use hex::decode;
use orion::hazardous::kdf::argon2::*;

#[test]
fn test_case_argon2i() {
    let mem: u32 = 32;
    let passes: u32 = 3;
    let parallelism: u32 = 4;
    let password =
        decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = decode("02020202020202020202020202020202").unwrap();
    let secret_value = decode("0303030303030303").unwrap();
    let associated_data = decode("040404040404040404040404").unwrap();
    let expected_hash =
        decode("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8").unwrap();

    let mut actual_hash = vec![0u8; expected_hash.len()];
    Argon2::<I, Sequential>::derive_key(
        &password,
        &salt,
        passes,
        mem,
        parallelism,
        Some(&secret_value),
        Some(&associated_data),
        &mut actual_hash,
    )
    .unwrap();
    assert_eq!(expected_hash, actual_hash);
    assert!(
        Argon2::<I, Sequential>::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            parallelism,
            Some(&secret_value),
            Some(&associated_data),
            &mut actual_hash
        )
        .is_ok()
    );
}

#[test]
fn test_case_argon2id() {
    let mem: u32 = 32;
    let passes: u32 = 3;
    let parallelism: u32 = 4;
    let password =
        decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = decode("02020202020202020202020202020202").unwrap();
    let secret_value = decode("0303030303030303").unwrap();
    let associated_data = decode("040404040404040404040404").unwrap();
    let expected_hash =
        decode("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659").unwrap();

    let mut actual_hash = vec![0u8; expected_hash.len()];
    Argon2::<ID, Sequential>::derive_key(
        &password,
        &salt,
        passes,
        mem,
        parallelism,
        Some(&secret_value),
        Some(&associated_data),
        &mut actual_hash,
    )
    .unwrap();
    assert_eq!(expected_hash, actual_hash);
    assert!(
        Argon2::<ID, Sequential>::verify(
            &expected_hash,
            &password,
            &salt,
            passes,
            mem,
            parallelism,
            Some(&secret_value),
            Some(&associated_data),
            &mut actual_hash
        )
        .is_ok()
    );
}
