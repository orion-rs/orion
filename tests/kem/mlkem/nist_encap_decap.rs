// ml_kem_encapdecap_internalProjection.json
// taken at commit: https://github.com/usnistgov/ACVP-Server/commit/203f667c26e10a1be89dfe8da7a54498fde2d848

use orion::hazardous::kem::mlkem1024;
use orion::hazardous::kem::mlkem512;
use orion::hazardous::kem::mlkem768;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemEncapDecap {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<MlKemEncapDecapTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemEncapDecapTestGroup {
    tgId: u32,
    testType: String,
    parameterSet: String,
    function: String,
    tests: Vec<TestVector>,

    // The following are for "function": "decapsulation" tests
    ek: Option<String>,
    dk: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    deferred: bool,
    ek: Option<String>, // Not in "function": "decapsulation" tests
    dk: Option<String>, // Not in "function": "decapsulation" tests
    c: String,
    k: String,
    m: Option<String>, // Not in "function": "decapsulation" tests
    reason: String,
}

fn mlkem_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlKemEncapDecap = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        if test_group.parameterSet == "ML-KEM-512" {
            if test_group.function == "encapsulation" {
                for test in test_group.tests.iter() {
                    if test.reason != "valid decapsulation" {
                        unimplemented!();
                    }

                    let mut k = [0u8; 32];
                    let mut m = [0u8; 32];
                    let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                    let mut dk_expected = [0u8; mlkem512::MlKem512::DK_SIZE];
                    let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(test.m.as_ref().unwrap(), &mut m).unwrap();
                    hex::decode_to_slice(test.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                    hex::decode_to_slice(test.dk.as_ref().unwrap(), &mut dk_expected).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let ek = mlkem512::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    let (k_actual, ct_actual) = ek.encap_deterministic(&m).unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());
                    assert_eq!(ct_expected, ct_actual.as_ref());

                    let dk =
                        mlkem512::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem512::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }

            if test_group.function == "decapsulation" {
                let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                let mut dk_expected = [0u8; mlkem512::MlKem512::DK_SIZE];
                hex::decode_to_slice(test_group.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                hex::decode_to_slice(test_group.dk.as_ref().unwrap(), &mut dk_expected).unwrap();

                for test in test_group.tests.iter() {
                    let mut k = [0u8; 32];
                    let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let dk =
                        mlkem512::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem512::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }
        }
        if test_group.parameterSet == "ML-KEM-768" {
            if test_group.function == "encapsulation" {
                for test in test_group.tests.iter() {
                    if test.reason != "valid decapsulation" {
                        unimplemented!();
                    }

                    let mut k = [0u8; 32];
                    let mut m = [0u8; 32];
                    let mut ek_expected = [0u8; mlkem768::MlKem768::EK_SIZE];
                    let mut dk_expected = [0u8; mlkem768::MlKem768::DK_SIZE];
                    let mut ct_expected = [0u8; mlkem768::MlKem768::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(test.m.as_ref().unwrap(), &mut m).unwrap();
                    hex::decode_to_slice(test.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                    hex::decode_to_slice(test.dk.as_ref().unwrap(), &mut dk_expected).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let ek = mlkem768::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    let (k_actual, ct_actual) = ek.encap_deterministic(&m).unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());
                    assert_eq!(ct_expected, ct_actual.as_ref());

                    let dk =
                        mlkem768::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem768::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }

            if test_group.function == "decapsulation" {
                let mut ek_expected = [0u8; mlkem768::MlKem768::EK_SIZE];
                let mut dk_expected = [0u8; mlkem768::MlKem768::DK_SIZE];
                hex::decode_to_slice(test_group.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                hex::decode_to_slice(test_group.dk.as_ref().unwrap(), &mut dk_expected).unwrap();

                for test in test_group.tests.iter() {
                    let mut k = [0u8; 32];
                    let mut ct_expected = [0u8; mlkem768::MlKem768::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let dk =
                        mlkem768::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem768::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }
        }

        if test_group.parameterSet == "ML-KEM-1024" {
            if test_group.function == "encapsulation" {
                for test in test_group.tests.iter() {
                    if test.reason != "valid decapsulation" {
                        unimplemented!();
                    }

                    let mut k = [0u8; 32];
                    let mut m = [0u8; 32];
                    let mut ek_expected = [0u8; mlkem1024::MlKem1024::EK_SIZE];
                    let mut dk_expected = [0u8; mlkem1024::MlKem1024::DK_SIZE];
                    let mut ct_expected = [0u8; mlkem1024::MlKem1024::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(test.m.as_ref().unwrap(), &mut m).unwrap();
                    hex::decode_to_slice(test.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                    hex::decode_to_slice(test.dk.as_ref().unwrap(), &mut dk_expected).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let ek = mlkem1024::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    let (k_actual, ct_actual) = ek.encap_deterministic(&m).unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());
                    assert_eq!(ct_expected, ct_actual.as_ref());

                    let dk =
                        mlkem1024::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem1024::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }

            if test_group.function == "decapsulation" {
                let mut ek_expected = [0u8; mlkem1024::MlKem1024::EK_SIZE];
                let mut dk_expected = [0u8; mlkem1024::MlKem1024::DK_SIZE];
                hex::decode_to_slice(test_group.ek.as_ref().unwrap(), &mut ek_expected).unwrap();
                hex::decode_to_slice(test_group.dk.as_ref().unwrap(), &mut dk_expected).unwrap();

                for test in test_group.tests.iter() {
                    let mut k = [0u8; 32];
                    let mut ct_expected = [0u8; mlkem1024::MlKem1024::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(&test.k, &mut k).unwrap();
                    hex::decode_to_slice(&test.c, &mut ct_expected).unwrap();

                    let dk =
                        mlkem1024::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                    let k_actual = dk
                        .decap(&mlkem1024::Ciphertext::from_slice(&ct_expected).unwrap())
                        .unwrap();
                    assert_eq!(k, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }
        }
    }

    assert_eq!(tests_run, 105);
}

#[test]
fn test_acvp_mlkem_encapdecap() {
    mlkem_runner(
        "./tests/test_data/third_party/nist/ML-KEM/ml_kem_encapdecap_internalProjection.json",
    );
}
