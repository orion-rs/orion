// Test vectors taken at commit: https://github.com/C2SP/wycheproof/commit/fca0d3ba9f1286c3af57801ace39c633e29a88f1

use orion::hazardous::kem::mlkem1024;
use orion::hazardous::kem::mlkem512;
use orion::hazardous::kem::mlkem768;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemTest {
    algorithm: String,
    schema: String,
    numberOfTests: u32,
    #[serde(skip)]
    #[allow(dead_code)]
    notes: Vec<String>,
    testGroups: Vec<MlKemTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemTestGroup {
    #[serde(rename(deserialize = "type"))]
    testType: String,
    source: TestSource,
    parameterSet: String,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestSource {
    name: String,
    version: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    comment: Option<String>,
    flags: Option<Vec<String>>,
    seed: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    c: Option<String>,
    K: Option<String>,
    m: Option<String>,
    result: String,
}

fn mlkem_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlKemTest = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test_vector in test_group.tests.iter() {
            if test_group.testType == "MLKEMKeyGen" && test_group.source.name == "FIPS 203" {
                assert!(test_vector.seed.is_some());
                assert!(test_vector.ek.is_some());
                assert!(test_vector.dk.is_some());

                let mut seed = [0u8; 64];

                if test_group.parameterSet == "ML-KEM-512" {
                    let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                    let mut dk_expected = [0u8; mlkem512::MlKem512::DK_SIZE];
                    hex::decode_to_slice(test_vector.seed.as_ref().unwrap(), &mut seed).unwrap();
                    hex::decode_to_slice(test_vector.ek.as_ref().unwrap(), &mut ek_expected)
                        .unwrap();
                    hex::decode_to_slice(test_vector.dk.as_ref().unwrap(), &mut dk_expected)
                        .unwrap();

                    let keypair =
                        mlkem512::KeyPair::try_from(&mlkem512::Seed::from_slice(&seed).unwrap())
                            .unwrap();
                    let ek = mlkem512::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    let dk =
                        mlkem512::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();

                    assert_eq!(keypair.public(), &ek);
                    assert_eq!(keypair.private(), &dk);

                    tests_run += 1;
                }

                // TODO: 768, 1024.
            }

            if test_group.testType == "MLKEMEncapsTest" {
                if test_vector.result == "invalid" {
                    // NOTE: While `m` is some for these tests, Orion doesn't expose a public function that
                    // takes an `ek` _and_ an `m` for deterministic encapsulation. Only way to uss `ek` is through
                    // `from_slice()` so `m` will never need to be included.
                    assert!(test_vector.m.is_some());
                    assert!(test_vector.ek.is_some());

                    match test_group.parameterSet.as_str() {
                        "ML-KEM-512" => {
                            assert!(mlkem512::EncapsulationKey::from_slice(
                                &hex::decode(test_vector.ek.as_ref().unwrap()).unwrap()
                            )
                            .is_err());
                        }

                        "ML-KEM-768" => {
                            assert!(mlkem768::EncapsulationKey::from_slice(
                                &hex::decode(test_vector.ek.as_ref().unwrap()).unwrap()
                            )
                            .is_err());
                        }

                        "ML-KEM-1024" => {
                            assert!(mlkem1024::EncapsulationKey::from_slice(
                                &hex::decode(test_vector.ek.as_ref().unwrap()).unwrap()
                            )
                            .is_err());
                        }
                        _ => panic!("a test parameter set was unaccounted for"),
                    }

                    tests_run += 1;
                    continue;
                }

                assert!(test_vector.m.is_some());
                assert!(test_vector.ek.is_some());
                assert!(test_vector.c.is_some());
                assert!(test_vector.K.is_some());

                let mut m = [0u8; 32];
                let mut shared_expected = [0u8; 32];

                if test_group.parameterSet == "ML-KEM-512" {
                    let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                    let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(test_vector.m.as_ref().unwrap(), &mut m).unwrap();
                    hex::decode_to_slice(test_vector.K.as_ref().unwrap(), &mut shared_expected)
                        .unwrap();
                    hex::decode_to_slice(test_vector.ek.as_ref().unwrap(), &mut ek_expected)
                        .unwrap();
                    hex::decode_to_slice(test_vector.c.as_ref().unwrap(), &mut ct_expected)
                        .unwrap();

                    let ek = mlkem512::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    let ciphertext = mlkem512::Ciphertext::from_slice(&ct_expected).unwrap();
                    let (k_actual, c_acutal) = ek.encap_deterministic(&m).unwrap();

                    assert_eq!(ciphertext, c_acutal);
                    assert_eq!(&shared_expected, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }

                // TODO: 768, 1024.
            }

            if test_group.testType == "MLKEMDecapsValidationTest"
                && test_group.source.name == "github/aws/aws-lc"
            {
                assert!(test_vector.c.is_some());
                assert!(test_vector.dk.is_some());

                if test_group.parameterSet == "ML-KEM-512" {
                    if test_vector.result == "invalid" {
                        match test_vector.tcId {
                            2..=3 => {
                                assert!(mlkem512::Ciphertext::from_slice(
                                    &hex::decode(test_vector.c.as_ref().unwrap()).unwrap()
                                )
                                .is_err());
                            }
                            4..=7 => {
                                assert!(mlkem512::DecapsulationKey::unchecked_from_slice(
                                    &hex::decode(test_vector.dk.as_ref().unwrap()).unwrap()
                                )
                                .is_err());
                            }
                            _ => panic!("uncovered tcId - we need all for this test"),
                        }

                        tests_run += 1;
                        continue;
                    }

                    if test_vector.result == "valid" {
                        let mut dk_expected = [0u8; mlkem512::MlKem512::DK_SIZE];
                        let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                        hex::decode_to_slice(test_vector.dk.as_ref().unwrap(), &mut dk_expected)
                            .unwrap();
                        hex::decode_to_slice(test_vector.c.as_ref().unwrap(), &mut ct_expected)
                            .unwrap();

                        let dk =
                            mlkem512::DecapsulationKey::unchecked_from_slice(&dk_expected).unwrap();
                        let ciphertext = mlkem512::Ciphertext::from_slice(&ct_expected).unwrap();
                        assert!(dk.decap(&ciphertext).is_ok());
                        tests_run += 1;
                    }
                }

                // TODO: 768, 1024.
            }

            if test_group.testType == "MLKEMTest" {
                assert!(test_vector.seed.is_some());
                assert!(test_vector.c.is_some());
                assert!(test_vector.K.is_some());

                let mut seed = [0u8; 64];
                let mut shared_expected = [0u8; 32];

                if test_group.parameterSet == "ML-KEM-512" {
                    if test_vector.result == "invalid" {
                        match test_vector.comment.as_ref().unwrap().as_str() {
                            "Private key too short" | "Private key too long" => {
                                assert!(mlkem512::Seed::from_slice(
                                    &hex::decode(test_vector.seed.as_ref().unwrap()).unwrap()
                                )
                                .is_err());
                            }
                            "Ciphertext too short" | "Ciphertext too long" => {
                                assert!(mlkem512::Ciphertext::from_slice(
                                    &hex::decode(test_vector.c.as_ref().unwrap()).unwrap()
                                )
                                .is_err());
                            }
                            _ => panic!("a test parameter set was unaccounted for"),
                        }

                        tests_run += 1;
                        continue;
                    }

                    assert!(test_vector.ek.is_some());

                    let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                    let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(test_vector.seed.as_ref().unwrap(), &mut seed).unwrap();
                    hex::decode_to_slice(test_vector.K.as_ref().unwrap(), &mut shared_expected)
                        .unwrap();
                    hex::decode_to_slice(test_vector.ek.as_ref().unwrap(), &mut ek_expected)
                        .unwrap();
                    hex::decode_to_slice(test_vector.c.as_ref().unwrap(), &mut ct_expected)
                        .unwrap();

                    let keypair =
                        mlkem512::KeyPair::try_from(&mlkem512::Seed::from_slice(&seed).unwrap())
                            .unwrap();
                    let ek = mlkem512::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    assert_eq!(keypair.public(), &ek);

                    let ciphertext = mlkem512::Ciphertext::from_slice(&ct_expected).unwrap();
                    let k_actual =
                        mlkem512::MlKem512::decap(keypair.private(), &ciphertext).unwrap();
                    assert_eq!(&shared_expected, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }

                // TODO: 768, 1024.
            }
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_c2sp_wycheproof_mlkem_512() {
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_512_encaps_test.json");
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_512_keygen_seed_test.json");
    mlkem_runner(
        "./tests/test_data/third_party/c2sp_wycheproof/mlkem_512_semi_expanded_decaps_test.json",
    );
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_512_test.json");
}
/*
#[test]
fn test_c2sp_wycheproof_mlkem() {
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_test.json");
}
*/
/*
#[test]
fn test_c2sp_wycheproof_mlkem() {
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_test.json");
}
*/
