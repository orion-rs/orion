// c2sp_wycheproof/mlkem_test.json
// Test vectors taken at commit: https://github.com/C2SP/wycheproof/commit/3bfb67fca7c7a2ef436e263da53cdabe0fa1dd36

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
    flags: Vec<String>,
    seed: Option<String>,
    ek: String,
    c: String,
    K: String,
    result: String,
}

fn mlkem_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlKemTest = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        for test_vector in test_group.tests.iter() {
            if test_group.source.name == "CCTV/strcmp" {
                assert!(test_vector.seed.is_some());
                let mut seed = [0u8; 64];
                let mut shared_expected = [0u8; 32];

                if test_group.parameterSet == "ML-KEM-512" {
                    let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                    let mut ct_expected = [0u8; mlkem512::MlKem512::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(test_vector.seed.as_ref().unwrap(), &mut seed).unwrap();
                    hex::decode_to_slice(&test_vector.K, &mut shared_expected).unwrap();
                    hex::decode_to_slice(&test_vector.ek, &mut ek_expected).unwrap();
                    hex::decode_to_slice(&test_vector.c, &mut ct_expected).unwrap();

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

                if test_group.parameterSet == "ML-KEM-768" {
                    let mut ek_expected = [0u8; mlkem768::MlKem768::EK_SIZE];
                    let mut ct_expected = [0u8; mlkem768::MlKem768::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(test_vector.seed.as_ref().unwrap(), &mut seed).unwrap();
                    hex::decode_to_slice(&test_vector.K, &mut shared_expected).unwrap();
                    hex::decode_to_slice(&test_vector.ek, &mut ek_expected).unwrap();
                    hex::decode_to_slice(&test_vector.c, &mut ct_expected).unwrap();

                    let keypair =
                        mlkem768::KeyPair::try_from(&mlkem768::Seed::from_slice(&seed).unwrap())
                            .unwrap();
                    let ek = mlkem768::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    assert_eq!(keypair.public(), &ek);

                    let ciphertext = mlkem768::Ciphertext::from_slice(&ct_expected).unwrap();
                    let k_actual =
                        mlkem768::MlKem768::decap(keypair.private(), &ciphertext).unwrap();
                    assert_eq!(&shared_expected, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }

                if test_group.parameterSet == "ML-KEM-1024" {
                    let mut ek_expected = [0u8; mlkem1024::MlKem1024::EK_SIZE];
                    let mut ct_expected = [0u8; mlkem1024::MlKem1024::CIPHERTEXT_SIZE];
                    hex::decode_to_slice(test_vector.seed.as_ref().unwrap(), &mut seed).unwrap();
                    hex::decode_to_slice(&test_vector.K, &mut shared_expected).unwrap();
                    hex::decode_to_slice(&test_vector.ek, &mut ek_expected).unwrap();
                    hex::decode_to_slice(&test_vector.c, &mut ct_expected).unwrap();

                    let keypair =
                        mlkem1024::KeyPair::try_from(&mlkem1024::Seed::from_slice(&seed).unwrap())
                            .unwrap();
                    let ek = mlkem1024::EncapsulationKey::from_slice(&ek_expected).unwrap();
                    assert_eq!(keypair.public(), &ek);

                    let ciphertext = mlkem1024::Ciphertext::from_slice(&ct_expected).unwrap();
                    let k_actual =
                        mlkem1024::MlKem1024::decap(keypair.private(), &ciphertext).unwrap();
                    assert_eq!(&shared_expected, k_actual.unprotected_as_bytes());

                    tests_run += 1;
                }
            }

            if test_group.source.name == "CCTV/modulus" {
                if test_group.parameterSet == "ML-KEM-512" {
                    assert!(mlkem512::EncapsulationKey::from_slice(
                        &hex::decode(&test_vector.ek).unwrap()
                    )
                    .is_err());
                    tests_run += 1;
                }

                if test_group.parameterSet == "ML-KEM-768" {
                    assert!(mlkem768::EncapsulationKey::from_slice(
                        &hex::decode(&test_vector.ek).unwrap()
                    )
                    .is_err());
                    tests_run += 1;
                }

                if test_group.parameterSet == "ML-KEM-1024" {
                    assert!(mlkem1024::EncapsulationKey::from_slice(
                        &hex::decode(&test_vector.ek).unwrap()
                    )
                    .is_err());
                    tests_run += 1;
                }
            }
        }
    }

    assert_eq!(tests_run, tests.numberOfTests);
}

#[test]
fn test_c2sp_wycheproof_mlkem() {
    mlkem_runner("./tests/test_data/third_party/c2sp_wycheproof/mlkem_test.json");
}
