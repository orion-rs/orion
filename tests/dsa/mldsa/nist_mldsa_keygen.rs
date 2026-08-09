// ML-DSA commit: https://github.com/usnistgov/ACVP-Server/commit/2972def23bf9f3680c2c531561ed9bdd0f1086ad

use orion::{
    KP,
    hazardous::dsa::ml_dsa::{self, Seed, internal::MlDsaParameters},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaKeyGen {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<MlDsaKeyGenTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaKeyGenTestGroup {
    tgId: u32,
    testType: String,
    parameterSet: String,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    deferred: bool,
    seed: String,
    pk: String,
    sk: String,
}

fn mldsa_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlDsaKeyGen = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        if test_group.parameterSet == "ML-DSA-44" {
            for test in test_group.tests.iter() {
                let mut seed = [0u8; 32];
                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa44::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa44::PUBLIC_KEY_SIZE];
                hex::decode_to_slice(&test.seed, &mut seed).unwrap();
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();

                let kp = ml_dsa::mldsa44::KeyPair::new(Seed::from(seed)).unwrap();
                assert_eq!(kp.public(), &pk_expected[..]);
                assert_eq!(kp.private(), &sk_expected[..]);

                tests_run += 1;
            }
        }
        if test_group.parameterSet == "ML-DSA-65" {
            for test in test_group.tests.iter() {
                let mut seed = [0u8; 32];
                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa65::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa65::PUBLIC_KEY_SIZE];
                hex::decode_to_slice(&test.seed, &mut seed).unwrap();
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();

                let kp = ml_dsa::mldsa65::KeyPair::new(Seed::from(seed)).unwrap();
                assert_eq!(kp.public(), &pk_expected[..]);
                assert_eq!(kp.private(), &sk_expected[..]);

                tests_run += 1;
            }
        }

        if test_group.parameterSet == "ML-DSA-87" {
            for test in test_group.tests.iter() {
                let mut seed = [0u8; 32];
                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa87::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa87::PUBLIC_KEY_SIZE];
                hex::decode_to_slice(&test.seed, &mut seed).unwrap();
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();

                let kp = ml_dsa::mldsa87::KeyPair::new(Seed::from(seed)).unwrap();
                assert_eq!(kp.public(), &pk_expected[..]);
                assert_eq!(kp.private(), &sk_expected[..]);

                tests_run += 1;
            }
        }
    }

    assert_eq!(tests_run, 25);
}

#[test]
fn test_acvp_mldsa_keygen() {
    mldsa_runner("./tests/test_data/third_party/nist/ML-DSA/ml_dsa_keygen_internalProjection.json");
}
