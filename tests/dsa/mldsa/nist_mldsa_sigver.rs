// ML-DSA commit: https://github.com/usnistgov/ACVP-Server/commit/2972def23bf9f3680c2c531561ed9bdd0f1086ad

use orion::hazardous::dsa::{mldsa44, mldsa65, mldsa87};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaSigVer {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<MlDsaSigVerTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaSigVerTestGroup {
    tgId: u32,
    testType: String,
    parameterSet: String,
    signatureInterface: String,
    preHash: String,
    externalMu: bool,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    testPassed: bool,
    deferred: bool,
    message: Option<String>,
    mu: Option<String>,
    pk: String,
    sk: String,
    context: Option<String>,
    hashAlg: String,
    signature: String,
    reason: String,
}

fn mldsa_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlDsaSigVer = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        if test_group.preHash == "preHash" {
            // HashML- impl not there yet
            continue;
        }

        match test_group.parameterSet.as_str() {
            "ML-DSA-44" => {
                let mut pk_expected = [0u8; mldsa44::VERIFYING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa44::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let vk = mldsa44::VerifyingKey::try_from(&pk_expected).unwrap();

                    if mldsa44::Signature::try_from(&sig_expected).is_err() && !test.testPassed {
                        tests_run += 1;
                        continue;
                    } else {
                        if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref())
                        {
                            let m = hex::decode(m).unwrap();
                            let ctx = hex::decode(ctx).unwrap();
                            let signature = mldsa44::Signature::try_from(&sig_expected).unwrap();
                            let verified = vk.verify(&m, &ctx, &signature);
                            assert_eq!(test.testPassed, verified.is_ok());

                            tests_run += 1;
                        }
                    }
                }
            }
            "ML-DSA-65" => {
                let mut pk_expected = [0u8; mldsa65::VERIFYING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa65::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let vk = mldsa65::VerifyingKey::try_from(&pk_expected).unwrap();

                    if mldsa65::Signature::try_from(&sig_expected).is_err() && !test.testPassed {
                        tests_run += 1;
                        continue;
                    } else {
                        if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref())
                        {
                            let m = hex::decode(m).unwrap();
                            let ctx = hex::decode(ctx).unwrap();
                            let signature = mldsa65::Signature::try_from(&sig_expected).unwrap();
                            let verified = vk.verify(&m, &ctx, &signature);
                            assert_eq!(test.testPassed, verified.is_ok());

                            tests_run += 1;
                        }
                    }
                }
            }
            "ML-DSA-87" => {
                let mut pk_expected = [0u8; mldsa87::VERIFYING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa87::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let vk = mldsa87::VerifyingKey::try_from(&pk_expected).unwrap();

                    if mldsa87::Signature::try_from(&sig_expected).is_err() && !test.testPassed {
                        tests_run += 1;
                        continue;
                    } else {
                        if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref())
                        {
                            let m = hex::decode(m).unwrap();
                            let ctx = hex::decode(ctx).unwrap();
                            let signature = mldsa87::Signature::try_from(&sig_expected).unwrap();
                            let verified = vk.verify(&m, &ctx, &signature);
                            assert_eq!(test.testPassed, verified.is_ok());

                            tests_run += 1;
                        }
                    }
                }
            }
            other => panic!("unknown parameter set: {other}"),
        }
    }

    assert_eq!(tests_run, 66);
}

#[test]
fn test_acvp_mldsa_sigver() {
    mldsa_runner("./tests/test_data/third_party/nist/ML-DSA/ml_dsa_sigver_internalProjection.json");
}
