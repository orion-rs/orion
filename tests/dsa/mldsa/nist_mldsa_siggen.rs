// ML-DSA commit: https://github.com/usnistgov/ACVP-Server/commit/2972def23bf9f3680c2c531561ed9bdd0f1086ad

use orion::hazardous::dsa::{mldsa44, mldsa65, mldsa87};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaSigGen {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<MlDsaSigGenTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaSigGenTestGroup {
    tgId: u32,
    testType: String,
    parameterSet: String,
    deterministic: bool,
    signatureInterface: String,
    preHash: String,
    externalMu: bool,
    cornerCase: String,
    tests: Vec<TestVector>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    tcId: u64,
    deferred: bool,
    message: Option<String>,
    mu: Option<String>,
    pk: String,
    sk: String,
    context: Option<String>,
    rnd: Option<String>,
    hashAlg: String,
    signature: String,
}

fn mldsa_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlDsaSigGen = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        match test_group.parameterSet.as_str() {
            "ML-DSA-44" => {
                let mut sk_expected = [0u8; mldsa44::SIGNING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa44::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let sk = mldsa44::SigningKey::try_from(&sk_expected).unwrap();
                    assert!(mldsa44::Signature::try_from(&sig_expected).is_ok());

                    // `rnd` is present when the group is deterministic = False.
                    let rnd = match test.rnd.as_ref() {
                        Some(rnd) => {
                            mldsa44::ExplicitRandom::try_from(&hex::decode(rnd).unwrap()).unwrap()
                        }
                        None => mldsa44::ExplicitRandom::deterministic(),
                    };

                    match test.hashAlg.as_str() {
                        "pure" => (),
                        "none" => (),
                        // No support for HashML-DSA.
                        _ => continue,
                    };

                    if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                        let m = hex::decode(m).unwrap();
                        let ctx = hex::decode(ctx).unwrap();

                        let signature = sk.sign_with_rnd(&m, &ctx, &rnd).unwrap();
                        assert_eq!(signature, &sig_expected[..]);
                        let vk = mldsa44::VerifyingKey::try_from(&sk).unwrap();
                        assert!(vk.verify(&m, &ctx, &signature).is_ok());

                        tests_run += 1;
                    }
                }
            }
            "ML-DSA-65" => {
                let mut sk_expected = [0u8; mldsa65::SIGNING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa65::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let sk = mldsa65::SigningKey::try_from(&sk_expected).unwrap();
                    assert!(mldsa65::Signature::try_from(&sig_expected).is_ok());

                    // `rnd` is present when the group is deterministic = False.
                    let rnd = match test.rnd.as_ref() {
                        Some(rnd) => {
                            mldsa65::ExplicitRandom::try_from(&hex::decode(rnd).unwrap()).unwrap()
                        }
                        None => mldsa65::ExplicitRandom::deterministic(),
                    };

                    match test.hashAlg.as_str() {
                        "pure" => (),
                        "none" => (),
                        // No support for HashML-DSA.
                        _ => continue,
                    };

                    if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                        let m = hex::decode(m).unwrap();
                        let ctx = hex::decode(ctx).unwrap();

                        let signature = sk.sign_with_rnd(&m, &ctx, &rnd).unwrap();
                        assert_eq!(signature, &sig_expected[..]);
                        let vk = mldsa65::VerifyingKey::try_from(&sk).unwrap();
                        assert!(vk.verify(&m, &ctx, &signature).is_ok());

                        tests_run += 1;
                    }
                }
            }
            "ML-DSA-87" => {
                let mut sk_expected = [0u8; mldsa87::SIGNING_KEY_SIZE];
                let mut sig_expected = [0u8; mldsa87::SIGNATURE_SIZE];

                for test in test_group.tests.iter() {
                    hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                    hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

                    let sk = mldsa87::SigningKey::try_from(&sk_expected).unwrap();
                    assert!(mldsa87::Signature::try_from(&sig_expected).is_ok());

                    // `rnd` is present when the group is deterministic = False.
                    let rnd = match test.rnd.as_ref() {
                        Some(rnd) => {
                            mldsa87::ExplicitRandom::try_from(&hex::decode(rnd).unwrap()).unwrap()
                        }
                        None => mldsa87::ExplicitRandom::deterministic(),
                    };

                    match test.hashAlg.as_str() {
                        "pure" => (),
                        "none" => (),
                        // No support for HashML-DSA.
                        _ => continue,
                    };

                    if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                        let m = hex::decode(m).unwrap();
                        let ctx = hex::decode(ctx).unwrap();

                        let signature = sk.sign_with_rnd(&m, &ctx, &rnd).unwrap();
                        assert_eq!(signature, &sig_expected[..]);
                        let vk = mldsa87::VerifyingKey::try_from(&sk).unwrap();
                        assert!(vk.verify(&m, &ctx, &signature).is_ok());

                        tests_run += 1;
                    }
                }
            }
            other => panic!("unknown parameter set: {other}"),
        }
    }

    assert_eq!(tests_run, 90);
}

#[test]
fn test_acvp_mldsa_siggen() {
    mldsa_runner("./tests/test_data/third_party/nist/ML-DSA/ml_dsa_siggen_internalProjection.json");
}
