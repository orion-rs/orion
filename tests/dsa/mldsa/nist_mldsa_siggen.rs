// ML-DSA commit: https://github.com/usnistgov/ACVP-Server/commit/2972def23bf9f3680c2c531561ed9bdd0f1086ad

use orion::hazardous::dsa::ml_dsa::{
    self,
    internal::{MlDsa44, MlDsa65, MlDsa87, MlDsaParameters},
};
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
        if test_group.parameterSet == "ML-DSA-44" {
            for test in test_group.tests.iter() {
                if test_group.preHash != "" && test_group.preHash != "none" {
                    // TODO: NOT IMPLEMENTED YET.
                    continue;
                }

                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa44::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa44::PUBLIC_KEY_SIZE];
                let mut sig_expected = [0u8; ml_dsa::internal::MlDsa44::SIGNATURE_SIZE];
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();
                let signkey = ml_dsa::internal::InternalSigningKey::<
                    { MlDsa44::PRIVATE_KEY_SIZE },
                    { MlDsa44::SIGNATURE_SIZE },
                    { MlDsa44::CLEN },
                    { MlDsa44::COMMITMENT_HASH_LEN },
                    { MlDsa44::W1_BITPACK_SIZE },
                    { MlDsa44::DIM_K },
                    { MlDsa44::DIM_L },
                    MlDsa44,
                >::try_from(&sk_expected[..])
                .unwrap();

                let rnd = if let Some(rnd) = test.rnd.as_ref() {
                    hex::decode(&rnd).unwrap()
                } else {
                    [0u8; 32].to_vec()
                };

                if let Some(mu) = test.mu.as_ref() {
                    let mu = hex::decode(&mu).unwrap();
                    let signature = signkey.sign_internal_deterministic(&[&mu], &rnd).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }

                if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                    let ctx = hex::decode(&ctx).unwrap();
                    let m = hex::decode(&m).unwrap();
                    let signature = signkey.sign_deterministic(&m, &ctx).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }
            }
        }
        if test_group.parameterSet == "ML-DSA-65" {
            for test in test_group.tests.iter() {
                if test_group.preHash != "" && test_group.preHash != "none" {
                    // TODO: NOT IMPLEMENTED YET.
                    continue;
                }

                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa65::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa65::PUBLIC_KEY_SIZE];
                let mut sig_expected = [0u8; ml_dsa::internal::MlDsa65::SIGNATURE_SIZE];
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();
                let signkey = ml_dsa::internal::InternalSigningKey::<
                    { MlDsa65::PRIVATE_KEY_SIZE },
                    { MlDsa65::SIGNATURE_SIZE },
                    { MlDsa65::CLEN },
                    { MlDsa65::COMMITMENT_HASH_LEN },
                    { MlDsa65::W1_BITPACK_SIZE },
                    { MlDsa65::DIM_K },
                    { MlDsa65::DIM_L },
                    MlDsa65,
                >::try_from(&sk_expected[..])
                .unwrap();

                let rnd = if let Some(rnd) = test.rnd.as_ref() {
                    hex::decode(&rnd).unwrap()
                } else {
                    [0u8; 32].to_vec()
                };

                if let Some(mu) = test.mu.as_ref() {
                    let mu = hex::decode(&mu).unwrap();
                    let signature = signkey.sign_internal_deterministic(&[&mu], &rnd).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }

                if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                    let ctx = hex::decode(&ctx).unwrap();
                    let m = hex::decode(&m).unwrap();
                    let signature = signkey.sign_deterministic(&m, &ctx).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }
            }
        }

        if test_group.parameterSet == "ML-DSA-87" {
            for test in test_group.tests.iter() {
                if test_group.preHash != "" && test_group.preHash != "none" {
                    // TODO: NOT IMPLEMENTED YET.
                    continue;
                }

                let mut sk_expected = [0u8; ml_dsa::internal::MlDsa87::PRIVATE_KEY_SIZE];
                let mut pk_expected = [0u8; ml_dsa::internal::MlDsa87::PUBLIC_KEY_SIZE];
                let mut sig_expected = [0u8; ml_dsa::internal::MlDsa87::SIGNATURE_SIZE];
                hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
                hex::decode_to_slice(&test.pk, &mut pk_expected).unwrap();
                hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();
                let signkey = ml_dsa::internal::InternalSigningKey::<
                    { MlDsa87::PRIVATE_KEY_SIZE },
                    { MlDsa87::SIGNATURE_SIZE },
                    { MlDsa87::CLEN },
                    { MlDsa87::COMMITMENT_HASH_LEN },
                    { MlDsa87::W1_BITPACK_SIZE },
                    { MlDsa87::DIM_K },
                    { MlDsa87::DIM_L },
                    MlDsa87,
                >::try_from(&sk_expected[..])
                .unwrap();

                let rnd = if let Some(rnd) = test.rnd.as_ref() {
                    hex::decode(&rnd).unwrap()
                } else {
                    [0u8; 32].to_vec()
                };

                if let Some(mu) = test.mu.as_ref() {
                    let mu = hex::decode(&mu).unwrap();
                    let signature = signkey.sign_internal_deterministic(&[&mu], &rnd).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }

                if let (Some(m), Some(ctx)) = (test.message.as_ref(), test.context.as_ref()) {
                    let ctx = hex::decode(&ctx).unwrap();
                    let m = hex::decode(&m).unwrap();
                    let signature = signkey.sign_deterministic(&m, &ctx).unwrap();
                    assert_eq!(sig_expected, signature);

                    tests_run += 1;
                    continue;
                }
            }
        }
    }

    assert_eq!(tests_run, 25);
}

#[test]
fn test_acvp_mldsa_siggen() {
    mldsa_runner("./tests/test_data/third_party/nist/ML-DSA/ml_dsa_siggen_internalProjection.json");
}
