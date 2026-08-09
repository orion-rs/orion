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

fn run_test<
    const SK_SIZE: usize,
    const SIG_SIZE: usize,
    const CLEN: usize,
    const COMMITHASH_LEN: usize,
    const W1_ENCODE_SIZE: usize,
    const K: usize,
    const L: usize,
    P: MlDsaParameters,
>(
    group: &MlDsaSigGenTestGroup,
    tests_run: &mut usize,
) {
    for test in group.tests.iter() {
        let mut sk_expected = [0u8; SK_SIZE];
        let mut sig_expected = [0u8; SIG_SIZE];
        hex::decode_to_slice(&test.sk, &mut sk_expected).unwrap();
        hex::decode_to_slice(&test.signature, &mut sig_expected).unwrap();

        let signkey = ml_dsa::internal::InternalSigningKey::<
            SK_SIZE,
            SIG_SIZE,
            CLEN,
            COMMITHASH_LEN,
            W1_ENCODE_SIZE,
            K,
            L,
            P,
        >::try_from(&sk_expected[..])
        .unwrap();

        // `rnd` is present exactly when the group is non-deterministic.
        let rnd: [u8; 32] = match test.rnd.as_ref() {
            Some(rnd) => hex::decode(rnd).unwrap().try_into().unwrap(),
            None => [0u8; 32],
        };

        let signature = if group.externalMu {
            // `mu` is supplied; Sign_internal is entered with it directly.
            let mu: [u8; 64] = hex::decode(test.mu.as_ref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            signkey.sign_internal_with_mu(&mu, &rnd).unwrap()
        } else if group.signatureInterface == "internal" {
            let m = hex::decode(test.message.as_ref().unwrap()).unwrap();
            signkey.sign_internal(&[&m], &rnd).unwrap()
        } else {
            let m = hex::decode(test.message.as_ref().unwrap()).unwrap();
            let ctx = hex::decode(test.context.as_ref().unwrap()).unwrap();
            signkey.sign(&m, &ctx, &rnd).unwrap()
        };

        assert_eq!(&sig_expected, &signature);
        *tests_run += 1;
    }
}

fn mldsa_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlDsaSigGen = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        if test_group.preHash == "preHash" {
            // HashML- impl not there yet
            continue;
        }

        match test_group.parameterSet.as_str() {
            "ML-DSA-44" => run_test::<
                { MlDsa44::PRIVATE_KEY_SIZE },
                { MlDsa44::SIGNATURE_SIZE },
                { MlDsa44::CLEN },
                { MlDsa44::COMMITMENT_HASH_LEN },
                { MlDsa44::W1_BITPACK_SIZE * MlDsa44::DIM_K },
                { MlDsa44::DIM_K },
                { MlDsa44::DIM_L },
                MlDsa44,
            >(test_group, &mut tests_run),
            "ML-DSA-65" => run_test::<
                { MlDsa65::PRIVATE_KEY_SIZE },
                { MlDsa65::SIGNATURE_SIZE },
                { MlDsa65::CLEN },
                { MlDsa65::COMMITMENT_HASH_LEN },
                { MlDsa65::W1_BITPACK_SIZE * MlDsa65::DIM_K },
                { MlDsa65::DIM_K },
                { MlDsa65::DIM_L },
                MlDsa65,
            >(test_group, &mut tests_run),
            "ML-DSA-87" => run_test::<
                { MlDsa87::PRIVATE_KEY_SIZE },
                { MlDsa87::SIGNATURE_SIZE },
                { MlDsa87::CLEN },
                { MlDsa87::COMMITMENT_HASH_LEN },
                { MlDsa87::W1_BITPACK_SIZE * MlDsa87::DIM_K },
                { MlDsa87::DIM_K },
                { MlDsa87::DIM_L },
                MlDsa87,
            >(test_group, &mut tests_run),
            other => panic!("unknown parameter set: {other}"),
        }
    }

    assert_eq!(tests_run, 270);
}

#[test]
fn test_acvp_mldsa_siggen() {
    mldsa_runner("./tests/test_data/third_party/nist/ML-DSA/ml_dsa_siggen_internalProjection.json");
}
