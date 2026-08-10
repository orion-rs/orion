// Taken at commit: https://github.com/C2SP/wycheproof/commit/6d7cccd0fcb1917368579adeeac10fe802f1b521

use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaTest {
    algorithm: String,
    generatorVersion: Option<String>, // only present on mldsa_KL_verify_test.json
    header: Vec<String>,
    numberOfTests: u32,
    #[serde(skip)]
    #[allow(dead_code)]
    notes: Vec<String>,
    testGroups: Vec<MlDsaTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlDsaTestGroup {
    #[serde(rename(deserialize = "type"))]
    testType: String,
    publicKey: Option<String>, // none when the private key is malformed

    publicKeyDer: Option<String>,    // mldsa_KL_verify_test.json
    privateKeyPkcs8: Option<String>, // mldsa_KL_sign_seed_test.json
    privateSeed: Option<String>,     // mldsa_KL_sign_seed_test.json
    privateKey: Option<String>,      // mldsa_KL_sign_noseed_test.json

    source: Option<TestSource>, // some verify groups missing this
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
    msg: Option<String>,
    mu: Option<String>,
    sig: Option<String>,
    ctx: Option<String>,
    rnd: Option<String>,
    result: String,
}

macro_rules! wycheproof_mldsa {
    ($suite:ident, $ml:ident, $kl:literal) => {
        mod $suite {
            use super::*;
            use orion::KP;
            use orion::hazardous::dsa::$ml::{
                ExplicitRandom, KeyPair, SEED_SIZE, SIGNATURE_SIZE, SIGNING_KEY_SIZE, Seed,
                Signature, SigningKey, VERIFYING_KEY_SIZE, VerifyingKey,
            };

            fn testfile_path(kind: &str) -> String {
                format!(
                    "./tests/test_data/third_party/c2sp_wycheproof/mldsa_{}_{}_test.json",
                    $kl, kind
                )
            }

            fn rnd_of(test: &TestVector) -> ExplicitRandom {
                match test.rnd.as_ref() {
                    Some(rnd) => ExplicitRandom::try_from(&hex::decode(rnd).unwrap()).unwrap(),
                    None => ExplicitRandom::deterministic(),
                }
            }

            fn sign_tests(
                sk: &SigningKey,
                vk: &VerifyingKey,
                tests: &[TestVector],
            ) -> (usize, usize) {
                let (mut run, mut skipped) = (0usize, 0usize);

                for test in tests.iter() {
                    let Some(msg) = test.msg.as_ref() else {
                        // Skip `mu` tests where `msg` is none
                        skipped += 1;
                        continue;
                    };

                    let msg = hex::decode(msg).unwrap();
                    let ctx = test
                        .ctx
                        .as_ref()
                        .map_or(vec![], |c| hex::decode(c).unwrap());
                    let produced = sk.sign_with_rnd(&msg, &ctx, &rnd_of(test));

                    if test.result == "valid" {
                        let signature = produced.unwrap();
                        let sig_expected = hex::decode(test.sig.as_ref().unwrap()).unwrap();
                        assert_eq!(signature.as_ref(), &sig_expected[..], "tcId {}", test.tcId,);

                        assert!(
                            vk.verify(&msg, &ctx, &signature).is_ok(),
                            "tcId {}",
                            test.tcId
                        );
                    } else {
                        assert!(produced.is_err(), "tcId {}", test.tcId);
                    }

                    run += 1;
                }

                (run, skipped)
            }

            #[test]
            fn sign_seed() {
                let file = File::open(testfile_path("sign_seed")).unwrap();
                let reader = BufReader::new(file);
                let tests: MlDsaTest = serde_json::from_reader(reader).unwrap();
                let (mut run, mut skipped) = (0usize, 0usize);

                for group in tests.testGroups.iter() {
                    let seed = hex::decode(group.privateSeed.as_ref().unwrap()).unwrap();

                    let Ok(seed) = <[u8; SEED_SIZE]>::try_from(seed.as_slice()) else {
                        assert!(group.publicKey.is_none());
                        for test in group.tests.iter() {
                            assert_eq!(test.result, "invalid", "tcId {}", test.tcId);
                            run += 1;
                        }
                        continue;
                    };

                    let kp = KeyPair::new(Seed::try_from(&seed).unwrap()).unwrap();

                    assert_eq!(
                        hex::encode(kp.public().as_ref()),
                        group.publicKey.as_ref().unwrap().to_lowercase(),
                    );

                    let (r, s) = sign_tests(kp.private(), kp.public(), &group.tests);
                    run += r;
                    skipped += s;
                }

                assert_eq!(run + skipped, tests.numberOfTests as usize);
            }

            #[test]
            fn sign_noseed() {
                let file = File::open(testfile_path("sign_noseed")).unwrap();
                let reader = BufReader::new(file);
                let tests: MlDsaTest = serde_json::from_reader(reader).unwrap();
                let (mut run, mut skipped) = (0usize, 0usize);

                for group in tests.testGroups.iter() {
                    let sk = hex::decode(group.privateKey.as_ref().unwrap()).unwrap();
                    let sk = <[u8; SIGNING_KEY_SIZE]>::try_from(sk.as_slice())
                        .ok()
                        .and_then(|b| SigningKey::try_from(&b).ok());

                    let Some(sk) = sk else {
                        for test in group.tests.iter() {
                            assert_eq!(test.result, "invalid", "tcId {}", test.tcId);
                            run += 1;
                        }
                        continue;
                    };

                    let mut pk = [0u8; VERIFYING_KEY_SIZE];
                    hex::decode_to_slice(group.publicKey.as_ref().unwrap(), &mut pk).unwrap();
                    let vk = VerifyingKey::try_from(&pk).unwrap();

                    let (r, s) = sign_tests(&sk, &vk, &group.tests);
                    run += r;
                    skipped += s;
                }

                assert_eq!(run + skipped, tests.numberOfTests as usize);
            }

            #[test]
            fn verify() {
                let file = File::open(testfile_path("verify")).unwrap();
                let reader = BufReader::new(file);
                let tests: MlDsaTest = serde_json::from_reader(reader).unwrap();
                let mut run = 0usize;

                for group in tests.testGroups.iter() {
                    let pk = hex::decode(group.publicKey.as_ref().unwrap()).unwrap();

                    let vk = <[u8; VERIFYING_KEY_SIZE]>::try_from(pk.as_slice())
                        .ok()
                        .and_then(|b| VerifyingKey::try_from(&b).ok());

                    for test in group.tests.iter() {
                        let accepted = match vk.as_ref() {
                            None => false,
                            Some(vk) => {
                                let msg = hex::decode(test.msg.as_ref().unwrap()).unwrap();
                                let ctx = test
                                    .ctx
                                    .as_ref()
                                    .map_or(vec![], |c| hex::decode(c).unwrap());
                                let sig = hex::decode(test.sig.as_ref().unwrap()).unwrap();

                                <[u8; SIGNATURE_SIZE]>::try_from(sig.as_slice())
                                    .ok()
                                    .and_then(|b| Signature::try_from(&b).ok())
                                    .is_some_and(|s| vk.verify(&msg, &ctx, &s).is_ok())
                            }
                        };

                        assert_eq!(accepted, test.result == "valid", "tcId {}", test.tcId,);
                        run += 1;
                    }
                }

                assert_eq!(run, tests.numberOfTests as usize);
            }
        }
    };
}

wycheproof_mldsa!(mldsa44, mldsa44, "44");
wycheproof_mldsa!(mldsa65, mldsa65, "65");
wycheproof_mldsa!(mldsa87, mldsa87, "87");
