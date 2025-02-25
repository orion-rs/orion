// ml_kem_keygen_internalProjection.json
// taken at commit: https://github.com/usnistgov/ACVP-Server/commit/203f667c26e10a1be89dfe8da7a54498fde2d848

use orion::hazardous::kem::mlkem1024;
use orion::hazardous::kem::mlkem512;
use orion::hazardous::kem::mlkem768;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemKeyGen {
    vsId: u32,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<MlKemKeyGenTestGroup>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MlKemKeyGenTestGroup {
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
    z: String,
    d: String,
    ek: String,
    dk: String,
}

fn mlkem_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: MlKemKeyGen = serde_json::from_reader(reader).unwrap();

    let mut tests_run = 0;
    for test_group in tests.testGroups.iter() {
        if test_group.parameterSet == "ML-KEM-512" {
            for test in test_group.tests.iter() {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                let mut ek_expected = [0u8; mlkem512::MlKem512::EK_SIZE];
                let mut dk_expected = [0u8; mlkem512::MlKem512::DK_SIZE];
                hex::decode_to_slice(&test.z, &mut z).unwrap();
                hex::decode_to_slice(&test.d, &mut d).unwrap();
                hex::decode_to_slice(&test.ek, &mut ek_expected).unwrap();
                hex::decode_to_slice(&test.dk, &mut dk_expected).unwrap();

                let mut dz = d.to_vec();
                dz.extend(&z);

                let seed = mlkem512::Seed::from_slice(&dz).unwrap();
                let kp = mlkem512::KeyPair::try_from(&seed).unwrap();

                assert_eq!(ek_expected, kp.public().as_ref());
                assert_eq!(kp.private(), &dk_expected.as_ref());

                tests_run += 1;
            }
        }
        if test_group.parameterSet == "ML-KEM-768" {
            for test in test_group.tests.iter() {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                let mut ek_expected = [0u8; mlkem768::MlKem768::EK_SIZE];
                let mut dk_expected = [0u8; mlkem768::MlKem768::DK_SIZE];
                hex::decode_to_slice(&test.z, &mut z).unwrap();
                hex::decode_to_slice(&test.d, &mut d).unwrap();
                hex::decode_to_slice(&test.ek, &mut ek_expected).unwrap();
                hex::decode_to_slice(&test.dk, &mut dk_expected).unwrap();

                let mut dz = d.to_vec();
                dz.extend(&z);

                let seed = mlkem768::Seed::from_slice(&dz).unwrap();
                let kp = mlkem768::KeyPair::try_from(&seed).unwrap();

                assert_eq!(ek_expected, kp.public().as_ref());
                assert_eq!(kp.private(), &dk_expected.as_ref());

                tests_run += 1;
            }
        }

        if test_group.parameterSet == "ML-KEM-1024" {
            for test in test_group.tests.iter() {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                let mut ek_expected = [0u8; mlkem1024::MlKem1024::EK_SIZE];
                let mut dk_expected = [0u8; mlkem1024::MlKem1024::DK_SIZE];
                hex::decode_to_slice(&test.z, &mut z).unwrap();
                hex::decode_to_slice(&test.d, &mut d).unwrap();
                hex::decode_to_slice(&test.ek, &mut ek_expected).unwrap();
                hex::decode_to_slice(&test.dk, &mut dk_expected).unwrap();

                let mut dz = d.to_vec();
                dz.extend(&z);

                let seed = mlkem1024::Seed::from_slice(&dz).unwrap();
                let kp = mlkem1024::KeyPair::try_from(&seed).unwrap();

                assert_eq!(ek_expected, kp.public().as_ref());
                assert_eq!(kp.private(), &dk_expected.as_ref());

                tests_run += 1;
            }
        }
    }

    assert_eq!(tests_run, 75);
}

#[test]
fn test_acvp_mlkem_encapdecap() {
    mlkem_runner("./tests/test_data/third_party/nist/ML-KEM/ml_kem_keygen_internalProjection.json");
}
