use hex::decode;
use orion::hazardous::kem::x25519_hkdf_sha256::*;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct HpkeTest {
    pub(crate) mode: u64,
    pub(crate) kem_id: u64,
    pub(crate) kdf_id: u64,
    pub(crate) aead_id: u64,
    pub(crate) info: String,
    pub(crate) ikmR: String,
    pub(crate) ikmE: String,
    pub(crate) ikmS: Option<String>,
    pub(crate) skRm: String,
    pub(crate) skSm: Option<String>,
    pub(crate) skEm: String,
    pub(crate) pkRm: String,
    pub(crate) pkSm: Option<String>,
    pub(crate) pkEm: String,
    pub(crate) enc: String,
    pub(crate) shared_secret: String,
    pub(crate) key_schedule_context: String,
    pub(crate) secret: String,
    pub(crate) key: String,
    pub(crate) base_nonce: String,
    pub(crate) exporter_secret: String,
    pub(crate) encryptions: Vec<EncryptionTest>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EncryptionTest {
    pub(crate) aad: String,
    pub(crate) ct: String,
    pub(crate) nonce: String,
}

fn hpke_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<HpkeTest> = serde_json::from_reader(reader).unwrap();

    let mut test_counter = 0;
    for test in tests {
        if test.kem_id != 32 {
            // We don't support any KEM except X25519-HKDF-SHA256.
            continue;
        }

        let secret_recip = PrivateKey::from_slice(&decode(&test.skRm).unwrap()).unwrap();
        let public_recip = PublicKey::from_slice(&decode(&test.pkRm).unwrap()).unwrap();
        let derived_kp = DhKem::derive_keypair(&decode(&test.ikmR).unwrap()).unwrap();
        assert_eq!(secret_recip, derived_kp.0);
        assert_eq!(public_recip, derived_kp.1);

        let secret_eph = PrivateKey::from_slice(&decode(&test.skEm).unwrap()).unwrap();
        let public_eph = PublicKey::from_slice(&decode(&test.pkEm).unwrap()).unwrap();
        let derived_kp = DhKem::derive_keypair(&decode(&test.ikmE).unwrap()).unwrap();
        assert_eq!(secret_eph, derived_kp.0);
        assert_eq!(public_eph, derived_kp.1);

        match test.mode {
            0 => {
                let shared = DhKem::decap(&public_eph, &secret_recip).unwrap();
                assert_eq!(
                    shared.unprotected_as_bytes(),
                    &decode(test.shared_secret).unwrap()
                );
            }
            2 => {
                // We only have values for the sender in this mode
                let secret_sender = PrivateKey::from_slice(&decode(&test.skSm.unwrap()).unwrap()).unwrap();
                let public_sender = PublicKey::from_slice(&decode(&test.pkSm.unwrap()).unwrap()).unwrap();
                let derived_kp = DhKem::derive_keypair(&decode(&test.ikmS.unwrap()).unwrap()).unwrap();
                assert_eq!(secret_sender, derived_kp.0);
                assert_eq!(public_sender, derived_kp.1);

                let shared = DhKem::auth_decap(&public_eph, &secret_recip, &public_sender).unwrap();
                assert_eq!(
                    shared.unprotected_as_bytes(),
                    &decode(test.shared_secret).unwrap()
                );
            }
            _ => {
                continue; // Unsupported mode
            }
        }

        test_counter += 1;
    }

    assert_eq!(
        test_counter, 16,
        "There should be 32 tests for our KEM+mode. Have more been added?"
    );
}

#[test]
fn test_hpke_kats() {
    hpke_runner("./tests/test_data/third_party/rfc9180/test-vectors.json");
}
