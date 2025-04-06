use hex::decode;
use orion::hazardous::hpke::DHKEM_X25519_SHA256_CHACHA20;
use orion::hazardous::hpke::{ModeAuth, ModeAuthPsk, ModeBase, ModePsk};
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
    pub(crate) psk: Option<String>,
    pub(crate) psk_id: Option<String>,
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
    pub(crate) pt: String,
}

fn hpke_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<HpkeTest> = serde_json::from_reader(reader).unwrap();

    let mut test_counter = 0;
    for test in tests {
        if test.kem_id as u16 != u16::from_be_bytes(DHKEM_X25519_SHA256_CHACHA20::KEM_ID)
            || test.kdf_id as u16 != u16::from_be_bytes(DHKEM_X25519_SHA256_CHACHA20::KDF_ID)
            || test.aead_id as u16 != u16::from_be_bytes(DHKEM_X25519_SHA256_CHACHA20::AEAD_ID)
        {
            // Currently only support DHKEM_X25519_SHA256_CHACHA20.
            continue;
        }

        // NOTE: There is a bug in the HPKE test vectors where the private key are not clamped,
        // so we cannot compare that output: https://github.com/cfrg/draft-irtf-cfrg-hpke/issues/255.
        // Test that we get the same values for derived keys.
        if let Some(ikm_s) = test.ikmS {
            assert!(
                test.mode as u8 == ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID
                    || test.mode as u8 == ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID
            );

            let secret_sender =
                PrivateKey::from_slice(&decode(test.skSm.as_ref().unwrap()).unwrap()).unwrap();
            let public_sender =
                PublicKey::from_slice(&decode(test.pkSm.as_ref().unwrap()).unwrap()).unwrap();
            let derived_kp_sender = DhKem::derive_keypair(&decode(ikm_s).unwrap()).unwrap();
            assert_eq!(secret_sender, derived_kp_sender.0);
            assert_eq!(public_sender, derived_kp_sender.1);
            assert_eq!(
                &public_sender.to_bytes(),
                decode(test.pkSm.as_ref().unwrap()).unwrap().as_slice()
            );
        }

        let secret_recip = PrivateKey::from_slice(&decode(&test.skRm).unwrap()).unwrap();
        let public_recip = PublicKey::from_slice(&decode(&test.pkRm).unwrap()).unwrap();
        let derived_kp_recip = DhKem::derive_keypair(&decode(&test.ikmR).unwrap()).unwrap();
        assert_eq!(secret_recip, derived_kp_recip.0);
        assert_eq!(public_recip, derived_kp_recip.1);
        assert_eq!(
            &public_recip.to_bytes(),
            decode(&test.pkRm).unwrap().as_slice()
        );

        let secret_eph = PrivateKey::from_slice(&decode(&test.skEm).unwrap()).unwrap();
        let public_eph = PublicKey::from_slice(&decode(&test.pkEm).unwrap()).unwrap();
        let derived_kp_eph = DhKem::derive_keypair(&decode(&test.ikmE).unwrap()).unwrap();
        assert_eq!(secret_eph, derived_kp_eph.0);
        assert_eq!(public_eph, derived_kp_eph.1);
        assert_eq!(
            &public_eph.to_bytes(),
            decode(&test.pkEm).unwrap().as_slice()
        );

        let info = hex::decode(test.info).unwrap();
        let shared_secret = hex::decode(test.shared_secret).unwrap();
        let base_nonce = hex::decode(test.base_nonce).unwrap();
        let exporter_secret = hex::decode(test.exporter_secret).unwrap();
        let enc = PublicKey::from_slice(&hex::decode(test.enc).unwrap()).unwrap();

        match test.mode as u8 {
            ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID => {
                let (mut hpke_ctx_s, actual_enc) =
                    ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender_deterministic(
                        &public_recip,
                        &info,
                        secret_eph,
                    )
                    .unwrap();
                assert_eq!(actual_enc, enc);

                let mut hpke_ctx_r = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                    &enc,
                    &secret_recip,
                    &info,
                )
                .unwrap();

                // todo
                //assert_eq!(hpke_ctx._testing_base_nonce(), &base_nonce);
                //assert_eq!(hpke_ctx._testing_exporter_secret(), &exporter_secret);

                for encryption in test.encryptions.iter() {
                    let aad = hex::decode(&encryption.aad).unwrap();
                    let ct = hex::decode(&encryption.ct).unwrap();
                    let nonce = hex::decode(&encryption.nonce).unwrap();
                    let pt = hex::decode(&encryption.pt).unwrap();
                    let mut out = vec![0u8; ct.len() - 16];
                    let mut out_ct = vec![0u8; ct.len()];

                    hpke_ctx_s
                        .seal(&pt, &aad, &mut out_ct)
                        .expect("Failed encryption");
                    assert_eq!(&out_ct, &ct);

                    hpke_ctx_r
                        .open(&ct, &aad, &mut out)
                        .expect("Failed decryption");
                    assert_eq!(&pt, &out);
                }

                test_counter += 1;
            }
            ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID => {
                assert!(test.psk.is_some());
                assert!(test.psk_id.is_some());

                let psk = hex::decode(test.psk.unwrap()).unwrap();
                let psk_id = hex::decode(test.psk_id.unwrap()).unwrap();

                let (mut hpke_ctx_s, actual_enc) =
                    ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender_deterministic(
                        &public_recip,
                        &info,
                        &psk,
                        &psk_id,
                        secret_eph,
                    )
                    .unwrap();
                assert_eq!(actual_enc, enc);

                let mut hpke_ctx_r = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                    &enc,
                    &secret_recip,
                    &info,
                    &psk,
                    &psk_id,
                )
                .unwrap();

                // todo
                //assert_eq!(hpke_ctx._testing_base_nonce(), &base_nonce);
                //assert_eq!(hpke_ctx._testing_exporter_secret(), &exporter_secret);

                for encryption in test.encryptions.iter() {
                    let aad = hex::decode(&encryption.aad).unwrap();
                    let ct = hex::decode(&encryption.ct).unwrap();
                    let nonce = hex::decode(&encryption.nonce).unwrap();
                    let pt = hex::decode(&encryption.pt).unwrap();
                    let mut out = vec![0u8; ct.len() - 16];
                    let mut out_ct = vec![0u8; ct.len()];

                    hpke_ctx_s
                        .seal(&pt, &aad, &mut out_ct)
                        .expect("Failed encryption");
                    assert_eq!(&out_ct, &ct);

                    hpke_ctx_r
                        .open(&ct, &aad, &mut out)
                        .expect("Failed decryption");
                    assert_eq!(&pt, &out);
                }

                test_counter += 1;
            }
            ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID => {
                assert!(test.pkSm.is_some());
                assert!(test.skSm.is_some());
                let secret_sender =
                    PrivateKey::from_slice(&decode(test.skSm.unwrap()).unwrap()).unwrap();
                let public_sender =
                    PublicKey::from_slice(&decode(test.pkSm.unwrap()).unwrap()).unwrap();

                let (mut hpke_ctx_s, actual_enc) =
                    ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_sender_deterministic(
                        &public_recip,
                        &info,
                        &secret_sender,
                        secret_eph,
                    )
                    .unwrap();
                assert_eq!(actual_enc, enc);

                let mut hpke_ctx_r = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                    &enc,
                    &secret_recip,
                    &info,
                    &public_sender,
                )
                .unwrap();

                // todo
                //assert_eq!(hpke_ctx._testing_base_nonce(), &base_nonce);
                //assert_eq!(hpke_ctx._testing_exporter_secret(), &exporter_secret);

                for encryption in test.encryptions.iter() {
                    let aad = hex::decode(&encryption.aad).unwrap();
                    let ct = hex::decode(&encryption.ct).unwrap();
                    let nonce = hex::decode(&encryption.nonce).unwrap();
                    let pt = hex::decode(&encryption.pt).unwrap();
                    let mut out = vec![0u8; ct.len() - 16];
                    let mut out_ct = vec![0u8; ct.len()];

                    hpke_ctx_s
                        .seal(&pt, &aad, &mut out_ct)
                        .expect("Failed encryption");
                    assert_eq!(&out_ct, &ct);

                    hpke_ctx_r
                        .open(&ct, &aad, &mut out)
                        .expect("Failed decryption");
                    assert_eq!(&pt, &out);
                }

                test_counter += 1;
            }
            ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::MODE_ID => {
                assert!(test.pkSm.is_some());
                assert!(test.skSm.is_some());
                assert!(test.psk.is_some());
                assert!(test.psk_id.is_some());

                let psk = hex::decode(test.psk.unwrap()).unwrap();
                let psk_id = hex::decode(test.psk_id.unwrap()).unwrap();

                let secret_sender =
                    PrivateKey::from_slice(&decode(test.skSm.unwrap()).unwrap()).unwrap();
                let public_sender =
                    PublicKey::from_slice(&decode(test.pkSm.unwrap()).unwrap()).unwrap();

                let (mut hpke_ctx_s, actual_enc) =
                    ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender_deterministic(
                        &public_recip,
                        &info,
                        &psk,
                        &psk_id,
                        &secret_sender,
                        secret_eph,
                    )
                    .unwrap();
                assert_eq!(actual_enc, enc);

                let mut hpke_ctx_r = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
                    &enc,
                    &secret_recip,
                    &info,
                    &psk,
                    &psk_id,
                    &public_sender,
                )
                .unwrap();

                // todo
                //assert_eq!(hpke_ctx._testing_base_nonce(), &base_nonce);
                //assert_eq!(hpke_ctx._testing_exporter_secret(), &exporter_secret);

                for encryption in test.encryptions.iter() {
                    let aad = hex::decode(&encryption.aad).unwrap();
                    let ct = hex::decode(&encryption.ct).unwrap();
                    let nonce = hex::decode(&encryption.nonce).unwrap();
                    let pt = hex::decode(&encryption.pt).unwrap();
                    let mut out = vec![0u8; ct.len() - 16];
                    let mut out_ct = vec![0u8; ct.len()];

                    hpke_ctx_s
                        .seal(&pt, &aad, &mut out_ct)
                        .expect("Failed encryption");
                    assert_eq!(&out_ct, &ct);

                    hpke_ctx_r
                        .open(&ct, &aad, &mut out)
                        .expect("Failed decryption");
                    assert_eq!(&pt, &out);
                }

                test_counter += 1;
            }
            _ => panic!("invalid test.mode part of KATs"),
        }
    }

    assert_eq!(test_counter, 4); // One test-set for each HPKE mode (4 modes), per scheme.
}

#[test]
fn test_hpke_kats() {
    hpke_runner("./tests/test_data/third_party/rfc9180/test-vectors.json");
}
