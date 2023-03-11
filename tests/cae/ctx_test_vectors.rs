use hex::decode;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

use orion::hazardous::cae::chacha20poly1305blake2b::{self, SecretKey, TAG_SIZE};
use orion::hazardous::cae::xchacha20poly1305blake2b;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestVector {
    pub(crate) Key: String,
    pub(crate) Nonce: String,
    pub(crate) Ad: String,
    pub(crate) Msg: String,
    pub(crate) Ciphertext: String,
    pub(crate) CommitmentTag: String,
    pub(crate) Result: String,
    pub(crate) Comment: String,
}

pub(crate) fn custom_ctx_runner(path: &str) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<TestVector> = serde_json::from_reader(reader).unwrap();

    let is_ietf = match decode(&tests[0].Nonce).unwrap().len() {
        12 => true,
        24 => false,
        _ => panic!("Unexpected nonce length"),
    };

    for test in tests.iter() {
        let should_test_pass: bool = match test.Result.as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("Unexpected test outcome for custom CTX tests"),
        };

        let key = SecretKey::from_slice(&decode(&test.Key).unwrap()).unwrap();
        let nonce = &decode(&test.Nonce).unwrap();
        let aad = &decode(&test.Ad).unwrap();
        let input = &decode(&test.Msg).unwrap();
        let mut dst_ct_out = vec![0u8; input.len() + TAG_SIZE];
        let mut dst_pt_out = vec![0u8; input.len()];

        // Test vectors have ciphertext appended with underlying AE tag.
        // So we remove this and append the BLAKE2b commitment tag instead.
        let mut output = vec![0u8; dst_ct_out.len()];
        output[..input.len()].copy_from_slice(&decode(&test.Ciphertext).unwrap()[..input.len()]);
        output[input.len()..].copy_from_slice(&decode(&test.CommitmentTag).unwrap());

        if test.Comment == "wrong Poly1305 tag" {
            // This test is for implementations that internally cannot re-compute the Poly1305 tag
            // due to lack of access to such an API (and consequently also store this alongside the
            // commitment tag). Orion does re-compute the Poly1305 tag, so this test vector won't pass
            // as we re-compute it internally and don't accept it from the outside.
            continue;
        }

        if should_test_pass {
            if is_ietf {
                let nonce = chacha20poly1305blake2b::Nonce::from_slice(nonce).unwrap();
                chacha20poly1305blake2b::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)
                    .unwrap();
                chacha20poly1305blake2b::open(
                    &key,
                    &nonce,
                    &dst_ct_out,
                    Some(aad),
                    &mut dst_pt_out,
                )
                .unwrap();
            } else {
                let nonce = xchacha20poly1305blake2b::Nonce::from_slice(nonce).unwrap();
                xchacha20poly1305blake2b::seal(&key, &nonce, input, Some(aad), &mut dst_ct_out)
                    .unwrap();
                xchacha20poly1305blake2b::open(
                    &key,
                    &nonce,
                    &dst_ct_out,
                    Some(aad),
                    &mut dst_pt_out,
                )
                .unwrap();
            }

            assert_eq!(dst_ct_out, output);
            assert_eq!(dst_pt_out[..].as_ref(), input);
        } else {
            if is_ietf {
                let nonce = chacha20poly1305blake2b::Nonce::from_slice(nonce).unwrap();
                assert!(chacha20poly1305blake2b::open(
                    &key,
                    &nonce,
                    &output,
                    Some(aad),
                    &mut dst_pt_out
                )
                .is_err())
            } else {
                let nonce = xchacha20poly1305blake2b::Nonce::from_slice(nonce).unwrap();
                assert!(xchacha20poly1305blake2b::open(
                    &key,
                    &nonce,
                    &output,
                    Some(aad),
                    &mut dst_pt_out
                )
                .is_err())
            }
        }
    }
}
