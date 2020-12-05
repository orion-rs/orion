// Testing against PyNaCl test vectors
// Latest commit when these test vectors were pulled: https://github.com/pyca/pynacl/commit/3bb12aef959c92f9042c150deec42cf104c40dfa
// The generated test vectors have been generated the 26th October 2019.

use hex::decode;
use orion::hazardous::aead::streaming::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::{fs::File, io::BufReader};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestCase {
    key: String,
    header: String,
    chunks: Vec<TestCaseStreamingMessage>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct TestCaseStreamingMessage {
    tag: u8,
    ad: String,
    message: String,
    ciphertext: String,
}

fn run_tests_from_json(path_to_vectors: &str) {
    let file = File::open(path_to_vectors).unwrap();
    let reader = BufReader::new(file);
    let tests: Vec<TestCase> = serde_json::from_reader(reader).unwrap();

    for test in tests.iter() {
        let key = SecretKey::from_slice(&decode(&test.key).unwrap()).unwrap();
        let nonce = &Nonce::from_slice(&decode(&test.header).unwrap()).unwrap();

        let mut ctx_seal = StreamXChaCha20Poly1305::new(&key, &nonce);
        let mut ctx_open = StreamXChaCha20Poly1305::new(&key, &nonce);

        for chunk in test.chunks.iter() {
            let chunk_msg = decode(&chunk.message).unwrap();
            let chunk_ct = decode(&chunk.ciphertext).unwrap();
            let chunk_ad = decode(&chunk.ad).unwrap();

            let mut chunk_out_ct = vec![0u8; chunk_ct.len()];
            let mut chunk_out_pt = vec![0u8; chunk_msg.len()];

            ctx_seal
                .seal_chunk(
                    &chunk_msg,
                    Some(&chunk_ad),
                    &mut chunk_out_ct,
                    StreamTag::try_from(chunk.tag).unwrap(),
                )
                .unwrap();

            ctx_open
                .open_chunk(&chunk_ct, Some(&chunk_ad), &mut chunk_out_pt)
                .unwrap();

            assert_eq!(chunk_out_pt, chunk_msg);
            assert_eq!(chunk_out_ct, chunk_ct);
        }
    }
}

#[test]
fn test_pynacl() {
    run_tests_from_json(
        "./tests/test_data/third_party/pynacl/pynacl_secretstream_test_vectors.json",
    );
    run_tests_from_json("./tests/test_data/pynacl_generated.json");
    run_tests_from_json("./tests/test_data/pynacl_generated_with_rekey.json");
}
