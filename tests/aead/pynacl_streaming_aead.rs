// Testing against PyNaCl test vectors
// Latest commit when these test vectors were pulled: https://github.com/pyca/pynacl/commit/3bb12aef959c92f9042c150deec42cf104c40dfa
// The generated test vectors have been generated the 26th October 2019.
extern crate hex;
extern crate orion;
extern crate serde_json;

use self::hex::decode;
use core::convert::TryFrom;

use self::serde_json::{Deserializer, Value};
use std::{fs::File, io::BufReader};

use orion::hazardous::aead::streaming::*;

fn run_tests_from_json(path_to_vectors: &str) {
	let file = File::open(path_to_vectors).unwrap();
	let reader = BufReader::new(file);
	let stream = Deserializer::from_reader(reader).into_iter::<Value>();

	for test_file in stream {
		for test_groups in test_file.unwrap().as_array() {
			for test_case in test_groups {
				let key = decode(test_case.get("key").unwrap().as_str().unwrap()).unwrap();
				let nonce = decode(test_case.get("header").unwrap().as_str().unwrap()).unwrap();

				let mut ctx_seal = StreamXChaCha20Poly1305::new(
					&SecretKey::from_slice(&key).unwrap(),
					&Nonce::from_slice(&nonce).unwrap(),
				);

				let mut ctx_open = StreamXChaCha20Poly1305::new(
					&SecretKey::from_slice(&key).unwrap(),
					&Nonce::from_slice(&nonce).unwrap(),
				);

				for stream_chunks in test_case.get("chunks").unwrap().as_array() {
					for chunk in stream_chunks {
						let chunk_ad = decode(chunk.get("ad").unwrap().as_str().unwrap()).unwrap();
						let chunk_tag =
							StreamTag::try_from(chunk.get("tag").unwrap().as_u64().unwrap() as u8)
								.unwrap();
						let chunk_msg =
							decode(chunk.get("message").unwrap().as_str().unwrap()).unwrap();
						let chunk_ct =
							decode(chunk.get("ciphertext").unwrap().as_str().unwrap()).unwrap();

						let mut chunk_out_ct = vec![0u8; chunk_ct.len()];
						let mut chunk_out_pt = vec![0u8; chunk_msg.len()];

						ctx_seal
							.seal_chunk(&chunk_msg, Some(&chunk_ad), &mut chunk_out_ct, chunk_tag)
							.unwrap();
						ctx_open
							.open_chunk(&chunk_ct, Some(&chunk_ad), &mut chunk_out_pt)
							.unwrap();

						assert_eq!(chunk_out_pt, chunk_msg);
						assert_eq!(chunk_out_ct, chunk_ct);
					}
				}
			}
		}
	}
}

#[test]
fn test_pynacl() {
	run_tests_from_json("./tests/test_data/original/pynacl_secretstream_test_vectors.json");
	run_tests_from_json("./tests/test_data/pynacl_generated.json");
	run_tests_from_json("./tests/test_data/pynacl_generated_with_rekey.json");
}
