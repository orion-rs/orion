use hex::decode;
use serde_json::Value;
use std::{fs::File, io::BufReader};

// Helper to construct the looping sequential input array defined by the BLAKE3 spec
fn build_blake3_input(len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    for i in 0..len {
        data.push((i % 251) as u8);
    }
    data
}

#[test]
fn test_blake3_kat() {
    let file = File::open("./tests/test_data/third_party/blake3_test_vectors.json").unwrap();
    let reader = BufReader::new(file);

    // Parse the entire JSON document
    let root: Value = serde_json::from_reader(reader).unwrap();

    // Extract the global key used for all keyed hash test cases
    let key_str = root.get("key").unwrap().as_str().unwrap();
    let key = key_str.as_bytes().to_vec();

    // Iterate over the "cases" array
    if let Some(cases) = root.get("cases").unwrap().as_array() {
        for test_case in cases {
            let input_len = test_case.get("input_len").unwrap().as_u64().unwrap() as usize;
            println!("Input len (= iteration) = {}\n", input_len);

            // Extract the expected hex strings
            let hash_hex = test_case.get("hash").unwrap().as_str().unwrap();
            let keyed_hash_hex = test_case.get("keyed_hash").unwrap().as_str().unwrap();

            // Build the input and decode the expected outputs
            let input = build_blake3_input(input_len);
            let expected_hash = decode(hash_hex).unwrap();
            let expected_keyed_hash = decode(keyed_hash_hex).unwrap();

            // Run both standard and keyed checks
            super::blake3_test_runner(&input, &key, &expected_hash, &expected_keyed_hash);
        }
    }
}
