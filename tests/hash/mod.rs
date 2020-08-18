pub mod blake2b_kat;
pub mod other_blake2b;
pub mod sha512_nist_cavp;

extern crate orion;
use self::orion::hazardous::hash::{blake2b, sha512};

extern crate hex;

use self::hex::decode;
use std::{fs::File, io::BufRead, io::BufReader, io::Lines};

use super::TestCase;

fn blake2b_test_runner(input: &[u8], key: &[u8], output: &[u8]) {
    // Only make SecretKey if test case key value is not empty.
    let mut state = if key.is_empty() {
        blake2b::Blake2b::new(None, output.len()).unwrap()
    } else {
        let secret_key = blake2b::SecretKey::from_slice(key).unwrap();
        blake2b::Blake2b::new(Some(&secret_key), output.len()).unwrap()
    };

    state.update(input).unwrap();
    let digest = state.finalize().unwrap();
    assert!(digest.len() == output.len());
    assert!(digest.as_ref() == &output[..]);
}

fn sha512_test_runner(data: &[u8], output: &[u8]) {
    let mut state = sha512::Sha512::new();
    state.update(data).unwrap();
    let digest = state.finalize().unwrap();

    let digest_one_shot = sha512::Sha512::digest(data).unwrap();

    assert!(digest.as_ref() == digest_one_shot.as_ref());
    assert!(digest.as_ref() == output);
}

#[derive(Debug)]
pub struct TestReader {
    lines: Lines<BufReader<File>>,
    test_case_count: u32,
}

impl TestReader {
    ///
    pub fn new(test_file_path: &str) -> Self {
        let test_file = File::open(test_file_path).unwrap();
        let reader = BufReader::new(test_file);
        let lines = reader.lines().into_iter();

        Self {
            lines,
            test_case_count: 0,
        }
    }
}

impl Iterator for TestReader {
    type Item = TestCase;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut current = self.lines.next();

            match current {
                Some(Ok(string)) => {
                    if string.starts_with("Len = ") {
                        // Advance to the input data
                        current = self.lines.next();
                        // We can call unwraps here because the test-vector file obviously
                        // doesn't include incomplete tests
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Msg = "));
                        let msg = string.split(" = ").collect::<Vec<&str>>()[1];

                        // Advance to the expected result
                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("MD = "));
                        let md = string.split(" = ").collect::<Vec<&str>>()[1];

                        let input = match msg {
                            // This is the special case where decoding "00" doesn't give an empty array
                            // as is intended but an array = [0].
                            "00" => vec![0u8; 0], // This is the special case where
                            _ => decode(msg).unwrap(),
                        };
                        let expected_output = decode(md).unwrap();
                        self.test_case_count += 1;

                        let mut test_case = TestCase::new();
                        test_case.add_input_data("input", &input);
                        test_case.add_input_data("expected_output", &expected_output);
                        test_case.set_expected_outcome(true);
                        test_case.test_case_number = self.test_case_count as u64;

                        return Some(test_case);
                    }
                }
                _ => return None,
            }
        }
    }
}
