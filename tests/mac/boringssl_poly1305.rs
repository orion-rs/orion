// Testing against BoringSSL test vector from [boringssl](https://boringssl.googlesource.com/boringssl/+/master/crypto/poly1305/poly1305_tests.txt).
// Pulled at commit (master): 0f5ecd3a854546d943104e1f7421e489b7f4d5aa

extern crate hex;
use self::hex::decode;
use crate::mac::poly1305_test_runner;

use super::super::TestCase;
use std::{fs::File, io::BufRead, io::BufReader, io::Lines};

#[derive(Debug)]
pub struct TestReader {
    lines: Lines<BufReader<File>>,
    test_case_count: u32,
    should_read_tests: bool,
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
            should_read_tests: false,
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
                    // Each test case starts with "Key = *"
                    if string.starts_with("Key = ") && self.should_read_tests {
                        fn parse(data: &str, split_at: &str) -> Vec<u8> {
                            assert!(data.starts_with(split_at));
                            // .trim() removes whitespace if it's a non-empty string.
                            let string = data.split(split_at).collect::<Vec<&str>>()[1].trim();

                            if string.is_empty() {
                                return vec![0u8; 0];
                            }

                            // Some of the inputs are strings and not hexadecimal.
                            if string.contains("\'") || string.contains("\"") {
                                // If it's a string, it will the original quotes but escaped.
                                string.replace("\"", "").as_bytes().to_vec()
                            } else {
                                match string {
                                    // This is the special case where decoding "00" doesn't give an empty array
                                    // as is intended but an array = [0].
                                    "00" => vec![0u8; 0], // This is the special case where
                                    _ => decode(string).unwrap(),
                                }
                            }
                        }

                        let secret_key = parse(&string, "Key =");

                        current = self.lines.next();
                        // We can call unwraps here because the test-vector file obviously
                        // doesn't include incomplete tests
                        let string = current.unwrap().unwrap();
                        let input = parse(&string, "Input =");

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let expected_output = parse(&string, "MAC =");

                        self.test_case_count += 1;

                        let mut test_case = TestCase::new();
                        test_case.add_input_data("secret_key", &secret_key);
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

#[test]
fn test_boringssl_poly1305() {
    let mut test_reader = TestReader::new(
        "./tests/test_data/third_party/google/boringssl/boringssl_poly1305_tests.txt",
    );
    test_reader.should_read_tests = true;
    let mut test_case = test_reader.next();

    while test_case.is_some() {
        let mut key: Vec<u8> = Vec::new();
        let mut input: Vec<u8> = Vec::new();
        let mut expected_output: Vec<u8> = Vec::new();

        for (data_name, data) in test_case.unwrap().data {
            match data_name.as_str() {
                "secret_key" => key = data,
                "input" => input = data,
                "expected_output" => expected_output = data,
                _ => (),
            }
        }

        poly1305_test_runner(&key[..], &input[..], &expected_output[..]);
        test_case = test_reader.next();
    }
}
