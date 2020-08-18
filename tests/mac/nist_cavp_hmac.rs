extern crate hex;
use self::hex::decode;
use crate::mac::hmac_test_runner;

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
        // The tests for each SHA variant are usually ordered. So SHA512 comes last
        // in the file, at the time of writing. Should more tests be added however,
        // this may not be the case. So we need to track whether we're "in scope"
        // of SHA512. As soon as we encounter anything "[L=*]" after "[L=64]",
        // this bool is set to false so that we can again skip those potentially,
        // new test vectors. We use TestReader.should_read_test to track this.

        loop {
            let mut current = self.lines.next();

            match current {
                Some(Ok(string)) => {
                    // The test file includes tests for HMAC with different SHAs.
                    // We only want the tests with SHA512.
                    if string.starts_with("[L=") {
                        if string.starts_with("[L=64]") {
                            self.should_read_tests = true;
                        } else {
                            self.should_read_tests = false;
                        }
                    }

                    // Each test case starts with "Count = *"
                    if string.starts_with("Count = ") && self.should_read_tests {
                        let test_case_number = string.split(" = ").collect::<Vec<&str>>()[1];

                        current = self.lines.next();
                        // We can call unwraps here because the test-vector file obviously
                        // doesn't include incomplete tests
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Klen = "));
                        let key_length = string.split(" = ").collect::<Vec<&str>>()[1];

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Tlen = "));
                        let tag_length = string.split(" = ").collect::<Vec<&str>>()[1];

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Key = "));
                        let key = string.split(" = ").collect::<Vec<&str>>()[1];

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Msg = "));
                        let msg = string.split(" = ").collect::<Vec<&str>>()[1];

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        assert!(string.starts_with("Mac = "));
                        let mac = string.split(" = ").collect::<Vec<&str>>()[1];

                        let secret_key = match key {
                            // This is the special case where decoding "00" doesn't give an empty array
                            // as is intended but an array = [0].
                            "00" => vec![0u8; 0], // This is the special case where
                            _ => decode(key).unwrap(),
                        };
                        let input = match msg {
                            // This is the special case where decoding "00" doesn't give an empty array
                            // as is intended but an array = [0].
                            "00" => vec![0u8; 0], // This is the special case where
                            _ => decode(msg).unwrap(),
                        };
                        let expected_output = decode(mac).unwrap();
                        self.test_case_count += 1;

                        let mut test_case = TestCase::new();
                        test_case.add_input_data("count", test_case_number.as_bytes());
                        test_case.add_input_data("key_length", key_length.as_bytes());
                        test_case.add_input_data("tag_length", tag_length.as_bytes());
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
fn test_nist_cavp() {
    let mut cavs_reader = TestReader::new("./tests/test_data/third_party/nist/HMAC.rsp");
    let mut test_case = cavs_reader.next();

    while test_case.is_some() {
        let mut key: Vec<u8> = Vec::new();
        let mut input: Vec<u8> = Vec::new();
        let mut tag_length: usize = 0;
        let mut expected_output: Vec<u8> = Vec::new();

        for (data_name, data) in test_case.unwrap().data {
            match data_name.as_str() {
                "tag_length" => {
                    tag_length = String::from_utf8_lossy(&data).parse::<usize>().unwrap()
                }
                "secret_key" => key = data,
                "input" => input = data,
                "expected_output" => expected_output = data,
                _ => (),
            }
        }

        hmac_test_runner(
            &expected_output[..],
            &key[..],
            &input[..],
            Some(tag_length),
            true,
        );
        test_case = cavs_reader.next();
    }
}
