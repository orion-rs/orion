extern crate hex;

use self::hex::decode;
use super::super::TestCase;
use super::*;
use std::{fs::File, io::BufRead, io::BufReader, io::Lines};

extern crate orion;
use self::{
    aead::{
        chacha20poly1305::{self, SecretKey},
        xchacha20poly1305,
    },
    orion::{
        errors::UnknownCryptoError,
        hazardous::{
            aead,
            mac::poly1305::POLY1305_OUTSIZE,
            stream::{
                chacha20::{CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE},
                xchacha20::XCHACHA_NONCESIZE,
            },
        },
        test_framework::aead_interface::AeadTestRunner,
    },
};

#[derive(Debug)]
pub struct TestReader {
    lines: Lines<BufReader<File>>,
    test_case_count: u32,
    test_cases_skipped: u32,
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
            test_cases_skipped: 0,
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
                    // Each test case starts with "KEY: *"
                    if string.starts_with("KEY:") && self.should_read_tests {
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

                        let key = parse(&string, "KEY:");

                        // We can call unwraps here because the test-vector file obviously
                        // doesn't include incomplete tests
                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let nonce = parse(&string, "NONCE:");

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let input = parse(&string, "IN:");

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let ad = parse(&string, "AD:");

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let ct = parse(&string, "CT:");

                        current = self.lines.next();
                        let string = current.unwrap().unwrap();
                        let tag = parse(&string, "TAG:");

                        self.test_case_count += 1;

                        let mut test_case = TestCase::new();
                        test_case.add_input_data("key", &key);
                        test_case.add_input_data("nonce", &nonce);
                        test_case.add_input_data("input", &input);
                        test_case.add_input_data("ad", &ad);
                        test_case.add_input_data("ct", &ct);
                        test_case.add_input_data("tag", &tag);
                        test_case.test_case_number = self.test_case_count as u64;
                        // Checking for length happens later. This method does not know
                        // if it's XChaCha20 or ChaCha20 and thus cannot determine
                        // what size the nonce may be.
                        test_case.set_expected_outcome(true);

                        return Some(test_case);
                    }
                }
                _ => return None,
            }
        }
    }
}

fn boringssl_runner(path: &str, is_ietf: bool) {
    let mut test_reader = TestReader::new(path);
    test_reader.should_read_tests = true;
    let mut test_case = test_reader.next();

    while test_case.is_some() {
        let mut key: Vec<u8> = Vec::new();
        let mut nonce: Vec<u8> = Vec::new();
        let mut input: Vec<u8> = Vec::new();
        let mut ad: Vec<u8> = Vec::new();
        let mut expected_output: Vec<u8> = Vec::new();
        let mut tag: Vec<u8> = Vec::new();

        let mut tc = test_case.unwrap();
        test_case = test_reader.next();

        for (data_name, data) in tc.data {
            match data_name.as_str() {
                "key" => key = data,
                "nonce" => nonce = data,
                "ad" => ad = data,
                "input" => input = data,
                "ct" => expected_output = data,
                "tag" => tag = data,
                _ => (),
            }
        }

        // Sanity check to make we actually got any values
        assert!(!key.is_empty());
        assert!(!nonce.is_empty());
        assert!(!tag.is_empty());

        if key.len() != CHACHA_KEYSIZE {
            tc.outcome = false;
        }
        if is_ietf && (nonce.len() != IETF_CHACHA_NONCESIZE) {
            tc.outcome = false;
        }
        if !is_ietf && (nonce.len() != XCHACHA_NONCESIZE) {
            tc.outcome = false;
        }
        if input.is_empty() || expected_output.is_empty() {
            tc.outcome = false;
        }
        if tag.len() != POLY1305_OUTSIZE {
            tc.outcome = false;
        }

        assert!(wycheproof_test_runner(
            &key[..],
            &nonce[..],
            &ad[..],
            &tag[..],
            &input[..],
            &expected_output[..],
            tc.outcome,
            tc.test_case_number,
            is_ietf,
        )
        .is_ok());
    }
}

#[test]
fn test_chacha20poly1305() {
    boringssl_runner(
        "./tests/test_data/third_party/google/boringssl/boringssl_chacha20_poly1305.txt",
        true,
    );
}

#[test]
fn test_xchacha20poly1305() {
    boringssl_runner(
        "./tests/test_data/third_party/google/boringssl/boringssl_xchacha20_poly1305.txt",
        false,
    );
}
