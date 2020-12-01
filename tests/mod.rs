#[cfg(feature = "safe_api")]
#[cfg(test)]
pub mod aead;
#[cfg(feature = "safe_api")]
#[cfg(test)]
pub mod hash;
#[cfg(test)]
pub mod kdf;
#[cfg(test)]
pub mod mac;
#[cfg(feature = "safe_api")]
#[cfg(test)]
pub mod stream;

extern crate hex;

use self::hex::decode;

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
};

#[derive(Debug)]
///
pub struct TestCase {
    pub data: HashMap<String, String>,
    pub outcome: bool,
    pub test_case_number: u64,
}

impl core::fmt::Display for TestCase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Number: {}\nExpected outcome: {}\nData: {:#?}",
            self.test_case_number, self.outcome, self.data
        )
    }
}

impl TestCase {
    ///
    pub fn new() -> Self {
        Self {
            data: HashMap::<String, String>::new(),
            outcome: true,
            test_case_number: 0,
        }
    }

    ///
    pub fn set_expected_outcome(&mut self, expected_outcome: bool) {
        self.outcome = expected_outcome;
    }

    pub fn add_input_data(&mut self, data_name: &str, input_data: &str) {
        self.data
            .insert(data_name.to_string(), input_data.to_string());
    }

    pub fn get_data(&self, field: &str) -> &str {
        self.data
            .get(field)
            .expect("TestCase: Test case field does no exists.")
    }
}

#[derive(Debug)]
pub struct TestCaseReader {
    lines: Lines<BufReader<File>>,
    test_case_count: u32,
    test_cases_skipped: u32,
    // All fields that define a test case: Eg. Key, Nonce, etc
    // NOTE: They MUST be in correct order from beginning to end.
    test_case_fields: Vec<String>,
    // The separator that separates the test case fields name and data (eg. '=')
    test_case_field_separator: String,
}

impl TestCaseReader {
    ///
    pub fn new(
        path_to_test_file: &str,
        test_case_fields: Vec<String>,
        test_case_field_separator: &str,
    ) -> Self {
        let test_file = File::open(path_to_test_file)
            .expect(format!("TestCaseReader: Unable to open file: {}", path_to_test_file).as_str());

        let reader = BufReader::new(test_file);
        let lines = reader.lines().into_iter();

        Self {
            lines,
            test_case_count: 0,
            test_cases_skipped: 0,
            test_case_fields,
            test_case_field_separator: test_case_field_separator.to_string(),
        }
    }

    /// The default parser. Parses strings and hex.
    pub fn default_parse(data: &str) -> Vec<u8> {
        if data.is_empty() {
            return vec![0u8; 0];
        }

        // Some of the inputs are strings and not hexadecimal.
        if data.contains("\'") || data.contains("\"") {
            // If it's a string, it will be the original quotes but escaped in the file.
            data.replace("\"", "").as_bytes().to_vec()
        } else {
            match data {
                // This is the special case where decoding "00" doesn't give an empty array
                // as is intended but an array = [0].
                "00" => vec![0u8; 0], // This is the special case where
                _ => decode(data).unwrap(),
            }
        }
    }
}

impl Iterator for TestCaseReader {
    type Item = TestCase;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Read the first line
            let mut current = self.lines.next();

            match current {
                Some(Ok(mut string)) => {
                    // TODO: Don't differentiate between upper/lower case
                    if string.starts_with(&self.test_case_fields[0]) {
                        let mut test_case = TestCase::new();

                        // We iterate through the fields and go to the next line each time.
                        // Because the fields vector is ordered according to a test case,
                        // the first field we encounter will match the current line.
                        for field in self.test_case_fields.iter() {
                            // We need to find the first occurrence of the separator. If not the first,
                            // parts of the field data may be truncated.
                            // For example, BoringSSL has "IN:" and another ':' in the input string,
                            // which gets cut off, if we don't split at the first occurrence only.
                            let split_at_idx = string.find(&self.test_case_field_separator).expect(
                                "TestCaseReader: Could not find separator in test case field",
                            );

                            // .trim() removes whitespace if it's a non-empty string.
                            // split_at_idx + 1 to not include the separator
                            let test_case_data = string.split_at(split_at_idx + 1).1.trim();

                            test_case.add_input_data(field, test_case_data);

                            if string.starts_with(self.test_case_fields.last().unwrap()) {
                                self.test_case_count += 1;
                                test_case.test_case_number = self.test_case_count as u64;

                                return Some(test_case);
                            }

                            // Update to next line
                            current = self.lines.next();
                            string = current.unwrap().unwrap();
                        }
                    }
                }
                _ => return None,
            }
        }
    }
}
