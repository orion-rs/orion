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

use hex::decode;

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
};

#[derive(Debug)]
/// A test case from a given set of tests.
pub struct TestCase {
    /// <Field name, Field Data>, eg.: <"Mac", "d545gfdfggf42312...">
    pub data: HashMap<String, String>,
    /// If the test is expected to pass or fail
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
    pub fn new() -> Self {
        Self {
            data: HashMap::<String, String>::new(),
            outcome: true,
            test_case_number: 0,
        }
    }

    pub fn add_input_data(&mut self, data_name: &str, input_data: &str) {
        self.data.insert(data_name.into(), input_data.into());
    }

    pub fn get_data(&self, field: &str) -> &str {
        self.data
            .get(field)
            .expect("TestCase: Test case field does no exists.")
    }
}

#[derive(Debug)]
pub struct TestCaseReader {
    /// A reader over all lines in a file
    lines: Lines<BufReader<File>>,
    test_case_count: u64,
    test_cases_skipped: u64,
    // All fields that define a test case: Eg. Key, Nonce, etc
    // NOTE: They MUST be in correct order from beginning to end.
    test_case_fields: Vec<String>,
    // The separator that separates the test case fields name and data (eg. '=')
    test_case_field_separator: String,
    // Optional stop flags. When one of these strings are encountered, next() will return None.
    stop_flags: Option<Vec<String>>,
    // Indicates whether the most recent next() => None was caused by a stop flag.
    stop_flag_hit: bool,
}

impl TestCaseReader {
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
            stop_flags: None,
            stop_flag_hit: false,
        }
    }

    /// The default parser. Parses strings and hex.
    pub fn default_parse(data: &str) -> Vec<u8> {
        if data.is_empty() {
            return vec![0u8; 0];
        }

        // If `data` is a string quoted with '"', remove quotes.
        if data.contains("\'") || data.contains("\"") {
            data.replace("\"", "").as_bytes().to_vec()
        } else {
            match data {
                // This is the special case where decoding "00" doesn't give an empty array
                // as is intended but an array = [0].
                "00" => vec![0u8; 0],
                _ => decode(data).unwrap(),
            }
        }
    }

    /// Set a stop flag that will cause .next() to return None, when the flag is encountered.
    pub fn set_stop_flag(&mut self, flags: Vec<String>) {
        self.stop_flags = Some(flags);
    }

    /// Return true if the most recent None from next() was due to a stop flag.
    pub fn did_hit_flag(&self) -> bool {
        self.stop_flag_hit
    }
}

impl Iterator for TestCaseReader {
    type Item = TestCase;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Reset
            self.stop_flag_hit = false;

            // Read the first line
            let mut current = self.lines.next();

            match current {
                Some(Ok(mut string)) => {
                    // First check if a stop_flags are set and if we've encountered one.
                    match &self.stop_flags {
                        Some(flags) => {
                            for flag in flags.iter() {
                                if &string == flag {
                                    self.stop_flag_hit = true;
                                    return None;
                                }
                            }
                        }
                        None => (),
                    }

                    // Test case fields are ordered, so this is the beginning of a test case
                    if string.starts_with(&self.test_case_fields[0]) {
                        let mut test_case = TestCase::new();

                        // Because test case fields are ordered, iter() on fields, together
                        // with line.next(), will return the right fields in the right order.
                        for field in self.test_case_fields.iter() {
                            // We need to find the first occurrence of the separator. If not, the first
                            // parts of the field data may be truncated.
                            // For example, BoringSSL has "IN:" and another ':' in the input string,
                            // which gets cut off, if we don't split at the first occurrence only.
                            let split_at_idx = string.find(&self.test_case_field_separator).expect(
                                "TestCaseReader: Could not find separator in test case field",
                            );

                            // .trim() removes whitespace if it's a non-empty string.
                            // split_at_idx + 1 to not include the separator itself
                            let test_case_data = string.split_at(split_at_idx + 1).1.trim();

                            test_case.add_input_data(field, test_case_data);

                            if string.starts_with(self.test_case_fields.last().unwrap()) {
                                self.test_case_count += 1;
                                test_case.test_case_number = self.test_case_count;

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
