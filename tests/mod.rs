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

#[derive(Debug, Clone)]
pub struct TestCase {
    pub data: Vec<(String, Vec<u8>)>,
    pub outcome: bool,
    pub test_case_number: u64,
}

impl TestCase {
    pub fn new() -> Self {
        Self {
            data: Vec::<(String, Vec<u8>)>::new(),
            outcome: false,
            test_case_number: 0,
        }
    }

    pub fn set_expected_outcome(&mut self, expected_outcome: bool) {
        self.outcome = expected_outcome;
    }

    pub fn add_input_data(&mut self, data_name: &str, input_data: &[u8]) {
        self.data.push((data_name.to_string(), input_data.to_vec()));
    }
}
