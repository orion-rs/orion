use crate::{TestCase, TestCaseReader};

#[test]
fn test_nist_cavp() {
    let nist_cavp_fields: Vec<String> = vec![
        "Count".into(),
        "Klen".into(),
        "Tlen".into(),
        "Key".into(),
        "Msg".into(),
        "Mac".into(),
    ];

    let mut nist_cavp_reader = TestCaseReader::new(
        "./tests/test_data/third_party/nist/HMAC.rsp",
        nist_cavp_fields,
        "=",
    );
    // Set variant separators.
    nist_cavp_reader.set_stop_flags(vec!["[L=32]".into(), "[L=48]".into(), "[L=64]".into()]);
    // The current HMAC variant being tested.
    let mut current_variant = String::new();
    let mut test_case: Option<TestCase>;

    loop {
        // Keeps reading until a flag is hit. The first will be [L=32].
        // So the first None should be [L=32].
        test_case = nist_cavp_reader.next();

        match test_case {
            Some(ref tc) => {
                if current_variant.is_empty() {
                    // We've found a test case and parsed it, but Orion
                    // doesn't support the variant.
                    continue;
                }

                let key: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Key"));
                let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Msg"));
                let tag_length: usize = tc.get_data("Tlen").parse::<usize>().unwrap();
                let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Mac"));

                if current_variant == "[L=32]" {
                    super::hmac256_test_runner(
                        &expected_output[..],
                        &key[..],
                        &input[..],
                        Some(tag_length),
                        true,
                    );
                }
                if current_variant == "[L=48]" {
                    super::hmac384_test_runner(
                        &expected_output[..],
                        &key[..],
                        &input[..],
                        Some(tag_length),
                        true,
                    );
                }
                if current_variant == "[L=64]" {
                    super::hmac512_test_runner(
                        &expected_output[..],
                        &key[..],
                        &input[..],
                        Some(tag_length),
                        true,
                    );
                }

                dbg!(&tc);
            }
            None => {
                if nist_cavp_reader.did_hit_flag() {
                    current_variant = nist_cavp_reader.last_stop_flag();
                    // We hit the flag and updated the current, so resume parsing.
                    continue;
                }

                // If it's not a flag and None, then we're done.
                break;
            }
        }
    }
}
