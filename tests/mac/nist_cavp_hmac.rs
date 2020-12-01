use crate::mac::hmac_test_runner;
use crate::TestCaseReader;

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

    // Skip ahead in the file until [L=64] is reached so that we read
    // only SHA512 test cases.
    let mut line = nist_cavp_reader.lines.next().unwrap().unwrap();
    while line != "[L=64]" {
        line = nist_cavp_reader.lines.next().unwrap().unwrap();
    }

    let mut test_case = nist_cavp_reader.next();
    while test_case.is_some() {
        let tc = test_case.unwrap();

        let key: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Key"));
        let input: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Msg"));
        let tag_length: usize = tc.get_data("Tlen").parse::<usize>().unwrap();
        let expected_output: Vec<u8> = TestCaseReader::default_parse(tc.get_data("Mac"));

        hmac_test_runner(
            &expected_output[..],
            &key[..],
            &input[..],
            Some(tag_length),
            true,
        );

        // Read the next one
        test_case = nist_cavp_reader.next();
    }
}
