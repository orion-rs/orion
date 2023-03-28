use crate::hash::nist_cavp_runner;

#[test]
fn test_nist_cavp_long_msg() {
    nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHA3_256LongMsg.rsp");
}

#[test]
fn test_nist_cavp_short_msg() {
    nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHA3_256ShortMsg.rsp");
}
