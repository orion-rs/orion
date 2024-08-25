use crate::hash::sha_nist_cavp_runner;

#[test]
fn test_nist_cavp_long_msg() {
    sha_nist_cavp_runner("./tests/test_data/third_party/nist/SHA2/SHA512LongMsg.rsp");
}

#[test]
fn test_nist_cavp_short_msg() {
    sha_nist_cavp_runner("./tests/test_data/third_party/nist/SHA2/SHA512ShortMsg.rsp");
}
