use super::shake_nist_cavp_runner;

#[test]
fn test_shake256_short() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE256ShortMsg.rsp")
}

#[test]
fn test_shake256_long() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE256LongMsg.rsp")
}

#[test]
fn test_shake256_variable() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE256VariableOut.rsp")
}
