use super::shake_nist_cavp_runner;

#[test]
fn test_shake128_short() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE128ShortMsg.rsp")
}

#[test]
fn test_shake128_long() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE128LongMsg.rsp")
}

#[test]
fn test_shake128_variable() {
    shake_nist_cavp_runner("./tests/test_data/third_party/nist/SHA3/SHAKE/SHAKE128VariableOut.rsp")
}
