use crate::hash::nist_cavp_runner;
use orion::hazardous::hash::sha2::sha512;

#[test]
fn test_streaming_1() {
    let expected = [
        6, 175, 119, 168, 193, 244, 168, 253, 174, 247, 10, 85, 159, 123, 186, 251, 242, 189, 49,
        190, 118, 36, 52, 177, 180, 18, 122, 176, 66, 16, 119, 93, 95, 225, 58, 192, 68, 39, 86,
        12, 27, 163, 230, 18, 5, 177, 101, 139, 48, 181, 89, 201, 150, 28, 75, 251, 67, 237, 202,
        106, 255, 35, 70, 171,
    ];

    let mut state = sha512::Sha512::new();
    state.update(b"hello world").unwrap();
    state.update(b"hello world").unwrap();
    state.update(b"hello world").unwrap();
    let res = state.finalize().unwrap();

    assert_eq!(&expected[..], res.as_ref());
}

#[test]
fn test_streaming_2() {
    let expected = [
        207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5,
        11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242,
        176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50,
        122, 249, 39, 218, 62,
    ];

    let mut state = sha512::Sha512::new();
    state.update(b"").unwrap();
    let res = state.finalize().unwrap();

    assert_eq!(&expected[..], res.as_ref());
}

#[test]
fn test_streaming_3() {
    let expected = [
        105, 63, 149, 213, 131, 131, 166, 22, 45, 42, 171, 73, 235, 96, 57, 93, 204, 75, 178, 34,
        149, 18, 12, 175, 63, 33, 227, 3, 144, 3, 35, 11, 40, 124, 86, 106, 3, 199, 160, 202, 90,
        204, 174, 210, 19, 60, 112, 11, 28, 179, 248, 46, 223, 138, 220, 189, 220, 146, 180, 249,
        251, 153, 16, 198,
    ];

    let mut state = sha512::Sha512::new();
    state.update(&[0u8; 256]).unwrap();
    let res = state.finalize().unwrap();

    assert_eq!(&expected[..], res.as_ref());
}

#[test]
fn test_nist_cavp_long_msg() {
    nist_cavp_runner("./tests/test_data/third_party/nist/SHA512LongMsg.rsp");
}

#[test]
fn test_nist_cavp_short_msg() {
    nist_cavp_runner("./tests/test_data/third_party/nist/SHA512ShortMsg.rsp");
}
