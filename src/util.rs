use rand::{OsRng, Rng};

#[inline(never)]
/// Return a random byte vector of a given length.
pub fn gen_rand_key(len: usize) -> Vec<u8> {
    let mut generator = OsRng::new().unwrap();
    let mut rand_bytes_vec = vec![0u8; len];
    generator.fill_bytes(&mut rand_bytes_vec);

    rand_bytes_vec
}

#[inline(never)]
/// Comparison in constant time.
pub fn compare_ct(x: &[u8], y: &[u8]) -> bool {

    let length = x.len();

    if length != y.len() {
        false;
    }

    let mut result: u8 = 0;

    for n in 0..length {
        result |= x[n] ^ y[n];
    }

    result == 0
}

#[test]
// Test that compare_ct() returns expected values.
fn test_compare_ct_results() {
    let test_v_1 = vec![0x61; 32];
    let test_v_2 = vec![0x61; 32];
    let test_v_3 = vec![0x64; 32];
    let test_v_4 = vec![0x64; 64];
    assert_eq!(compare_ct(&test_v_1, &test_v_2), true);
    assert_ne!(compare_ct(&test_v_1, &test_v_3), true);
    assert_eq!(compare_ct(&test_v_1, &test_v_4), false);
}
