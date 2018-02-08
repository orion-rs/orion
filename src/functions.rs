use rand::{OsRng, Rng};

pub fn gen_rand_key(len: usize) -> Vec<u8> {
    let mut generator = OsRng::new().unwrap();
    let mut rand_bytes_vec = vec![0u8; len];
    generator.fill_bytes(&mut rand_bytes_vec);
    rand_bytes_vec
}

#[test]
fn test_random_not_duplicate() {
    // Test that two randomly generated keys are not equal
    assert_ne!(gen_rand_key(5), gen_rand_key(5));
    assert_ne!(gen_rand_key(7), gen_rand_key(7));
}
