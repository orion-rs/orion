use rand::{OsRng, Rng};

#[inline(never)]
/// Return a random byte vector of a given length. This uses the [rand](https://crates.io/crates/rand) crate, 
/// which means that random data is read from the OS source /dev/urandom or CryptGenRandom().
pub fn gen_rand_key(len: usize) -> Vec<u8> {
    let mut generator = OsRng::new().unwrap();
    let mut rand_bytes_vec = vec![0u8; len];
    generator.fill_bytes(&mut rand_bytes_vec);

    rand_bytes_vec
}
