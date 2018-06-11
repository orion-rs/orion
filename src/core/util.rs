// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.





use rand::{OsRng, RngCore};
use core::errors;
use constant_time_eq::constant_time_eq;

#[inline(never)]
/// Return a random byte vector of a given length. This uses the [rand](https://crates.io/crates/rand) crate,
/// which means that random data is read from the OS source /dev/urandom or CryptGenRandom().
/// Length must be >= 1.
pub fn gen_rand_key(len: usize) -> Result<Vec<u8>, errors::UnknownCryptoError> {

    if len < 1 {
        return Err(errors::UnknownCryptoError);
    } else {
        let mut rand_vec = vec![0x00; len];
        let mut generator = OsRng::new()?;
        generator.try_fill_bytes(&mut rand_vec)?;

        Ok(rand_vec)
    }
}

/// Compare two equal length slices in constant time, using the constant_time_eq crate.
pub fn compare_ct(a: &[u8], b: &[u8]) -> Result<bool, errors::UnknownCryptoError> {

    if a.len() != b.len() {
        return Err(errors::UnknownCryptoError)
    }

    if constant_time_eq(a, b) {
        Ok(true)
    } else { Err(errors::UnknownCryptoError) }
}

#[test]
fn rand_key_len_ok() {

    gen_rand_key(64).unwrap();
}

#[test]
fn rand_key_error() {

    assert!(gen_rand_key(0).is_err());

    let err = gen_rand_key(0).unwrap_err();
    assert_eq!(err, errors::UnknownCryptoError);

}

#[test]
fn test_ct_eq_ok() {
    let buf_1 = vec![0x06; 10];
    let buf_2 = vec![0x06; 10];

    assert_eq!(compare_ct(&buf_1, &buf_2).unwrap(), true);
    assert_eq!(compare_ct(&buf_2, &buf_1).unwrap(), true);
}

#[test]
fn test_ct_eq_wrong_len() {

    let buf_1 = vec![0x06; 10];
    let buf_2 = vec![0x06; 5];

    assert!(compare_ct(&buf_1, &buf_2).is_err());
    assert!(compare_ct(&buf_2, &buf_1).is_err());

}

#[test]
fn test_ct_eq_err() {

    let buf_1 = vec![0x06; 10];
    let buf_2 = vec![0x76; 10];

    assert!(compare_ct(&buf_1, &buf_2).is_err());
    assert!(compare_ct(&buf_2, &buf_1).is_err());

}
