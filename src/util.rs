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
use errors;

#[inline(never)]
/// Return a random byte vector of a given length. This uses the [rand](https://crates.io/crates/rand) crate, 
/// which means that random data is read from the OS source /dev/urandom or CryptGenRandom().
pub fn gen_rand_key(len: usize) -> Result<Vec<u8>, errors::UnknownCryptoError> {

    if len < 1 {
        return Err(errors::UnknownCryptoError);
    } else {
        let mut rand_vec = Vec::<u8>::with_capacity(len);
        let mut generator = OsRng::new()?;
        generator.try_fill_bytes(&mut rand_vec)?;

        Ok(rand_vec)
    }
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