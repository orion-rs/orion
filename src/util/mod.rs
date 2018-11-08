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

use errors;
#[cfg(feature = "safe_api")]
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;

#[inline(never)]
#[cfg(feature = "safe_api")]
/// Generate random bytes. Not available in `no_std` context.
///
/// # About:
/// This function can be used to generate cryptographic keys, salts or other values that rely
/// on strong randomness. This function fills `dst` with random bytes and the amount of bytes is therefor
/// implied by the length of `dst`.
///
/// This uses rand's [OsRng](https://docs.rs/rand/0.5.5/rand/rngs/struct.OsRng.html).
///
/// # Exceptions:
/// An exception will be thrown if:
/// - The `OsRng` fails to initialize or read from its source
/// - `dst` is empty
///
/// # Example:
/// ```
/// use orion::util;
///
/// let mut salt = [0u8; 16];
///
/// util::gen_rand_key(&mut salt).unwrap();
/// ```
pub fn gen_rand_key(dst: &mut [u8]) -> Result<(), errors::UnknownCryptoError> {
    if dst.is_empty() {
        return Err(errors::UnknownCryptoError);
    }

    let mut generator = OsRng::new()?;
    generator.try_fill_bytes(dst)?;

    Ok(())
}

/// Compare two equal length slices in constant time.
///
/// # About:
/// Compare two equal length slices, in constant time, using the
/// [subtle](https://crates.io/crates/subtle) crate.
///
/// # Exceptions:
/// An exception will be thrown if:
/// - `a` and `b` do not have the same length
/// - `a` is not equal to `b`
///
/// # Example:
/// ```
/// use orion::util;
///
/// let mut mac = [0u8; 64];
///
/// assert!(util::compare_ct(&mac, &[0u8; 64]).is_ok());
///
/// util::gen_rand_key(&mut mac).unwrap();
/// assert!(util::compare_ct(&mac, &[0u8; 64]).is_err());
/// ```
pub fn compare_ct(a: &[u8], b: &[u8]) -> Result<bool, errors::UnknownCryptoError> {
    if a.len() != b.len() {
        return Err(errors::UnknownCryptoError);
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        Ok(true)
    } else {
        Err(errors::UnknownCryptoError)
    }
}

#[cfg(feature = "safe_api")]
#[test]
fn rand_key_len_ok() {
    let mut dst = [0u8; 64];
    gen_rand_key(&mut dst).unwrap();
}

#[cfg(feature = "safe_api")]
#[test]
fn rand_key_len_error() {
    let mut dst = [0u8; 0];
    assert!(gen_rand_key(&mut dst).is_err());

    let mut dst = [0u8; 0];
    let err = gen_rand_key(&mut dst).unwrap_err();
    assert_eq!(err, errors::UnknownCryptoError);
}

#[cfg(feature = "safe_api")]
#[test]
fn test_ct_eq_ok() {
    let buf_1 = [0x06; 10];
    let buf_2 = [0x06; 10];

    assert_eq!(compare_ct(&buf_1, &buf_2).unwrap(), true);
    assert_eq!(compare_ct(&buf_2, &buf_1).unwrap(), true);
}

#[test]
fn test_ct_eq_diff_len() {
    let buf_1 = [0x06; 10];
    let buf_2 = [0x06; 5];

    assert!(compare_ct(&buf_1, &buf_2).is_err());
    assert!(compare_ct(&buf_2, &buf_1).is_err());
}

#[test]
fn test_ct_ne() {
    let buf_1 = [0x06; 10];
    let buf_2 = [0x76; 10];

    assert!(compare_ct(&buf_1, &buf_2).is_err());
    assert!(compare_ct(&buf_2, &buf_1).is_err());
}

#[test]
fn test_ct_ne_reg() {
    assert!(compare_ct(&[0], &[0, 1]).is_err());
    assert!(compare_ct(&[0, 1], &[0]).is_err());
}
