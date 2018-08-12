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

use core::{mem, ptr};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use utilities::errors;

#[inline(never)]
pub fn memzero(src: &mut [u8]) {
    assert_eq!(src.is_empty(), false);
    let src_len = mem::size_of_val(src);

    unsafe {
        let src_ptr: *mut u8 = src.as_mut_ptr();
        ptr::write_bytes(src_ptr, 0u8, src_len);
    }

    mem::drop(src)
}

#[inline(never)]
/// Return a random byte vector of a given length. This uses rand's
/// [OsRng](https://docs.rs/rand/0.5.1/rand/rngs/struct.OsRng.html). Length of `dst` must be >= 1.
pub fn gen_rand_key(dst: &mut [u8]) -> Result<(), errors::UnknownCryptoError> {
    if dst.len() < 1 {
        return Err(errors::UnknownCryptoError);
    }

    let mut generator = OsRng::new()?;
    generator.try_fill_bytes(dst)?;

    Ok(())
}

/// Compare two equal length slices in constant time, using the
/// [subtle](https://crates.io/crates/subtle) crate.
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

#[test]
fn rand_key_len_ok() {
    let mut dst = [0u8; 64];
    gen_rand_key(&mut dst).unwrap();
}

#[test]
fn rand_key_len_error() {
    let mut dst = [0u8; 0];
    assert!(gen_rand_key(&mut dst).is_err());

    let mut dst = [0u8; 0];
    let err = gen_rand_key(&mut dst).unwrap_err();
    assert_eq!(err, errors::UnknownCryptoError);
}

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

#[test]
fn memzero_1() {
    let mut src = [0x3F; 64];
    let mut res = true;
    memzero(&mut src);

    for idx in 0..64 {
        let tmp = src[idx] ^ 0u8;

        if tmp ^ 0u8 != 0u8 {
            res = false;
            break;
        }
    }

    assert!(res);
}

#[test]
fn memzero_2() {
    let mut src = [0x6F; 128];
    let mut res = true;
    memzero(&mut src);

    for idx in 0..128 {
        let tmp = src[idx] ^ 0u8;

        if tmp ^ 0u8 != 0u8 {
            res = false;
            break;
        }
    }

    assert!(res);
}

#[test]
#[should_panic]
fn memzero_mod() {
    let mut src = [0x5C; 128];
    let mut res = true;
    memzero(&mut src);

    src[5..17].copy_from_slice(&[0x35; 12]);

    for idx in 0..128 {
        let tmp = src[idx] ^ 0u8;

        if tmp ^ 0u8 != 0u8 {
            res = false;
            break;
        }
    }

    assert!(res);
}

#[test]
#[should_panic]
fn memzero_empty_src() {
    let mut src = [0x5C; 0];
    memzero(&mut src);
}
