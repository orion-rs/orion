// MIT License

// Copyright (c) 2025 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Based off of the original Go implementation
//
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! # About:
//! scrypt as specified in [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html). This implementation is available with features `safe_api` and `alloc`.
//!
//! # Note:
//! - This implementation is only supported on platforms with pointer sizes of
//! at least 32 bits.
//! - This implementation is single-threaded. Values for `p > 1` will not
//!   benefit from the speedup of being run in parallel.
//!
//! # Parameters:
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `n`: The CPU/Memory cost parameter.
//! - `r`: The blocksize parameter.
//! - `p`: The parallelization parameter.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dst_out`.
//! - `expected`: The expected derived key.
//!
//! # Errors:
//! An error will be returned if:
//! - `n` is not larger than `1` or a power of `2`.
//! - `r * p >=` [RP_MAX].
//! - `r * 128 * p >=` [RP_BLK_MAX].
//! - `r * 256 >=` [R_BLK_MAX].
//! - `n * 128 * r >=` [N_MAX].
//! - The length of `dst_out` is less than 1.
//! - The hashed password does not match the expected when verifying.
//!
//! # Security
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - Please note that when verifying, a copy of the computed password hash is placed into
//! `dst_out`. If the derived hash is considered sensitive and you want to provide defense
//! in depth against an attacker reading your application's private memory, then you as
//! the user are responsible for zeroing out this buffer (see the [`zeroize` crate]).
//! - The minimum recommended length for a salt is `16` bytes.
//! - The minimum recommended length for a hashed password is `16` bytes.
//! - The minimum recommended `n` is `2^17`/`131072`
//! - The minimum recommended `r` is `8`.
//! - The minimum recommended `p` is `1`.
//! - Please check [OWASP] for changes to recommended cost parameters in the future.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::scrypt, util};
//!
//! let n: u32 = 1 << 17; // 2^17
//! let r: u32 = 8;
//! let p: u32 = 1;
//!
//! let mut salt = [0u8; 64];
//! util::secure_rand_bytes(&mut salt)?;
//!
//! let mut dst_out = [0u8; 64];
//! scrypt::derive_key(b"Secret Password", &salt, n, r, p, &mut dst_out)?;
//!
//! let mut verify_dst_out = [0u8; 64];
//! assert!(scrypt::verify(&dst_out, b"Secret Password", &salt, n, r, p, &mut verify_dst_out).is_ok());
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes
//! [`zeroize` crate]: https://crates.io/crates/zeroize
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
//! [RP_MAX]: crate::hazardous::kdf::scrypt::RP_MAX
//! [RP_BLK_MAX]: crate::hazardous::kdf::scrypt::RP_BLK_MAX
//! [R_BLK_MAX]: crate::hazardous::kdf::scrypt::R_BLK_MAX
//! [N_MAX]: crate::hazardous::kdf::scrypt::N_MAX

use alloc::vec;

use crate::errors::UnknownCryptoError;
use crate::hazardous::kdf::pbkdf2::sha256 as pbkdf2;
use crate::util;
use zeroize::Zeroize;

/// scrypt `r * p` must be less than `2^30`.
pub const RP_MAX: u64 = 1 << 30;
/// scrypt `r * 128 * p` must be less than [i32::MAX].
pub const RP_BLK_MAX: u32 = (i32::MAX as u32) / 128;
/// scrypt `r * 256` must be less than [i32::MAX].
pub const R_BLK_MAX: u32 = (i32::MAX as u32) / 256;
/// scrypt `n * 128 * r` must be less than [i32::MAX].
pub const N_MAX: u32 = (i32::MAX as u32) / 128;

// Copies n numbers from src into dst
fn block_copy(dst: &mut [u32], src: &[u32], n: usize) {
    dst[..n].copy_from_slice(&src[..n]);
}

// XORs numbers from dst with n numbers from src
fn block_xor(dst: &mut [u32], src: &[u32], n: usize) {
    for (i, elem) in src[..n].iter().enumerate() {
        dst[i] ^= elem;
    }
}

// Applies Salsa20/8 to the XOR of 16 numbers from tmp and inn,
// and puts the result into both tmp and out.
#[rustfmt::skip]
fn salsa_xor(tmp: &mut [u32], inn: &[u32], out: &mut [u32]) {
    let w0 = tmp[0] ^ inn[0];
    let w1 = tmp[1] ^ inn[1];
    let w2 = tmp[2] ^ inn[2];
    let w3 = tmp[3] ^ inn[3];
    let w4 = tmp[4] ^ inn[4];
    let w5 = tmp[5] ^ inn[5];
    let w6 = tmp[6] ^ inn[6];
    let w7 = tmp[7] ^ inn[7];
    let w8 = tmp[8] ^ inn[8];
    let w9 = tmp[9] ^ inn[9];
    let w10 = tmp[10] ^ inn[10];
    let w11 = tmp[11] ^ inn[11];
    let w12 = tmp[12] ^ inn[12];
    let w13 = tmp[13] ^ inn[13];
    let w14 = tmp[14] ^ inn[14];
    let w15 = tmp[15] ^ inn[15];

    let mut x0 = w0;
    let mut x1 = w1;
    let mut x2 = w2;
    let mut x3 = w3;
    let mut x4 = w4;
    let mut x5 = w5;
    let mut x6 = w6;
    let mut x7 = w7;
    let mut x8 = w8;
    let mut x9 = w9;
    let mut x10 = w10;
    let mut x11 = w11;
    let mut x12 = w12;
    let mut x13 = w13;
    let mut x14 = w14;
    let mut x15 = w15;

    for _ in (0..8).step_by(2) {
        x4 ^= x0.wrapping_add(x12).rotate_left(7);
		x8 ^= x4.wrapping_add(x0).rotate_left(9);
		x12 ^= x8.wrapping_add(x4).rotate_left(13);
		x0 ^= x12.wrapping_add(x8).rotate_left(18);

		x9 ^= x5.wrapping_add(x1).rotate_left(7);
		x13 ^= x9.wrapping_add(x5).rotate_left(9);
		x1 ^= x13.wrapping_add(x9).rotate_left(13);
		x5 ^= x1.wrapping_add(x13).rotate_left(18);

		x14 ^= x10.wrapping_add(x6).rotate_left(7);
		x2 ^= x14.wrapping_add(x10).rotate_left(9);
		x6 ^= x2.wrapping_add(x14).rotate_left(13);
		x10 ^= x6.wrapping_add(x2).rotate_left(18);

		x3 ^= x15.wrapping_add(x11).rotate_left(7);
		x7 ^= x3.wrapping_add(x15).rotate_left(9);
		x11 ^= x7.wrapping_add(x3).rotate_left(13);
		x15 ^= x11.wrapping_add(x7).rotate_left(18);

		x1 ^= x0.wrapping_add(x3).rotate_left(7);
		x2 ^= x1.wrapping_add(x0).rotate_left(9);
		x3 ^= x2.wrapping_add(x1).rotate_left(13);
		x0 ^= x3.wrapping_add(x2).rotate_left(18);

		x6 ^= x5.wrapping_add(x4).rotate_left(7);
		x7 ^= x6.wrapping_add(x5).rotate_left(9);
		x4 ^= x7.wrapping_add(x6).rotate_left(13);
		x5 ^= x4.wrapping_add(x7).rotate_left(18);

		x11 ^= x10.wrapping_add(x9).rotate_left(7);
		x8 ^= x11.wrapping_add(x10).rotate_left(9);
		x9 ^= x8.wrapping_add(x11).rotate_left(13);
		x10 ^= x9.wrapping_add(x8).rotate_left(18);

		x12 ^= x15.wrapping_add(x14).rotate_left(7);
		x13 ^= x12.wrapping_add(x15).rotate_left(9);
		x14 ^= x13.wrapping_add(x12).rotate_left(13);
		x15 ^= x14.wrapping_add(x13).rotate_left(18);
    }

    x0 = x0.wrapping_add(w0);
    x1 = x1.wrapping_add(w1);
    x2 = x2.wrapping_add(w2);
    x3 = x3.wrapping_add(w3);
    x4 = x4.wrapping_add(w4);
    x5 = x5.wrapping_add(w5);
    x6 = x6.wrapping_add(w6);
    x7 = x7.wrapping_add(w7);
    x8 = x8.wrapping_add(w8);
    x9 = x9.wrapping_add(w9);
    x10 = x10.wrapping_add(w10);
    x11 = x11.wrapping_add(w11);
    x12 = x12.wrapping_add(w12);
    x13 = x13.wrapping_add(w13);
    x14 = x14.wrapping_add(w14);
    x15 = x15.wrapping_add(w15);

    out[0] = x0; tmp[0] = x0;
    out[1] = x1; tmp[1] = x1;
    out[2] = x2; tmp[2] = x2;
    out[3] = x3; tmp[3] = x3;
    out[4] = x4; tmp[4] = x4;
    out[5] = x5; tmp[5] = x5;
    out[6] = x6; tmp[6] = x6;
    out[7] = x7; tmp[7] = x7;
    out[8] = x8; tmp[8] = x8;
    out[9] = x9; tmp[9] = x9;
    out[10] = x10; tmp[10] = x10;
    out[11] = x11; tmp[11] = x11;
    out[12] = x12; tmp[12] = x12;
    out[13] = x13; tmp[13] = x13;
    out[14] = x14; tmp[14] = x14;
    out[15] = x15; tmp[15] = x15;
}

#[rustfmt::skip]
fn block_mix(tmp: &mut [u32], inn: &[u32], out: &mut [u32], r: usize) {
    block_copy(tmp, &inn[(2*r-1)*16..], 16);
    for i in (0..2*r).step_by(2) {
        salsa_xor(tmp, &inn[i*16..], &mut out[i*8..]);
        salsa_xor(tmp, &inn[i*16+16..], &mut out[i*8+r*16..]);
    }
}

fn integer(b: &[u32], r: usize) -> u64 {
    let j = (2 * r - 1) * 16;
    u64::from(b[j]) | u64::from(b[j + 1]) << 32
}

#[allow(non_snake_case)]
#[allow(clippy::needless_range_loop)]
fn smix(b: &mut [u8], r: usize, N: usize, v: &mut [u32], x: &mut [u32], y: &mut [u32]) {
    let mut tmp = [0u32; 16];
    let R = 32 * r;

    let mut j = 0;
    for i in 0..R {
        x[i] = u32::from_le_bytes(b[j..j + 4].try_into().unwrap());
        j += 4;
    }

    for i in (0..N).step_by(2) {
        block_copy(&mut v[i * R..], x, R);
        block_mix(&mut tmp, x, y, r);

        block_copy(&mut v[(i + 1) * R..], y, R);
        block_mix(&mut tmp, y, x, r);
    }

    for _ in (0..N).step_by(2) {
        let j = (integer(x, r) & (N - 1) as u64) as usize;
        block_xor(x, &v[j * R..], R);
        block_mix(&mut tmp, x, y, r);

        let j = (integer(y, r) & (N - 1) as u64) as usize;
        block_xor(y, &v[j * R..], R);
        block_mix(&mut tmp, y, x, r);
    }

    let mut j = 0;
    for v in &x[..R] {
        b[j..j + 4].copy_from_slice(&v.to_le_bytes());
        j += 4;
    }
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// scrypt key derivation function as specified in [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html).
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if n <= 1
        || n & (n - 1) != 0
        || ((r as u64) * (p as u64)) >= RP_MAX
        || r > RP_BLK_MAX / p
        || r > R_BLK_MAX
        || n > N_MAX / r
        || usize::BITS < 32
    {
        return Err(UnknownCryptoError);
    }

    let n: usize = n as usize;
    let r: usize = r as usize;
    let p: usize = p as usize;

    let vlen: usize = 32 * n * r;
    let mut x = vec![0u32; 32 * r];
    let mut y = vec![0u32; 32 * r];
    let mut v = vec![0u32; vlen];
    let pass = pbkdf2::Password::from_slice(password)?;
    let blen: usize = p * 128 * r;
    let mut b = vec![0u8; blen];

    pbkdf2::derive_key(&pass, salt, 1, &mut b).inspect_err(|_| {
        b.zeroize();
    })?;

    for i in 0..p {
        smix(&mut b[i * 128 * r..], r, n, &mut v, &mut x, &mut y);
    }

    pbkdf2::derive_key(&pass, &b, 1, dst_out).inspect_err(|_| {
        b.zeroize();
    })?;

    b.zeroize();

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Verify a scrypt derived key in constant time.
pub fn verify(
    expected: &[u8],
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    derive_key(password, salt, n, r, p, dst_out)?;
    util::secure_cmp(dst_out, expected)
}

#[cfg(test)]
mod tests {
    use super::{derive_key, verify};

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    mod test_verify {
        use super::*;
        use alloc::vec;

        #[test]
        fn test_verify_input() {
            let password = b"password";
            let salt = b"salt";
            const DK_LEN: usize = 32;
            let n = 2;
            let r = 10;
            let p = 10;
            let expected_dk: [u8; DK_LEN] = [
                72, 44, 133, 142, 34, 144, 85, 230, 47, 65, 224, 236, 129, 154, 94, 225, 139, 219,
                135, 37, 26, 83, 79, 117, 172, 217, 90, 197, 229, 10, 161, 95,
            ];
            let modified_dk: [u8; DK_LEN] = [
                73, 44, 133, 142, 34, 144, 85, 230, 47, 65, 224, 236, 129, 154, 94, 225, 139, 219,
                135, 37, 26, 83, 79, 117, 172, 217, 90, 197, 229, 10, 161, 95,
            ];
            let mut dst_out = vec![0u8; DK_LEN];
            assert!(verify(&expected_dk, password, salt, n, r, p, &mut dst_out).is_ok());
            assert!(verify(&modified_dk, password, salt, n, r, p, &mut dst_out).is_err());
            assert!(verify(&expected_dk, password, b"tlas", n, r, p, &mut dst_out).is_err());

            let mut dkshort = [0u8; DK_LEN - 1];
            let mut dklong = [0u8; DK_LEN + 1];
            let mut dkzero = [0u8; 0];
            assert!(verify(&expected_dk, password, salt, n, r, p, &mut dkshort).is_err());
            assert!(verify(&expected_dk, password, salt, n, r, p, &mut dklong).is_err());
            assert!(verify(&expected_dk, password, salt, n, r, p, &mut dkzero).is_err());
        }
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    mod test_derive_key {
        use super::derive_key;
        use alloc::vec;

        struct ScryptVector<'a> {
            password: &'a [u8],
            salt: &'a [u8],
            n: u32,
            r: u32,
            p: u32,
            dk_len: usize,
            expected_dk: &'a [u8],
        }

        // Test vectors are from [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914.html#section-12)
        static SCRYPT_VECTORS: [ScryptVector<'_>; 7] = [
            ScryptVector {
                password: b"password",
                salt: b"salt",
                n: 2,
                r: 10,
                p: 10,
                dk_len: 32,
                expected_dk: &[
                    72, 44, 133, 142, 34, 144, 85, 230, 47, 65, 224, 236, 129, 154, 94, 225, 139,
                    219, 135, 37, 26, 83, 79, 117, 172, 217, 90, 197, 229, 10, 161, 95,
                ],
            },
            ScryptVector {
                password: b"password",
                salt: b"salt",
                n: 16,
                r: 100,
                p: 100,
                dk_len: 32,
                expected_dk: &[
                    136, 189, 94, 219, 82, 209, 221, 0, 24, 135, 114, 173, 54, 23, 18, 144, 34, 78,
                    116, 130, 149, 37, 177, 141, 115, 35, 165, 127, 145, 150, 60, 55,
                ],
            },
            ScryptVector {
                password: b"this is a long \x00 password",
                salt: b"and this is a long \x00 salt",
                n: 16384,
                r: 8,
                p: 1,
                dk_len: 77,
                expected_dk: &[
                    195, 241, 130, 238, 45, 236, 132, 110, 112, 166, 148, 47, 181, 41, 152, 90, 58,
                    9, 118, 94, 240, 76, 97, 41, 35, 177, 127, 24, 85, 90, 55, 7, 109, 235, 43,
                    152, 48, 214, 157, 229, 73, 38, 81, 228, 80, 106, 229, 119, 109, 150, 212, 15,
                    103, 170, 238, 55, 225, 119, 123, 138, 213, 195, 17, 20, 50, 187, 59, 111, 126,
                    18, 100, 64, 24, 121, 230, 65, 174,
                ],
            },
            ScryptVector {
                password: b"p",
                salt: b"s",
                n: 2,
                r: 1,
                p: 1,
                dk_len: 16,
                expected_dk: &[
                    72, 176, 210, 168, 163, 39, 38, 17, 152, 76, 80, 235, 214, 48, 175, 82,
                ],
            },
            ScryptVector {
                password: b"",
                salt: b"",
                n: 16,
                r: 1,
                p: 1,
                dk_len: 64,
                expected_dk: &[
                    119, 214, 87, 98, 56, 101, 123, 32, 59, 25, 202, 66, 193, 138, 4, 151, 241,
                    107, 72, 68, 227, 7, 74, 232, 223, 223, 250, 63, 237, 226, 20, 66, 252, 208, 6,
                    157, 237, 9, 72, 248, 50, 106, 117, 58, 15, 200, 31, 23, 232, 211, 224, 251,
                    46, 13, 54, 40, 207, 53, 226, 12, 56, 209, 137, 6,
                ],
            },
            ScryptVector {
                password: b"password",
                salt: b"NaCl",
                n: 1024,
                r: 8,
                p: 16,
                dk_len: 64,
                expected_dk: &[
                    253, 186, 190, 28, 157, 52, 114, 0, 120, 86, 231, 25, 13, 1, 233, 254, 124,
                    106, 215, 203, 200, 35, 120, 48, 231, 115, 118, 99, 75, 55, 49, 98, 46, 175,
                    48, 217, 46, 34, 163, 136, 111, 241, 9, 39, 157, 152, 48, 218, 199, 39, 175,
                    185, 74, 131, 238, 109, 131, 96, 203, 223, 162, 204, 6, 64,
                ],
            },
            ScryptVector {
                password: b"pleaseletmein",
                salt: b"SodiumChloride",
                n: 16384,
                r: 8,
                p: 1,
                dk_len: 64,
                expected_dk: &[
                    112, 35, 189, 203, 58, 253, 115, 72, 70, 28, 6, 205, 129, 253, 56, 235, 253,
                    168, 251, 186, 144, 79, 142, 62, 169, 181, 67, 246, 84, 93, 161, 242, 213, 67,
                    41, 85, 97, 63, 15, 207, 98, 212, 151, 5, 36, 42, 154, 249, 230, 30, 133, 220,
                    13, 101, 30, 64, 223, 207, 1, 123, 69, 87, 88, 135,
                ],
            },
        ];

        #[test]
        fn test_scrypt_vectors() {
            for case in SCRYPT_VECTORS.iter().take(SCRYPT_VECTORS.len() - 1) {
                let mut got = vec![0u8; case.dk_len];
                derive_key(case.password, case.salt, case.n, case.r, case.p, &mut got)
                    .expect("invalid scrypt parameters");
                let exp = case.expected_dk;
                assert_eq!(exp, got.as_slice())
            }
        }

        #[test]
        fn test_invalid_params() {
            let valid_n = 1024;
            let valid_r = 8;
            let valid_p = 1;

            let password = b"password";
            let salt = b"salt";

            let invalid_n = 1025;
            let invalid_r = u32::MAX / 255;
            let invalid_p = u32::MAX;

            let mut dk = vec![0u8; 32];

            assert!(derive_key(password, salt, valid_n, valid_r, valid_p, &mut dk).is_ok());
            assert!(derive_key(password, salt, invalid_n, invalid_r, invalid_p, &mut dk).is_err());

            assert!(derive_key(password, salt, invalid_n, valid_r, valid_p, &mut dk).is_err());
            assert!(derive_key(password, salt, invalid_n, valid_r, invalid_p, &mut dk).is_err());
            assert!(derive_key(password, salt, invalid_n, invalid_r, valid_p, &mut dk).is_err());
            assert!(derive_key(password, salt, valid_n, invalid_r, invalid_p, &mut dk).is_err());
            assert!(derive_key(password, salt, valid_n, valid_r, invalid_p, &mut dk).is_err());
            assert!(derive_key(password, salt, valid_n, invalid_r, valid_p, &mut dk).is_err());
        }
    }
}
