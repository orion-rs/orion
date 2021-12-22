// MIT License

// Copyright (c) 2020-2021 The orion Developers

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

//! # About:
//! Argon2i version 1.3. This implementation is available with features `safe_api` and `alloc`.
//!
//! # Note:
//! This implementation only supports a single thread/lane.
//!
//! # Parameters:
//! - `expected`: The expected derived key.
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `iterations`: Iteration count.
//! - `memory`: Memory size in kibibytes (KiB).
//! - `secret`: Optional secret value used for hashing.
//! - `ad`: Optional associated data used for hashing.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dst_out`.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of the `password` is greater than [`u32::MAX`].
//! - The length of the `salt` is greater than [`u32::MAX`] or less than `8`.
//! - The length of the `secret` is greater than [`u32::MAX`].
//! - The length of the `ad` is greater than [`u32::MAX`].
//! - The length of `dst_out` is greater than [`u32::MAX`] or less than `4`.
//! - `iterations` is less than `1`.
//! - `memory` is less than `8`.
//! - The hashed password does not match the expected when verifying.
//!
//! # Panics:
//! A panic will occur if:
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - The minimum recommended length for a salt is `16` bytes.
//! - The minimum recommended length for a hashed password is `16` bytes.
//! - The minimum recommended iteration count is `3`.
//! - Password hashes should always be compared in constant-time.
//! - Please note that when verifying, a copy of the computed password hash is placed into
//! `dst_out`. If the derived hash is considered sensitive and you want to provide defense
//! in depth against an attacker reading your application's private memory, then you as
//! the user are responsible for zeroing out this buffer (see the [`zeroize` crate]).
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::argon2i, util};
//!
//! let mut salt = [0u8; 16];
//! util::secure_rand_bytes(&mut salt)?;
//! let password = b"Secret password";
//! let mut dst_out = [0u8; 64];
//!
//! argon2i::derive_key(password, &salt, 3, 1<<16, None, None, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(argon2i::verify(
//!     &expected_dk,
//!     password,
//!     &salt,
//!     3,
//!     1<<16,
//!     None,
//!     None,
//!     &mut dst_out
//! )
//! .is_ok());
//! # Ok::<(), orion::errors::UnknownCryptoError>(()) }
//! ```
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes
//! [`zeroize` crate]: https://crates.io/crates/zeroize

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b::Blake2b;
use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_OUTSIZE;
use crate::util;
use crate::util::endianness::{load_u64_into_le, store_u64_into_le};
use zeroize::Zeroize;

/// The Argon2 version (0x13).
pub const ARGON2_VERSION: u32 = 0x13;

/// The Argon2 variant (i).
pub const ARGON2_VARIANT: u32 = 1;

/// The amount of segments per lane, as defined in the spec.
const SEGMENTS_PER_LANE: usize = 4;

/// The amount of lanes supported.
pub(crate) const LANES: u32 = 1;

/// The minimum amount of memory.
pub(crate) const MIN_MEMORY: u32 = 8 * LANES;

/// The minimum amount of iterations.
pub(crate) const MIN_ITERATIONS: u32 = 1;

const fn lower_mult_add(x: u64, y: u64) -> u64 {
    let mask = 0xFFFF_FFFFu64;
    let x_l = x & mask;
    let y_l = y & mask;
    let xy = x_l.wrapping_mul(y_l);
    x.wrapping_add(y.wrapping_add(xy.wrapping_add(xy)))
}

/// BLAKE2 G with 64-bit multiplications.
fn g(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    *a = lower_mult_add(*a, *b);
    *d = (*d ^ *a).rotate_right(32);
    *c = lower_mult_add(*c, *d);
    *b = (*b ^ *c).rotate_right(24);
    *a = lower_mult_add(*a, *b);
    *d = (*d ^ *a).rotate_right(16);
    *c = lower_mult_add(*c, *d);
    *b = (*b ^ *c).rotate_right(63);
}

#[allow(clippy::too_many_arguments)]
fn permutation_p(
    v0: &mut u64,
    v1: &mut u64,
    v2: &mut u64,
    v3: &mut u64,
    v4: &mut u64,
    v5: &mut u64,
    v6: &mut u64,
    v7: &mut u64,
    v8: &mut u64,
    v9: &mut u64,
    v10: &mut u64,
    v11: &mut u64,
    v12: &mut u64,
    v13: &mut u64,
    v14: &mut u64,
    v15: &mut u64,
) {
    g(v0, v4, v8, v12);
    g(v1, v5, v9, v13);
    g(v2, v6, v10, v14);
    g(v3, v7, v11, v15);
    g(v0, v5, v10, v15);
    g(v1, v6, v11, v12);
    g(v2, v7, v8, v13);
    g(v3, v4, v9, v14);
}

/// H0 as defined in the specification.
fn initial_hash(
    hash_length: u32,
    memory_kib: u32,
    passes: u32,
    p: &[u8],
    s: &[u8],
    k: &[u8],
    x: &[u8],
) -> Result<[u8; 72], UnknownCryptoError> {
    // We save additional 8 bytes in H0 for when the first two blocks are processed,
    // so that this may contain two little-endian integers.
    let mut h0 = [0u8; 72];
    let mut hasher = Blake2b::new(BLAKE2B_OUTSIZE)?;

    // Collect the first part to reduce times we update the hasher state.
    h0[0..4].copy_from_slice(&LANES.to_le_bytes());
    h0[4..8].copy_from_slice(&hash_length.to_le_bytes());
    h0[8..12].copy_from_slice(&memory_kib.to_le_bytes());
    h0[12..16].copy_from_slice(&passes.to_le_bytes());
    h0[16..20].copy_from_slice(&ARGON2_VERSION.to_le_bytes());
    h0[20..24].copy_from_slice(&ARGON2_VARIANT.to_le_bytes());
    h0[24..28].copy_from_slice(&(p.len() as u32).to_le_bytes());

    hasher.update(&h0[..28])?;
    hasher.update(p)?;
    hasher.update(&(s.len() as u32).to_le_bytes())?;
    hasher.update(s)?;
    hasher.update(&(k.len() as u32).to_le_bytes())?;
    hasher.update(k)?;
    hasher.update(&(x.len() as u32).to_le_bytes())?;
    hasher.update(x)?;
    h0[0..BLAKE2B_OUTSIZE].copy_from_slice(hasher.finalize()?.as_ref());

    Ok(h0)
}

/// H' as defined in the specification.
fn extended_hash(input: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError> {
    if dst.is_empty() {
        return Err(UnknownCryptoError);
    }

    let outlen = dst.len() as u32;

    if dst.len() <= BLAKE2B_OUTSIZE {
        let mut ctx = Blake2b::new(dst.len())?;
        ctx.update(&outlen.to_le_bytes())?;
        ctx.update(input)?;
        dst.copy_from_slice(ctx.finalize()?.as_ref());
    } else {
        let mut ctx = Blake2b::new(BLAKE2B_OUTSIZE)?;
        ctx.update(&outlen.to_le_bytes())?;
        ctx.update(input)?;

        let mut tmp = ctx.finalize()?;
        dst[..BLAKE2B_OUTSIZE].copy_from_slice(tmp.as_ref());

        let mut pos = BLAKE2B_OUTSIZE / 2;
        let mut toproduce = dst.len() - BLAKE2B_OUTSIZE / 2;

        while toproduce > BLAKE2B_OUTSIZE {
            ctx.reset()?;
            ctx.update(tmp.as_ref())?;
            tmp = ctx.finalize()?;

            dst[pos..(pos + BLAKE2B_OUTSIZE)].copy_from_slice(tmp.as_ref());
            pos += BLAKE2B_OUTSIZE / 2;
            toproduce -= BLAKE2B_OUTSIZE / 2;
        }

        ctx = Blake2b::new(toproduce)?;
        ctx.update(tmp.as_ref())?;
        tmp = ctx.finalize()?;
        dst[pos..outlen as usize].copy_from_slice(&tmp.as_ref()[..toproduce]);
    }

    Ok(())
}

#[rustfmt::skip]
fn fill_block(w: &mut [u64; 128]) {
	
	let mut v0:  u64; let mut v1:  u64; let mut v2:  u64; let mut v3:  u64;
	let mut v4:  u64; let mut v5:  u64; let mut v6:  u64; let mut v7:  u64; 
	let mut v8:  u64; let mut v9:  u64; let mut v10: u64; let mut v11: u64;
	let mut v12: u64; let mut v13: u64; let mut v14: u64; let mut v15: u64;

	let mut idx = 0;
	
	// Operate on columns.
	while idx < 128 {
		v0  = w[idx      ]; v1  = w[idx +  1]; v2  = w[idx +  2]; v3  = w[idx +  3];
		v4  = w[idx +   4]; v5  = w[idx +  5]; v6  = w[idx +  6]; v7  = w[idx +  7];
		v8  = w[idx +   8]; v9  = w[idx +  9]; v10 = w[idx + 10]; v11 = w[idx + 11];
		v12 = w[idx +  12]; v13 = w[idx + 13]; v14 = w[idx + 14]; v15 = w[idx + 15];

		permutation_p(
			&mut v0,  &mut v1,  &mut v2,  &mut v3, 
			&mut v4,  &mut v5,  &mut v6,  &mut v7, 
			&mut v8,  &mut v9,  &mut v10, &mut v11, 
			&mut v12, &mut v13, &mut v14, &mut v15
		);

		w[idx     ] =  v0; w[idx +  1] =  v1; w[idx +  2] =  v2; w[idx +  3] =  v3;
		w[idx +  4] =  v4; w[idx +  5] =  v5; w[idx +  6] =  v6; w[idx +  7] =  v7;
		w[idx +  8] =  v8; w[idx +  9] =  v9; w[idx + 10] = v10; w[idx + 11] = v11;
		w[idx + 12] = v12; w[idx + 13] = v13; w[idx + 14] = v14; w[idx + 15] = v15;

		idx += 16;
	}

	idx = 0;
	// Operate on rows.
	while idx < 16 {
		v0  = w[idx     ]; v1  = w[idx +  1]; v2  = w[idx +  16]; v3  = w[idx +  17];
		v4  = w[idx + 32]; v5  = w[idx + 33]; v6  = w[idx +  48]; v7  = w[idx +  49];
		v8  = w[idx + 64]; v9  = w[idx + 65]; v10 = w[idx +  80]; v11 = w[idx +  81];
		v12 = w[idx + 96]; v13 = w[idx + 97]; v14 = w[idx + 112]; v15 = w[idx + 113];

		permutation_p(
			&mut v0,  &mut v1,  &mut v2,  &mut v3, 
			&mut v4,  &mut v5,  &mut v6,  &mut v7, 
			&mut v8,  &mut v9,  &mut v10, &mut v11, 
			&mut v12, &mut v13, &mut v14, &mut v15
		);

		w[idx     ] =  v0; w[idx +  1] =  v1; w[idx +  16] =  v2; w[idx +  17] =  v3;
		w[idx + 32] =  v4; w[idx + 33] =  v5; w[idx +  48] =  v6; w[idx +  49] =  v7;
		w[idx + 64] =  v8; w[idx + 65] =  v9; w[idx +  80] = v10; w[idx +  81] = v11;
		w[idx + 96] = v12; w[idx + 97] = v13; w[idx + 112] = v14; w[idx + 113] = v15;

		idx += 2;
	}
}

/// Data-independent indexing.
struct Gidx {
    block: [u64; 128],
    addresses: [u64; 128],
    segment_length: u32,
    offset: u32,
}

impl Gidx {
    fn new(blocks: u32, passes: u32, segment_length: u32) -> Self {
        let mut block = [0u64; 128];
        block[1] = 0u64; // Lane number, we only support one (0u64).
        block[3] = u64::from(blocks);
        block[4] = u64::from(passes);
        block[5] = u64::from(ARGON2_VARIANT); // The Argon2i variant

        Self {
            block,
            addresses: [0u64; 128],
            segment_length,
            offset: 0,
        }
    }

    fn init(&mut self, pass_n: u32, segment_n: u32, offset: u32, tmp_block: &mut [u64; 128]) {
        self.block[0] = u64::from(pass_n);
        self.block[2] = u64::from(segment_n);
        self.block[6] = 0u64; // Counter
        self.offset = offset;

        self.next_addresses(tmp_block);

        // The existing values in self.addresses are not read
        // when generating a new address block. Therefor we
        // do not have to zero it out.
    }

    fn next_addresses(&mut self, tmp_block: &mut [u64; 128]) {
        self.block[6] += 1;
        // G-two operation
        tmp_block.copy_from_slice(&self.block);
        fill_block(tmp_block);
        xor_slices!(self.block, tmp_block);

        self.addresses.copy_from_slice(tmp_block);
        fill_block(&mut self.addresses);
        xor_slices!(tmp_block, self.addresses);
    }

    fn get_next(&mut self, segment_idx: u32, tmp_block: &mut [u64; 128]) -> u32 {
        // We get J1 and discard J2, as J2 is only relevant if we had more than
        // a single lane.
        let j1: u64 = self.addresses[self.offset as usize] & 0xFFFF_FFFFu64;
        self.offset = (self.offset + 1) % 128; // Wrap-around on block length.
        if self.offset == 0 {
            self.next_addresses(tmp_block);
        }

        // The Argon2 specification for this version (1.3) does not conform
        // to the official reference implementation. This implementation follows
        // the reference implementation and ignores the specification where they
        // disagree. See https://github.com/P-H-C/phc-winner-argon2/issues/183.

        let n_blocks = self.block[3] as u32;
        let pass_n = self.block[0] as u32;
        let segment_n = self.block[2] as u32;

        let ref_start_pos: u32 = if pass_n == 0 && segment_n == 0 {
            segment_idx - 1
        } else if pass_n == 0 {
            segment_n * self.segment_length + segment_idx - 1
        } else {
            n_blocks - self.segment_length + segment_idx - 1
        };

        let mut ref_pos: u64 = (j1 * j1) >> 32;
        ref_pos = (ref_start_pos as u64 * ref_pos) >> 32;
        ref_pos = (ref_start_pos as u64 - 1) - ref_pos;

        if pass_n == 0 || segment_n == 3 {
            ref_pos as u32 % n_blocks
        } else {
            (self.segment_length * (segment_n + 1) + ref_pos as u32) % n_blocks
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Argon2i password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory: u32,
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if password.len() > 0xFFFF_FFFF {
        return Err(UnknownCryptoError);
    }
    if salt.len() > 0xFFFF_FFFF || salt.len() < 8 {
        return Err(UnknownCryptoError);
    }
    if iterations < MIN_ITERATIONS {
        return Err(UnknownCryptoError);
    }
    if memory < MIN_MEMORY {
        return Err(UnknownCryptoError);
    }

    let k = match secret {
        Some(n_val) => {
            if n_val.len() > 0xFFFF_FFFF {
                return Err(UnknownCryptoError);
            }

            n_val
        }
        None => &[0u8; 0],
    };

    let x = match ad {
        Some(n_val) => {
            if n_val.len() > 0xFFFF_FFFF {
                return Err(UnknownCryptoError);
            }

            n_val
        }
        None => &[0u8; 0],
    };

    if dst_out.len() > 0xFFFF_FFFF || dst_out.len() < 4 {
        return Err(UnknownCryptoError);
    }

    // Round down to 4 * p threads
    let n_blocks = memory - (memory & 3);
    // Divide by 4 (SEGMENTS_PER_LANE)
    let segment_length = n_blocks >> 2;

    let mut blocks = vec![[0u64; 128]; n_blocks as usize];

    // Fill first two blocks
    let mut h0 = initial_hash(
        dst_out.len() as u32,
        memory,
        iterations,
        password,
        salt,
        k,
        x,
    )?;
    let mut tmp = [0u8; 1024];
    debug_assert_eq!(
        h0.len(),
        ((core::mem::size_of::<u32>() * 2) + BLAKE2B_OUTSIZE)
    );
    debug_assert!(
        h0[BLAKE2B_OUTSIZE..(BLAKE2B_OUTSIZE + core::mem::size_of::<u32>())]
            == [0u8; core::mem::size_of::<u32>()]
    ); // Block 0
    debug_assert!(
        h0[BLAKE2B_OUTSIZE + core::mem::size_of::<u32>()..] == [0u8; core::mem::size_of::<u32>()]
    ); // Lane

    // H' into the first two blocks
    extended_hash(&h0, &mut tmp)?;
    load_u64_into_le(&tmp, &mut blocks[0]);
    h0[BLAKE2B_OUTSIZE..(BLAKE2B_OUTSIZE + core::mem::size_of::<u32>())]
        .copy_from_slice(&1u32.to_le_bytes()); // Block 1
    extended_hash(&h0, &mut tmp)?;
    load_u64_into_le(&tmp, &mut blocks[1]);

    let mut gidx = Gidx::new(n_blocks, iterations, segment_length);
    let mut working_block = [0u64; 128];

    for pass_n in 0..iterations as usize {
        for segment_n in 0..SEGMENTS_PER_LANE {
            let offset = match (pass_n, segment_n) {
                (0, 0) => 2, // The first two blocks have already been processed
                _ => 0,
            };

            gidx.init(pass_n as u32, segment_n as u32, offset, &mut working_block);

            for segment_idx in offset..segment_length {
                let reference_idx = gidx.get_next(segment_idx, &mut working_block);
                let current_idx = segment_n as u32 * segment_length + segment_idx as u32;
                let previous_idx = if current_idx > 0 {
                    current_idx - 1
                } else {
                    n_blocks - 1
                };

                let prev_b = blocks.get(previous_idx as usize).unwrap();
                let ref_b = blocks.get(reference_idx as usize).unwrap();

                // G-xor operation
                for (el_tmp, (el_prev, el_ref)) in working_block
                    .iter_mut()
                    .zip(prev_b.iter().zip(ref_b.iter()))
                {
                    *el_tmp = el_prev ^ el_ref;
                }
                let cur_b = blocks.get_mut(current_idx as usize).unwrap();
                xor_slices!(working_block, cur_b);
                fill_block(&mut working_block);
                xor_slices!(working_block, cur_b);
            }
        }
    }

    store_u64_into_le(blocks.get(n_blocks as usize - 1).unwrap(), &mut tmp);
    extended_hash(&tmp, dst_out)?;

    working_block.zeroize();
    tmp.zeroize();
    h0.zeroize();
    for block in blocks.iter_mut() {
        block.zeroize();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// Verify Argon2i derived key in constant time.
pub fn verify(
    expected: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory: u32,
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    derive_key(password, salt, iterations, memory, secret, ad, dst_out)?;
    util::secure_cmp(dst_out, expected)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[cfg(feature = "safe_api")]
    mod test_verify {
        use super::*;

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_same_input_verify_true(
            hlen: u32,
            kib: u32,
            p: Vec<u8>,
            s: Vec<u8>,
            k: Vec<u8>,
            x: Vec<u8>,
        ) -> bool {
            let passes = 1;
            let mem = if kib < 8 || kib > 4096 { 1024 } else { kib };
            let salt = if s.len() < 8 { vec![37u8; 8] } else { s };

            let mut dst_out = if hlen < 4 || hlen > 512 {
                vec![0u8; 32]
            } else {
                vec![0u8; hlen as usize]
            };

            let mut dst_out_verify = dst_out.clone();
            derive_key(&p, &salt, passes, mem, Some(&k), Some(&x), &mut dst_out).unwrap();

            verify(
                &dst_out,
                &p,
                &salt,
                passes,
                mem,
                Some(&k),
                Some(&x),
                &mut dst_out_verify,
            )
            .is_ok()
        }
    }

    mod test_derive_key {
        use super::*;

        #[test]
        fn test_invalid_mem() {
            // mem must be at least 8p, where p == threads (1)
            let mut dst_out = [0u8; 32];
            assert!(derive_key(&[], &[0u8; 8], 1, 9, None, None, &mut dst_out).is_ok());
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out).is_ok());
            assert!(derive_key(&[], &[0u8; 8], 1, 7, None, None, &mut dst_out).is_err());
        }

        #[test]
        fn test_invalid_passes() {
            let mut dst_out = [0u8; 32];
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out).is_ok());
            assert!(derive_key(&[], &[0u8; 8], 0, 8, None, None, &mut dst_out).is_err());
        }

        #[test]
        fn test_dst_out() {
            let mut dst_out_less = [0u8; 3];
            let mut dst_out_exact = [0u8; 4];
            let mut dst_out_above = [0u8; 5];
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out_less).is_err());
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out_exact).is_ok());
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out_above).is_ok());
        }

        #[test]
        fn test_invalid_salt() {
            let mut dst_out = [0u8; 32];
            assert!(derive_key(&[], &[0u8; 8], 1, 8, None, None, &mut dst_out).is_ok());
            assert!(derive_key(&[], &[0u8; 9], 1, 8, None, None, &mut dst_out).is_ok());
            assert!(derive_key(&[], &[0u8; 7], 1, 8, None, None, &mut dst_out).is_err());
        }

        #[test]
        fn test_some_or_none_same_result() {
            let mut dst_one = [0u8; 32];
            let mut dst_two = [0u8; 32];

            derive_key(&[255u8; 16], &[1u8; 16], 1, 8, None, None, &mut dst_one).unwrap();
            derive_key(
                &[255u8; 16],
                &[1u8; 16],
                1,
                8,
                Some(&[]),
                Some(&[]),
                &mut dst_two,
            )
            .unwrap();

            assert_eq!(dst_one, dst_two);
        }

        #[test]
        fn test_hash_1() {
            let mem = 4096;
            let passes = 3;
            let p = [
                191, 68, 49, 232, 45, 162, 83, 188, 177, 167, 232, 149, 172, 236, 153, 8, 237, 115,
                232, 128, 171, 254, 47, 84, 192, 208, 196, 121, 127, 221, 93, 126,
            ];
            let s = [
                52, 225, 42, 12, 59, 186, 118, 248, 198, 12, 16, 189, 191, 167, 211, 42, 89, 170,
                108, 9, 172, 4, 138, 232, 239, 58, 189, 238, 250, 33, 230, 130,
            ];
            let k = [
                124, 169, 187, 230, 55, 69, 29, 225, 228, 147, 41, 248, 255, 98, 195, 221, 202, 40,
                58, 17, 93, 122, 37, 57, 169, 9, 80, 64, 170, 177, 33, 89,
            ];
            let x = [
                129, 251, 22, 14, 88, 173, 198, 8, 123, 139, 94, 203, 61, 50, 174, 20, 153, 43,
                109, 154, 46, 8, 71, 4, 208, 83, 157, 133, 143, 171, 78, 195,
            ];

            let expected = [
                234, 181, 45, 90, 214, 219, 1, 146, 196, 60, 104, 29, 152, 103, 82, 77, 65, 214,
                212, 55, 121, 228, 57, 189, 202, 44, 100, 103, 180, 24, 125, 50,
            ];

            let mut actual = [0u8; 32];
            derive_key(&p, &s, passes, mem, Some(&k), Some(&x), &mut actual).unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }

        #[test]
        fn test_hash_2() {
            let mem = 4096;
            let passes = 3;
            let p = [
                99, 137, 197, 238, 38, 112, 35, 125, 195, 31, 121, 180, 52, 30, 19, 20, 198, 227,
                198, 9, 66, 209, 130, 225, 200, 43, 50, 221, 47, 59, 169, 160, 220, 64, 54, 202,
                55, 244, 226, 8, 225, 183, 155, 186, 56, 162, 30, 15, 12, 176, 15, 182, 243, 175,
                24, 142, 80, 247, 2, 210, 208, 57, 28, 59,
            ];
            let s = [
                94, 32, 63, 147, 115, 103, 179, 120, 17, 232, 110, 157, 92, 70, 77, 157, 82, 46,
                79, 122, 29, 191, 104, 146, 125, 208, 48, 24, 6, 8, 94, 196, 65, 238, 136, 255,
                180, 172, 187, 23, 214, 55, 18, 84, 171, 217, 253, 6, 51, 89, 173, 55, 222, 190,
                71, 183, 135, 156, 229, 77, 67, 78, 96, 90,
            ];
            let k = [
                18, 85, 39, 122, 166, 85, 120, 191, 243, 15, 174, 215, 32, 185, 255, 88, 134, 238,
                227, 159, 77, 121, 149, 134, 255, 105, 240, 88, 150, 252, 94, 158,
            ];
            let x = [
                240, 249, 197, 139, 242, 216, 12, 130, 192, 73, 44, 189, 130, 17, 225, 223, 135,
                30, 139, 255, 164, 168, 69, 140, 216, 121, 225, 194, 107, 123, 143, 120, 30, 131,
                216, 196, 200, 81, 71, 203, 26, 66, 171, 118, 236, 26, 18, 105, 100, 35, 227, 184,
                16, 108, 224, 222, 186, 255, 32, 112, 189, 13, 151, 22,
            ];

            let expected = [
                233, 201, 213, 214, 244, 141, 73, 220, 67, 19, 106, 102, 181, 1, 197, 122, 20, 147,
                99, 245, 236, 160, 3, 213, 22, 219, 155, 217, 194, 24, 65, 204, 239, 56, 34, 160,
                140, 114, 3, 191, 247, 48, 64, 79, 125, 154, 52, 185, 0, 69, 102, 85, 183, 242,
                167, 198, 170, 1, 124, 235, 235, 3, 184, 75,
            ];
            let mut actual = [0u8; 64];
            derive_key(&p, &s, passes, mem, Some(&k), Some(&x), &mut actual).unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }

        #[test]
        fn test_hash_3() {
            let mem = 4096;
            let passes = 3;
            let p = [
                175, 90, 106, 212, 141, 72, 174, 254, 80, 27, 64, 221, 238, 102, 191, 242, 3, 221,
                202, 111, 10, 217, 92, 143, 15, 200, 215, 210, 199, 59, 200, 59, 98, 141, 106, 228,
                166, 184, 5, 212, 172, 114, 32, 229, 179, 111, 227, 116, 216, 95, 164, 35, 31, 204,
                132, 215, 116, 156, 32, 7, 165, 15, 231, 148, 124, 95, 115, 150, 82, 168, 34, 154,
                52, 166, 104, 28, 207, 61, 162, 198, 228, 72, 196, 200, 228, 251, 124, 231, 44,
                151, 44, 44, 24, 70, 103, 169, 44, 240, 248, 75, 208, 142, 112, 36, 25, 49, 252,
                196, 121, 203, 74, 155, 220, 58, 89, 106, 82, 9, 177, 66, 30, 12, 245, 153, 116,
                72, 233, 233,
            ];
            let s = [
                205, 79, 28, 236, 67, 87, 187, 158, 25, 126, 159, 75, 129, 34, 145, 131, 219, 240,
                243, 73, 42, 223, 247, 12, 223, 190, 218, 212, 26, 109, 15, 151, 118, 77, 210, 18,
                171, 176, 224, 127, 48, 189, 216, 225, 175, 45, 205, 3, 196, 231, 185, 203, 127,
                210, 185, 238, 122, 197, 147, 147, 35, 231, 182, 42, 254, 104, 201, 72, 213, 122,
                46, 24, 21, 80, 26, 221, 252, 117, 51, 208, 107, 147, 24, 3, 72, 222, 32, 95, 20,
                107, 111, 47, 21, 43, 174, 153, 57, 154, 199, 208, 182, 89, 36, 91, 111, 117, 1,
                254, 254, 178, 239, 204, 146, 170, 34, 121, 126, 143, 63, 88, 94, 7, 155, 2, 126,
                79, 43, 183,
            ];
            let k = [
                196, 222, 200, 1, 157, 90, 55, 246, 173, 195, 253, 212, 118, 186, 31, 189, 35, 154,
                202, 137, 60, 32, 56, 89, 179, 44, 105, 140, 185, 225, 111, 242,
            ];
            let x = [
                28, 43, 133, 219, 80, 24, 121, 131, 89, 41, 81, 230, 215, 79, 73, 60, 59, 206, 46,
                22, 241, 113, 205, 178, 219, 91, 159, 220, 225, 106, 152, 3, 187, 167, 148, 23,
                143, 89, 43, 253, 188, 87, 150, 154, 249, 44, 189, 0, 77, 237, 69, 112, 56, 71,
                131, 235, 63, 141, 7, 202, 20, 247, 110, 221, 28, 72, 38, 209, 210, 171, 163, 51,
                42, 6, 54, 121, 208, 125, 160, 105, 81, 196, 237, 22, 206, 140, 35, 89, 160, 102,
                214, 22, 105, 14, 113, 54, 96, 33, 68, 149, 253, 82, 1, 222, 90, 224, 99, 228, 219,
                230, 5, 103, 235, 206, 183, 230, 163, 177, 51, 187, 200, 207, 244, 203, 197, 56,
                24, 132,
            ];

            let expected = [
                37, 212, 93, 127, 114, 22, 107, 220, 94, 83, 173, 159, 101, 143, 232, 110, 49, 192,
                93, 236, 251, 92, 209, 91, 145, 162, 48, 21, 140, 49, 59, 155, 48, 116, 129, 197,
                223, 12, 34, 240, 209, 200, 152, 9, 112, 175, 206, 35, 166, 229, 230, 13, 110, 89,
                211, 60, 28, 174, 248, 142, 43, 38, 87, 72, 175, 177, 244, 186, 81, 55, 111, 238,
                151, 206, 243, 145, 247, 255, 50, 126, 9, 250, 28, 80, 194, 144, 17, 173, 42, 222,
                251, 125, 11, 130, 169, 17, 17, 112, 45, 66, 129, 118, 96, 67, 36, 252, 61, 156,
                239, 121, 204, 210, 74, 162, 220, 212, 33, 239, 201, 77, 80, 231, 7, 238, 92, 151,
                51, 17,
            ];

            let mut actual = [0u8; 128];
            derive_key(&p, &s, passes, mem, Some(&k), Some(&x), &mut actual).unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }

        #[test]
        fn test_hash_4() {
            let mem = 4096;
            let passes = 3;
            let p = [
                129, 27, 156, 146, 197, 105, 114, 238, 251, 207, 14, 230, 59, 139, 249, 192, 99,
                228, 195, 63, 0, 133, 24, 243, 246, 198, 53, 3, 56, 81, 225, 43, 229, 192, 145, 23,
                31, 111, 106, 70, 77, 118, 182, 116, 107, 49, 237, 149, 237, 163, 136, 12, 26, 73,
                70, 124, 87, 238, 250, 1, 79, 136, 101, 184, 173, 23, 79, 182, 171, 60, 249, 231,
                55, 169, 114, 44, 73, 163, 82, 190, 186, 224, 86, 18, 155, 129, 29, 86, 213, 238,
                217, 185, 25, 14, 86, 107, 104, 223, 89, 78, 168, 29, 96, 209, 116, 35, 224, 208,
                249, 106, 161, 58, 220, 236, 76, 142, 67, 235, 10, 79, 209, 49, 147, 59, 187, 0,
                18, 203, 124, 97, 30, 250, 208, 228, 93, 42, 161, 54, 172, 53, 64, 220, 141, 140,
                161, 12, 106, 225, 212, 66, 79, 117, 83, 228, 213, 194, 217, 90, 0, 197, 115, 31,
                194, 40, 215, 247, 45, 20, 15, 65, 9, 78, 108, 186, 76, 167, 18, 87, 214, 202, 31,
                135, 80, 188, 133, 219, 64, 254, 24, 181, 113, 154, 229, 62, 54, 242, 236, 71, 202,
                79, 233, 195, 46, 255, 10, 166, 193, 79, 211, 11, 85, 250, 191, 92, 94, 191, 85,
                219, 133, 33, 211, 134, 90, 88, 239, 179, 167, 199, 154, 163, 213, 214, 63, 25,
                245, 75, 237, 2, 76, 240, 56, 155, 153, 53, 241, 72, 250, 129, 121, 139, 205, 112,
                38, 137, 12, 8,
            ];
            let s = [
                189, 41, 181, 148, 99, 179, 60, 75, 245, 112, 106, 213, 213, 78, 183, 229, 167, 54,
                98, 246, 27, 90, 214, 60, 178, 63, 130, 229, 150, 254, 141, 126, 99, 182, 108, 217,
                134, 102, 245, 53, 136, 72, 159, 194, 239, 7, 238, 82, 96, 198, 218, 50, 80, 3,
                234, 33, 18, 68, 33, 114, 146, 158, 129, 148, 38, 200, 203, 26, 163, 3, 46, 76,
                141, 41, 14, 106, 169, 246, 216, 25, 125, 226, 110, 78, 183, 228, 119, 135, 186,
                151, 117, 32, 220, 221, 54, 19, 142, 73, 92, 167, 191, 28, 46, 244, 171, 254, 80,
                251, 245, 135, 148, 32, 167, 118, 151, 129, 27, 197, 127, 77, 165, 130, 56, 189,
                43, 69, 150, 27, 166, 224, 79, 44, 145, 144, 163, 83, 176, 39, 103, 199, 175, 234,
                30, 202, 87, 229, 38, 238, 61, 9, 82, 247, 136, 122, 94, 157, 110, 58, 198, 137,
                47, 238, 207, 72, 178, 225, 197, 37, 45, 139, 121, 24, 49, 202, 119, 58, 127, 2,
                109, 214, 104, 16, 2, 118, 238, 109, 206, 208, 105, 101, 145, 146, 152, 239, 176,
                59, 32, 224, 220, 231, 135, 11, 173, 222, 65, 154, 206, 130, 164, 243, 113, 40, 33,
                208, 85, 166, 3, 134, 139, 104, 204, 181, 43, 192, 24, 70, 249, 128, 94, 185, 217,
                163, 133, 2, 112, 38, 117, 159, 48, 145, 46, 194, 177, 73, 43, 108, 158, 195, 228,
                32, 122, 21, 185, 109, 107, 235,
            ];
            let k = [
                85, 248, 24, 79, 146, 124, 133, 99, 94, 108, 110, 97, 217, 184, 249, 109, 60, 209,
                248, 195, 45, 90, 90, 31, 61, 11, 202, 90, 122, 99, 155, 197,
            ];
            let x = [
                42, 203, 81, 203, 86, 170, 17, 4, 219, 64, 68, 44, 196, 213, 234, 193, 172, 102,
                173, 159, 41, 0, 43, 6, 149, 224, 135, 50, 224, 63, 104, 211, 226, 97, 11, 219, 95,
                46, 246, 231, 106, 107, 221, 60, 113, 107, 119, 53, 177, 70, 45, 54, 229, 165, 118,
                165, 87, 246, 180, 84, 90, 75, 122, 29, 147, 148, 250, 64, 189, 116, 238, 40, 35,
                228, 126, 242, 39, 64, 153, 67, 166, 8, 197, 0, 36, 189, 182, 171, 85, 202, 134,
                251, 73, 198, 32, 243, 17, 51, 239, 5, 100, 88, 35, 137, 190, 170, 158, 48, 45,
                144, 215, 173, 199, 235, 124, 133, 131, 117, 181, 211, 16, 124, 171, 174, 113, 189,
                79, 86, 86, 103, 223, 47, 167, 97, 85, 219, 224, 70, 160, 214, 45, 85, 249, 70,
                166, 179, 174, 53, 174, 127, 132, 238, 203, 238, 154, 25, 149, 102, 132, 183, 44,
                71, 238, 155, 158, 135, 193, 80, 115, 115, 38, 80, 161, 117, 145, 68, 48, 158, 125,
                12, 23, 230, 66, 143, 9, 29, 122, 105, 105, 103, 222, 157, 230, 253, 56, 188, 160,
                180, 244, 77, 192, 167, 145, 100, 140, 9, 55, 255, 39, 122, 191, 81, 78, 76, 97,
                170, 20, 225, 82, 151, 167, 79, 180, 95, 192, 237, 104, 20, 168, 187, 3, 157, 113,
                108, 20, 129, 179, 182, 239, 33, 192, 233, 57, 79, 242, 63, 207, 107, 10, 1, 133,
                169, 50, 67, 2, 20,
            ];

            let expected = [
                66, 170, 191, 26, 194, 179, 196, 87, 184, 52, 195, 197, 179, 30, 53, 59, 193, 138,
                103, 175, 140, 92, 232, 252, 74, 138, 32, 61, 249, 50, 22, 21, 255, 149, 219, 8,
                135, 72, 210, 76, 172, 168, 105, 16, 114, 201, 98, 51, 31, 15, 34, 201, 58, 82,
                248, 74, 12, 163, 190, 155, 249, 214, 49, 124, 196, 163, 177, 21, 11, 245, 119, 68,
                25, 68, 220, 169, 209, 151, 123, 16, 68, 236, 2, 145, 31, 230, 80, 203, 181, 208,
                154, 193, 185, 161, 139, 253, 142, 158, 211, 17, 205, 62, 195, 202, 115, 58, 110,
                253, 249, 59, 148, 61, 35, 18, 199, 60, 183, 188, 61, 102, 89, 109, 93, 51, 144,
                254, 84, 43, 217, 203, 232, 229, 123, 126, 171, 240, 179, 26, 168, 1, 146, 13, 161,
                128, 175, 209, 18, 166, 95, 107, 19, 91, 221, 120, 44, 40, 114, 159, 77, 133, 150,
                167, 85, 46, 10, 201, 2, 41, 28, 60, 189, 129, 116, 97, 231, 174, 105, 202, 90,
                227, 99, 3, 239, 102, 175, 241, 246, 111, 20, 76, 96, 252, 49, 31, 226, 225, 33,
                118, 1, 227, 171, 251, 231, 104, 159, 60, 217, 69, 178, 226, 175, 194, 100, 77,
                160, 38, 180, 65, 210, 156, 230, 242, 61, 72, 64, 65, 1, 59, 77, 131, 196, 18, 59,
                219, 33, 159, 18, 207, 113, 249, 21, 237, 79, 143, 180, 104, 61, 84, 238, 234, 254,
                33, 84, 70, 106, 244,
            ];

            let mut actual = [0u8; 256];
            derive_key(&p, &s, passes, mem, Some(&k), Some(&x), &mut actual).unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }

        #[test]
        fn test_hash_5() {
            let mem = 4096;
            let passes = 3;
            let p = [
                48, 115, 86, 156, 252, 145, 208, 204, 187, 108, 23, 254, 163, 172, 29, 63, 200,
                218, 50, 100, 108, 23, 64, 12, 70, 88, 171, 112, 154, 113, 39, 238, 202, 1, 88,
                147, 37, 107, 10, 31, 179, 27, 92, 14, 196, 104, 92, 134, 193, 139, 207, 9, 4, 60,
                7, 81, 23, 63, 171, 175, 164, 40, 126, 187, 45, 142, 34, 221, 118, 39, 70, 201,
                192, 241, 70, 225, 70, 112, 42, 222, 151, 125, 218, 98, 246, 67, 244, 154, 9, 237,
                126, 152, 110, 229, 124, 125, 242, 180, 209, 57, 227, 101, 104, 128, 72, 95, 143,
                255, 15, 246, 59, 191, 21, 242, 102, 45, 158, 170, 38, 138, 151, 96, 199, 37, 26,
                240, 239, 52, 72, 23, 227, 111, 157, 80, 241, 7, 73, 150, 22, 251, 118, 3, 99, 216,
                139, 212, 53, 49, 51, 90, 49, 81, 252, 45, 91, 36, 32, 51, 65, 121, 67, 100, 22,
                106, 0, 250, 134, 118, 175, 81, 210, 93, 102, 18, 56, 161, 24, 81, 168, 37, 19, 44,
                23, 94, 50, 190, 77, 186, 144, 2, 97, 168, 59, 210, 183, 220, 168, 176, 112, 134,
                53, 57, 152, 213, 67, 14, 132, 125, 107, 212, 159, 249, 206, 89, 161, 221, 113,
                123, 173, 79, 11, 25, 247, 8, 208, 96, 247, 45, 163, 85, 223, 174, 123, 136, 7, 67,
                73, 204, 18, 235, 182, 27, 237, 32, 106, 215, 84, 253, 72, 224, 37, 146, 199, 157,
                238, 24, 11, 57, 191, 82, 93, 51, 131, 134, 101, 253, 177, 57, 219, 202, 246, 40,
                92, 241, 123, 92, 136, 66, 230, 22, 145, 181, 111, 90, 248, 45, 156, 88, 25, 49,
                234, 64, 117, 242, 70, 210, 242, 68, 88, 62, 76, 110, 113, 119, 57, 77, 254, 242,
                13, 109, 141, 252, 21, 74, 255, 128, 136, 114, 249, 161, 81, 99, 18, 54, 206, 139,
                220, 212, 126, 31, 188, 199, 221, 177, 222, 24, 11, 234, 84, 66, 99, 5, 56, 0, 79,
                134, 97, 79, 229, 69, 153, 211, 190, 88, 116, 198, 81, 194, 196, 21, 158, 99, 140,
                227, 97, 24, 81, 134, 32, 214, 196, 25, 134, 73, 51, 83, 59, 200, 2, 176, 180, 5,
                133, 104, 255, 103, 95, 109, 184, 156, 56, 239, 186, 58, 148, 102, 108, 90, 51, 57,
                96, 134, 15, 128, 114, 165, 104, 175, 221, 223, 255, 83, 245, 19, 205, 169, 107,
                179, 200, 235, 143, 104, 111, 85, 129, 124, 237, 173, 154, 227, 14, 37, 200, 62,
                100, 236, 219, 189, 203, 164, 255, 58, 190, 226, 160, 117, 211, 77, 213, 22, 163,
                231, 226, 61, 168, 11, 207, 27, 105, 153, 210, 41, 175, 83, 204, 116, 63, 118, 196,
                142, 210, 51, 199, 180, 211, 24, 169, 214, 119, 253, 6, 233, 137, 117, 144, 104,
                97, 173, 92, 31, 15, 52, 70, 8, 52, 248, 95, 89, 134, 165, 114, 164, 9, 140, 228,
                127, 147, 6, 189, 126, 89, 0,
            ];
            let s = [
                175, 218, 81, 18, 191, 80, 114, 142, 79, 149, 196, 40, 61, 237, 245, 255, 115, 78,
                114, 250, 187, 148, 98, 141, 118, 42, 225, 26, 129, 64, 145, 107, 127, 227, 222,
                164, 224, 187, 120, 123, 82, 13, 29, 239, 137, 26, 225, 201, 211, 142, 105, 59,
                240, 206, 95, 8, 15, 98, 116, 188, 68, 173, 97, 64, 84, 229, 153, 58, 169, 24, 147,
                143, 156, 194, 247, 47, 192, 230, 102, 39, 18, 219, 243, 23, 195, 26, 121, 231,
                204, 221, 38, 53, 236, 178, 142, 161, 197, 214, 232, 125, 202, 12, 26, 255, 214,
                113, 49, 152, 193, 111, 63, 59, 84, 243, 89, 42, 129, 194, 30, 181, 222, 12, 229,
                105, 129, 216, 133, 22, 16, 118, 48, 16, 162, 99, 198, 79, 136, 91, 141, 231, 47,
                70, 107, 60, 175, 168, 139, 254, 60, 208, 8, 135, 122, 141, 83, 141, 58, 153, 235,
                116, 228, 158, 165, 178, 105, 172, 197, 232, 152, 250, 201, 20, 39, 235, 175, 245,
                128, 47, 134, 96, 163, 176, 67, 254, 36, 219, 14, 134, 118, 17, 4, 106, 74, 201,
                15, 208, 179, 255, 1, 53, 229, 86, 204, 187, 183, 214, 213, 77, 100, 79, 22, 31,
                32, 200, 134, 95, 123, 10, 74, 99, 143, 115, 183, 50, 153, 131, 247, 204, 250, 82,
                141, 68, 229, 102, 2, 120, 196, 65, 221, 234, 189, 11, 141, 183, 162, 153, 144, 22,
                190, 24, 131, 14, 125, 143, 217, 191, 11, 185, 43, 224, 156, 114, 144, 103, 183,
                122, 174, 3, 139, 218, 82, 248, 7, 20, 19, 150, 226, 139, 224, 226, 181, 64, 112,
                193, 61, 54, 52, 219, 75, 19, 217, 109, 37, 2, 172, 53, 230, 31, 153, 5, 113, 154,
                9, 176, 101, 122, 199, 1, 179, 62, 250, 113, 134, 226, 204, 209, 78, 80, 14, 231,
                115, 245, 22, 221, 99, 131, 237, 163, 133, 13, 143, 246, 57, 1, 230, 128, 225, 97,
                210, 48, 181, 3, 151, 220, 97, 231, 138, 89, 136, 201, 184, 203, 18, 32, 141, 62,
                53, 24, 84, 142, 194, 78, 77, 155, 200, 117, 57, 12, 4, 78, 206, 16, 122, 90, 156,
                132, 17, 2, 83, 74, 249, 94, 242, 142, 96, 25, 226, 125, 142, 93, 223, 178, 180,
                232, 177, 70, 188, 31, 19, 165, 200, 137, 173, 96, 189, 242, 149, 118, 100, 142,
                45, 48, 239, 14, 210, 153, 120, 243, 250, 237, 151, 244, 143, 130, 114, 0, 52, 34,
                156, 186, 3, 145, 55, 219, 153, 37, 73, 204, 152, 228, 69, 64, 42, 209, 161, 121,
                66, 85, 251, 62, 127, 18, 193, 91, 187, 198, 52, 12, 88, 125, 52, 93, 135, 60, 65,
                176, 103, 32, 24, 108, 28, 172, 208, 106, 84, 230, 191, 240, 235, 21, 180, 14, 22,
                226, 41, 15, 198, 31, 98, 184, 111, 194, 206, 72, 115, 98, 135, 90, 27, 111, 64,
                87, 149, 20, 154, 158, 65, 172, 116, 134, 62, 49,
            ];
            let k = [
                231, 130, 29, 148, 24, 187, 24, 64, 111, 18, 54, 133, 243, 193, 55, 21, 180, 71,
                147, 96, 46, 96, 27, 198, 81, 167, 14, 201, 18, 221, 209, 3,
            ];
            let x = [
                241, 250, 184, 87, 167, 198, 131, 217, 47, 151, 247, 42, 139, 44, 27, 46, 227, 157,
                35, 46, 215, 150, 10, 236, 127, 16, 142, 203, 182, 135, 242, 203, 243, 219, 210,
                228, 68, 226, 135, 113, 103, 156, 13, 125, 236, 30, 50, 85, 116, 112, 221, 90, 99,
                197, 166, 167, 75, 140, 23, 140, 225, 186, 188, 116, 10, 59, 9, 145, 252, 193, 138,
                60, 148, 23, 88, 37, 213, 11, 124, 170, 22, 155, 13, 86, 84, 167, 182, 185, 59,
                215, 9, 101, 166, 218, 167, 180, 85, 238, 121, 226, 60, 99, 244, 94, 6, 47, 189,
                187, 132, 52, 37, 171, 40, 11, 159, 54, 0, 85, 196, 198, 11, 168, 68, 50, 135, 88,
                174, 37, 226, 249, 208, 26, 224, 55, 18, 65, 152, 215, 67, 57, 128, 226, 201, 13,
                45, 193, 25, 30, 39, 155, 170, 54, 53, 57, 73, 72, 18, 134, 34, 223, 24, 6, 198,
                224, 191, 23, 53, 230, 137, 1, 184, 167, 147, 217, 203, 119, 105, 100, 19, 161,
                209, 67, 192, 50, 31, 163, 108, 161, 163, 42, 11, 167, 24, 37, 163, 23, 51, 180,
                57, 81, 179, 163, 177, 150, 61, 23, 86, 112, 149, 38, 57, 127, 175, 214, 34, 94,
                206, 91, 129, 84, 179, 45, 106, 198, 26, 6, 213, 217, 217, 71, 232, 51, 85, 106, 6,
                220, 10, 78, 252, 221, 124, 23, 192, 247, 186, 93, 190, 89, 222, 57, 186, 228, 5,
                103, 88, 144, 54, 68, 190, 154, 231, 192, 228, 156, 254, 182, 145, 101, 224, 19,
                174, 125, 54, 41, 6, 254, 215, 86, 143, 110, 102, 102, 214, 229, 39, 184, 230, 183,
                220, 190, 193, 8, 26, 246, 76, 248, 100, 253, 211, 109, 108, 137, 52, 87, 88, 53,
                87, 154, 76, 204, 101, 215, 166, 231, 226, 65, 155, 149, 74, 171, 157, 82, 238,
                228, 244, 103, 203, 243, 75, 221, 193, 215, 186, 144, 67, 151, 5, 174, 208, 182,
                22, 195, 177, 197, 180, 177, 202, 144, 94, 109, 204, 3, 118, 42, 109, 131, 132,
                153, 125, 156, 34, 18, 128, 113, 176, 42, 240, 51, 173, 116, 185, 67, 229, 11, 53,
                237, 113, 79, 166, 83, 70, 87, 83, 182, 134, 155, 206, 42, 13, 190, 19, 169, 71,
                79, 33, 112, 204, 133, 147, 135, 243, 0, 90, 105, 191, 5, 154, 124, 50, 157, 209,
                55, 254, 97, 182, 112, 86, 107, 176, 2, 46, 11, 93, 205, 91, 146, 132, 202, 84,
                196, 222, 54, 223, 182, 158, 96, 66, 248, 177, 68, 203, 168, 166, 230, 105, 215,
                27, 75, 250, 125, 183, 10, 225, 35, 91, 250, 239, 63, 136, 87, 133, 192, 93, 122,
                47, 187, 224, 158, 91, 98, 70, 36, 230, 124, 189, 55, 198, 157, 53, 140, 103, 170,
                240, 100, 55, 41, 34, 221, 122, 66, 123, 249, 127, 15, 140, 198, 215, 70, 228, 206,
                186, 195, 4, 220, 116, 198, 105, 148, 180, 170, 148, 116,
            ];

            let expected = [
                57, 19, 91, 31, 121, 43, 175, 236, 30, 7, 247, 16, 69, 126, 137, 153, 113, 234, 23,
                97, 150, 124, 223, 248, 115, 179, 95, 64, 213, 230, 124, 203, 217, 56, 219, 160,
                56, 132, 249, 133, 214, 67, 197, 155, 191, 40, 151, 201, 159, 212, 144, 214, 71,
                146, 35, 223, 132, 164, 58, 22, 211, 23, 198, 155, 6, 152, 106, 65, 18, 81, 242,
                37, 252, 95, 118, 37, 65, 153, 138, 204, 143, 110, 17, 149, 12, 181, 31, 56, 173,
                194, 11, 65, 23, 10, 190, 66, 126, 4, 180, 53, 80, 65, 81, 140, 226, 22, 50, 16,
                182, 110, 126, 152, 180, 34, 60, 0, 19, 89, 211, 20, 199, 102, 60, 51, 106, 172,
                255, 153, 227, 230, 107, 180, 3, 181, 112, 128, 87, 67, 252, 193, 97, 171, 40, 115,
                8, 228, 234, 132, 33, 140, 206, 109, 98, 92, 221, 145, 164, 32, 190, 163, 23, 102,
                177, 230, 109, 207, 143, 42, 83, 119, 60, 13, 225, 155, 93, 147, 2, 163, 242, 241,
                41, 206, 124, 10, 150, 68, 57, 173, 120, 181, 81, 235, 237, 200, 27, 43, 118, 174,
                171, 238, 143, 242, 198, 247, 247, 114, 93, 187, 75, 165, 107, 88, 15, 245, 112,
                141, 204, 143, 46, 173, 190, 35, 190, 71, 126, 60, 61, 104, 62, 34, 71, 136, 236,
                67, 99, 112, 67, 145, 97, 15, 96, 18, 134, 192, 51, 62, 242, 195, 35, 85, 225, 155,
                139, 245, 129, 74, 86, 56, 18, 147, 222, 210, 152, 228, 252, 47, 227, 165, 109,
                106, 107, 163, 181, 34, 44, 226, 205, 34, 24, 99, 104, 226, 47, 70, 188, 9, 201,
                162, 100, 147, 24, 117, 134, 197, 169, 141, 211, 46, 77, 141, 158, 10, 126, 83,
                187, 199, 111, 227, 211, 154, 34, 14, 128, 200, 197, 76, 12, 230, 30, 24, 58, 74,
                116, 125, 80, 220, 174, 62, 204, 98, 242, 181, 67, 222, 84, 111, 35, 45, 236, 214,
                143, 204, 65, 47, 187, 8, 236, 100, 47, 32, 28, 171, 35, 14, 35, 96, 16, 6, 177,
                177, 147, 174, 180, 174, 62, 164, 232, 189, 144, 191, 209, 253, 85, 40, 205, 138,
                90, 53, 246, 29, 136, 145, 212, 151, 13, 13, 118, 73, 229, 134, 115, 103, 233, 93,
                82, 173, 51, 9, 183, 98, 70, 89, 40, 154, 252, 136, 206, 247, 190, 49, 64, 87, 236,
                209, 65, 10, 37, 0, 28, 8, 155, 45, 243, 53, 199, 96, 112, 25, 234, 128, 199, 95,
                172, 41, 141, 217, 151, 15, 124, 96, 18, 59, 33, 251, 34, 138, 60, 139, 137, 181,
                50, 111, 95, 247, 22, 110, 172, 112, 224, 130, 202, 215, 119, 211, 86, 59, 235,
                150, 55, 16, 193, 77, 240, 73, 101, 184, 57, 92, 0, 230, 186, 103, 43, 155, 225,
                210, 152, 28, 120, 138, 185, 242, 198, 18, 74, 140, 245, 130, 112, 217, 148, 129,
                224, 142, 214, 25, 81, 9, 42, 248, 39, 148,
            ];
            let mut actual = [0u8; 512];
            derive_key(&p, &s, passes, mem, Some(&k), Some(&x), &mut actual).unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }
    }
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
    use super::*;

    mod test_initial_hash {
        use super::*;

        #[test]
        fn initial_hash_test_1() {
            let hlen = 3496473570;
            let kib = 113001741;
            let passes = 172774226;
            let p = [
                225, 168, 40, 211, 31, 67, 71, 99, 229, 168, 106, 43, 101, 94, 51, 219, 193, 88,
                66, 234, 43, 144, 40, 25, 24, 168, 113, 144, 211, 83, 61, 103,
            ];
            let s = [
                123, 165, 225, 133, 80, 117, 28, 160, 138, 80, 59, 206, 190, 36, 171, 53, 127, 145,
                92, 208, 96, 218, 248, 198, 48, 23, 84, 226, 55, 30, 3, 81,
            ];
            let k = [
                235, 154, 1, 51, 161, 180, 78, 36, 109, 83, 83, 163, 59, 225, 74, 104, 79, 58, 127,
                252, 144, 52, 231, 101, 224, 139, 52, 181, 171, 154, 43, 215,
            ];
            let x = [
                236, 219, 129, 50, 196, 196, 170, 157, 179, 88, 71, 155, 243, 42, 69, 108, 238,
                251, 242, 152, 38, 90, 120, 148, 236, 215, 166, 155, 49, 32, 64, 183,
            ];

            let expected = [
                157, 152, 47, 97, 226, 116, 212, 144, 157, 93, 122, 3, 239, 211, 157, 66, 20, 33,
                133, 93, 0, 4, 53, 86, 167, 67, 88, 98, 125, 11, 137, 122, 142, 17, 16, 84, 146,
                17, 49, 11, 228, 22, 128, 161, 57, 188, 136, 75, 96, 197, 3, 206, 224, 204, 65,
                149, 190, 101, 231, 161, 232, 35, 87, 64, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let actual = initial_hash(hlen, kib, passes, &p, &s, &k, &x).unwrap();
            assert_eq!(expected.as_ref(), actual.as_ref());
        }

        #[test]
        fn initial_hash_test_2() {
            let hlen = 1360327050;
            let kib = 266855870;
            let passes = 263947785;
            let p = [
                62, 145, 210, 51, 41, 168, 197, 154, 64, 67, 181, 144, 73, 11, 90, 166, 13, 111,
                86, 19, 81, 103, 83, 26, 140, 110, 143, 91, 235, 175, 58, 220, 123, 172, 214, 144,
                96, 251, 34, 63, 205, 120, 252, 224, 127, 254, 117, 205, 251, 191, 5, 118, 112,
                219, 91, 16, 184, 80, 197, 229, 23, 239, 138, 200,
            ];
            let s = [
                229, 128, 59, 80, 127, 134, 112, 194, 29, 49, 206, 111, 254, 195, 72, 98, 51, 39,
                50, 55, 55, 47, 68, 231, 82, 91, 229, 226, 244, 102, 59, 32, 184, 171, 121, 57, 3,
                17, 155, 176, 102, 49, 168, 247, 225, 227, 144, 26, 15, 0, 233, 123, 199, 73, 73,
                150, 137, 140, 175, 219, 91, 4, 219, 129,
            ];
            let k = [
                230, 122, 163, 153, 60, 26, 74, 62, 99, 255, 192, 203, 137, 28, 66, 180, 48, 149,
                160, 238, 39, 236, 220, 231, 11, 133, 212, 190, 162, 126, 166, 173,
            ];
            let x = [
                76, 234, 237, 208, 211, 225, 108, 104, 95, 239, 241, 60, 218, 47, 169, 88, 111,
                253, 169, 144, 188, 39, 47, 249, 196, 104, 215, 24, 167, 126, 250, 143, 174, 175,
                167, 159, 115, 77, 127, 219, 142, 76, 37, 104, 64, 174, 241, 190, 204, 160, 149,
                122, 142, 40, 42, 235, 47, 173, 11, 59, 45, 8, 133, 143,
            ];

            let expected = [
                75, 173, 222, 46, 97, 96, 90, 145, 123, 113, 146, 135, 56, 148, 100, 59, 28, 233,
                228, 56, 215, 15, 138, 5, 90, 30, 128, 111, 131, 160, 92, 32, 97, 76, 216, 81, 134,
                15, 239, 64, 239, 203, 191, 226, 71, 213, 149, 238, 65, 124, 102, 1, 150, 230, 41,
                132, 23, 176, 221, 217, 237, 150, 154, 249, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let actual = initial_hash(hlen, kib, passes, &p, &s, &k, &x).unwrap();
            assert_eq!(expected.as_ref(), actual.as_ref());
        }

        #[test]
        fn initial_hash_test_3() {
            let hlen = 710460332;
            let kib = 75212384;
            let passes = 113373009;
            let p = [
                168, 246, 172, 189, 26, 25, 31, 227, 200, 19, 116, 185, 146, 217, 171, 125, 243,
                174, 179, 205, 67, 207, 224, 58, 252, 44, 132, 238, 174, 187, 196, 87, 75, 2, 130,
                86, 210, 179, 68, 75, 245, 217, 253, 148, 43, 88, 95, 4, 28, 124, 121, 203, 234,
                191, 91, 36, 69, 97, 241, 15, 2, 96, 46, 144, 136, 221, 112, 40, 120, 177, 41, 176,
                201, 2, 21, 217, 40, 94, 247, 62, 75, 68, 105, 41, 89, 211, 228, 254, 159, 194,
                175, 181, 134, 15, 249, 230, 169, 62, 237, 134, 45, 16, 180, 228, 171, 220, 129,
                254, 73, 175, 56, 51, 219, 122, 237, 223, 110, 172, 144, 220, 174, 241, 138, 155,
                204, 39, 183, 156,
            ];
            let s = [
                36, 185, 70, 134, 9, 131, 213, 227, 104, 174, 196, 186, 87, 63, 161, 245, 169, 29,
                72, 60, 248, 48, 0, 27, 179, 15, 177, 233, 121, 31, 13, 19, 103, 106, 105, 187,
                243, 50, 218, 0, 214, 73, 157, 103, 160, 229, 125, 160, 213, 199, 121, 21, 153, 34,
                73, 115, 232, 217, 223, 76, 189, 187, 123, 136, 128, 127, 123, 37, 188, 216, 194,
                184, 212, 137, 197, 19, 101, 25, 141, 7, 7, 85, 192, 179, 136, 244, 104, 84, 142,
                72, 22, 162, 101, 54, 5, 106, 29, 22, 177, 47, 141, 112, 136, 153, 89, 125, 97, 25,
                203, 169, 236, 24, 27, 144, 224, 147, 125, 1, 22, 191, 120, 13, 191, 76, 63, 18,
                238, 148,
            ];
            let k = [
                243, 70, 162, 106, 101, 169, 16, 249, 31, 59, 234, 10, 196, 82, 36, 84, 153, 233,
                22, 14, 198, 100, 178, 225, 157, 177, 233, 83, 27, 133, 114, 254,
            ];
            let x = [
                156, 6, 232, 138, 61, 133, 190, 151, 160, 41, 167, 51, 218, 112, 90, 97, 32, 238,
                123, 89, 149, 121, 166, 50, 186, 121, 189, 128, 157, 235, 134, 168, 14, 193, 154,
                215, 246, 8, 104, 94, 179, 239, 93, 17, 78, 184, 192, 166, 158, 222, 175, 235, 201,
                9, 117, 81, 127, 101, 75, 124, 44, 112, 211, 224, 221, 243, 130, 33, 68, 216, 191,
                127, 61, 180, 118, 25, 233, 51, 241, 68, 92, 159, 49, 95, 146, 142, 65, 93, 113,
                97, 80, 237, 242, 15, 15, 162, 67, 84, 108, 168, 165, 20, 230, 119, 19, 90, 13, 30,
                93, 152, 103, 90, 218, 174, 147, 32, 255, 33, 15, 28, 11, 232, 126, 184, 183, 222,
                6, 111,
            ];

            let expected = [
                201, 203, 51, 82, 36, 53, 35, 146, 170, 88, 139, 252, 221, 33, 198, 174, 96, 86,
                241, 236, 112, 62, 172, 141, 168, 39, 134, 110, 91, 103, 141, 136, 207, 165, 236,
                236, 58, 237, 193, 139, 30, 191, 244, 2, 176, 123, 134, 44, 251, 101, 255, 220,
                218, 109, 249, 231, 200, 45, 232, 240, 155, 10, 93, 111, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let actual = initial_hash(hlen, kib, passes, &p, &s, &k, &x).unwrap();
            assert_eq!(expected.as_ref(), actual.as_ref());
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_same_result(
            hlen: u32,
            kib: u32,
            passes: u32,
            p: Vec<u8>,
            s: Vec<u8>,
            k: Vec<u8>,
            x: Vec<u8>,
        ) -> bool {
            let first = initial_hash(hlen, kib, passes, &p, &s, &k, &x).unwrap();
            let second = initial_hash(hlen, kib, passes, &p, &s, &k, &x).unwrap();

            first.as_ref() == second.as_ref()
        }
    }

    mod test_extended_hash {
        use super::*;

        #[test]
        fn err_on_empty_dst() {
            let mut out = [0u8; 0];
            let input = [255u8; 256];

            assert!(extended_hash(&input, &mut out).is_err());
        }

        #[test]
        fn extended_hash_test_1() {
            let mut out = [
                49, 22, 190, 96, 55, 242, 247, 115, 242, 1, 96, 161, 138, 72, 108, 211, 135, 164,
                123, 9, 199, 223, 163, 248, 176, 81, 208, 255, 71, 67, 29, 215,
            ];
            let input = [
                33, 25, 138, 88, 116, 24, 7, 244, 116, 129, 14, 117, 135, 154, 207, 46, 65, 155,
                192, 39, 111, 117, 36, 109, 102, 49, 181, 172, 217, 21, 6, 201, 4, 229, 156, 175,
                201, 35, 84, 130, 195, 50, 97, 38, 137, 182, 162, 240, 16, 46, 202, 146, 2, 73,
                136, 4, 215, 200, 149, 252, 18, 47, 218, 17,
            ];
            let expected = [
                23, 122, 170, 179, 137, 61, 145, 86, 70, 228, 124, 82, 24, 135, 208, 96, 33, 127,
                145, 136, 189, 60, 123, 34, 55, 118, 245, 41, 197, 229, 209, 3,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[test]
        fn extended_hash_test_2() {
            let mut out = [
                241, 8, 207, 144, 211, 141, 215, 81, 145, 190, 184, 85, 99, 72, 157, 91, 32, 190,
                241, 192, 207, 205, 157, 119, 110, 28, 49, 117, 239, 220, 185, 246, 211, 188, 166,
                238, 223, 105, 163, 231, 21, 241, 70, 115, 155, 22, 160, 23, 242, 129, 144, 216,
                190, 110, 143, 221, 54, 4, 71, 239, 101, 95, 155, 196,
            ];
            let input = [
                66, 65, 147, 227, 144, 232, 121, 134, 153, 127, 210, 161, 10, 39, 254, 174, 144,
                104, 74, 63, 126, 53, 247, 145, 227, 229, 29, 255, 140, 246, 13, 65, 179, 149, 86,
                150, 216, 81, 178, 131, 136, 40, 139, 220, 43, 185, 119, 249, 161, 244, 0, 177,
                176, 139, 164, 135, 21, 68, 105, 204, 39, 107, 73, 47, 244, 228, 117, 203, 63, 82,
                81, 196, 135, 192, 148, 245, 77, 174, 184, 84, 150, 56, 11, 183, 234, 245, 88, 182,
                248, 223, 124, 252, 170, 111, 9, 48, 22, 227, 18, 118, 136, 22, 250, 22, 108, 229,
                176, 186, 19, 45, 67, 105, 19, 45, 94, 113, 16, 116, 215, 188, 91, 105, 36, 18, 77,
                235, 195, 113,
            ];
            let expected = [
                33, 81, 20, 93, 250, 207, 85, 11, 227, 90, 81, 170, 97, 236, 60, 207, 156, 65, 52,
                186, 53, 114, 252, 33, 118, 184, 12, 21, 239, 186, 19, 84, 98, 59, 219, 146, 117,
                222, 212, 217, 233, 173, 84, 38, 188, 102, 165, 73, 137, 64, 18, 214, 51, 167, 180,
                113, 50, 196, 175, 138, 96, 109, 95, 61,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[test]
        fn extended_hash_test_3() {
            let mut out = [
                70, 156, 46, 182, 87, 221, 0, 156, 124, 47, 167, 94, 57, 77, 222, 142, 130, 234,
                218, 139, 119, 27, 170, 129, 232, 219, 152, 79, 7, 237, 81, 3, 203, 33, 116, 167,
                159, 232, 31, 143, 142, 217, 118, 158, 40, 42, 42, 131, 249, 99, 63, 136, 182, 122,
                161, 8, 77, 7, 243, 7, 152, 54, 211, 102, 158, 7, 238, 103, 203, 249, 40, 204, 13,
                246, 0, 169, 235, 154, 14, 86, 4, 183, 145, 233, 248, 125, 155, 22, 8, 207, 80, 40,
                159, 55, 207, 151, 248, 170, 101, 233, 3, 68, 253, 88, 77, 164, 182, 211, 154, 101,
                210, 199, 58, 98, 110, 127, 189, 180, 158, 38, 30, 97, 124, 55, 82, 39, 183, 115,
            ];
            let input = [
                103, 132, 147, 55, 198, 201, 33, 151, 217, 248, 118, 190, 164, 159, 224, 197, 172,
                89, 93, 146, 170, 143, 72, 88, 75, 13, 41, 237, 20, 77, 117, 54, 100, 76, 198, 85,
                222, 182, 69, 119, 55, 251, 165, 141, 16, 105, 157, 25, 14, 70, 182, 131, 95, 21,
                156, 64, 3, 133, 179, 66, 9, 33, 181, 158, 165, 212, 142, 86, 22, 236, 235, 17,
                243, 34, 13, 109, 56, 111, 63, 75, 217, 153, 60, 159, 172, 233, 145, 142, 181, 136,
                210, 174, 187, 55, 153, 214, 105, 233, 196, 69, 64, 0, 59, 25, 21, 27, 233, 87,
                119, 31, 184, 15, 160, 55, 228, 132, 41, 110, 255, 79, 90, 141, 183, 156, 251, 89,
                90, 151, 199, 149, 220, 31, 85, 85, 87, 253, 79, 97, 18, 125, 251, 227, 120, 236,
                196, 203, 135, 195, 194, 160, 129, 89, 40, 111, 160, 222, 101, 149, 109, 153, 90,
                156, 220, 219, 89, 128, 8, 17, 104, 108, 145, 233, 121, 100, 124, 151, 96, 39, 187,
                132, 173, 9, 74, 154, 199, 126, 104, 241, 198, 190, 148, 221, 29, 50, 234, 19, 75,
                139, 135, 34, 247, 247, 226, 245, 142, 140, 152, 53, 210, 65, 174, 168, 70, 41, 13,
                11, 108, 29, 2, 93, 24, 156, 209, 159, 123, 80, 76, 111, 245, 39, 81, 252, 114, 82,
                175, 107, 42, 34, 131, 221, 209, 23, 231, 174, 242, 10, 17, 77, 251, 138, 239, 213,
                157, 197, 87, 96,
            ];
            let expected = [
                247, 38, 177, 59, 225, 220, 244, 197, 13, 169, 51, 184, 170, 167, 18, 78, 77, 196,
                23, 182, 207, 227, 211, 203, 66, 202, 238, 18, 72, 7, 110, 92, 162, 84, 125, 185,
                132, 129, 210, 217, 217, 93, 17, 93, 58, 18, 31, 165, 3, 194, 111, 223, 231, 8,
                120, 102, 201, 76, 149, 253, 233, 246, 199, 21, 157, 107, 186, 47, 123, 209, 94,
                151, 56, 53, 33, 8, 116, 26, 58, 53, 255, 51, 184, 18, 241, 179, 54, 15, 181, 18,
                117, 48, 83, 190, 250, 39, 126, 145, 178, 150, 185, 87, 172, 5, 176, 110, 227, 142,
                233, 63, 85, 225, 162, 85, 179, 166, 250, 222, 5, 10, 139, 187, 172, 105, 171, 171,
                140, 253,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[test]
        fn extended_hash_test_4() {
            let mut out = [
                231, 57, 92, 140, 212, 20, 239, 34, 56, 165, 207, 203, 237, 63, 103, 245, 135, 137,
                173, 240, 171, 105, 161, 221, 2, 15, 36, 47, 166, 126, 151, 21, 223, 34, 8, 141,
                193, 50, 70, 138, 65, 197, 165, 167, 25, 207, 114, 124, 147, 80, 192, 179, 171, 18,
                58, 180, 3, 79, 233, 231, 156, 157, 106, 2,
            ];
            let input = [
                213, 96, 143, 63, 224, 241, 183, 146, 44, 45, 66, 96, 200, 213, 151, 108, 41, 142,
                193, 159, 45, 198, 28, 146, 65, 13, 39, 36, 153, 46, 225, 14,
            ];
            let expected = [
                174, 131, 211, 180, 105, 12, 67, 55, 16, 72, 125, 125, 211, 93, 64, 180, 179, 188,
                77, 113, 119, 181, 98, 54, 13, 146, 57, 92, 43, 232, 224, 183, 219, 138, 143, 234,
                232, 151, 33, 76, 158, 96, 170, 104, 200, 127, 55, 239, 145, 241, 224, 146, 0, 11,
                64, 16, 212, 151, 227, 7, 65, 234, 92, 45,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[test]
        fn extended_hash_test_5() {
            let mut out = [
                53, 56, 9, 207, 79, 196, 6, 94, 170, 197, 204, 233, 69, 124, 20, 228, 227, 59, 102,
                30, 88, 45, 245, 144, 69, 50, 72, 163, 31, 100, 44, 12, 203, 9, 253, 13, 253, 221,
                216, 186, 92, 164, 37, 55, 195, 31, 13, 39, 110, 180, 40, 167, 40, 236, 138, 203,
                123, 174, 121, 219, 133, 211, 184, 133, 255, 239, 233, 193, 203, 90, 48, 59, 95,
                111, 55, 11, 95, 147, 178, 164, 241, 231, 109, 21, 16, 161, 192, 86, 156, 138, 137,
                224, 139, 52, 142, 192, 189, 231, 170, 54, 55, 150, 12, 122, 51, 250, 167, 127, 5,
                204, 63, 34, 71, 221, 162, 35, 33, 246, 22, 187, 187, 2, 41, 223, 81, 143, 231, 77,
            ];
            let input = [
                92, 110, 199, 162, 60, 226, 227, 26, 123, 30, 136, 146, 116, 38, 44, 194, 254, 14,
                137, 67, 183, 2, 112, 194, 30, 15, 100, 215, 248, 47, 223, 93, 156, 71, 98, 247,
                54, 74, 92, 233, 219, 165, 1, 45, 162, 225, 7, 80, 237, 172, 245, 25, 80, 162, 216,
                83, 35, 122, 156, 143, 55, 19, 5, 26,
            ];
            let expected = [
                253, 153, 55, 223, 21, 172, 36, 50, 109, 171, 45, 24, 40, 215, 239, 116, 92, 149,
                31, 40, 17, 99, 42, 25, 114, 52, 167, 230, 63, 36, 226, 178, 222, 163, 247, 175,
                100, 118, 54, 51, 223, 11, 164, 68, 126, 157, 94, 255, 196, 53, 177, 231, 81, 55,
                1, 250, 85, 91, 89, 45, 15, 121, 66, 157, 195, 162, 97, 243, 33, 195, 149, 253,
                193, 24, 150, 106, 234, 158, 122, 28, 52, 72, 48, 109, 206, 190, 116, 50, 163, 191,
                208, 86, 231, 170, 11, 210, 251, 135, 50, 46, 160, 202, 72, 101, 45, 24, 202, 72,
                210, 25, 239, 0, 229, 47, 200, 219, 202, 0, 39, 195, 197, 148, 15, 32, 211, 167,
                196, 128,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[test]
        fn extended_hash_test_6() {
            let mut out = [
                253, 1, 93, 186, 15, 159, 80, 7, 174, 85, 112, 241, 193, 170, 254, 103, 204, 254,
                154, 58, 228, 243, 244, 192, 223, 174, 103, 229, 21, 66, 203, 203, 221, 186, 76,
                40, 49, 66, 170, 52, 140, 254, 142, 95, 23, 200, 19, 117, 252, 9, 144, 94, 63, 14,
                66, 162, 168, 125, 112, 76, 45, 166, 241, 179, 54, 75, 107, 140, 92, 95, 211, 138,
                209, 143, 237, 130, 180, 19, 156, 242, 65, 22, 55, 228, 23, 106, 119, 14, 140, 66,
                188, 206, 107, 93, 130, 123, 6, 10, 85, 250, 177, 195, 46, 248, 177, 195, 86, 150,
                21, 10, 160, 108, 113, 75, 253, 51, 12, 173, 254, 71, 236, 160, 176, 130, 71, 161,
                205, 146, 104, 63, 189, 90, 117, 110, 141, 16, 18, 246, 158, 71, 201, 242, 53, 169,
                5, 3, 91, 227, 157, 11, 127, 150, 180, 200, 73, 27, 2, 78, 209, 89, 93, 78, 2, 136,
                70, 46, 65, 181, 217, 158, 54, 143, 135, 229, 217, 239, 22, 175, 156, 176, 111, 54,
                141, 230, 133, 232, 137, 100, 81, 147, 71, 176, 113, 125, 88, 48, 170, 19, 156,
                184, 91, 166, 195, 251, 143, 253, 135, 107, 215, 209, 224, 40, 96, 56, 222, 118,
                247, 22, 0, 251, 215, 62, 179, 190, 112, 75, 79, 96, 148, 246, 46, 15, 91, 117,
                142, 221, 133, 155, 237, 126, 144, 104, 240, 124, 130, 222, 19, 93, 87, 120, 83,
                117, 77, 75, 105, 104,
            ];
            let input = [
                89, 106, 243, 203, 190, 196, 239, 41, 217, 53, 96, 178, 255, 156, 212, 103, 117,
                255, 25, 219, 215, 212, 74, 47, 227, 67, 151, 151, 241, 100, 32, 178, 197, 211, 63,
                206, 247, 215, 141, 236, 41, 248, 232, 241, 106, 178, 52, 133, 83, 177, 65, 177,
                253, 118, 157, 226, 225, 137, 134, 127, 231, 48, 46, 156, 51, 224, 102, 94, 205,
                30, 222, 59, 173, 243, 205, 117, 78, 112, 160, 35, 66, 220, 113, 146, 100, 194, 56,
                85, 28, 75, 57, 59, 243, 201, 250, 140, 147, 24, 253, 84, 135, 91, 221, 190, 128,
                225, 118, 27, 74, 251, 27, 182, 254, 122, 44, 48, 222, 131, 32, 176, 254, 250, 200,
                2, 38, 202, 255, 207,
            ];
            let expected = [
                22, 21, 67, 184, 94, 20, 98, 6, 113, 81, 65, 110, 70, 42, 13, 58, 26, 213, 184,
                242, 234, 133, 185, 122, 112, 235, 18, 11, 94, 199, 64, 107, 116, 55, 49, 85, 178,
                118, 146, 51, 230, 150, 214, 229, 90, 162, 178, 225, 106, 138, 169, 206, 77, 161,
                112, 162, 86, 101, 48, 90, 227, 247, 147, 186, 120, 84, 101, 196, 141, 213, 215,
                115, 201, 150, 35, 182, 156, 243, 87, 242, 165, 45, 128, 127, 70, 51, 225, 40, 27,
                250, 173, 46, 109, 116, 254, 202, 206, 112, 48, 205, 21, 164, 129, 192, 181, 119,
                195, 126, 38, 177, 107, 55, 149, 126, 227, 44, 254, 225, 104, 15, 236, 141, 233,
                110, 132, 133, 241, 17, 210, 26, 22, 175, 135, 199, 106, 200, 214, 45, 20, 83, 164,
                49, 202, 69, 203, 191, 21, 92, 101, 206, 109, 136, 144, 123, 108, 24, 121, 142, 77,
                91, 122, 248, 117, 85, 82, 181, 228, 192, 197, 111, 169, 161, 30, 12, 201, 127, 24,
                17, 185, 88, 4, 126, 83, 107, 76, 6, 6, 146, 205, 164, 202, 151, 11, 189, 205, 159,
                146, 245, 79, 13, 127, 23, 148, 219, 156, 104, 161, 201, 155, 81, 126, 57, 34, 201,
                118, 110, 163, 135, 194, 38, 9, 2, 205, 54, 192, 55, 214, 98, 23, 35, 70, 113, 120,
                68, 206, 127, 130, 174, 252, 254, 135, 37, 160, 144, 108, 29, 86, 108, 159, 148,
                221, 54, 153, 234, 194, 103,
            ];
            extended_hash(&input, &mut out).unwrap();
            assert_eq!(expected.as_ref(), out.as_ref());
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_same_result(input: Vec<u8>, out: Vec<u8>) -> bool {
            let mut first = out.clone();
            let mut second = out.clone();

            if out.is_empty() && extended_hash(&input, &mut first).is_err() {
                return true;
            }

            extended_hash(&input, &mut first).unwrap();
            extended_hash(&input, &mut second).unwrap();

            first == second
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_diff_result(input: Vec<u8>, out: Vec<u8>) -> bool {
            let mut first = out.clone();
            let mut second = out.clone();

            if out.is_empty() && extended_hash(&input, &mut first).is_err() {
                return true;
            }

            extended_hash(&input, &mut first).unwrap();
            extended_hash(&first, &mut second).unwrap();

            first != second
        }
    }

    mod test_gidx {
        use super::*;

        #[test]
        fn gidx_test() {
            let n_blocks = 4096;
            let segment_length = 1024;
            let passes = 3;

            let mut gidx = Gidx::new(n_blocks, passes, segment_length);
            let mut tmp_block = [0u64; 128];

            let offset = 2;
            let pass_n = 0;
            let segment_n = 0;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1022] = [
                0, 1, 0, 3, 2, 1, 6, 3, 7, 8, 10, 11, 11, 4, 14, 7, 16, 13, 6, 17, 5, 20, 11, 19,
                20, 2, 26, 26, 22, 21, 28, 19, 31, 18, 30, 35, 31, 33, 35, 31, 28, 35, 24, 43, 41,
                42, 44, 41, 36, 32, 38, 48, 43, 53, 51, 42, 4, 44, 17, 45, 53, 49, 38, 27, 7, 24,
                53, 59, 24, 45, 19, 38, 55, 49, 74, 60, 41, 44, 17, 60, 0, 78, 45, 32, 83, 10, 18,
                65, 60, 65, 84, 26, 1, 93, 48, 67, 68, 97, 30, 76, 68, 53, 75, 42, 83, 25, 106, 2,
                108, 101, 110, 61, 34, 94, 14, 92, 26, 69, 108, 51, 94, 69, 122, 123, 120, 94, 3,
                67, 125, 39, 97, 14, 37, 41, 112, 124, 18, 125, 96, 107, 134, 134, 69, 121, 139,
                112, 52, 98, 138, 71, 129, 134, 126, 152, 153, 150, 43, 109, 152, 159, 157, 61,
                146, 153, 47, 42, 166, 78, 30, 43, 132, 171, 121, 149, 119, 172, 115, 13, 132, 140,
                165, 45, 29, 142, 76, 78, 175, 187, 150, 120, 182, 153, 192, 188, 67, 191, 193,
                125, 127, 183, 57, 138, 186, 24, 89, 40, 56, 207, 196, 64, 62, 211, 195, 70, 184,
                87, 45, 198, 53, 181, 129, 62, 164, 142, 59, 223, 173, 142, 228, 82, 230, 136, 160,
                194, 203, 235, 155, 181, 216, 143, 139, 102, 210, 180, 198, 235, 93, 177, 149, 245,
                245, 177, 252, 253, 20, 198, 143, 216, 102, 181, 91, 259, 200, 263, 106, 240, 200,
                267, 229, 160, 57, 116, 71, 203, 274, 182, 13, 237, 241, 202, 85, 278, 269, 261,
                219, 56, 283, 186, 280, 215, 265, 195, 292, 137, 293, 294, 277, 224, 106, 285, 300,
                82, 302, 289, 234, 236, 300, 242, 277, 52, 214, 244, 304, 259, 179, 235, 316, 305,
                28, 230, 242, 313, 59, 159, 133, 86, 103, 171, 225, 300, 223, 291, 233, 325, 144,
                41, 164, 261, 206, 70, 213, 44, 339, 229, 154, 279, 338, 218, 348, 326, 288, 344,
                284, 329, 257, 345, 353, 199, 276, 359, 279, 349, 8, 363, 357, 3, 364, 360, 262,
                82, 322, 366, 183, 197, 244, 375, 165, 377, 79, 106, 222, 321, 299, 61, 264, 340,
                283, 66, 382, 47, 321, 162, 374, 385, 26, 242, 392, 276, 384, 296, 306, 77, 23,
                105, 381, 316, 248, 40, 405, 112, 410, 409, 141, 261, 149, 275, 267, 39, 80, 394,
                259, 310, 421, 68, 70, 283, 361, 398, 90, 308, 83, 220, 87, 228, 342, 70, 337, 437,
                284, 179, 440, 440, 308, 149, 421, 42, 86, 419, 33, 23, 390, 132, 389, 364, 433,
                52, 222, 342, 291, 423, 459, 191, 382, 118, 463, 164, 384, 358, 150, 455, 246, 432,
                456, 473, 161, 309, 117, 109, 341, 283, 441, 40, 470, 254, 484, 36, 482, 430, 488,
                101, 484, 344, 491, 425, 474, 357, 403, 481, 195, 454, 360, 501, 470, 170, 495,
                277, 377, 441, 399, 362, 19, 436, 482, 392, 514, 305, 495, 508, 170, 102, 276, 315,
                89, 380, 433, 460, 523, 527, 50, 422, 191, 162, 532, 525, 459, 368, 71, 492, 208,
                173, 38, 443, 417, 57, 460, 521, 199, 356, 428, 180, 550, 497, 487, 546, 148, 461,
                389, 535, 360, 420, 460, 552, 449, 290, 558, 360, 154, 424, 240, 45, 428, 392, 566,
                555, 559, 109, 5, 404, 576, 118, 206, 543, 349, 173, 513, 287, 586, 380, 311, 87,
                206, 358, 182, 526, 447, 404, 437, 271, 417, 3, 237, 439, 534, 602, 231, 595, 522,
                366, 544, 491, 520, 278, 604, 607, 595, 370, 604, 509, 602, 463, 163, 270, 615,
                123, 563, 566, 626, 611, 579, 629, 58, 436, 522, 338, 527, 451, 41, 549, 635, 431,
                640, 387, 613, 571, 12, 510, 527, 593, 648, 465, 484, 625, 325, 197, 651, 617, 429,
                218, 627, 490, 656, 640, 79, 203, 480, 655, 627, 648, 648, 665, 132, 291, 667, 620,
                296, 243, 574, 673, 609, 642, 680, 484, 669, 239, 461, 678, 422, 677, 227, 430,
                503, 468, 78, 503, 112, 563, 639, 477, 232, 649, 345, 679, 473, 448, 459, 577, 18,
                315, 692, 618, 534, 656, 709, 294, 400, 648, 242, 488, 706, 198, 404, 369, 304,
                699, 698, 394, 572, 493, 216, 725, 406, 723, 548, 580, 158, 450, 731, 735, 25, 694,
                426, 741, 256, 98, 407, 12, 558, 445, 566, 748, 596, 180, 663, 663, 170, 330, 636,
                686, 738, 656, 679, 89, 605, 484, 155, 599, 619, 629, 55, 683, 474, 316, 311, 474,
                50, 21, 599, 202, 711, 477, 719, 77, 782, 737, 688, 427, 712, 165, 212, 437, 716,
                718, 792, 486, 606, 751, 61, 708, 667, 677, 116, 17, 787, 591, 678, 494, 4, 675,
                148, 796, 747, 524, 434, 603, 674, 744, 715, 629, 72, 1, 748, 735, 542, 808, 688,
                197, 826, 387, 757, 810, 41, 366, 826, 688, 814, 483, 319, 210, 37, 803, 51, 671,
                396, 690, 268, 292, 823, 599, 258, 595, 748, 844, 610, 454, 689, 62, 796, 687, 853,
                465, 257, 404, 811, 367, 665, 724, 520, 319, 667, 353, 843, 761, 870, 694, 606,
                597, 98, 867, 275, 878, 407, 389, 811, 272, 745, 416, 46, 401, 875, 316, 808, 687,
                683, 589, 392, 589, 245, 759, 637, 889, 472, 746, 363, 337, 884, 726, 481, 827,
                764, 447, 409, 911, 69, 872, 660, 567, 752, 825, 320, 495, 447, 807, 454, 838, 870,
                66, 737, 805, 906, 350, 334, 849, 713, 277, 698, 930, 795, 930, 840, 670, 933, 707,
                873, 35, 731, 149, 667, 671, 208, 833, 110, 814, 113, 880, 506, 951, 255, 48, 956,
                816, 951, 138, 274, 528, 154, 592, 778, 906, 572, 621, 955, 751, 802, 964, 801,
                891, 410, 513, 969, 896, 971, 286, 647, 76, 582, 767, 983, 822, 262, 288, 79, 895,
                973, 891, 982, 965, 813, 721, 905, 771, 981, 954, 311, 68, 912, 671, 643, 1006, 16,
                259, 49, 1009, 1012, 828, 416, 1015, 878, 802, 213, 230, 567, 392,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 0;
            let segment_n = 1;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                63, 227, 849, 503, 967, 726, 979, 1023, 1025, 514, 762, 161, 674, 961, 1033, 1035,
                440, 387, 3, 622, 1041, 1030, 17, 773, 934, 469, 197, 1004, 1048, 908, 357, 827,
                537, 950, 1000, 1049, 334, 219, 1006, 758, 1059, 137, 722, 462, 401, 236, 216,
                1045, 227, 1010, 1072, 1062, 755, 771, 922, 648, 26, 59, 1048, 1078, 626, 1034,
                157, 167, 552, 835, 1087, 936, 1028, 339, 442, 303, 207, 1033, 411, 348, 672, 954,
                888, 491, 815, 937, 733, 1079, 275, 427, 1103, 148, 571, 1078, 1069, 1113, 492,
                889, 962, 733, 1117, 921, 474, 277, 934, 555, 1035, 172, 1053, 804, 1079, 708, 206,
                1044, 1125, 454, 1086, 686, 408, 1136, 335, 1001, 200, 671, 341, 1115, 1016, 1043,
                1088, 629, 782, 600, 793, 684, 1056, 671, 1040, 4, 1156, 1037, 1145, 694, 607, 804,
                1125, 127, 829, 858, 580, 782, 661, 377, 1098, 946, 913, 90, 1070, 1099, 1064, 790,
                846, 675, 1042, 724, 738, 682, 1033, 994, 997, 1111, 378, 934, 771, 629, 1120,
                1193, 1177, 33, 1183, 691, 346, 1016, 374, 475, 110, 1185, 966, 730, 1118, 1004,
                237, 347, 803, 50, 790, 1136, 797, 146, 1214, 1162, 655, 1192, 1180, 1219, 1171,
                428, 252, 552, 1221, 1164, 1223, 834, 369, 696, 1197, 1187, 483, 1179, 1236, 982,
                890, 1182, 1238, 745, 1215, 756, 1188, 1244, 1151, 712, 718, 1205, 1167, 799, 1211,
                1253, 86, 1163, 1155, 1095, 151, 255, 1160, 765, 1080, 555, 963, 150, 1197, 1189,
                945, 1154, 1268, 840, 392, 172, 1191, 1108, 1271, 1059, 768, 813, 719, 964, 824,
                577, 1205, 1077, 307, 1199, 1287, 1066, 244, 1177, 38, 1004, 1281, 1273, 518, 1077,
                1263, 1225, 1043, 1243, 1199, 1237, 17, 368, 1021, 1245, 971, 1303, 849, 808, 1312,
                1313, 1161, 1185, 1154, 1215, 1201, 1037, 1269, 324, 649, 1092, 812, 983, 1305,
                782, 1050, 1270, 1108, 1327, 1311, 503, 1135, 1045, 1326, 748, 458, 139, 685, 1146,
                1338, 1326, 334, 224, 1345, 809, 847, 678, 569, 1316, 1335, 1353, 1114, 353, 1241,
                1123, 524, 950, 298, 1058, 631, 1260, 1161, 1315, 1037, 473, 1291, 946, 911, 1187,
                33, 1372, 643, 962, 120, 1172, 341, 566, 986, 6, 888, 1118, 1322, 1054, 22, 865,
                352, 1208, 1336, 1124, 1143, 1065, 1392, 1183, 1307, 1375, 617, 1351, 139, 1383,
                1018, 1392, 1402, 1145, 471, 962, 562, 1409, 1374, 1210, 1297, 361, 1085, 1415,
                1347, 794, 87, 1073, 759, 1241, 519, 1154, 1259, 1293, 1383, 551, 409, 1429, 587,
                64, 1285, 1314, 1305, 1371, 1161, 1196, 572, 1136, 1430, 1141, 926, 1439, 1005,
                1088, 354, 574, 1044, 1002, 1285, 707, 1264, 1114, 695, 1449, 1273, 693, 362, 846,
                397, 401, 1462, 1089, 1352, 1344, 979, 152, 1303, 985, 398, 1106, 1320, 916, 680,
                1475, 1353, 1314, 578, 479, 1045, 1350, 930, 34, 1484, 1028, 131, 64, 1255, 808,
                1437, 1168, 1051, 658, 732, 1035, 1346, 199, 640, 1323, 300, 433, 730, 1503, 560,
                422, 1371, 729, 1450, 1163, 267, 1496, 1078, 467, 76, 1473, 1498, 1115, 65, 979,
                114, 551, 1482, 1166, 1509, 1469, 1526, 1440, 961, 1002, 1530, 1050, 1295, 1161,
                1299, 1332, 1038, 1263, 420, 1490, 1495, 578, 1308, 1057, 1105, 620, 965, 1281,
                789, 1100, 820, 98, 1508, 942, 176, 939, 515, 51, 997, 849, 1294, 663, 325, 405,
                1417, 1544, 1308, 1325, 1492, 790, 975, 1101, 1339, 1470, 1570, 1486, 1567, 1397,
                2, 809, 499, 1580, 1578, 1461, 867, 830, 713, 968, 1574, 1587, 136, 1410, 1, 1288,
                1186, 1222, 1029, 1326, 1590, 4, 4, 1560, 280, 385, 1462, 54, 1406, 1156, 1035,
                1608, 1126, 145, 157, 708, 241, 889, 1426, 1514, 1569, 1607, 1064, 1259, 73, 1560,
                412, 802, 623, 1578, 1624, 1617, 1265, 1002, 1383, 1479, 1235, 1499, 1326, 1556,
                616, 1567, 1611, 1627, 1611, 141, 394, 384, 1473, 1639, 1113, 549, 1544, 226, 337,
                567, 628, 1332, 1612, 1634, 1654, 8, 1016, 1172, 508, 1521, 1308, 245, 545, 1593,
                1650, 927, 1668, 1402, 421, 1438, 1024, 444, 1061, 1579, 1496, 1272, 887, 1314,
                1187, 276, 574, 472, 1457, 529, 1669, 282, 691, 1553, 1688, 1471, 1694, 1690, 1594,
                1675, 1690, 1047, 1632, 1438, 1697, 1649, 59, 1677, 1443, 1420, 1471, 1675, 418,
                259, 1085, 788, 339, 64, 987, 5, 1421, 1636, 361, 1312, 1564, 1359, 74, 1666, 653,
                1714, 1584, 1192, 341, 1471, 907, 1591, 582, 775, 1412, 1674, 505, 385, 1301, 1505,
                1299, 985, 31, 1713, 762, 1747, 1705, 1685, 917, 636, 105, 1528, 513, 881, 1414,
                1645, 1602, 1313, 1537, 1746, 1738, 1453, 1625, 1750, 552, 411, 227, 1228, 1615,
                288, 1542, 1709, 1277, 1649, 1776, 1327, 1743, 1769, 863, 242, 1005, 1748, 972,
                1332, 46, 1758, 1740, 1582, 1789, 361, 678, 250, 576, 587, 1313, 703, 663, 443,
                1754, 1422, 1561, 1800, 1034, 452, 1493, 753, 1701, 1408, 145, 60, 692, 1804, 1716,
                1749, 1778, 1516, 1176, 1736, 1224, 1750, 368, 429, 1818, 1564, 1789, 711, 1451,
                1590, 1641, 1574, 1313, 1833, 1363, 1115, 1812, 1828, 1530, 1444, 928, 1695, 1492,
                1566, 289, 1705, 1745, 591, 1664, 517, 1072, 1474, 1327, 1853, 1049, 278, 1828,
                1857, 1828, 1543, 482, 1861, 1368, 1610, 1493, 1827, 1610, 975, 1678, 873, 1868,
                1765, 1420, 974, 1037, 1244, 1816, 1873, 1625, 108, 1217, 1208, 1360, 63, 1644,
                1368, 1860, 1624, 1748, 1661, 1677, 1871, 1594, 1859, 1790, 341, 1896, 1866, 285,
                905, 1576, 1575, 232, 1828, 428, 1806, 1531, 872, 1610, 1045, 1910, 769, 1897,
                1186, 1854, 1887, 1857, 1861, 980, 1594, 1635, 1892, 722, 1515, 1842, 1139, 1026,
                1383, 1920, 1558, 1108, 1831, 1867, 1206, 1390, 1848, 1358, 861, 209, 1909, 1883,
                445, 974, 477, 1937, 1391, 1187, 1726, 1253, 47, 1027, 1886, 1760, 1157, 1546, 545,
                877, 1192, 1843, 748, 1561, 1481, 318, 1207, 1905, 733, 1879, 784, 768, 1881, 1450,
                348, 1881, 949, 1511, 1670, 1966, 492, 1748, 1061, 1612, 1399, 348, 1575, 1736,
                639, 1986, 1978, 90, 1318, 1559, 1960, 1073, 1886, 733, 284, 268, 1972, 1969, 1912,
                1992, 60, 1457, 1769, 1335, 1345, 1999, 1843, 1925, 1475, 1850, 2004, 1077, 970,
                553, 1921, 1676, 1443, 1995, 1975, 660, 1142, 2008, 1453, 933, 1983, 1195, 1906,
                645, 627, 1525, 1752, 1490, 1040, 1873, 632, 383, 1590, 1924, 165, 1961, 1543,
                1719, 1171, 1881, 2031,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 0;
            let segment_n = 2;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                1171, 1043, 2046, 209, 1914, 1872, 570, 1427, 931, 1485, 2024, 1760, 2049, 1955,
                1265, 1039, 1693, 578, 1665, 1457, 1513, 1283, 2023, 1956, 1744, 1659, 2032, 145,
                1887, 1633, 2040, 1456, 440, 2044, 2080, 1856, 947, 976, 2084, 2085, 1826, 1774,
                2015, 1858, 701, 830, 2065, 1609, 1680, 1502, 653, 554, 201, 1819, 2081, 1898, 561,
                287, 1942, 969, 1981, 1300, 177, 2021, 1968, 772, 475, 1996, 1533, 1846, 1933,
                2113, 2115, 2026, 2023, 838, 1863, 857, 1470, 2030, 1990, 1339, 1055, 2021, 511,
                1197, 1776, 1718, 209, 1759, 2054, 1010, 210, 2063, 1005, 1586, 2141, 2007, 1323,
                347, 19, 68, 1796, 1041, 2053, 912, 2144, 443, 1388, 2154, 2028, 2039, 1528, 2120,
                1314, 1868, 2159, 1655, 865, 1852, 939, 129, 2168, 797, 707, 338, 1918, 1965, 1541,
                1983, 1942, 1160, 2049, 2126, 1974, 2075, 1326, 1557, 1700, 1377, 1054, 1570, 1743,
                272, 1884, 1716, 2023, 549, 1984, 1510, 634, 2182, 901, 1773, 1428, 2187, 1703,
                1906, 2148, 1394, 790, 584, 331, 2174, 1573, 1347, 1555, 1867, 156, 2206, 912,
                1728, 1803, 1883, 1111, 2136, 2221, 2173, 216, 2206, 2215, 1979, 2217, 1439, 1403,
                1019, 2150, 1978, 1823, 1838, 1244, 1679, 1882, 1848, 1752, 2241, 53, 2097, 2212,
                736, 2230, 2111, 852, 1435, 1829, 2122, 59, 233, 221, 1739, 2212, 1647, 1663, 2204,
                1739, 1911, 143, 456, 2044, 1735, 1345, 2027, 2186, 69, 540, 971, 2022, 2050, 1291,
                1159, 71, 1582, 2096, 1370, 2171, 1631, 2260, 2210, 1905, 2057, 1708, 2195, 1333,
                2141, 1605, 2286, 2211, 2261, 1737, 1239, 2166, 1901, 1709, 2205, 2147, 1918, 2292,
                1851, 1339, 2154, 2144, 1027, 197, 1856, 1543, 919, 2076, 1613, 2012, 1100, 1862,
                2316, 1717, 1044, 1999, 2298, 2268, 2228, 1454, 1540, 2046, 1667, 1703, 945, 111,
                1982, 2324, 2271, 276, 1327, 602, 1538, 1946, 1976, 2244, 2136, 495, 2205, 2333,
                1846, 27, 2332, 1047, 2039, 2116, 1116, 1933, 593, 189, 2094, 74, 1020, 1362, 1069,
                2203, 1627, 2279, 2332, 468, 2177, 2364, 2086, 1078, 1594, 1539, 2285, 64, 511,
                1509, 2155, 323, 2202, 2235, 2350, 1590, 1624, 2320, 2243, 1261, 1460, 2128, 1523,
                494, 2186, 874, 749, 1586, 694, 2319, 1978, 1365, 2239, 1042, 2098, 70, 1940, 2343,
                2249, 2152, 2259, 1306, 436, 2294, 1027, 2235, 2391, 653, 1056, 2233, 1700, 1388,
                2346, 2391, 1215, 2395, 815, 650, 2118, 1831, 2392, 1157, 1297, 2192, 2337, 2265,
                2271, 1647, 960, 448, 1558, 1546, 289, 2130, 1831, 2283, 636, 2214, 2409, 2435,
                2242, 2209, 584, 1263, 1451, 1024, 1798, 2451, 1482, 124, 1506, 2455, 1119, 1933,
                2432, 1953, 2369, 2176, 1838, 77, 788, 1787, 1848, 1711, 2178, 156, 1449, 1395,
                2166, 2156, 2161, 1706, 1007, 1225, 2456, 2463, 2412, 1660, 2428, 1643, 1518, 2034,
                2421, 651, 1381, 2388, 1425, 2062, 849, 1994, 2495, 2013, 2100, 704, 830, 2499,
                2057, 1953, 2419, 214, 1358, 2135, 2498, 2362, 2450, 1182, 1733, 299, 2392, 2514,
                2213, 1901, 1301, 791, 1521, 586, 2521, 956, 2353, 1060, 811, 2163, 1398, 1111,
                1584, 2434, 1788, 350, 814, 659, 1248, 2244, 517, 2513, 2003, 2270, 1878, 463,
                2540, 2489, 2541, 776, 607, 1098, 2374, 2197, 2551, 1493, 1182, 364, 857, 2005,
                1803, 2099, 465, 2347, 681, 2254, 1172, 1411, 2443, 2562, 437, 2259, 1535, 2570,
                2203, 2557, 2568, 2560, 2152, 2324, 1339, 2396, 121, 1663, 1236, 1577, 2199, 2249,
                2581, 2092, 2573, 2586, 224, 2216, 1958, 779, 2586, 1972, 335, 2461, 2284, 1296,
                2162, 2579, 46, 2529, 1022, 2412, 1917, 1682, 1431, 59, 2592, 2468, 2472, 2384,
                812, 866, 250, 1290, 122, 2064, 1246, 2213, 2618, 1867, 1219, 2250, 1215, 1876,
                2368, 2503, 2349, 2251, 186, 2615, 1698, 2591, 2118, 391, 2610, 1786, 2272, 709,
                1776, 1466, 2488, 2480, 2462, 2375, 1893, 2637, 2606, 2215, 1787, 1472, 2626, 955,
                1964, 2144, 2213, 2645, 2515, 2642, 520, 2354, 967, 2360, 171, 2660, 1611, 2476,
                1221, 2290, 2662, 2654, 1093, 2016, 2535, 612, 2032, 1955, 1923, 2676, 1506, 443,
                2659, 970, 1344, 2677, 2680, 1686, 54, 2433, 2472, 2187, 2485, 1061, 2216, 2572,
                2437, 1379, 2185, 1732, 2111, 2498, 1279, 1467, 2611, 2068, 2138, 2024, 2243, 2241,
                2482, 907, 339, 693, 1879, 976, 2415, 2120, 530, 2412, 2693, 278, 783, 111, 486,
                1475, 2588, 2728, 2463, 1761, 2379, 2701, 2465, 2504, 2733, 1464, 797, 2114, 1956,
                2182, 1404, 1698, 2572, 1246, 2055, 1296, 729, 2143, 1161, 1502, 2140, 2079, 1862,
                1546, 2565, 2461, 2631, 1369, 2020, 2755, 2159, 2650, 1459, 2064, 1198, 2680, 2317,
                1491, 62, 2369, 547, 539, 2576, 1553, 2633, 1269, 1720, 2768, 1754, 2246, 2393,
                1421, 2775, 621, 5, 1070, 2749, 2484, 1639, 2097, 1077, 318, 2757, 2283, 242, 743,
                2558, 30, 2711, 1584, 462, 2800, 2802, 2756, 1353, 717, 2745, 733, 1277, 2691,
                1112, 1250, 1900, 1796, 2689, 2815, 2209, 526, 2778, 2224, 2808, 1510, 2799, 2743,
                1493, 1017, 464, 2504, 2799, 2205, 2670, 1549, 2497, 2568, 228, 2735, 784, 2591,
                2027, 2799, 2389, 956, 2725, 2815, 1983, 2647, 2671, 363, 2849, 2848, 578, 1952,
                1326, 2158, 2855, 1638, 817, 2846, 1035, 2406, 984, 2299, 1777, 2084, 958, 2386,
                2866, 975, 2866, 670, 939, 2865, 1445, 2811, 2501, 2865, 2734, 2393, 204, 2835,
                1991, 2868, 1001, 2881, 2495, 1318, 581, 292, 2879, 231, 2664, 1878, 2647, 2303,
                2753, 1605, 538, 2345, 2755, 2860, 2663, 2735, 189, 2570, 2087, 162, 72, 2446,
                1728, 1153, 2198, 1049, 2875, 745, 1313, 1114, 2692, 592, 820, 469, 872, 1207,
                2756, 150, 1494, 1912, 1753, 2567, 2477, 572, 2734, 817, 519, 2471, 962, 1247, 802,
                2931, 1552, 2845, 2801, 2891, 2550, 447, 2704, 879, 2909, 1159, 2739, 1542, 2190,
                1888, 2530, 2521, 2904, 1095, 2856, 434, 368, 285, 2810, 1488, 2962, 761, 1732,
                2410, 2934, 2856, 2376, 1431, 2683, 2902, 1533, 2851, 2337, 1746, 2944, 2701, 137,
                628, 2838, 2157, 2456, 2519, 2391, 559, 961, 2962, 2378, 2727, 2841, 2200, 2701,
                1966, 2210, 2996, 2654, 1583, 2875, 2890, 2923, 2135, 2743, 2672, 86, 2986, 2691,
                2984, 2699, 2869, 179, 2419, 1993, 1523, 1378, 2696, 2188, 1774, 2330, 2582, 1958,
                2541, 2903, 3004, 487, 793, 2820, 2438, 2131, 1846, 2751, 3007, 21, 2102, 2128,
                614, 794, 3034, 129, 2965, 2963, 2474, 2575, 2850, 2659, 3024, 2553, 1912, 3048,
                2991, 754, 1039, 1208, 2939, 1302, 1746, 2418, 1473, 3058, 2931, 3060, 2368, 37,
                3021, 1483, 2941, 2676, 422, 1775,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 0;
            let segment_n = 3;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                1994, 1933, 3035, 2492, 2197, 748, 349, 140, 1121, 3079, 2168, 1970, 2197, 2830,
                1473, 2995, 827, 3087, 2246, 3046, 46, 3067, 1420, 1484, 3062, 2612, 2122, 2360,
                3011, 1097, 1455, 2069, 2660, 3103, 574, 1665, 3086, 2750, 3101, 1391, 2770, 3013,
                1691, 2929, 2411, 1272, 1296, 811, 2499, 3064, 2675, 2926, 212, 399, 1439, 2894,
                2697, 1881, 2007, 2706, 3130, 3046, 1253, 1722, 2461, 3023, 3128, 2093, 2757, 897,
                3057, 1176, 2290, 1336, 3108, 3145, 1445, 2613, 3133, 2501, 1305, 1654, 851, 2608,
                2289, 1673, 1057, 1657, 140, 2399, 419, 2186, 3033, 3161, 3115, 2430, 2574, 1914,
                2974, 3134, 2458, 3073, 2879, 226, 2871, 2926, 1917, 3015, 3147, 3030, 2852, 1399,
                878, 1885, 3182, 217, 3110, 1513, 1933, 1628, 3169, 220, 1147, 3116, 3010, 438,
                2263, 2382, 2443, 440, 2907, 404, 2897, 68, 2020, 2815, 3096, 3169, 3144, 1401,
                3029, 1072, 33, 663, 890, 2932, 3200, 3096, 628, 1371, 3096, 1851, 1144, 365, 2097,
                2344, 974, 978, 2558, 135, 3055, 446, 1128, 2599, 1680, 255, 2191, 1603, 1025,
                1842, 2017, 517, 3210, 3170, 966, 790, 811, 2253, 2222, 1163, 1933, 2902, 762, 546,
                3219, 198, 1729, 1650, 3208, 1435, 2689, 1729, 3113, 2222, 3206, 2918, 584, 829,
                2437, 3113, 2805, 2742, 3172, 2823, 356, 716, 1895, 2369, 2268, 3255, 2981, 2733,
                903, 1945, 1593, 553, 32, 3105, 1759, 238, 1154, 2399, 2691, 480, 2571, 3285, 3211,
                959, 1936, 2767, 2697, 375, 2833, 3264, 2837, 3305, 2938, 3284, 1696, 801, 485,
                1911, 3282, 3221, 1002, 876, 18, 1589, 2416, 3304, 160, 3097, 1387, 3074, 3322,
                3012, 3209, 2100, 1419, 2621, 2667, 856, 1981, 1456, 1902, 1690, 1318, 2344, 620,
                1141, 2449, 3063, 2904, 2311, 2441, 2419, 1166, 1786, 3338, 563, 3266, 2275, 2559,
                3352, 3352, 2638, 1635, 1671, 2322, 2914, 3333, 2832, 2522, 3050, 2184, 3045, 1692,
                474, 293, 803, 3271, 3192, 1902, 3363, 3094, 221, 2809, 3030, 791, 2951, 1791,
                3242, 3202, 2124, 1579, 1782, 2476, 1695, 2817, 2673, 1016, 1265, 2231, 1911, 3335,
                228, 303, 1179, 1439, 1720, 3400, 2533, 2439, 3355, 2596, 3061, 119, 318, 2476,
                1347, 3194, 2759, 1670, 2601, 3399, 1707, 3046, 2575, 2810, 2234, 2321, 1292, 1207,
                3409, 2350, 3237, 2156, 3385, 3286, 2872, 2743, 1195, 1246, 972, 1649, 996, 3093,
                2833, 3340, 3171, 1957, 3304, 908, 3431, 819, 322, 3212, 3077, 1972, 2919, 2679,
                2408, 2521, 2940, 2055, 3429, 2653, 2908, 1868, 2689, 3100, 3389, 2094, 1810, 3278,
                2796, 2819, 3052, 2430, 2080, 3464, 3150, 2448, 3084, 60, 2216, 1493, 3163, 3335,
                2886, 914, 1603, 3429, 3468, 3226, 2832, 2990, 3471, 483, 2746, 3181, 943, 547,
                1556, 778, 2143, 2401, 2108, 586, 3425, 320, 2811, 3501, 3326, 1887, 3444, 876,
                1612, 664, 2896, 907, 3438, 2041, 1891, 954, 3231, 640, 734, 3458, 2878, 3408, 621,
                3011, 2434, 770, 2784, 760, 3226, 3505, 251, 3070, 2046, 95, 513, 2968, 3523, 3353,
                1673, 2599, 2740, 495, 3515, 1649, 3542, 3105, 3535, 2339, 2537, 2100, 732, 3512,
                2167, 3480, 3016, 1366, 868, 3386, 711, 1839, 3403, 3439, 2795, 3535, 1514, 1629,
                2180, 3228, 2149, 3422, 3485, 2052, 3482, 320, 3069, 1410, 1403, 1091, 3257, 3173,
                1376, 2807, 2799, 208, 1410, 1003, 1733, 695, 3398, 619, 3549, 1557, 3422, 190,
                1925, 2222, 2676, 3523, 3086, 2714, 3131, 1158, 993, 3381, 1871, 193, 3442, 671,
                3583, 2495, 3288, 3398, 2887, 3159, 1794, 2334, 3606, 3573, 2011, 1480, 2701, 2231,
                3613, 3588, 2949, 1926, 3005, 3621, 2029, 415, 2734, 43, 1361, 3358, 3574, 3398,
                3247, 3378, 632, 2396, 1477, 3174, 222, 1372, 1804, 3267, 1834, 2155, 360, 3350,
                2856, 2645, 3089, 23, 3508, 3648, 999, 3100, 2664, 3467, 1482, 3534, 2781, 3150,
                2638, 3191, 1524, 2977, 3125, 851, 1556, 2222, 3669, 1880, 722, 953, 1260, 3638,
                3533, 3430, 3478, 2298, 3458, 2906, 3654, 2653, 2603, 2776, 1028, 3002, 328, 2747,
                2779, 1072, 3184, 3554, 3374, 3156, 1384, 3100, 3346, 1729, 1349, 3615, 3697, 3535,
                2686, 3610, 2074, 230, 37, 1497, 3489, 3384, 1671, 2232, 1013, 1453, 3649, 1058,
                3243, 3550, 177, 96, 604, 821, 633, 3287, 3320, 2220, 413, 3709, 3326, 2402, 3294,
                2790, 2368, 1661, 3308, 2701, 3725, 3330, 1705, 2927, 1502, 1837, 1100, 3746, 654,
                3319, 218, 1922, 3680, 1232, 3597, 860, 2108, 2154, 1082, 1995, 3753, 3462, 2466,
                318, 1409, 3764, 2731, 3603, 2844, 3757, 2056, 2602, 3741, 1681, 800, 3723, 2870,
                3288, 2446, 2389, 3004, 3604, 3682, 3142, 3039, 3630, 1750, 1344, 3730, 1941, 2803,
                2550, 2626, 3777, 762, 497, 3359, 2122, 3429, 600, 826, 3588, 3500, 1739, 3711,
                3676, 3399, 3402, 3466, 2549, 2556, 2734, 1176, 3757, 470, 1921, 3746, 3799, 563,
                2833, 2446, 1317, 3522, 227, 3672, 3260, 3470, 3410, 1927, 2243, 3316, 2320, 635,
                2812, 1504, 3785, 3228, 304, 2769, 311, 3367, 3392, 3726, 3816, 2705, 2129, 2989,
                335, 3833, 405, 2941, 2889, 3733, 3023, 2587, 3210, 3233, 3673, 2309, 2814, 3251,
                3150, 3496, 3169, 2995, 2407, 3712, 360, 3826, 3247, 2686, 2504, 3338, 3642, 2022,
                3774, 3508, 3792, 2212, 3797, 3778, 3715, 2145, 2512, 3171, 1064, 2584, 3869, 3585,
                3851, 3735, 738, 3848, 3254, 3886, 3672, 1251, 3138, 3453, 3143, 3619, 908, 2126,
                1793, 2885, 3848, 1124, 371, 2480, 2259, 847, 2984, 1946, 2711, 895, 3895, 3913,
                606, 3555, 3842, 3282, 2123, 3518, 3750, 2224, 2785, 3325, 2308, 3635, 886, 3620,
                3155, 3829, 2319, 3874, 2562, 2655, 3836, 46, 314, 3848, 3751, 2409, 2931, 1999,
                2616, 3702, 109, 84, 1304, 1813, 3010, 3349, 3821, 3408, 3952, 3328, 3799, 2967,
                3035, 3648, 2474, 1687, 1279, 3947, 2466, 1357, 3900, 3549, 1002, 2750, 2986, 3379,
                1172, 3133, 534, 3210, 3414, 2426, 3883, 3862, 3752, 2932, 1354, 3897, 1874, 2831,
                2539, 2703, 758, 3975, 3144, 2367, 1233, 3797, 1662, 593, 3642, 2411, 2952, 337,
                2414, 3672, 3025, 2729, 1912, 2480, 3965, 3085, 3863, 1709, 3944, 1021, 542, 1782,
                1727, 3879, 2812, 3276, 4018, 3267, 3672, 1016, 3486, 3657, 3735, 516, 3565, 3432,
                2371, 2634, 2072, 551, 2391, 2460, 3462, 787, 4015, 1804, 2544, 3707, 3879, 2939,
                3612, 861, 2213, 3021, 3818, 3902, 3944, 4045, 3272, 1861, 747, 3224, 4054, 3263,
                1623, 2018, 1460, 2158, 1170, 88, 1537, 3542, 1722, 4012, 1630, 3058, 2203, 2610,
                4059, 3730, 2042, 1090, 199, 1907, 3848, 3983, 3810, 3603, 1068, 3985, 2454, 3950,
                1163, 1752, 3677, 1553, 2352, 3650, 1758, 1756, 3893, 3566,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 1;
            let segment_n = 0;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                3988, 3490, 1643, 1572, 2, 2045, 1188, 3185, 1866, 1635, 3419, 1196, 3779, 2875,
                2786, 3906, 3086, 2300, 3, 3715, 3942, 3921, 4060, 3970, 22, 4095, 23, 11, 2880, 1,
                3617, 3244, 3935, 3222, 2814, 1706, 3349, 3372, 34, 1984, 1488, 3332, 3582, 3950,
                2803, 3986, 2228, 3844, 1767, 3772, 43, 3307, 3131, 3811, 3437, 3530, 2226, 4093,
                3934, 3401, 2948, 59, 4067, 3888, 32, 1302, 3233, 3650, 2178, 2376, 3271, 4094,
                2467, 2975, 3512, 3452, 3074, 3034, 57, 2174, 2062, 4072, 3086, 3175, 3988, 1343,
                48, 3438, 3295, 87, 1844, 4004, 3389, 46, 2672, 3108, 3065, 2149, 3720, 4057, 84,
                2027, 2275, 2567, 1600, 2653, 1444, 2508, 63, 3744, 1255, 3175, 49, 2728, 3522, 34,
                3046, 3728, 115, 1199, 2500, 3337, 96, 108, 28, 3502, 1317, 3739, 3318, 112, 4079,
                2308, 2026, 1040, 121, 2328, 3084, 56, 4088, 2008, 2194, 116, 1140, 2896, 135, 132,
                144, 2501, 143, 147, 3817, 2696, 2858, 3652, 3507, 19, 2382, 3342, 3957, 2451,
                3434, 1282, 1549, 4005, 3990, 3881, 2381, 3239, 2745, 2168, 2493, 4073, 3910, 109,
                110, 2368, 3030, 3839, 3248, 3830, 3761, 46, 3449, 70, 156, 2833, 2515, 3655, 2023,
                39, 3344, 180, 2053, 1684, 2909, 2463, 3773, 3520, 3941, 197, 3686, 4025, 192,
                2798, 202, 3435, 2350, 3632, 3295, 1999, 153, 2793, 3683, 209, 152, 1262, 2850,
                1430, 4028, 3260, 2211, 1700, 3592, 1209, 3571, 2943, 90, 3266, 3022, 3878, 218,
                1718, 8, 1771, 229, 229, 2940, 2986, 2155, 2464, 2345, 102, 1974, 3434, 1860, 3667,
                119, 245, 2392, 152, 1126, 3593, 3527, 3949, 2743, 2701, 3953, 3002, 221, 3610,
                2928, 1918, 1094, 261, 262, 3229, 3836, 24, 3257, 3270, 1076, 5, 2958, 3003, 4039,
                148, 2097, 2706, 3959, 3262, 3022, 3132, 56, 6, 1700, 162, 2764, 3144, 1230, 1445,
                1070, 3603, 4004, 3432, 282, 1736, 2961, 1993, 3222, 2212, 3370, 291, 268, 1639,
                3939, 2905, 1712, 1069, 1272, 3834, 2070, 286, 3625, 279, 3301, 3454, 162, 305,
                227, 302, 3646, 313, 3865, 1087, 2241, 1663, 4019, 1606, 326, 2658, 3750, 2135,
                328, 235, 2500, 2800, 279, 2614, 2567, 58, 37, 4069, 47, 3206, 342, 188, 2918,
                3825, 3460, 1495, 3265, 4031, 2745, 2380, 165, 278, 3606, 1443, 3855, 315, 2342,
                359, 303, 3392, 362, 3452, 2982, 3839, 1608, 1459, 2650, 368, 1814, 2275, 3642,
                2952, 369, 3927, 3159, 1622, 360, 334, 3930, 3472, 138, 3185, 374, 222, 3100, 1798,
                2777, 1706, 2917, 2649, 2096, 266, 394, 1427, 3497, 1292, 2206, 392, 2694, 1707,
                3555, 3896, 3302, 1105, 406, 406, 2399, 2411, 3565, 3063, 3925, 3997, 3725, 1447,
                318, 3664, 416, 2251, 131, 2895, 2403, 1350, 1749, 16, 426, 4019, 3332, 4018, 411,
                280, 2228, 3016, 3934, 435, 1872, 3959, 2684, 342, 1162, 2587, 3788, 4026, 353,
                400, 339, 2291, 413, 4077, 184, 4033, 3671, 346, 4048, 1047, 3619, 166, 3494, 2644,
                279, 2239, 456, 442, 322, 3818, 161, 1896, 3253, 438, 3402, 3643, 3521, 3839, 2954,
                203, 3217, 1807, 452, 3231, 4003, 2726, 181, 3880, 3289, 1694, 446, 474, 427, 66,
                1619, 2430, 3377, 3705, 2047, 472, 369, 120, 494, 2756, 2091, 180, 10, 1508, 1795,
                3633, 144, 337, 4051, 502, 3416, 504, 436, 1117, 3587, 3623, 2741, 3494, 502, 2813,
                115, 3231, 2974, 2351, 2250, 4063, 515, 502, 3553, 199, 1882, 3927, 2514, 3087,
                2321, 450, 92, 1073, 2338, 2016, 2364, 1586, 1697, 1759, 1708, 3172, 1211, 407,
                163, 3202, 501, 1832, 3385, 545, 4057, 215, 65, 1148, 3082, 3788, 500, 310, 2162,
                446, 1207, 384, 2331, 3702, 3438, 2386, 2511, 2751, 2311, 4016, 4038, 565, 2123,
                4005, 3441, 413, 2705, 349, 570, 2292, 568, 1324, 1481, 3874, 550, 545, 582, 3371,
                215, 592, 3841, 2807, 3537, 524, 1897, 1714, 3159, 596, 364, 1889, 3933, 457, 1317,
                2543, 1213, 2658, 181, 444, 2997, 3926, 1768, 1966, 1384, 3599, 3968, 433, 304,
                2624, 3085, 606, 3968, 1620, 114, 244, 441, 2426, 34, 2765, 2370, 4076, 3540, 438,
                602, 2860, 1727, 3750, 3888, 3848, 1457, 1851, 3201, 3435, 1397, 240, 3450, 4032,
                210, 2774, 3939, 650, 437, 315, 1374, 2614, 181, 1900, 2323, 2730, 3691, 2968, 486,
                636, 2549, 2433, 204, 268, 139, 2891, 572, 659, 3636, 568, 3588, 673, 665, 571,
                1273, 656, 1522, 3774, 433, 1740, 1225, 3837, 3810, 203, 2764, 466, 2456, 548,
                3811, 658, 647, 553, 3606, 548, 673, 3231, 253, 135, 16, 156, 2521, 3477, 108,
                2448, 670, 1430, 346, 616, 3352, 1418, 248, 2283, 717, 3306, 2386, 480, 1873, 2910,
                724, 2143, 557, 3569, 386, 2504, 728, 2769, 727, 2801, 501, 90, 680, 3921, 1721,
                711, 560, 1235, 52, 1741, 2917, 1716, 585, 744, 604, 73, 571, 338, 2417, 127, 1412,
                4086, 120, 686, 2937, 1667, 2503, 491, 754, 3941, 2376, 762, 737, 259, 528, 3686,
                3771, 1717, 761, 3968, 2662, 40, 1719, 775, 665, 4008, 706, 1365, 3115, 89, 2193,
                1136, 2328, 471, 2329, 638, 590, 66, 3378, 312, 3487, 324, 645, 639, 3706, 3909,
                4036, 1542, 692, 2490, 3814, 800, 15, 2687, 4077, 1627, 786, 568, 593, 3966, 3956,
                638, 2024, 733, 2862, 2482, 1728, 95, 613, 158, 793, 568, 3619, 55, 2964, 3020,
                794, 2147, 460, 3180, 1459, 309, 2983, 443, 3010, 3695, 2593, 790, 807, 1633, 843,
                361, 3141, 324, 499, 309, 43, 3856, 2354, 1853, 591, 1151, 687, 582, 1525, 1594,
                2164, 265, 421, 2592, 2636, 2356, 361, 834, 35, 2267, 3114, 3425, 1689, 2024, 857,
                1159, 3108, 195, 3849, 2516, 181, 202, 874, 2371, 774, 1535, 711, 794, 2686, 2642,
                3781, 2184, 1333, 2807, 524, 2409, 4083, 2988, 887, 864, 70, 3995, 3267, 1877,
                3963, 3247, 1600, 596, 307, 2273, 1344, 910, 475, 736, 2561, 304, 2636, 915, 2689,
                654, 1941, 1125, 2766, 461, 2247, 916, 3780, 3677, 454, 877, 3423, 842, 2621, 3791,
                50, 380, 3101, 844, 2594, 1216, 1812, 767, 888, 3541, 690, 233, 3272, 1511, 851,
                161, 767, 3583, 755, 1448, 1633, 907, 3078, 3961, 2910, 955, 3204, 1975, 1842, 817,
                2869, 1668, 779, 3339, 552, 969, 1058, 766, 955, 1722, 4014, 519, 2975, 1459, 874,
                2952, 947, 979, 1933, 2478, 665, 985, 982, 815, 21, 1179, 3217, 1056, 129, 815,
                1508, 739, 3801, 982, 768, 4038, 1788, 2571, 999, 2494, 3683, 1257, 1003, 751,
                4079, 1009, 184, 91, 3936, 1790, 3997, 719, 1012, 3540, 3910, 848, 980, 726,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 1;
            let segment_n = 1;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                3423, 3780, 3751, 584, 2089, 3394, 594, 952, 3177, 3537, 2536, 2720, 3812, 1004,
                795, 353, 487, 27, 458, 566, 404, 3545, 945, 998, 3517, 1047, 4008, 448, 515, 999,
                1048, 939, 277, 2497, 89, 2786, 989, 420, 3571, 384, 740, 331, 2268, 2791, 843,
                518, 2447, 3880, 918, 3041, 3534, 385, 134, 3210, 2690, 3631, 3050, 839, 358, 1062,
                2949, 910, 537, 874, 2462, 3775, 842, 1083, 1063, 3225, 3141, 944, 971, 2956, 4004,
                1030, 178, 850, 2505, 3374, 474, 2961, 20, 3616, 3197, 1028, 2236, 290, 851, 561,
                934, 914, 260, 235, 1078, 931, 94, 2329, 593, 717, 2290, 869, 555, 368, 644, 3422,
                822, 3169, 1105, 21, 2107, 1109, 803, 1123, 1135, 184, 4070, 661, 3376, 853, 2888,
                3867, 1072, 1128, 965, 2138, 1119, 186, 405, 2561, 3857, 481, 2208, 287, 1137,
                2389, 132, 646, 627, 1128, 4051, 1030, 2679, 123, 63, 1120, 3701, 1135, 1166, 4029,
                2725, 1173, 2213, 2216, 465, 986, 303, 983, 846, 1069, 1096, 1172, 324, 1071, 718,
                486, 1110, 1166, 1063, 276, 1081, 3791, 2574, 180, 3812, 825, 2481, 586, 2292,
                2777, 2725, 3779, 748, 92, 1193, 1007, 3302, 568, 2694, 255, 993, 897, 3676, 226,
                1104, 2778, 2121, 1201, 1064, 2908, 1195, 1223, 1092, 3153, 3966, 1227, 3241, 1228,
                3771, 1163, 1232, 5, 989, 3734, 3190, 1138, 1101, 3105, 1118, 3935, 1122, 787,
                2214, 2745, 913, 832, 769, 651, 3543, 3967, 406, 2304, 4031, 961, 3660, 1256, 335,
                2970, 2273, 3860, 3150, 1180, 2498, 974, 966, 3133, 652, 336, 735, 439, 3049, 1273,
                3191, 3631, 875, 1272, 1277, 3960, 1232, 2577, 637, 765, 2972, 737, 3569, 991,
                2892, 3886, 2767, 3809, 834, 1278, 630, 1173, 1090, 1152, 3560, 426, 1189, 1266,
                3572, 834, 956, 953, 1303, 475, 3508, 1293, 3134, 816, 2764, 2537, 1314, 3700,
                1261, 1317, 1176, 460, 978, 1003, 1282, 1323, 3823, 651, 674, 957, 2390, 3299, 857,
                4075, 3598, 1097, 1318, 1281, 3369, 4002, 1048, 1223, 1154, 1201, 591, 589, 1280,
                345, 353, 3883, 381, 348, 3228, 969, 2067, 2092, 2454, 2600, 147, 61, 608, 1134,
                356, 945, 1230, 475, 1075, 793, 2229, 908, 3184, 3554, 334, 1324, 2059, 1373, 1163,
                2796, 1274, 2943, 1377, 3114, 3960, 493, 3433, 3792, 1107, 3051, 2727, 3814, 1139,
                1150, 2592, 1016, 1013, 2566, 2993, 1367, 3031, 919, 664, 1344, 3670, 3018, 1382,
                348, 1080, 3092, 704, 924, 1370, 289, 4084, 1219, 487, 3658, 3809, 2875, 1096,
                1276, 211, 1227, 3640, 1305, 3344, 708, 2950, 1133, 563, 339, 1355, 1429, 704,
                3219, 1405, 1408, 3986, 1047, 189, 1198, 798, 1408, 430, 301, 1292, 1373, 3113,
                2234, 1396, 707, 271, 1218, 375, 1278, 596, 788, 477, 867, 2050, 1135, 1350, 1248,
                3662, 2118, 3123, 2568, 1250, 304, 461, 3974, 1095, 2358, 307, 2605, 1155, 1042,
                1310, 439, 1441, 3956, 3397, 2696, 377, 1159, 2307, 97, 461, 1141, 57, 660, 2627,
                355, 2825, 911, 1271, 3072, 2283, 165, 1445, 1497, 467, 1477, 767, 3004, 380, 3583,
                1008, 3091, 138, 3099, 501, 998, 3858, 1269, 3670, 1436, 898, 1272, 3119, 611,
                2150, 2508, 1294, 32, 1516, 3579, 1332, 1524, 2509, 745, 678, 878, 1513, 2944,
                1302, 1259, 3425, 1509, 1534, 1537, 1151, 3462, 867, 889, 2804, 859, 4019, 1041,
                1008, 1066, 1225, 2697, 1529, 3659, 905, 1025, 22, 2701, 1172, 2802, 3831, 211,
                3590, 288, 993, 288, 2970, 1425, 1295, 3629, 849, 1116, 1403, 1248, 1572, 1521, 55,
                1570, 1234, 1269, 1560, 2831, 3335, 1336, 2891, 191, 73, 807, 619, 1339, 1283,
                2525, 1587, 3490, 1413, 692, 734, 1229, 1541, 3022, 1395, 1482, 836, 2965, 1030,
                4039, 1586, 2197, 661, 1512, 3183, 2061, 2611, 4078, 1572, 2220, 1614, 383, 1488,
                1442, 1618, 3842, 617, 716, 3901, 1623, 2467, 1230, 3782, 197, 2217, 264, 2443,
                1217, 950, 2971, 713, 1054, 3040, 1060, 299, 4040, 1472, 1439, 1387, 3819, 724,
                524, 2224, 1625, 1530, 2646, 1506, 782, 30, 2640, 1385, 1651, 2720, 433, 1194,
                1573, 1423, 1661, 487, 1284, 1598, 1382, 1273, 3468, 1015, 2545, 3891, 1563, 1655,
                836, 1298, 1066, 2554, 336, 3767, 1212, 3388, 3602, 884, 698, 2443, 1350, 194,
                1030, 846, 2706, 1590, 51, 745, 1528, 1466, 1069, 569, 2592, 1349, 1321, 4042,
                1089, 3904, 1492, 3710, 3268, 2899, 504, 1513, 3313, 3066, 3315, 1066, 1441, 1374,
                831, 2758, 776, 1711, 1546, 1657, 1182, 1699, 200, 1665, 4007, 734, 1605, 1725,
                1480, 8, 1544, 3834, 1717, 1697, 2960, 1654, 1420, 987, 89, 1352, 380, 2300, 1589,
                193, 3457, 1536, 1710, 1260, 3183, 1408, 1205, 38, 1726, 465, 711, 1181, 303, 1703,
                3837, 1343, 3576, 2656, 3250, 1001, 3675, 1353, 2677, 156, 4062, 99, 693, 2337,
                271, 3933, 2452, 183, 2611, 3123, 1746, 727, 1146, 554, 2827, 1784, 3763, 3486,
                520, 3369, 676, 758, 3872, 1261, 3440, 1268, 710, 2928, 4016, 1572, 1425, 2108,
                1333, 1632, 2949, 2341, 648, 1777, 3100, 1719, 1491, 654, 1634, 887, 517, 1789,
                1179, 1780, 131, 1788, 1278, 1820, 3597, 3244, 3527, 701, 1460, 3122, 4014, 687,
                3583, 1824, 1445, 1479, 1825, 1609, 1200, 3708, 2330, 3749, 2597, 487, 1421, 1405,
                2865, 1637, 230, 1086, 2748, 899, 1693, 1815, 1840, 4084, 1837, 1804, 2474, 1802,
                1192, 3934, 220, 3029, 1732, 461, 1828, 486, 2251, 922, 1867, 1353, 476, 503, 339,
                1808, 1823, 874, 2751, 1866, 3880, 1792, 37, 3212, 1309, 1479, 146, 3790, 290,
                1882, 2349, 1884, 1870, 1889, 1872, 1105, 1206, 1525, 2595, 687, 1261, 1826, 1740,
                1791, 1851, 3759, 3588, 1389, 1664, 1783, 26, 1626, 2808, 1840, 3685, 746, 1265,
                3869, 2599, 1495, 310, 1307, 1611, 1390, 234, 2423, 1912, 3334, 1361, 4074, 45,
                2171, 1891, 1726, 804, 1506, 3422, 1678, 1720, 1909, 1779, 3583, 718, 1551, 1800,
                1662, 1733, 1571, 1631, 1175, 1492, 1760, 2327, 2943, 1721, 3728, 1597, 1034, 991,
                153, 3318, 238, 807, 1270, 2344, 1846, 3776, 781, 332, 1622, 344, 3123, 246, 2578,
                185, 35, 1953, 1727, 2469, 2365, 757, 1960, 1257, 4041, 2354, 944, 362, 1848, 160,
                2763, 2290, 2289, 1866, 1805, 1615, 1929, 3689, 1658, 3432, 399, 3833, 246, 2218,
                1694, 3069, 1447, 2312, 1997, 1423, 1484, 1795, 2003, 303, 1688, 452, 631, 1006,
                3922, 3495, 3408, 3505, 1469, 3679, 1390, 185, 1848, 1999, 3947, 835, 1703, 1068,
                2140, 2319, 13, 3447, 3743, 3946, 345, 237, 1944, 929, 1616, 3037, 1789, 1760,
                2035, 2712, 3411, 1658,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 1;
            let segment_n = 2;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                1513, 2045, 1126, 245, 3943, 2044, 513, 1861, 1947, 1963, 2051, 1644, 1154, 1569,
                1920, 1869, 2013, 1470, 2044, 406, 1797, 2023, 2060, 1863, 1686, 3886, 1888, 1995,
                428, 940, 3907, 2071, 1058, 3602, 349, 863, 1968, 1221, 557, 1582, 944, 1583, 2088,
                1142, 853, 107, 2057, 1991, 3307, 1401, 451, 1164, 889, 1924, 1462, 2081, 3412,
                2103, 506, 803, 1961, 4062, 185, 1296, 1534, 16, 2100, 1768, 1941, 277, 3997, 1009,
                387, 1785, 1396, 1628, 2113, 3422, 2122, 1218, 615, 2127, 1743, 2095, 948, 3469,
                647, 543, 1923, 135, 1474, 1126, 2124, 924, 2140, 2115, 1123, 482, 1441, 1478,
                1546, 4076, 1818, 2020, 1720, 1933, 1841, 2153, 2154, 1811, 1370, 2066, 1362, 2031,
                2152, 2095, 1788, 2163, 2080, 2077, 2119, 1220, 859, 1921, 1940, 1830, 1761, 1347,
                645, 3286, 1196, 976, 1664, 2098, 1600, 1185, 1811, 1718, 1581, 1079, 2101, 1820,
                3408, 1714, 1979, 1774, 3723, 2180, 764, 706, 1467, 2003, 428, 575, 2070, 1566,
                1824, 295, 1333, 2185, 877, 527, 889, 1473, 3166, 2064, 2190, 1681, 1529, 3957,
                2214, 1479, 294, 4051, 1063, 1418, 2112, 3085, 768, 1651, 3359, 205, 1911, 2026,
                622, 325, 1877, 2172, 2195, 3758, 1028, 1937, 3589, 2088, 1583, 2172, 3657, 1075,
                2229, 701, 1655, 2247, 60, 3949, 1936, 1145, 380, 2082, 3785, 3366, 1363, 3509,
                989, 2185, 3289, 355, 2067, 2248, 3467, 2237, 1156, 2264, 2044, 2042, 2016, 362,
                1417, 2035, 2092, 1935, 572, 190, 3761, 1993, 1514, 315, 1406, 2282, 2216, 2192,
                3292, 1234, 442, 2257, 2219, 1875, 3399, 4092, 3126, 3610, 682, 1565, 2077, 2180,
                1416, 1854, 2293, 2288, 2232, 2001, 104, 2262, 887, 1954, 2281, 3947, 244, 1339,
                1474, 571, 2300, 287, 1803, 1868, 492, 1943, 4077, 3227, 511, 2206, 3179, 3779,
                3668, 1438, 1246, 1194, 1953, 1937, 2333, 1797, 2316, 2011, 1234, 3784, 2210, 1814,
                621, 1047, 3893, 2036, 345, 3745, 819, 2326, 2338, 889, 1928, 935, 1957, 3157, 569,
                728, 2219, 3279, 1156, 1934, 324, 635, 2131, 2314, 3740, 2348, 1824, 2008, 645,
                2269, 2354, 3085, 1653, 3497, 585, 701, 3604, 3798, 1801, 3229, 533, 4, 1676, 1781,
                4088, 1897, 1803, 2316, 2150, 2045, 1951, 1958, 2079, 849, 3774, 1300, 2354, 2134,
                1313, 2227, 2101, 2198, 116, 2400, 110, 2143, 764, 468, 2042, 3435, 2374, 2236,
                1323, 956, 1738, 1775, 10, 2064, 1931, 2267, 1383, 2291, 3468, 3500, 3210, 249,
                2428, 1463, 1847, 2426, 1754, 2324, 1683, 1462, 2361, 1508, 1870, 660, 2440, 2363,
                1455, 1002, 2430, 3263, 876, 3896, 3698, 1960, 2417, 178, 1203, 3587, 883, 2090,
                2430, 2252, 285, 3825, 2383, 2395, 2389, 3183, 2199, 381, 262, 2466, 2463, 167,
                1462, 1741, 1183, 1357, 837, 2458, 2267, 3893, 2453, 631, 2427, 1576, 1366, 1468,
                534, 1315, 2317, 3613, 2466, 3995, 1715, 3409, 1110, 3513, 2191, 2158, 1674, 2429,
                2007, 1926, 2421, 2490, 3496, 1740, 2483, 34, 1103, 1845, 1313, 3405, 3538, 2073,
                2512, 2299, 279, 2389, 2303, 1221, 352, 2519, 2454, 3118, 2479, 2519, 1664, 2205,
                524, 2009, 3915, 2485, 2332, 593, 2327, 2363, 3715, 2099, 2507, 1092, 1994, 2263,
                2341, 2370, 1126, 1628, 2535, 252, 773, 3748, 2547, 711, 2025, 1273, 323, 3187,
                1140, 620, 2517, 1221, 3710, 2058, 3398, 2357, 2119, 1424, 3824, 875, 741, 1247,
                3244, 2568, 568, 2277, 2570, 905, 2255, 124, 1658, 1680, 1060, 3235, 3820, 308,
                932, 1301, 343, 2554, 361, 2358, 2559, 2589, 2416, 2591, 2553, 1777, 2470, 1277,
                2589, 1888, 2531, 263, 1292, 1961, 2079, 2597, 1948, 2603, 3547, 193, 1748, 2545,
                2553, 1079, 1147, 3603, 592, 4033, 18, 2467, 1665, 2554, 2582, 2528, 1789, 1964,
                3765, 1414, 470, 2342, 1653, 2572, 1128, 3388, 2542, 723, 903, 2594, 2122, 2376,
                1666, 2566, 2637, 3476, 3818, 2618, 2188, 3996, 2600, 549, 1600, 960, 3146, 2377,
                2650, 1152, 3394, 2569, 1943, 2275, 2627, 3707, 2651, 3554, 972, 2556, 1917, 2636,
                1191, 3930, 1159, 1016, 765, 1944, 1424, 745, 3832, 2664, 102, 3179, 2608, 2469,
                1789, 3197, 3877, 1494, 2681, 2461, 805, 2594, 1643, 2397, 3751, 1717, 2515, 2550,
                2554, 1179, 2696, 2373, 1801, 3136, 2700, 87, 2606, 428, 34, 3817, 2311, 3668,
                2464, 2466, 2083, 1214, 2009, 849, 2714, 2119, 3726, 2703, 3685, 2599, 1364, 2509,
                2601, 2544, 3525, 1573, 1414, 1405, 2418, 2667, 1536, 64, 332, 1373, 930, 2067,
                2006, 304, 3259, 2227, 1821, 2718, 2649, 2721, 2026, 3998, 3552, 2021, 2742, 2236,
                2693, 3594, 2487, 1927, 2480, 563, 3090, 1812, 2548, 2061, 2758, 2490, 3, 455,
                1663, 3641, 1832, 2737, 945, 853, 2633, 1405, 1700, 2771, 2648, 2721, 2642, 3919,
                3837, 2488, 2669, 2393, 1373, 3511, 1129, 2602, 1648, 2595, 3852, 2679, 2281, 202,
                1579, 1665, 2643, 3787, 2739, 2746, 1737, 1736, 1922, 1602, 2303, 2151, 2722, 871,
                2767, 1178, 648, 1010, 2300, 2742, 2540, 779, 2703, 2805, 2589, 3297, 729, 731,
                1806, 2406, 3255, 2607, 614, 650, 844, 479, 3314, 3703, 3179, 609, 2776, 3164,
                1720, 634, 519, 2475, 1053, 1684, 589, 2564, 3687, 2836, 1908, 2330, 1396, 2840,
                2640, 2757, 1896, 19, 3919, 2825, 864, 48, 1554, 2345, 2474, 1751, 3898, 2391,
                2354, 775, 351, 2863, 2866, 682, 2160, 144, 2824, 2871, 2865, 1096, 1667, 469,
                2869, 306, 2642, 125, 2556, 2873, 2829, 2236, 683, 579, 1650, 2797, 2038, 2144,
                3779, 1848, 2398, 2719, 1223, 2751, 2848, 2529, 3195, 1749, 2407, 604, 2898, 1417,
                2804, 1883, 2735, 2774, 2781, 2869, 2632, 2595, 2912, 3259, 3475, 895, 531, 290,
                2918, 2710, 2655, 1254, 2407, 1924, 2746, 2560, 2903, 2729, 2837, 523, 1711, 2919,
                2887, 2627, 2867, 3430, 2089, 1121, 2391, 2408, 2850, 2349, 2863, 1617, 1443, 2931,
                4093, 1911, 3908, 2746, 1924, 1760, 3498, 1425, 3294, 1569, 1981, 792, 2313, 2954,
                2904, 396, 2850, 1309, 2060, 542, 703, 2184, 2259, 2629, 1993, 1000, 1350, 802,
                2896, 2746, 2778, 2729, 285, 155, 2676, 2685, 2960, 2941, 1617, 2585, 2833, 2913,
                2594, 1245, 3191, 674, 62, 355, 2382, 2194, 2441, 2077, 2907, 2418, 283, 2897,
                1010, 2228, 2991, 2811, 2852, 2468, 2998, 2942, 2627, 2164, 2111, 1737, 1688, 243,
                1557, 2043, 446, 3135, 381, 522, 2915, 2963, 2838, 2344, 2480, 3992, 1206, 3020,
                2327, 1195, 3303, 2923, 206, 3141, 2669, 2737, 1129, 2236, 2928, 2756, 1524, 3040,
                452, 1215, 2897, 2571, 2526, 2908, 2195, 2753, 3526, 2665, 2252, 2706, 1081, 3026,
                2313, 430, 3057, 2824, 2721, 1792, 1944, 3026, 3907, 2236, 978, 2126,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 1;
            let segment_n = 3;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                1181, 2089, 2541, 1308, 2531, 2731, 2917, 2994, 551, 2431, 3080, 1148, 2328, 3025,
                2798, 2494, 2871, 1571, 1922, 2617, 910, 1553, 1431, 1393, 262, 2679, 3042, 2806,
                1705, 883, 137, 1122, 3070, 2945, 2562, 3096, 2991, 2326, 786, 3079, 2432, 562,
                2555, 2598, 1499, 1226, 3065, 841, 319, 3048, 371, 3094, 3100, 2390, 370, 2207,
                2965, 1263, 2574, 1478, 2992, 1602, 2749, 2480, 3108, 3135, 190, 1490, 1794, 502,
                2878, 3054, 469, 2726, 3111, 3135, 2708, 2488, 2699, 2598, 2097, 2631, 2615, 1710,
                1203, 148, 2686, 1136, 2669, 1542, 1789, 2185, 788, 1608, 2759, 3035, 2721, 1592,
                2730, 2750, 2154, 525, 3020, 2224, 3028, 1104, 3095, 1903, 438, 3179, 2980, 1683,
                820, 2727, 3166, 1192, 811, 703, 796, 3178, 334, 3191, 3138, 3117, 2580, 2410,
                1334, 2033, 1872, 1028, 435, 2089, 96, 3135, 2081, 377, 3126, 3204, 1227, 1744,
                3134, 2021, 2370, 470, 1334, 2745, 1739, 1230, 136, 60, 3099, 2613, 3172, 352,
                1599, 2530, 2382, 3198, 1797, 2601, 3083, 2540, 1784, 3233, 1357, 1989, 3234, 3044,
                2849, 2980, 3238, 2663, 3225, 3060, 610, 2598, 2001, 2497, 2161, 771, 1965, 2229,
                681, 3135, 2302, 3245, 2783, 2965, 449, 3125, 3199, 1739, 2975, 2936, 848, 3263,
                3256, 1013, 2491, 2039, 3238, 3220, 3117, 2029, 3265, 3192, 2672, 3168, 2584, 2329,
                626, 2430, 1362, 3281, 1974, 3048, 1302, 1880, 2898, 2833, 1854, 3277, 2615, 1466,
                1451, 1874, 2165, 3032, 2678, 3186, 2011, 3111, 1031, 571, 1823, 1165, 1568, 2635,
                3079, 1125, 2177, 3219, 426, 2283, 3296, 2767, 1524, 3267, 2556, 2508, 1996, 1072,
                1692, 3231, 3266, 3117, 2604, 3327, 2315, 3024, 1584, 1357, 3312, 1939, 2889, 1216,
                1509, 3152, 1231, 1371, 1710, 1549, 3253, 3268, 2725, 578, 3263, 3132, 50, 2647,
                1680, 3265, 2508, 2445, 3325, 2833, 1517, 3192, 1894, 3305, 1371, 1918, 2651, 1630,
                70, 934, 1676, 2348, 2400, 3218, 3278, 2631, 550, 94, 3014, 924, 3376, 1301, 2836,
                1051, 1477, 2888, 2105, 2346, 1844, 2052, 2859, 1735, 1429, 2436, 3047, 2856, 806,
                670, 3225, 624, 174, 1525, 3384, 3285, 2973, 2959, 3072, 2783, 3402, 3269, 1589,
                42, 2713, 856, 1843, 2265, 3379, 3079, 3004, 3405, 2636, 1782, 3416, 937, 3009,
                895, 2832, 1730, 3264, 3364, 3049, 3420, 1286, 2841, 3110, 2738, 3227, 3260, 3431,
                713, 3360, 2348, 1585, 3428, 3202, 1035, 3186, 2066, 145, 2814, 2684, 2836, 625,
                3420, 3371, 3418, 2395, 2766, 3454, 1403, 2782, 2102, 3430, 3339, 3436, 373, 54,
                2941, 3381, 916, 3453, 283, 3466, 2354, 773, 1781, 3452, 3333, 180, 368, 2057,
                1840, 3123, 3410, 3468, 2963, 3122, 3470, 1137, 1103, 391, 924, 2782, 1611, 2943,
                3489, 1682, 2538, 963, 2769, 1713, 2728, 2258, 3411, 2651, 317, 2177, 2610, 3005,
                3470, 3475, 3419, 3040, 2506, 3378, 1722, 623, 2415, 303, 165, 3516, 946, 1442,
                527, 3319, 3472, 2312, 3506, 1820, 3095, 3522, 3516, 2522, 2477, 577, 1423, 1026,
                758, 3299, 3154, 2818, 2883, 2111, 3209, 2107, 637, 2202, 3542, 1875, 1116, 3416,
                1776, 2639, 3452, 2668, 1398, 913, 2671, 3455, 1941, 3553, 386, 3521, 2064, 1071,
                1107, 3539, 236, 3253, 3511, 42, 3156, 784, 2774, 2412, 3014, 585, 600, 325, 1593,
                3561, 2343, 3430, 2507, 3509, 2925, 3438, 2295, 3361, 3583, 2748, 1078, 3580, 1964,
                2685, 206, 2447, 1745, 1724, 3257, 1607, 3506, 534, 1324, 1215, 2820, 2281, 1874,
                1541, 3600, 2775, 2684, 2275, 463, 975, 2529, 496, 792, 3295, 3237, 2407, 2908,
                1090, 1246, 821, 955, 1722, 1455, 3618, 3624, 680, 2559, 2107, 2102, 2024, 2809,
                2216, 3458, 3620, 3229, 3427, 3446, 3537, 2424, 2833, 3438, 3629, 1625, 1486, 58,
                3577, 3444, 1249, 2847, 3103, 1864, 2747, 1459, 2584, 3613, 1045, 157, 3606, 569,
                3558, 3602, 2711, 595, 1869, 3663, 3598, 3592, 3666, 3550, 2688, 1483, 3088, 3325,
                400, 2790, 1412, 850, 726, 3072, 277, 21, 1876, 3520, 2697, 2752, 2014, 3639, 1604,
                3506, 3643, 3691, 1467, 3264, 1647, 3625, 1591, 3195, 1432, 1967, 3700, 3563, 924,
                3342, 3566, 1130, 3502, 3689, 2209, 3524, 3308, 3488, 259, 72, 2418, 2630, 3478,
                3707, 1736, 1926, 305, 2759, 1670, 2385, 3250, 2974, 3094, 2653, 1620, 1873, 1678,
                2093, 3164, 2832, 2034, 1924, 3593, 1840, 558, 2318, 2625, 1398, 3095, 1939, 3741,
                1890, 2959, 3508, 3394, 2992, 3651, 2954, 3728, 3492, 1744, 3476, 3570, 1030, 2148,
                3351, 2202, 2292, 12, 129, 3629, 3613, 1707, 3754, 3098, 3769, 3672, 3763, 781,
                1649, 416, 1027, 706, 2595, 3773, 1971, 1696, 3278, 3490, 3783, 3766, 3698, 3179,
                1650, 2181, 2424, 260, 3755, 2190, 1406, 3177, 3105, 2323, 3124, 2046, 3209, 3571,
                3702, 1657, 3011, 1578, 3252, 3456, 3194, 1251, 1973, 636, 1139, 1412, 3483, 336,
                3623, 3764, 1665, 3814, 3610, 631, 186, 2617, 2523, 2590, 3587, 3724, 2904, 3802,
                3627, 2680, 3562, 3403, 138, 1720, 1655, 3342, 1439, 989, 3376, 3836, 3839, 3544,
                2461, 3800, 3711, 3456, 1270, 966, 3726, 3659, 3773, 3852, 3515, 3755, 293, 2235,
                1752, 458, 3666, 2797, 3005, 2463, 3093, 3161, 2767, 3477, 3162, 3406, 3485, 2151,
                2023, 3032, 1855, 3464, 2437, 2708, 3813, 1847, 3339, 1085, 36, 3159, 1401, 736,
                3872, 1044, 3150, 3745, 3603, 1918, 2150, 3888, 2250, 2914, 1597, 33, 3725, 3676,
                3837, 3758, 3834, 513, 3262, 1524, 3884, 3289, 3876, 3877, 18, 56, 3293, 1101,
                1249, 3090, 3837, 1468, 3652, 120, 3537, 2991, 1170, 883, 538, 3885, 2368, 2954,
                810, 3369, 3221, 1751, 3914, 3049, 1760, 3919, 3190, 3868, 3935, 3767, 2025, 3902,
                3131, 3857, 3902, 567, 690, 2499, 637, 1555, 230, 3335, 1355, 3937, 1240, 2733,
                1503, 1042, 1877, 2097, 3959, 1686, 3863, 3838, 854, 1131, 371, 3635, 1791, 709,
                1472, 2959, 2226, 482, 1152, 1024, 3169, 3677, 3788, 1907, 3059, 1606, 3809, 2782,
                3983, 2563, 3578, 222, 3363, 1830, 861, 1397, 3990, 720, 2864, 3973, 3848, 620,
                884, 3872, 3999, 2968, 3515, 3894, 3887, 3883, 2778, 1957, 2448, 2833, 3832, 3884,
                3951, 1638, 176, 3370, 3871, 3812, 516, 2483, 133, 384, 3978, 1783, 2078, 3731,
                3199, 4026, 3973, 2744, 4018, 2598, 3490, 2800, 3695, 3891, 57, 2391, 3983, 812,
                3863, 4031, 2483, 1602, 3667, 3503, 1166, 2270, 3603, 3459, 3921, 4049, 2050, 368,
                28, 4008, 1554, 3169, 3978, 3996, 2652, 2447, 4042, 764, 1182, 732, 3878, 4026,
                1383, 3860, 4061, 1363, 3942, 2083, 2428, 934, 3865, 3540, 3307, 2368, 2666, 3483,
                4010, 2728, 1454, 2225, 3648, 3476, 3811, 3592, 3339, 3548, 3973, 3979, 4061,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 2;
            let segment_n = 0;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                3058, 3853, 3996, 3939, 1160, 3958, 2783, 2771, 3906, 3745, 2022, 3383, 2446, 4078,
                2898, 4091, 2517, 1562, 1308, 3, 4075, 3762, 3623, 1619, 4055, 4090, 4071, 2811,
                2414, 3947, 3842, 26, 3829, 3742, 2823, 2080, 2772, 2814, 36, 3879, 38, 3755, 3824,
                3921, 3814, 4049, 1744, 2237, 44, 47, 3914, 4071, 3283, 41, 3991, 9, 1207, 2279,
                2572, 1204, 3898, 42, 1276, 4002, 3593, 3311, 1593, 12, 3465, 30, 1965, 27, 3744,
                1184, 1793, 1827, 3963, 1574, 2898, 2945, 75, 2729, 3982, 3178, 46, 3227, 67, 1565,
                3377, 1784, 2444, 2511, 3723, 3486, 3934, 4087, 2188, 3037, 3263, 2394, 2859, 2784,
                3427, 11, 4057, 3699, 2739, 3690, 10, 1193, 85, 3513, 3712, 3198, 3759, 36, 3752,
                4076, 2378, 22, 101, 1829, 48, 3728, 1, 2863, 55, 1750, 4017, 3894, 55, 1958, 2442,
                3950, 4024, 1767, 4082, 74, 3754, 1149, 138, 1982, 4076, 1571, 3017, 143, 3387,
                2051, 2260, 1249, 3789, 1259, 2502, 1948, 100, 3732, 3070, 155, 2362, 4, 157, 2516,
                1208, 2827, 3377, 15, 147, 1296, 2341, 3295, 1810, 167, 3910, 141, 4062, 3032,
                3592, 163, 1808, 141, 3443, 97, 3562, 58, 1525, 1235, 3953, 17, 1783, 3650, 3495,
                147, 1407, 151, 3702, 182, 3493, 3562, 80, 1394, 2525, 4020, 2600, 3701, 140, 2550,
                3581, 1661, 1216, 2051, 2569, 2315, 132, 3036, 3927, 148, 3011, 1180, 98, 211,
                1561, 3798, 3754, 3622, 1663, 179, 1493, 3975, 3365, 3797, 4039, 2775, 222, 3191,
                1207, 1989, 2631, 3464, 191, 155, 1299, 3724, 3415, 3052, 2193, 3950, 1239, 3797,
                3613, 2637, 1454, 149, 3735, 1994, 2608, 3662, 157, 51, 2561, 3755, 3913, 2933,
                4042, 4067, 2901, 3462, 3961, 2567, 2862, 169, 121, 4, 3912, 1349, 4051, 1699, 273,
                1727, 276, 1867, 3118, 2998, 172, 1680, 2118, 25, 1980, 3089, 2164, 3828, 226, 273,
                3623, 4019, 2632, 280, 2009, 141, 2790, 2501, 1636, 4062, 299, 301, 3874, 3785,
                2463, 1664, 3601, 2163, 128, 177, 3014, 1738, 4031, 2055, 3119, 220, 283, 3179,
                3725, 3460, 2479, 4055, 1767, 2109, 3384, 3505, 4016, 3655, 2880, 3629, 3110, 1403,
                1393, 1523, 1533, 3925, 2515, 281, 1705, 221, 3406, 167, 3397, 1082, 326, 248,
                4061, 3268, 348, 1919, 1040, 291, 3994, 1733, 159, 281, 3482, 3840, 3908, 322, 242,
                2896, 323, 2115, 3049, 2547, 159, 355, 1522, 2090, 3999, 3526, 269, 3234, 3864,
                2647, 4055, 353, 1348, 3530, 359, 3262, 162, 3802, 381, 3706, 289, 3107, 3746,
                3662, 3109, 371, 2049, 3413, 3415, 2118, 2636, 163, 2396, 3566, 343, 396, 1447,
                2139, 404, 1552, 2442, 1648, 1522, 259, 218, 385, 3020, 1915, 406, 2360, 1970,
                2470, 3671, 2444, 2730, 3714, 2803, 1732, 3859, 227, 4017, 420, 2443, 200, 1966,
                296, 2940, 416, 243, 138, 418, 99, 406, 148, 3108, 3354, 3598, 368, 2626, 330,
                1780, 2970, 2752, 2354, 2360, 2648, 422, 1870, 3581, 446, 1355, 2820, 1972, 277,
                1396, 3807, 3626, 323, 196, 1903, 2051, 3693, 3041, 343, 2071, 3462, 1052, 2422,
                471, 2634, 1060, 1801, 3204, 3006, 1722, 1618, 1294, 1729, 304, 1881, 3998, 2183,
                2038, 3005, 218, 99, 491, 3470, 1964, 420, 2160, 2000, 2562, 1849, 91, 148, 242,
                3840, 2665, 2523, 253, 37, 1503, 2947, 3106, 507, 1399, 1546, 3281, 1906, 241,
                1254, 166, 330, 3267, 2960, 3322, 3658, 4014, 3336, 449, 3025, 225, 2588, 3133,
                140, 2394, 2280, 30, 196, 2418, 3234, 3362, 371, 2280, 317, 2089, 2096, 3265, 135,
                2328, 1093, 1863, 3852, 3920, 3155, 462, 1941, 3730, 514, 1965, 425, 2262, 3648,
                377, 2598, 2204, 281, 467, 326, 3136, 3698, 2074, 2290, 417, 1445, 3815, 392, 531,
                2503, 3932, 360, 494, 3464, 1906, 3779, 2719, 1366, 255, 577, 2807, 3710, 1962,
                2136, 310, 333, 3721, 2256, 1954, 2880, 43, 467, 1394, 2442, 207, 3683, 372, 596,
                1258, 3204, 2256, 3816, 608, 528, 2415, 3834, 235, 3352, 2616, 3447, 3751, 3372,
                3086, 284, 573, 3016, 533, 1150, 9, 3793, 2824, 554, 1599, 2002, 588, 3541, 513,
                612, 601, 424, 4094, 3084, 34, 3438, 1802, 1325, 641, 2232, 3743, 279, 346, 570,
                1494, 1140, 291, 4041, 646, 3652, 157, 566, 2510, 2160, 3838, 1545, 1048, 566,
                3305, 584, 2678, 634, 179, 1724, 2191, 669, 3655, 595, 3555, 402, 129, 1663, 2849,
                2758, 2725, 565, 3331, 681, 279, 2112, 505, 3634, 1954, 3995, 3253, 3566, 361, 688,
                192, 570, 3814, 2131, 1564, 2718, 308, 2879, 1247, 1933, 648, 2675, 1107, 2115,
                2766, 2083, 1666, 2952, 710, 3295, 1642, 1752, 498, 130, 3500, 2187, 717, 64, 3504,
                2226, 4026, 719, 3656, 603, 176, 3668, 2410, 1248, 2643, 1850, 196, 2817, 728, 612,
                3225, 245, 648, 238, 726, 3525, 2901, 1525, 230, 540, 3479, 735, 3108, 459, 377,
                735, 1396, 3137, 3899, 669, 2199, 3822, 527, 3470, 54, 754, 3000, 2673, 2338, 600,
                3911, 1807, 4079, 3644, 413, 4078, 609, 592, 748, 2437, 1585, 2297, 334, 1828, 33,
                1760, 3046, 760, 2789, 476, 779, 353, 1736, 3326, 625, 1826, 637, 747, 568, 640,
                2909, 512, 4062, 492, 3001, 765, 194, 1369, 637, 196, 806, 3050, 586, 2583, 728,
                2073, 533, 796, 812, 2494, 3823, 729, 55, 516, 3129, 2735, 793, 6, 719, 554, 768,
                690, 3235, 818, 2714, 2818, 4050, 829, 2117, 1983, 3143, 2707, 587, 783, 1684, 460,
                2502, 278, 828, 3609, 568, 1822, 1584, 211, 604, 3429, 624, 212, 3131, 3708, 2853,
                1662, 124, 455, 1054, 433, 1751, 3257, 283, 308, 456, 1745, 1341, 183, 1182, 655,
                687, 4047, 508, 3890, 3948, 1273, 498, 1037, 774, 821, 537, 373, 586, 1924, 638,
                2047, 2263, 1582, 2722, 824, 856, 3894, 739, 477, 409, 567, 3199, 852, 359, 2558,
                445, 2936, 3781, 2128, 617, 558, 1694, 3969, 4013, 3970, 2373, 3606, 426, 3545,
                1838, 1454, 1956, 915, 1227, 3411, 863, 339, 1703, 874, 1506, 2982, 77, 3407, 4015,
                697, 192, 4054, 3737, 3634, 186, 747, 1230, 20, 938, 1206, 801, 3529, 375, 487,
                2595, 925, 2865, 1230, 2263, 948, 3773, 87, 2227, 1037, 2741, 3943, 3986, 265, 905,
                3295, 917, 497, 292, 3292, 1688, 749, 3908, 66, 2665, 469, 1291, 3939, 1166, 436,
                2058, 2046, 930, 3745, 3928, 929, 707, 3462, 3951, 3657, 308, 164, 4046, 3826,
                2108, 2555, 3633, 721, 208, 2778, 3144, 1349, 957, 2632, 256, 992, 3949, 3977, 772,
                1484, 731, 1500, 346, 1490, 353, 3955, 2943, 362, 1964, 468, 81, 549, 59, 377, 351,
                402,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 2;
            let segment_n = 1;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                245, 305, 3307, 2804, 3940, 209, 4024, 3645, 611, 3393, 168, 3928, 855, 917, 956,
                2253, 2645, 956, 3289, 927, 259, 2123, 3793, 470, 886, 392, 1024, 4063, 697, 1047,
                2858, 315, 2069, 2236, 2652, 871, 682, 996, 2717, 4003, 888, 2851, 948, 563, 3795,
                749, 846, 3966, 3264, 980, 427, 2546, 527, 108, 243, 666, 2669, 3825, 3882, 374,
                1056, 2290, 1077, 162, 3737, 3960, 3477, 316, 1042, 3933, 3274, 4014, 1079, 1092,
                3586, 4061, 566, 4000, 4061, 2186, 3418, 3459, 463, 3180, 3358, 785, 439, 3488,
                910, 1093, 2716, 3731, 1061, 939, 3079, 1097, 2319, 613, 3867, 448, 1074, 176, 528,
                2936, 516, 3759, 463, 99, 3882, 22, 1031, 549, 1047, 623, 710, 1093, 2886, 584,
                1140, 3834, 3626, 1101, 2137, 2626, 590, 846, 3532, 1149, 1119, 1115, 3105, 1130,
                246, 3008, 17, 2494, 705, 199, 2383, 1105, 18, 2638, 1124, 1075, 3896, 1083, 1102,
                4040, 788, 3048, 1157, 3309, 515, 3434, 798, 83, 3501, 1179, 304, 2806, 888, 1107,
                2551, 754, 3122, 2054, 877, 3501, 1185, 3636, 1192, 3037, 623, 286, 575, 2929, 420,
                1196, 2193, 980, 1105, 2523, 432, 3219, 869, 4049, 240, 1055, 1133, 1192, 739, 863,
                2193, 2298, 925, 2196, 1148, 1030, 732, 870, 1084, 2500, 349, 1225, 1121, 4017,
                4054, 611, 623, 1022, 1195, 562, 3575, 1233, 2288, 2974, 1020, 3573, 461, 589, 417,
                47, 303, 1074, 648, 1231, 1248, 3161, 838, 688, 2296, 3065, 126, 691, 980, 2487,
                1129, 229, 3139, 151, 1136, 427, 47, 2320, 958, 239, 1268, 47, 308, 751, 1150,
                2048, 1263, 3980, 998, 1189, 2903, 3569, 1086, 1016, 3418, 2253, 3556, 4005, 1180,
                1207, 965, 923, 86, 3912, 1241, 443, 3707, 2237, 644, 1065, 3369, 2427, 1132, 44,
                1237, 3181, 1249, 1276, 1097, 1260, 174, 1300, 3652, 1297, 3291, 654, 1289, 960,
                830, 994, 2510, 1318, 499, 3525, 1265, 1141, 3494, 897, 1288, 33, 2643, 10, 2199,
                3067, 3918, 972, 1232, 645, 430, 516, 2337, 2623, 1039, 25, 725, 777, 3300, 1123,
                2342, 4025, 993, 324, 3892, 1338, 1027, 1238, 4002, 968, 1331, 37, 3431, 2581,
                3063, 3096, 1328, 2057, 1009, 563, 769, 362, 3542, 475, 965, 873, 2513, 2631, 1359,
                314, 1285, 1294, 235, 1119, 3155, 2273, 2207, 1018, 22, 590, 2601, 1139, 3405,
                1382, 168, 3976, 2053, 2563, 1034, 2179, 1325, 828, 1396, 1301, 694, 738, 890, 898,
                1389, 408, 3932, 1363, 176, 2630, 445, 3327, 3657, 1412, 3156, 831, 443, 2650, 606,
                78, 2486, 1308, 517, 974, 2541, 443, 1359, 2459, 490, 962, 4073, 950, 827, 1248,
                700, 815, 3514, 1409, 1417, 1381, 2050, 2938, 1350, 332, 3609, 2575, 1441, 4055,
                634, 2524, 4074, 1358, 1444, 1432, 1077, 590, 1424, 2313, 897, 886, 1166, 1364,
                3767, 2997, 898, 1431, 539, 1141, 3348, 2795, 868, 1232, 1269, 909, 1347, 3624,
                3245, 1044, 334, 179, 892, 109, 1470, 773, 765, 291, 2756, 2283, 913, 846, 2810,
                871, 2756, 1234, 1245, 179, 204, 2128, 1160, 3116, 1477, 2512, 390, 767, 1074,
                2523, 262, 1502, 1312, 2838, 2184, 768, 1487, 1405, 991, 1096, 2645, 2984, 3528,
                769, 3452, 2780, 1450, 3164, 1433, 4, 490, 383, 2964, 2970, 3040, 1405, 38, 552,
                1534, 758, 3430, 329, 1497, 1232, 3708, 1128, 1083, 3133, 1467, 1545, 1466, 508,
                2348, 870, 1004, 1476, 1552, 534, 3803, 1405, 3588, 3265, 3260, 674, 1439, 711,
                1137, 970, 1045, 1539, 545, 1550, 1568, 1177, 3757, 125, 1567, 895, 377, 28, 2674,
                2505, 748, 2593, 3465, 1029, 1183, 804, 3142, 1053, 1544, 1116, 494, 2078, 1120,
                1549, 2581, 2397, 3376, 2176, 636, 1093, 2823, 1503, 937, 3053, 571, 1581, 299,
                1333, 1486, 1598, 1606, 3975, 911, 1583, 1587, 3454, 1152, 1558, 970, 1550, 3723,
                2663, 1476, 1128, 1489, 1589, 1433, 3506, 2497, 1552, 1287, 1387, 55, 1434, 4005,
                3971, 3550, 1611, 459, 995, 3143, 1637, 1619, 1390, 513, 1411, 502, 3425, 1597,
                1535, 2383, 109, 1436, 3216, 1346, 1421, 3212, 1601, 616, 1443, 1648, 2301, 1645,
                1328, 1650, 82, 226, 307, 1666, 861, 414, 3262, 1014, 1003, 1473, 4035, 4079, 984,
                374, 3761, 4021, 1150, 2932, 1196, 1455, 1681, 1625, 1132, 405, 1273, 1552, 2947,
                3987, 2071, 3912, 3980, 1694, 1589, 1112, 55, 1493, 1461, 1465, 1557, 934, 1687,
                1044, 1317, 3014, 1466, 3961, 3956, 3299, 214, 2427, 3963, 3145, 676, 491, 3522,
                2841, 1588, 1706, 1694, 35, 1719, 1188, 1707, 1304, 3273, 1564, 1690, 2256, 1471,
                100, 607, 940, 2693, 1334, 1640, 852, 1738, 588, 1733, 3203, 1517, 1677, 2448,
                1742, 3501, 1714, 444, 1673, 1416, 4011, 2284, 1753, 3912, 1231, 2921, 2947, 861,
                3720, 1496, 1263, 1384, 2112, 1281, 1480, 3686, 3955, 3989, 1290, 3489, 1124, 1770,
                2283, 618, 2836, 1413, 1503, 2257, 802, 1026, 2386, 516, 1412, 2787, 502, 1167,
                3816, 1701, 1603, 2125, 316, 3629, 1473, 1426, 1452, 1478, 1747, 3456, 1184, 2563,
                1681, 3136, 1617, 1406, 3562, 866, 153, 1621, 21, 1660, 1765, 1054, 1642, 335,
                1792, 730, 3773, 2429, 1732, 1378, 1746, 947, 1431, 3103, 945, 1698, 1488, 3433, 4,
                1831, 736, 469, 3095, 303, 376, 2759, 2259, 202, 854, 1348, 2437, 2954, 1828, 1206,
                1344, 1837, 3780, 1794, 747, 3928, 1817, 929, 1662, 1772, 1199, 3262, 1297, 1191,
                1773, 2908, 1122, 1860, 1214, 2310, 2918, 1829, 3371, 24, 1868, 1777, 536, 732,
                2223, 3738, 783, 1594, 1555, 703, 1131, 1257, 2780, 1666, 1671, 2690, 1181, 1769,
                23, 1016, 1551, 3351, 1660, 1493, 106, 765, 1598, 1043, 1699, 1889, 1057, 1901,
                2070, 3725, 857, 739, 2359, 49, 1486, 293, 3395, 3384, 2468, 1867, 1631, 3838,
                1432, 1450, 822, 2971, 1303, 1847, 3460, 1621, 772, 1924, 1287, 1926, 1654, 303,
                2395, 3994, 172, 3677, 1920, 1755, 2844, 1651, 1922, 1513, 4058, 854, 3068, 2, 741,
                1739, 1296, 1794, 3229, 1872, 1924, 2254, 730, 1023, 3703, 1349, 1692, 1406, 3815,
                1492, 40, 3040, 334, 1727, 591, 1503, 1733, 2691, 3063, 1204, 2722, 1665, 3895,
                1924, 3565, 3795, 1905, 3843, 3897, 1817, 1888, 1538, 224, 1476, 2081, 1280, 3972,
                2200, 1105, 3469, 3685, 1909, 974, 2516, 382, 1389, 2366, 2750, 136, 2174, 1915,
                1622, 2519, 3999, 3674, 1649, 1706, 757, 3776, 2898, 1614, 158, 450, 15, 2013,
                1852, 1930, 438, 1851, 775, 1746, 1870, 1021, 997, 1742, 1756, 2767, 1982, 1882,
                72, 1961, 2296, 2940, 2570, 2569, 2878, 3652, 3774, 2212, 2599, 30, 2183, 248, 508,
                1543, 2967,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 2;
            let segment_n = 2;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                2035, 1527, 238, 1387, 1882, 1932, 772, 2047, 1735, 918, 619, 450, 1107, 783, 1692,
                181, 1995, 1895, 1973, 2045, 630, 1584, 1150, 3855, 2055, 2068, 3155, 1949, 3884,
                2064, 1369, 3749, 1961, 1505, 2058, 3972, 1019, 3196, 1559, 334, 1041, 3306, 2080,
                3189, 1988, 770, 805, 3651, 990, 486, 981, 237, 1270, 4085, 161, 18, 1821, 1330,
                1615, 3327, 2074, 487, 1759, 1580, 241, 4002, 1819, 1152, 2113, 3801, 1057, 1844,
                3249, 214, 719, 3415, 1180, 1917, 1546, 2085, 65, 1568, 2108, 960, 1645, 1794,
                2095, 686, 1295, 1334, 1685, 1041, 1959, 594, 1253, 1184, 1896, 529, 960, 2037,
                1027, 1117, 2085, 4042, 353, 3849, 3936, 69, 1912, 2006, 3887, 502, 655, 2139, 330,
                1314, 3872, 3847, 937, 390, 1126, 2129, 252, 2078, 1960, 2134, 891, 329, 1555,
                3363, 1063, 119, 1836, 978, 1896, 2072, 1517, 1828, 3173, 2159, 1246, 987, 1801,
                1742, 1975, 1655, 539, 1680, 457, 541, 2159, 1433, 447, 484, 8, 3129, 221, 2050,
                2185, 1393, 3686, 1950, 1543, 2121, 1955, 46, 2102, 1364, 2179, 2208, 2207, 2201,
                1802, 2142, 3986, 1943, 1240, 2197, 1812, 1624, 1790, 2023, 3355, 856, 1343, 1692,
                2079, 941, 3515, 2049, 2223, 1295, 1925, 2203, 3630, 696, 1966, 1206, 598, 3214,
                1658, 723, 2223, 1747, 236, 3337, 1868, 1392, 1965, 2110, 1514, 495, 1677, 2082,
                4052, 1710, 2110, 1918, 1324, 209, 3166, 1858, 1639, 1968, 1222, 1703, 1312, 2086,
                3249, 1263, 585, 245, 1354, 1907, 1829, 1338, 2280, 2189, 2246, 2170, 4095, 2103,
                2016, 612, 1554, 408, 1300, 1448, 4004, 2247, 2196, 1611, 248, 2242, 1056, 435,
                1470, 3828, 3731, 2302, 1054, 620, 3198, 1184, 2231, 3501, 1603, 2298, 73, 1048,
                2033, 1083, 1408, 1217, 274, 685, 3146, 2276, 2318, 2267, 1215, 2226, 2318, 3464,
                2328, 83, 2117, 2084, 2224, 3485, 209, 1872, 3575, 1809, 360, 1550, 3677, 3607,
                4004, 2343, 2043, 2341, 1501, 1661, 2218, 3854, 3250, 2098, 2036, 2355, 61, 419,
                2313, 1461, 2009, 2045, 2362, 344, 1799, 1832, 1092, 3573, 984, 3644, 1308, 2253,
                3240, 2332, 1096, 1225, 1769, 2226, 2284, 1260, 2214, 1693, 1240, 1936, 1619, 2240,
                2198, 2371, 3453, 3394, 1961, 2140, 304, 728, 1263, 2390, 1404, 2280, 2397, 3945,
                2101, 2381, 309, 435, 2160, 505, 1047, 1230, 1615, 2326, 2268, 2403, 1512, 3918,
                778, 3112, 1563, 2126, 88, 1048, 2418, 1924, 2419, 3248, 2377, 2307, 2098, 2062,
                1810, 1076, 2404, 2179, 2243, 1305, 2400, 1665, 1967, 2268, 4034, 3705, 2234, 1704,
                1814, 2414, 879, 1628, 902, 835, 337, 1010, 2332, 1992, 1013, 2407, 639, 454, 2333,
                1974, 720, 2448, 894, 1865, 3662, 1562, 611, 318, 1662, 670, 2364, 1748, 2280,
                1884, 1018, 2170, 2428, 881, 422, 2403, 2181, 2003, 3416, 3384, 2156, 3463, 3256,
                951, 1222, 1660, 1499, 1802, 644, 1432, 1886, 1431, 2398, 1953, 1760, 601, 469,
                2429, 1034, 3421, 1881, 1723, 1311, 509, 1924, 147, 2266, 1958, 2473, 3313, 1730,
                2371, 1176, 2475, 1968, 4088, 1736, 2057, 2143, 3518, 1874, 2011, 1144, 912, 2251,
                1926, 3997, 232, 50, 1051, 98, 2315, 2366, 1077, 894, 3202, 1669, 547, 3956, 1429,
                2193, 1156, 330, 1568, 143, 1071, 933, 1409, 2245, 2493, 153, 3256, 3702, 2374,
                2544, 3867, 2362, 1948, 1353, 2404, 1787, 1249, 2101, 555, 3478, 572, 2413, 838,
                2510, 690, 2018, 1479, 748, 2513, 2506, 808, 2557, 1671, 2504, 2581, 2077, 1660,
                826, 636, 2531, 3192, 3694, 18, 1865, 2295, 2523, 1469, 3764, 2454, 2020, 3543,
                2202, 1490, 2596, 2474, 3426, 2381, 474, 2384, 1500, 2137, 2467, 2545, 2496, 1799,
                2462, 2319, 2497, 3108, 1526, 1792, 1522, 2558, 2217, 2621, 3115, 2406, 1886, 2361,
                1047, 117, 331, 2257, 1277, 628, 2460, 2515, 2399, 1183, 2489, 769, 3784, 2633,
                3490, 1349, 1715, 2043, 1635, 2217, 3882, 2617, 2172, 2278, 1986, 2399, 2545, 2114,
                2205, 1769, 2618, 916, 3855, 85, 4010, 2365, 688, 882, 2401, 1883, 2401, 1728,
                2630, 1495, 3974, 1969, 2163, 2672, 2407, 2293, 2398, 3379, 1552, 3484, 2286, 2467,
                127, 614, 1644, 1243, 2570, 1436, 949, 1805, 1497, 1025, 3865, 1522, 3241, 2611,
                2178, 2684, 330, 1889, 3549, 535, 2252, 3890, 2408, 1604, 2337, 450, 4062, 1590,
                2709, 2206, 2313, 270, 1379, 1281, 719, 2622, 2457, 2482, 3595, 1234, 1854, 2718,
                2147, 2719, 2164, 1910, 289, 2516, 3366, 1953, 1347, 1671, 2059, 2650, 2686, 1720,
                2714, 2138, 2636, 1658, 1030, 1365, 634, 1873, 993, 2541, 543, 2707, 590, 2636,
                647, 3604, 3337, 3418, 3921, 2480, 3347, 2422, 1033, 3756, 2354, 2732, 1562, 2687,
                3757, 3553, 1962, 2069, 2696, 1944, 94, 54, 2710, 1133, 2341, 1271, 88, 3516, 734,
                3683, 1328, 3323, 2770, 2785, 1317, 2352, 2738, 1973, 2065, 2160, 2685, 2275, 3378,
                902, 3209, 441, 2228, 1205, 368, 2566, 2136, 2800, 2804, 2551, 2196, 2354, 2559,
                2655, 2659, 1754, 1629, 1334, 2743, 2778, 1044, 766, 3295, 1868, 3241, 116, 2818,
                2670, 3890, 332, 2734, 1835, 406, 683, 2625, 2383, 2251, 3388, 3615, 2659, 680,
                3667, 1525, 567, 1707, 2400, 2095, 2261, 2368, 2584, 2111, 2580, 1070, 1023, 2796,
                2492, 1196, 1106, 615, 1094, 2030, 2219, 2254, 2830, 1822, 2229, 2851, 1889, 2753,
                1157, 2388, 1418, 367, 2816, 1513, 2865, 763, 2161, 2793, 2680, 2634, 2598, 2188,
                3423, 2871, 2839, 2427, 933, 710, 1300, 2825, 2536, 2578, 789, 1387, 2245, 2708,
                2543, 49, 2702, 1166, 862, 2898, 2203, 1409, 3405, 2297, 2572, 375, 2755, 3209,
                489, 2904, 2865, 2545, 3812, 822, 473, 3135, 2915, 342, 3509, 2847, 2793, 1574,
                2456, 2517, 1100, 1330, 892, 2836, 3089, 3665, 1413, 2887, 1303, 218, 3378, 1333,
                1253, 2290, 2727, 132, 2805, 2424, 912, 551, 298, 1178, 2084, 2862, 3739, 2637,
                1538, 2780, 818, 2950, 2909, 367, 759, 2510, 1192, 4048, 152, 964, 2960, 1699,
                2898, 2865, 2283, 2568, 1537, 3974, 3300, 2138, 2083, 890, 2798, 1547, 65, 2815,
                2105, 920, 245, 1841, 2298, 1993, 2117, 2088, 2691, 1495, 940, 2704, 338, 3322,
                3797, 562, 97, 885, 2154, 1804, 209, 2267, 1714, 2252, 977, 3183, 2821, 2269, 2493,
                2440, 1060, 2817, 323, 1022, 1216, 2998, 2843, 3595, 3945, 1765, 2894, 3175, 1471,
                3668, 1426, 2172, 1766, 2821, 1321, 1238, 2172, 2586, 82, 2691, 2744, 1962, 670,
                1797, 1041, 2964, 3210, 4078, 2710, 2481, 710, 1630, 3461, 560, 106, 2097, 2669,
                2057, 2404, 2172, 2158, 3484, 3043, 3983, 3055, 3944, 3050, 3979, 3551, 1834, 2393,
                3171, 349, 1296, 1876, 2988, 1789, 3580, 1396,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }

            let offset = 0;
            let pass_n = 2;
            let segment_n = 3;

            gidx.init(pass_n, segment_n, offset, &mut tmp_block);

            let expected_ref_idx: [u32; 1024] = [
                1775, 3037, 2997, 1590, 386, 2714, 2140, 2437, 2432, 3079, 3079, 3044, 2964, 1089,
                398, 1962, 147, 2898, 764, 2571, 3066, 2723, 2452, 3078, 1811, 3091, 2278, 2171,
                2975, 2769, 3075, 3059, 2287, 2984, 1204, 1290, 1391, 2408, 1067, 2605, 2863, 1713,
                2479, 2690, 2005, 2619, 3116, 2718, 2142, 2468, 3112, 2400, 2547, 3093, 159, 1185,
                3126, 3080, 1683, 853, 838, 3044, 3101, 2693, 190, 2946, 1083, 1338, 470, 2521,
                2953, 2942, 2715, 3061, 3134, 3144, 832, 2058, 2223, 2002, 2015, 1887, 1236, 1367,
                3094, 3155, 419, 3084, 2718, 1890, 3158, 1458, 2741, 515, 1658, 1262, 1105, 2431,
                3166, 938, 800, 3160, 489, 3005, 3155, 2399, 3110, 1567, 3028, 2841, 3129, 841,
                3110, 3154, 3183, 2132, 37, 3127, 2310, 746, 3111, 1939, 1903, 1636, 3153, 1758,
                929, 2829, 988, 1130, 3148, 2130, 439, 1507, 1142, 1977, 784, 1131, 1494, 2481,
                1606, 1878, 2940, 955, 3087, 957, 1532, 2962, 397, 3204, 3158, 2651, 3204, 3192,
                157, 1903, 1050, 2595, 2738, 3129, 3229, 1987, 547, 2474, 3092, 3125, 3165, 3075,
                945, 2061, 2555, 1040, 2797, 823, 406, 3173, 3246, 3208, 2812, 2411, 1723, 1508,
                3145, 2944, 1977, 3208, 1036, 2971, 3093, 923, 2206, 204, 3257, 1160, 1484, 1694,
                3249, 1132, 1774, 2050, 2430, 1477, 2204, 1408, 2149, 3186, 3217, 3160, 660, 1875,
                1157, 617, 2748, 1973, 1881, 753, 314, 3030, 1987, 2162, 2711, 876, 3021, 2418,
                2394, 1813, 569, 2873, 210, 2765, 3287, 2916, 120, 3123, 3303, 2921, 1881, 751,
                1292, 1914, 3307, 1939, 2144, 1985, 3250, 645, 1324, 1965, 1193, 1043, 1264, 3143,
                310, 3247, 3085, 2670, 140, 1466, 3125, 2527, 3227, 2486, 1920, 3230, 3334, 1211,
                3241, 2593, 1396, 3339, 3116, 3164, 197, 2695, 1489, 1769, 1342, 1941, 2711, 311,
                3127, 2464, 921, 2398, 3218, 2936, 2620, 533, 2460, 1775, 1306, 1965, 3168, 1882,
                3292, 3303, 3219, 3251, 2616, 1435, 2191, 2254, 387, 3254, 2921, 3308, 2759, 851,
                1799, 3367, 3224, 1728, 2347, 1832, 3016, 3350, 2206, 3340, 1146, 3389, 3256, 1231,
                1966, 3122, 2962, 3087, 3375, 2410, 3117, 2759, 3073, 3304, 3402, 3159, 3369, 3403,
                1138, 1542, 2281, 3297, 2358, 724, 3072, 2656, 1737, 1099, 3326, 1334, 3366, 202,
                2835, 1833, 498, 3141, 226, 3077, 3125, 3364, 3287, 3214, 1519, 1703, 1715, 2652,
                1504, 3339, 2566, 3259, 1462, 2979, 3349, 1955, 1343, 3431, 1414, 3143, 3279, 583,
                1337, 2458, 3210, 1467, 3450, 1628, 3030, 2147, 1686, 3391, 1352, 1815, 792, 1189,
                3168, 3041, 3028, 202, 2700, 3414, 2447, 3422, 1267, 3200, 785, 3402, 1081, 3339,
                553, 2950, 2959, 2628, 2252, 2829, 3068, 2489, 3151, 2854, 3271, 1167, 536, 3355,
                3483, 2289, 3167, 2527, 1175, 2643, 3452, 3369, 1212, 163, 3134, 2528, 2769, 3481,
                2495, 138, 28, 3012, 2431, 610, 2772, 1706, 3507, 1733, 2968, 3495, 3309, 1860,
                225, 1301, 814, 1040, 3408, 253, 69, 3364, 2958, 666, 3395, 2936, 499, 3531, 2939,
                811, 3080, 3535, 2026, 3270, 127, 924, 3427, 1110, 3517, 3323, 3510, 1569, 3173,
                3542, 1016, 432, 3153, 2738, 798, 2811, 1199, 146, 234, 1277, 3397, 592, 3035,
                3043, 2841, 860, 2509, 2832, 3517, 3516, 2302, 3325, 1223, 3141, 3394, 1958, 257,
                2196, 958, 2652, 3416, 3265, 3446, 3546, 3335, 2798, 570, 3240, 2617, 1031, 3578,
                1768, 2767, 3587, 3588, 592, 865, 3530, 2813, 1742, 3177, 1400, 1233, 3236, 3368,
                702, 1087, 2580, 2976, 2733, 109, 3378, 3432, 2733, 3578, 3457, 537, 2644, 3587,
                1484, 3610, 3589, 3570, 1212, 2479, 1890, 2806, 490, 3274, 2528, 3628, 2317, 3618,
                3140, 2599, 3514, 3614, 3152, 353, 3186, 335, 3338, 3436, 3640, 174, 2053, 2313,
                149, 3561, 3637, 2245, 2978, 978, 3267, 818, 2328, 2442, 3164, 2826, 958, 3108,
                3639, 1313, 2787, 2502, 785, 3563, 3337, 1928, 3039, 3275, 3175, 654, 3641, 1238,
                3267, 961, 3344, 3610, 2188, 3568, 3645, 3650, 2739, 2453, 3329, 2250, 3366, 1835,
                877, 2135, 2479, 3425, 1106, 3458, 1106, 2769, 711, 2068, 3665, 560, 2255, 237,
                3356, 1259, 2466, 1327, 1673, 3654, 3275, 1711, 2422, 2215, 1551, 2230, 3142, 2559,
                1328, 2091, 2896, 768, 3705, 1066, 3184, 227, 2174, 3315, 3444, 168, 3012, 2873,
                2287, 2585, 3439, 3720, 2461, 815, 850, 3035, 802, 3348, 3699, 2864, 1015, 3178,
                1144, 3621, 2045, 3356, 1793, 1870, 2745, 550, 3654, 1373, 3653, 3687, 3236, 2760,
                1995, 1337, 3703, 3375, 2925, 3570, 3239, 3563, 3068, 3765, 3415, 1394, 2905, 3190,
                1223, 2870, 3197, 3366, 3368, 1648, 194, 2142, 2568, 3390, 2240, 2029, 3639, 3241,
                1822, 3025, 1630, 2413, 3643, 2724, 558, 2752, 2251, 2979, 3070, 2997, 3017, 2105,
                3190, 3559, 3762, 3337, 3087, 3494, 2808, 3126, 1800, 3109, 3804, 1040, 2418, 3233,
                2616, 1783, 3155, 1950, 2406, 3678, 3714, 3237, 3641, 3216, 2601, 1685, 3300, 3681,
                3030, 36, 1241, 1864, 520, 3305, 1622, 2582, 1333, 3176, 775, 3835, 2397, 2493,
                2466, 3471, 1337, 3827, 2298, 3846, 3444, 3818, 1586, 2712, 402, 2765, 2259, 1639,
                1066, 3787, 2836, 758, 3608, 2271, 399, 2943, 1712, 2736, 3656, 1345, 3594, 1382,
                624, 349, 2777, 71, 3740, 501, 1989, 1402, 2028, 449, 1984, 3091, 437, 2927, 3124,
                2515, 3856, 2, 3386, 3570, 1938, 2889, 2161, 3839, 575, 1536, 3080, 1811, 3895,
                2440, 3829, 1049, 887, 3431, 3824, 3878, 3864, 662, 3808, 3489, 3785, 2410, 3899,
                2697, 1389, 2079, 2094, 1599, 3766, 3819, 3919, 3873, 2841, 3921, 3868, 2214, 3371,
                2377, 2872, 1957, 3858, 1804, 3479, 1230, 3383, 456, 3572, 3918, 2468, 1153, 1961,
                3286, 3734, 2458, 2457, 3944, 3668, 3205, 1744, 9, 3899, 923, 890, 2710, 1022,
                3574, 3562, 1232, 1601, 2337, 3406, 3473, 3601, 1580, 3462, 0, 3268, 3290, 2073,
                2763, 1929, 3747, 659, 3692, 3555, 3758, 3605, 3220, 3153, 1570, 3333, 1437, 2664,
                2211, 1621, 3835, 2955, 3565, 3917, 1179, 3880, 1682, 439, 2077, 2153, 3976, 3962,
                62, 370, 2051, 3135, 3724, 2903, 3768, 3535, 2539, 3504, 1636, 3941, 422, 66, 2069,
                3188, 1213, 302, 2374, 3028, 3050, 3948, 4018, 1230, 3408, 3512, 2028, 2495, 4011,
                890, 1845, 3940, 3627, 1185, 1782, 3486, 3807, 1924, 854, 3047, 3497, 3875, 1892,
                687, 4027, 2591, 3639, 4032, 3278, 3094, 502, 3705, 1079, 3161, 4047, 3553, 2777,
                3264, 1325, 3845, 851, 3968, 3631, 3301, 2450, 519, 2243, 3689, 1142, 694, 3529,
                2267, 2057, 4037, 807, 3706, 2217, 2864, 3956, 3116, 1907, 4064, 3217, 3775, 3238,
                688, 1143, 599, 3050, 3856, 3094, 2281, 356, 3916, 3918, 3209, 349, 1317,
            ];

            let mut idx = offset;
            for expected in expected_ref_idx.iter() {
                // Mimic offset..segment_length runs with idx
                assert_eq!(
                    *expected,
                    gidx.get_next(idx as u32, &mut tmp_block),
                    "Invalid at {}",
                    idx
                );
                idx += 1;
            }
        }
    }

    mod test_g {
        use super::*;

        #[test]
        fn g_test() {
            let mut w0: u64 = 15555726891008754466;
            let mut w1: u64 = 5510367530937399982;
            let mut w2: u64 = 11481008432838211339;
            let mut w3: u64 = 8667059981748828325;

            let r0: u64 = 12666226408741176632;
            let r1: u64 = 839899491230516963;
            let r2: u64 = 17298398443694995777;
            let r3: u64 = 10383764314571024184;

            g(&mut w0, &mut w1, &mut w2, &mut w3);

            assert_eq!(w0, r0);
            assert_eq!(w1, r1);
            assert_eq!(w2, r2);
            assert_eq!(w3, r3);
        }
    }

    mod test_p {
        use super::*;

        #[test]
        fn p_test() {
            let mut v0: u64 = 862185360016812330;
            let mut v1: u64 = 9264562855185177247;
            let mut v2: u64 = 17733520444968542606;
            let mut v3: u64 = 13219822890422175473;
            let mut v4: u64 = 6801067205434763034;
            let mut v5: u64 = 10578543507696639262;
            let mut v6: u64 = 10108704228654865903;
            let mut v7: u64 = 2299791359568756431;
            let mut v8: u64 = 15201093463674093404;
            let mut v9: u64 = 13723714563716750079;
            let mut v10: u64 = 9719717710557384967;
            let mut v11: u64 = 1845563056782807427;
            let mut v12: u64 = 1829242492466781631;
            let mut v13: u64 = 17659944659119723559;
            let mut v14: u64 = 14852831888916040100;
            let mut v15: u64 = 12286853237524317048;

            let r0: u64 = 560590257705063197;
            let r1: u64 = 9520578903939690713;
            let r2: u64 = 3436672759520932446;
            let r3: u64 = 14405027955696943046;
            let r4: u64 = 17277966793721620420;
            let r5: u64 = 3246848157586690114;
            let r6: u64 = 13237761561989265024;
            let r7: u64 = 9829692378347117758;
            let r8: u64 = 1155007077473720963;
            let r9: u64 = 10252695060491707233;
            let r10: u64 = 10189249967016125740;
            let r11: u64 = 14693238843422479195;
            let r12: u64 = 13413025648622208818;
            let r13: u64 = 16791374424966705294;
            let r14: u64 = 11596653054387906253;
            let r15: u64 = 12616166200637387407;

            permutation_p(
                &mut v0, &mut v1, &mut v2, &mut v3, &mut v4, &mut v5, &mut v6, &mut v7, &mut v8,
                &mut v9, &mut v10, &mut v11, &mut v12, &mut v13, &mut v14, &mut v15,
            );

            assert_eq!(v0, r0);
            assert_eq!(v1, r1);
            assert_eq!(v2, r2);
            assert_eq!(v3, r3);
            assert_eq!(v4, r4);
            assert_eq!(v5, r5);
            assert_eq!(v6, r6);
            assert_eq!(v7, r7);
            assert_eq!(v8, r8);
            assert_eq!(v9, r9);
            assert_eq!(v10, r10);
            assert_eq!(v11, r11);
            assert_eq!(v12, r12);
            assert_eq!(v13, r13);
            assert_eq!(v14, r14);
            assert_eq!(v15, r15);
        }
    }
}
