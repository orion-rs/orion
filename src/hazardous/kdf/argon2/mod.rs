// MIT License

// Copyright (c) 2020-2026 The orion Developers

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
//! Argon2 version 1.3. This implementation is available with features `safe_api` and `alloc`.
//!
//! # Note:
//! This implementation only supports a single thread, so modifying the parallelism degree beyond `1`
//! will simply make them run sequentially.
//!
//! # Parameters:
//! - `expected`: The expected derived key.
//! - `password`: Password.
//! - `salt`: Salt value.
//! - `iterations`: Iteration count.
//! - `memory`: Memory size in kibibytes (KiB).
//! - `parallelism:` Degree of parallelism.
//! - `secret`: Optional secret value used for hashing.
//! - `ad`: Optional associated data used for hashing.
//! - `dst_out`: Destination buffer for the derived key. The length of the
//!   derived key is implied by the length of `dst_out`.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of the `password` is greater than [`MAX_PASSWORD_LEN`].
//! - The length of the `salt` is greater than [`MAX_SALT_LEN`].
//! - The length of the `secret` is greater than [`MAX_SECRET_LEN`].
//! - The length of the `ad` is greater than [`MAX_AD_LEN`].
//! - The length of `dst_out` is greater than [`u32::MAX`] or less than `4`.
//! - `iterations` is less than [`MIN_ITERATIONS_T`].
//! - `memory` is less than `8 * parallelism`.
//! - `parallelism` is less then [`MIN_PARALLELISM_P`] or greater than [`MAX_PARALLELISM_P`].
//! - The hashed password does not match the expected when verifying.
//!
//! # Security:
//! - Salts should always be generated using a CSPRNG.
//!   [`secure_rand_bytes()`] can be used for this.
//! - The minimum recommended length for a salt is `16` bytes.
//! - Password hashes should always be compared in constant-time.
//! - Please note that when verifying, a copy of the computed password hash is placed into
//! `dst_out`. If the derived hash is considered sensitive and you want to provide defense
//! in depth against an attacker reading your application's private memory, then you as
//! the user are responsible for zeroing out this buffer (see the [`zeroize` crate]).
//!
//! Please be sure to check [OWASP] for the latest recommended cost parameters.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::{hazardous::kdf::argon2::*, util};
//!
//! let mut salt = [0u8; 16];
//! util::secure_rand_bytes(&mut salt)?;
//! let password = b"Secret password";
//! let mut dst_out = [0u8; 64];
//!
//! Argon2::<ID, Sequential>::derive_key(password, &salt, 3, 1<<16, None, None, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(Argon2::<ID, Sequential>::::verify(
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
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`secure_rand_bytes()`]: crate::util::secure_rand_bytes
//! [`zeroize` crate]: https://crates.io/crates/zeroize
//! [OWASP]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

use core::marker::PhantomData;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b::{BLAKE2B_MAX_OUTSIZE, Blake2b};
use crate::util::endianness::{load_u64_into_le, store_u64_into_le};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// The Argon2 version (0x13).
pub const ARGON2_VERSION_19: u32 = 0x13;

/// The Argon2 variant (i).
const ARGON2_I_VARIANT: u32 = 1;

/// The Argon2 variant (id).
const ARGON2_ID_VARIANT: u32 = 2;

/// The minimum amount of iterations/passes.
pub const MIN_ITERATIONS_T: u32 = 1;

/// The maximum amount of iterations/passes.
pub const MAX_ITERATIONS_T: u32 = u32::MAX;

/// The maximum length of the password.
pub const MAX_PASSWORD_LEN: u32 = u32::MAX;

/// The maximum length of the salt.
pub const MAX_SALT_LEN: u32 = u32::MAX;

/// The maximum memory cost.
pub const MAX_MEMORY_M: u32 = u32::MAX;

/// The minimum parellism degree.
pub const MIN_PARALLELISM_P: u32 = 1;

/// The maximum parellism degree.
pub const MAX_PARALLELISM_P: u32 = (1 << 24) - 1;

/// The maximum length of the optional secret.
pub const MAX_SECRET_LEN: u32 = u32::MAX;

/// The maximum length of the optional additional data.
pub const MAX_AD_LEN: u32 = u32::MAX;

/// The amount of segments per lane, as defined in the spec.
const SEGMENTS_PER_LANE: usize = 4;

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
    version: u32,
    lanes: u32,
    variant: u32,
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
    let mut hasher = Blake2b::new(BLAKE2B_MAX_OUTSIZE)?;

    // Collect the first part to reduce times we update the hasher state.
    h0[0..4].copy_from_slice(&lanes.to_le_bytes());
    h0[4..8].copy_from_slice(&hash_length.to_le_bytes());
    h0[8..12].copy_from_slice(&memory_kib.to_le_bytes());
    h0[12..16].copy_from_slice(&passes.to_le_bytes());
    h0[16..20].copy_from_slice(&version.to_le_bytes());
    h0[20..24].copy_from_slice(&variant.to_le_bytes());
    h0[24..28].copy_from_slice(&(p.len() as u32).to_le_bytes());

    hasher.update(&h0[..28])?;
    hasher.update(p)?;
    hasher.update(&(s.len() as u32).to_le_bytes())?;
    hasher.update(s)?;
    hasher.update(&(k.len() as u32).to_le_bytes())?;
    hasher.update(k)?;
    hasher.update(&(x.len() as u32).to_le_bytes())?;
    hasher.update(x)?;
    h0[0..BLAKE2B_MAX_OUTSIZE].copy_from_slice(hasher.finalize()?.as_ref());

    Ok(h0)
}

/// H' as defined in the specification.
fn extended_hash(input: &[u8], dst: &mut [u8]) -> Result<(), UnknownCryptoError> {
    if dst.is_empty() {
        return Err(UnknownCryptoError);
    }

    let outlen = dst.len() as u32;

    if dst.len() <= BLAKE2B_MAX_OUTSIZE {
        let mut ctx = Blake2b::new(dst.len())?;
        ctx.update(&outlen.to_le_bytes())?;
        ctx.update(input)?;
        dst.copy_from_slice(ctx.finalize()?.as_ref());
    } else {
        let mut ctx = Blake2b::new(BLAKE2B_MAX_OUTSIZE)?;
        ctx.update(&outlen.to_le_bytes())?;
        ctx.update(input)?;

        let mut tmp = ctx.finalize()?;
        dst[..BLAKE2B_MAX_OUTSIZE].copy_from_slice(tmp.as_ref());

        let mut pos = BLAKE2B_MAX_OUTSIZE / 2;
        let mut toproduce = dst.len() - BLAKE2B_MAX_OUTSIZE / 2;

        while toproduce > BLAKE2B_MAX_OUTSIZE {
            ctx.reset()?;
            ctx.update(tmp.as_ref())?;
            tmp = ctx.finalize()?;

            dst[pos..(pos + BLAKE2B_MAX_OUTSIZE)].copy_from_slice(tmp.as_ref());
            pos += BLAKE2B_MAX_OUTSIZE / 2;
            toproduce -= BLAKE2B_MAX_OUTSIZE / 2;
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
    fn new(variant: u32, blocks: u32, passes: u32, segment_length: u32, lane: u32) -> Self {
        let mut block = [0u64; 128];
        block[1] = u64::from(lane);
        block[3] = u64::from(blocks);
        block[4] = u64::from(passes);
        block[5] = u64::from(variant);

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
        // when generating a new address block. Therefore we
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

    /// Get J1/J2 indice-pair.
    fn get_next_j1j2(&mut self, tmp_block: &mut [u64; 128]) -> (u64, u64) {
        let j1: u64 = self.addresses[self.offset as usize] & 0xFFFF_FFFFu64;
        let j2: u64 = self.addresses[self.offset as usize] >> 32;
        self.offset = (self.offset + 1) % 128; // Wrap-around on block length.
        if self.offset == 0 {
            self.next_addresses(tmp_block);
        }

        (j1, j2)
    }
}

// The Argon2 specification for this version (1.3) does not conform
// to the official reference implementation. This implementation follows
// the reference implementation and ignores the specification where they
// disagree. See https://github.com/P-H-C/phc-winner-argon2/issues/183.
fn reference_idx(
    j1: u64,
    j2: u64,
    lanes: u32,
    lane: u32,
    lane_len: u32,
    pass_n: u32,
    segment_n: u32,
    segment_idx: u32,
    segment_length: u32,
) -> (u32, u32) {
    let ref_start_lane = if pass_n == 0 && segment_n == 0 {
        lane
    } else {
        (j2 % lanes as u64) as u32
    };

    let is_same_lane = ref_start_lane == lane;
    let ref_start_pos: u64 = if pass_n == 0 {
        if segment_n == 0 {
            u64::from(segment_idx) - 1
        } else if is_same_lane {
            u64::from(segment_n) * u64::from(segment_length) + u64::from(segment_idx) - 1
        } else {
            u64::from(segment_n) * u64::from(segment_length) - u64::from(segment_idx == 0)
        }
    } else if is_same_lane {
        u64::from(lane_len) - u64::from(segment_length) + u64::from(segment_idx) - 1
    } else {
        u64::from(lane_len) - u64::from(segment_length) - u64::from(segment_idx == 0)
    };

    let mut ref_pos: u64 = (j1 * j1) >> 32;
    ref_pos = (ref_start_pos as u64 * ref_pos) >> 32;
    ref_pos = (ref_start_pos as u64 - 1) - ref_pos;

    let start_pos: u32 = if pass_n == 0 || segment_n == SEGMENTS_PER_LANE as u32 - 1 {
        0
    } else {
        (segment_n + 1) * segment_length
    };

    (
        ref_start_lane,
        ((start_pos as u64 + ref_pos) % lane_len as u64) as u32,
    )
}

/// Determine mased on variant and pass+segment if data-independent addressing should
/// be used.
const fn is_data_independent(variant: u32, pass_n: u32, segment_n: usize) -> bool {
    match variant {
        ARGON2_I_VARIANT => true,
        ARGON2_ID_VARIANT => pass_n == 0 && segment_n < 2,
        _ => false,
    }
}

fn check_minimum_memory(memory: u32, parallelism: u32) -> Result<(), UnknownCryptoError> {
    match 8u32.checked_mul(parallelism) {
        Some(min) => {
            if !(min..=u32::MAX).contains(&memory) {
                dbg!("C1");
                return Err(UnknownCryptoError);
            }

            Ok(())
        }
        None => Err(UnknownCryptoError),
    }
}

mod sealed {

    pub trait Sealed {}

    pub trait Variant: Sealed {
        const VALUE: u32;
    }
}

// TODO(brycx): RwLock + thread::scoped
// #[derive(Debug, PartialEq)]
// #[cfg(feature = "safe_api")]
// pub struct Threaded;

#[derive(Debug, PartialEq)]
/// Sequential processing. This means, regardless of what parellelism `p` is set to,
/// Argon2 will run with no extra threads, sequentially.
pub struct Sequential;
impl sealed::Sealed for Sequential {}

#[derive(Debug, PartialEq)]
/// Argon2i password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub struct I;
impl sealed::Sealed for I {}
impl sealed::Variant for I {
    const VALUE: u32 = ARGON2_I_VARIANT;
}

#[derive(Debug, PartialEq)]
/// Argon2id password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub struct ID;
impl sealed::Sealed for ID {}
impl sealed::Variant for ID {
    const VALUE: u32 = ARGON2_ID_VARIANT;
}

#[derive(Debug)]
/// Argon2 password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub struct Argon2<V: sealed::Variant, Threading: sealed::Sealed> {
    _variant: PhantomData<V>,
    _threading: PhantomData<Threading>,
}

impl<V: sealed::Variant, Threading: sealed::Sealed> Argon2<V, Threading> {
    fn validate_parameters(
        version: u32,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        memory: u32,
        parallelism: u32,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(version, ARGON2_VERSION_19);
        debug_assert!(V::VALUE == ARGON2_ID_VARIANT || V::VALUE == ARGON2_I_VARIANT);

        if !(MIN_PARALLELISM_P..=MAX_PARALLELISM_P).contains(&parallelism) {
            return Err(UnknownCryptoError);
        }

        check_minimum_memory(memory, parallelism)?;
        if password.len() > MAX_PASSWORD_LEN as usize {
            return Err(UnknownCryptoError);
        }
        if salt.len() > MAX_SALT_LEN as usize {
            return Err(UnknownCryptoError);
        }
        if !(MIN_ITERATIONS_T..=MAX_ITERATIONS_T).contains(&iterations) {
            dbg!(
                "C2",
                iterations,
                (MIN_ITERATIONS_T..=MAX_ITERATIONS_T).contains(&iterations)
            );
            return Err(UnknownCryptoError);
        }

        let _k = match secret {
            Some(n_val) => {
                if n_val.len() > 0xFFFF_FFFF {
                    return Err(UnknownCryptoError);
                }

                n_val
            }
            None => &[0u8; 0],
        };

        let _x = match ad {
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

        Ok(())
    }
}

impl<V: sealed::Variant> Argon2<V, Sequential> {
    #[allow(clippy::too_many_arguments)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Run KDF.
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        memory: u32,
        parallelism: u32,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let version = ARGON2_VERSION_19;
        Self::validate_parameters(
            version,
            password,
            salt,
            iterations,
            memory,
            parallelism,
            secret,
            ad,
            dst_out,
        )?;

        debug_assert!(4 * MAX_PARALLELISM_P <= u32::MAX);
        let four_lanes = 4 * parallelism;
        let n_blocks = (memory / four_lanes) * four_lanes;
        let lane_len = n_blocks / parallelism;
        // segment_lengt := lane_length / 4
        let segment_length = lane_len >> 2;

        let mut blocks: Vec<[u64; 128]> = vec![[0u64; 128]; n_blocks as usize];

        let mut h0 = initial_hash(
            version,
            parallelism,
            V::VALUE,
            dst_out.len() as u32,
            memory,
            iterations,
            password,
            salt,
            secret.unwrap_or(&[]),
            ad.unwrap_or(&[]),
        )?;
        let mut tmp = [0u8; 1024];

        for lane in 0..parallelism {
            debug_assert_eq!(h0.len(), ((size_of::<u32>() * 2) + BLAKE2B_MAX_OUTSIZE));
            h0[BLAKE2B_MAX_OUTSIZE..(BLAKE2B_MAX_OUTSIZE + size_of::<u32>())]
                .copy_from_slice(&0u32.to_le_bytes()); // Block 0.
            h0[BLAKE2B_MAX_OUTSIZE + size_of::<u32>()..].copy_from_slice(&lane.to_le_bytes()); // Lane

            extended_hash(&h0, &mut tmp)?;
            load_u64_into_le(&tmp, &mut blocks[(lane * lane_len) as usize]);

            h0[BLAKE2B_MAX_OUTSIZE..(BLAKE2B_MAX_OUTSIZE + size_of::<u32>())]
                .copy_from_slice(&1u32.to_le_bytes()); // Block 1.
            extended_hash(&h0, &mut tmp)?;
            load_u64_into_le(&tmp, &mut blocks[(lane * lane_len + 1) as usize]);
        }

        let mut working_block = [0u64; 128];

        for pass_n in 0..iterations as usize {
            for segment_n in 0..SEGMENTS_PER_LANE {
                let offset = match (pass_n, segment_n) {
                    (0, 0) => 2, // The first two blocks have already been processed
                    _ => 0,
                };

                let use_gidx = is_data_independent(V::VALUE, pass_n as u32, segment_n);

                for lane in 0..parallelism {
                    // Argon2id only requires this in first round
                    let mut gidx: Option<Gidx> = if use_gidx {
                        let mut gidx =
                            Gidx::new(V::VALUE, n_blocks, iterations, segment_length, lane);
                        gidx.init(pass_n as u32, segment_n as u32, offset, &mut working_block);

                        Some(gidx)
                    } else {
                        None
                    };

                    for segment_idx in offset..segment_length {
                        let current_within_lane = segment_n as u32 * segment_length + segment_idx;
                        let previous_within_lane = if current_within_lane > 0 {
                            current_within_lane - 1
                        } else {
                            lane_len - 1
                        };

                        let current_idx = (lane * lane_len + current_within_lane) as usize;
                        let previous_idx = (lane * lane_len + previous_within_lane) as usize;

                        let (j1_idx, j2_idx) = if let Some(gidx) = gidx.as_mut() {
                            gidx.get_next_j1j2(&mut working_block)
                        } else {
                            // Data-dependent is lower 32 bits of previous block first word
                            let previous = blocks[previous_idx as usize][0];
                            (previous & (u32::MAX as u64), previous >> 32)
                        };

                        let (reference_lane, reference_idx) = reference_idx(
                            j1_idx,
                            j2_idx,
                            parallelism,
                            lane,
                            lane_len,
                            pass_n as u32,
                            segment_n as u32,
                            segment_idx,
                            segment_length,
                        );
                        let reference_idx = (reference_lane * lane_len + reference_idx) as usize;

                        if let (Some(prev_b), Some(ref_b)) = (
                            blocks.get(previous_idx as usize),
                            blocks.get(reference_idx as usize),
                        ) {
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
                        } else {
                            return Err(UnknownCryptoError);
                        }
                    }
                }
            }
        }

        // XOR last block of each lane
        let mut ret_block = [0u64; 128];
        for lane in 0..parallelism {
            for (ret_block, last) in ret_block
                .iter_mut()
                .zip(blocks[(lane * lane_len + lane_len - 1) as usize].iter())
            {
                *ret_block ^= *last;
            }
        }

        store_u64_into_le(&ret_block, &mut tmp);
        extended_hash(&tmp, dst_out)?;

        #[cfg(feature = "zeroize")]
        {
            ret_block.zeroize();
            working_block.zeroize();
            tmp.zeroize();
            h0.zeroize();
            for block in blocks.iter_mut() {
                block.zeroize();
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Verify derived key in constant time.
    pub fn verify(
        expected: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        memory: u32,
        parallelism: u32,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        Self::derive_key(
            password,
            salt,
            iterations,
            memory,
            parallelism,
            secret,
            ad,
            dst_out,
        )?;
        crate::util::secure_cmp(dst_out, expected)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_memory_requirements() {
        assert!(check_minimum_memory(7, 1).is_err()); // below min by 1
        assert!(check_minimum_memory(8, 1).is_ok()); // min

        assert!(check_minimum_memory(15, 2).is_err()); // below min by 1
        assert!(check_minimum_memory(16, 2).is_ok()); // min

        assert!(check_minimum_memory(8, u32::MAX).is_err()); // overflows (and invalid parallelism)
        assert!(check_minimum_memory(MAX_MEMORY_M, MAX_PARALLELISM_P).is_ok());
    }

    #[test]
    fn test_validate_parameters_passes_parallelism() {
        let mut tmp = [0u8; 4];

        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MIN_ITERATIONS_T - 1,
                8,
                1,
                None,
                None,
                &mut tmp
            )
            .is_err()
        );
        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MIN_ITERATIONS_T,
                8,
                1,
                None,
                None,
                &mut tmp
            )
            .is_ok()
        );
        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MAX_ITERATIONS_T,
                8,
                1,
                None,
                None,
                &mut tmp
            )
            .is_ok()
        );

        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MIN_ITERATIONS_T,
                8,
                MIN_PARALLELISM_P - 1,
                None,
                None,
                &mut tmp
            )
            .is_err()
        );
        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MIN_ITERATIONS_T,
                8,
                MIN_PARALLELISM_P,
                None,
                None,
                &mut tmp
            )
            .is_ok()
        );
        assert!(
            Argon2::<I, Sequential>::validate_parameters(
                ARGON2_VERSION_19,
                &[],
                &[],
                MIN_ITERATIONS_T,
                MAX_PARALLELISM_P * 8,
                MAX_PARALLELISM_P,
                None,
                None,
                &mut tmp
            )
            .is_ok()
        );
    }
}
