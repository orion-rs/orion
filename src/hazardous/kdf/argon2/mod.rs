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
//! - The length of the `salt` is less than [`MIN_SALT_LEN`] or greater than [`MAX_SALT_LEN`].
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
//! let cost = CostParams::new(1, 47104, 1)?;
//!
//! Argon2::<ID, Sequential>::derive_key(password, &salt, &cost, None, None, &mut dst_out)?;
//!
//! let expected_dk = dst_out;
//!
//! assert!(Argon2::<ID, Sequential>::verify(
//!     &expected_dk,
//!     password,
//!     &salt,
//!     &cost,
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
//! [`PasswordHash::try_from()`]: crate::hazardous::kdf::argon2::PasswordHash::try_from
//! [`MAX_PASSWORD_LEN`]: crate::hazardous::kdf::argon2::MAX_PASSWORD_LEN
//! [`MAX_SALT_LEN`]: crate::hazardous::kdf::argon2::MAX_SALT_LEN
//! [`MIN_SALT_LEN`]: crate::hazardous::kdf::argon2::MIN_SALT_LEN
//! [`MAX_SECRET_LEN`]: crate::hazardous::kdf::argon2::MAX_SECRET_LEN
//! [`MAX_AD_LEN`]: crate::hazardous::kdf::argon2::MAX_AD_LEN
//! [`MIN_ITERATIONS_T`]: crate::hazardous::kdf::argon2::MIN_ITERATIONS_T
//! [`MIN_PARALLELISM_P`]: crate::hazardous::kdf::argon2::MIN_PARALLELISM_P
//! [`MAX_PARALLELISM_P`]: crate::hazardous::kdf::argon2::MAX_PARALLELISM_P

use core::marker::PhantomData;

use crate::errors::UnknownCryptoError;
use crate::hazardous::hash::blake2::blake2b::{BLAKE2B_MAX_OUTSIZE, Blake2b};
#[cfg(feature = "safe_api")]
use crate::hazardous::kdf::argon2::phc::Argon2Phc;
use crate::hazardous::kdf::sealed;
use crate::util::endianness::{load_u64_into_le, store_u64_into_le};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

#[cfg(feature = "safe_api")]
mod phc;

#[cfg(feature = "safe_api")]
use crate::generics::{Secret, TypeSpec};

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

/// The minimum length of the salt.
pub const MIN_SALT_LEN: u32 = 8;

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

#[derive(Debug)]
#[cfg(feature = "safe_api")]
/// Marker type for a password hash, in P-H-C string format, produced by [`Argon2`]. See [`PasswordHash`] type for convenience.
pub struct Argon2PasswordHash;

#[cfg(feature = "safe_api")]
impl crate::generics::sealed::Sealed for Argon2PasswordHash {}

#[cfg(feature = "safe_api")]
impl TypeSpec for Argon2PasswordHash {
    const NAME: &'static str = stringify!(PasswordHash);
    // Parsing logic in Data-impl under [`Argon2Phc`] (applies to `parse_bytes()`).
    type TypeData = Argon2Phc;
}

#[cfg(feature = "safe_api")]
/// A type to represent the P-H-C encoded [`PasswordHash`] that [`Argon2``] returns when used for password hashing.
///
///
/// # Errors:
/// An error will be returned if:
/// - Any of the parameter validations that apply to [`Argon2`] fails.
/// - The encoded password hash contains whitespace.
/// - The encoded password contains any other fields than: The algorithm name,
///   version, m, t, p and the salt and password hash.
/// - The encoded password hash contains invalid Base64 encoding.
/// - Any decimal parameter value, such as m, contains leading zeroes and is longer
///   than a single character.
/// - The encoded password hash contains numerical values that cannot
///   be represented as a `u32`.
/// - The parameters in the encoded password hash are not correctly ordered. The ordering must be:
///   - `$argon2i$v=19$m=<value>,t=<value>,p=<value>$<salt>$<hash>`
///   - `$argon2id$v=19$m=<value>,t=<value>,p=<value>$<salt>$<hash>`
///
/// # Panics:
/// A panic will occur if:
/// - Overflowing calculations happen on `usize` when decoding the password and salt from Base64.
///
/// # Security:
/// - __**Avoid using**__ `unprotected_as_ref()` to validate passwords. Use instead the provided [`Argon2::verify`] functions.
/// - This is a secret type and does not include the password hashes in `Debug` impl. However, the entire purpose of this format
///   is for storage, so `unprotected_as_str()` is provided. Only use for storage operations and __**NOT**__ for debugging, risking password
///   hash leaks.
pub type PasswordHash = Secret<Argon2PasswordHash>;

impl PasswordHash {
    #[inline]
    /// Return the [`PasswordHash`] in P-H-C encoding.
    pub fn unprotected_as_str(&self) -> &str {
        self.data.phc_string.as_str()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// `PasswordHash` serializes as would a [`String`](std::string::String). Note that
/// the serialized type likely does not have the same protections that Orion
/// provides, such as constant-time operations. A good rule of thumb is to only
/// serialize these types for storage. Don't operate on the serialized types.
impl Serialize for PasswordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded_string = self.unprotected_as_str();
        serializer.serialize_str(encoded_string)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
/// `PasswordHash` deserializes from a [`String`](std::string::String).
impl<'de> Deserialize<'de> for PasswordHash {
    fn deserialize<D>(deserializer: D) -> Result<PasswordHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded_str = String::deserialize(deserializer)?;
        PasswordHash::try_from(encoded_str.as_str()).map_err(de::Error::custom)
    }
}

impl TryFrom<&str> for PasswordHash {
    type Error = UnknownCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self::from_data(Argon2Phc::try_from(value)?))
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
/// [`Argon2`] cost parameters.
pub struct CostParams {
    pub(crate) iterations: u32,
    pub(crate) memory: u32,
    pub(crate) parallelism: u32,
}

impl CostParams {
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

    fn validate_cost_parameters(
        iterations: u32,
        memory: u32,
        parallelism: u32,
    ) -> Result<(), UnknownCryptoError> {
        if !(MIN_PARALLELISM_P..=MAX_PARALLELISM_P).contains(&parallelism) {
            return Err(UnknownCryptoError);
        }

        Self::check_minimum_memory(memory, parallelism)?;
        if !(MIN_ITERATIONS_T..=MAX_ITERATIONS_T).contains(&iterations) {
            return Err(UnknownCryptoError);
        }

        Ok(())
    }

    /// Validate and create new [`CostParams`].
    pub fn new(iterations: u32, memory: u32, parallelism: u32) -> Result<Self, UnknownCryptoError> {
        Self::validate_cost_parameters(iterations, memory, parallelism)?;

        Ok(Self {
            iterations,
            memory,
            parallelism,
        })
    }
}

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

#[allow(clippy::too_many_arguments)]
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
    offset: u32,
}

impl Gidx {
    fn new(variant: u32, blocks: u32, passes: u32, lane: u32) -> Self {
        let mut block = [0u64; 128];
        block[1] = u64::from(lane);
        block[3] = u64::from(blocks);
        block[4] = u64::from(passes);
        block[5] = u64::from(variant);

        Self {
            block,
            addresses: [0u64; 128],
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

#[allow(clippy::too_many_arguments)]
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
    ref_pos = (ref_start_pos * ref_pos) >> 32;
    ref_pos = (ref_start_pos - 1) - ref_pos;

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
    const PHC_ID: &'static str = "argon2i";
}

#[derive(Debug, PartialEq)]
/// Argon2id password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub struct ID;
impl sealed::Sealed for ID {}
impl sealed::Variant for ID {
    const VALUE: u32 = ARGON2_ID_VARIANT;
    const PHC_ID: &'static str = "argon2id";
}

#[allow(clippy::too_many_arguments)]
fn validate_parameters(
    version: u32,
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    debug_assert_eq!(version, ARGON2_VERSION_19);
    if password.len() > MAX_PASSWORD_LEN as usize {
        return Err(UnknownCryptoError);
    }
    if salt.len() < MIN_SALT_LEN as usize || salt.len() > MAX_SALT_LEN as usize {
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

// **TODO**:
// - Move scrypt and pbkdf2 to a struct as well for API consistency (HKDF already is in v0.18.0)
// - Implement P-H-C string format for those two as well

#[derive(Debug)]
/// Argon2 password hashing function as described in the [P-H-C specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf).
pub struct Argon2<V: sealed::Variant, Threading: sealed::Sealed> {
    _variant: PhantomData<V>,
    _threading: PhantomData<Threading>,
}

impl<V: sealed::Variant> Argon2<V, Sequential> {
    #[cfg(feature = "safe_api")]
    #[allow(clippy::too_many_arguments)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Equivalent to [`Self::derive_key`] but returns a P-H-C encoded [`PasswordHash`] object.
    pub fn derive_key_encoded(
        password: &[u8],
        salt: &[u8],
        cost: &CostParams,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        hash_len: usize,
    ) -> Result<PasswordHash, UnknownCryptoError> {
        let mut pwhash = Argon2Phc {
            variant: V::PHC_ID.into(),
            version: ARGON2_VERSION_19,
            memory: cost.memory,
            iterations: cost.iterations,
            parallelism: cost.parallelism,
            salt: salt.to_vec(),
            hash: vec![0u8; hash_len],
            phc_string: String::new(),
        };

        Self::derive_key(password, salt, cost, secret, ad, &mut pwhash.hash)?;
        pwhash.encode_to_phc()?;

        Ok(PasswordHash::from_data(pwhash))
    }

    #[cfg(feature = "safe_api")]
    #[allow(clippy::too_many_arguments)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Equivalent to [`Self::derive_key`] but verifies a P-H-C encoded [`PasswordHash`] object.
    pub fn verify_encoded(
        expected: &PasswordHash,
        password: &[u8],
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
    ) -> Result<(), UnknownCryptoError> {
        if expected.data.variant.as_str() != V::PHC_ID {
            // Skip entirely computing if the variants differ.
            return Err(UnknownCryptoError);
        }

        let cost = CostParams::new(
            expected.data.iterations,
            expected.data.memory,
            expected.data.parallelism,
        )?;

        let actual = Self::derive_key_encoded(
            password,
            &expected.data.salt,
            &cost,
            secret,
            ad,
            expected.data.hash.len(),
        )?;

        if expected != &actual {
            Err(UnknownCryptoError)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Run KDF.
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        cost: &CostParams,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        let version = ARGON2_VERSION_19;
        validate_parameters(version, password, salt, secret, ad, dst_out)?;

        let four_lanes = 4 * cost.parallelism;
        let n_blocks = (cost.memory / four_lanes) * four_lanes;
        let lane_len = n_blocks / cost.parallelism;
        // segment_lengt := lane_length / 4
        let segment_length = lane_len >> 2;

        let mut blocks: Vec<[u64; 128]> = vec![[0u64; 128]; n_blocks as usize];

        let mut h0 = initial_hash(
            version,
            cost.parallelism,
            V::VALUE,
            dst_out.len() as u32,
            cost.memory,
            cost.iterations,
            password,
            salt,
            secret.unwrap_or(&[]),
            ad.unwrap_or(&[]),
        )?;
        let mut tmp = [0u8; 1024];

        for lane in 0..cost.parallelism {
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

        for pass_n in 0..cost.iterations as usize {
            for segment_n in 0..SEGMENTS_PER_LANE {
                let offset = match (pass_n, segment_n) {
                    (0, 0) => 2, // The first two blocks have already been processed
                    _ => 0,
                };

                let use_gidx = is_data_independent(V::VALUE, pass_n as u32, segment_n);

                for lane in 0..cost.parallelism {
                    // Argon2id only requires this in first round
                    let mut gidx: Option<Gidx> = if use_gidx {
                        let mut gidx = Gidx::new(V::VALUE, n_blocks, cost.iterations, lane);
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
                            let previous = blocks[previous_idx][0];
                            (previous & (u32::MAX as u64), previous >> 32)
                        };

                        let (reference_lane, reference_idx) = reference_idx(
                            j1_idx,
                            j2_idx,
                            cost.parallelism,
                            lane,
                            lane_len,
                            pass_n as u32,
                            segment_n as u32,
                            segment_idx,
                            segment_length,
                        );
                        let reference_idx = (reference_lane * lane_len + reference_idx) as usize;

                        if let (Some(prev_b), Some(ref_b)) =
                            (blocks.get(previous_idx), blocks.get(reference_idx))
                        {
                            // G-xor operation
                            for (el_tmp, (el_prev, el_ref)) in working_block
                                .iter_mut()
                                .zip(prev_b.iter().zip(ref_b.iter()))
                            {
                                *el_tmp = el_prev ^ el_ref;
                            }
                            let cur_b = blocks.get_mut(current_idx).unwrap();
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
        for lane in 0..cost.parallelism {
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
        cost: &CostParams,
        secret: Option<&[u8]>,
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        Self::derive_key(password, salt, cost, secret, ad, dst_out)?;
        crate::util::secure_cmp(dst_out, expected)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_memory_requirements() {
        assert!(CostParams::check_minimum_memory(7, 1).is_err()); // below min by 1
        assert!(CostParams::check_minimum_memory(8, 1).is_ok()); // min

        assert!(CostParams::check_minimum_memory(15, 2).is_err()); // below min by 1
        assert!(CostParams::check_minimum_memory(16, 2).is_ok()); // min

        assert!(CostParams::check_minimum_memory(8, u32::MAX).is_err()); // overflows (and invalid parallelism)
        assert!(CostParams::check_minimum_memory(MAX_MEMORY_M, MAX_PARALLELISM_P).is_ok());
    }

    #[test]
    fn test_validate_parameters_passes_parallelism() {
        assert!(CostParams::new(MIN_ITERATIONS_T - 1, 8, 1,).is_err());
        assert!(CostParams::new(MIN_ITERATIONS_T, 8, 1,).is_ok());
        assert!(CostParams::new(MAX_ITERATIONS_T, 8, 1,).is_ok());

        assert!(CostParams::new(MIN_ITERATIONS_T, 8, MIN_PARALLELISM_P - 1,).is_err());
        assert!(CostParams::new(MIN_ITERATIONS_T, 8, MIN_PARALLELISM_P,).is_ok());
        assert!(
            CostParams::new(MIN_ITERATIONS_T, MAX_PARALLELISM_P * 8, MAX_PARALLELISM_P,).is_ok()
        );

        let mut tmp = [0u8; 16];
        assert!(
            validate_parameters(ARGON2_VERSION_19, &[], &[0u8; 7], None, None, &mut tmp).is_err()
        );
        assert!(
            validate_parameters(ARGON2_VERSION_19, &[], &[0u8; 9], None, None, &mut tmp).is_ok()
        );
    }
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[cfg(feature = "safe_api")]
    mod test_passwordhash {
        use super::*;

        #[test]
        #[cfg(feature = "safe_api")]
        fn test_debug_impl() {
            let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let password_hash = PasswordHash::try_from(valid).unwrap();
            let debug = format!("{password_hash:?}");
            let expected = "PasswordHash {***OMITTED***}";
            assert_eq!(debug, expected);

            let valid = "$argon2id$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let password_hash = PasswordHash::try_from(valid).unwrap();
            let debug = format!("{password_hash:?}");
            let expected = "PasswordHash {***OMITTED***}";
            assert_eq!(debug, expected);
        }

        #[test]
        fn test_password_hash_eq() {
            let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            let password_hash = PasswordHash::try_from(valid.as_bytes()).unwrap();
            assert_eq!(password_hash.len(), valid.len());
            assert_eq!(password_hash.unprotected_as_ref(), valid.as_bytes());
            assert_eq!(
                password_hash,
                PasswordHash::try_from(valid.as_bytes()).unwrap()
            );

            let password_hash_again =
                PasswordHash::try_from(password_hash.unprotected_as_str()).unwrap();
            assert_eq!(password_hash, password_hash_again);

            let valid = "$argon2id$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            let password_hash = PasswordHash::try_from(valid.as_bytes()).unwrap();
            assert_eq!(password_hash.len(), valid.len());
            assert_eq!(password_hash.unprotected_as_ref(), valid.as_bytes());
            assert_eq!(
                password_hash,
                PasswordHash::try_from(valid.as_bytes()).unwrap()
            );

            let password_hash_again =
                PasswordHash::try_from(password_hash.unprotected_as_str()).unwrap();
            assert_eq!(password_hash, password_hash_again);
        }

        #[test]
        fn test_password_hash_ne() {
            let valid = "$argon2i$v=19$m=65536,t=3,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
            let invalid = "$argon2i$v=19$m=65536,t=2,p=1$cHBwcHBwcHBwcHBwcHBwcA$MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";

            let password_hash = PasswordHash::try_from(valid.as_bytes()).unwrap();
            assert_ne!(password_hash.unprotected_as_ref(), invalid.as_bytes());
            assert_ne!(
                password_hash,
                PasswordHash::try_from(invalid.as_bytes()).unwrap()
            );

            let password_hash_again = PasswordHash::try_from(invalid.as_bytes()).unwrap();
            assert_ne!(password_hash, password_hash_again);
        }

        #[cfg(feature = "serde")]
        mod test_serde_impls {
            use super::*;

            #[test]
            fn test_valid_deserialization() {
                let encoded_hash = "$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$fRsRY9PAt5H+qAKuXRzL0/6JbFShsCd62W5aHzESk/c";
                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                let deserialized: PasswordHash =
                    serde_json::from_str(format!("\"{encoded_hash}\"").as_str()).unwrap();
                assert_eq!(deserialized, expected);

                let encoded_hash = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$fRsRY9PAt5H+qAKuXRzL0/6JbFShsCd62W5aHzESk/c";
                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                let deserialized: PasswordHash =
                    serde_json::from_str(format!("\"{encoded_hash}\"").as_str()).unwrap();
                assert_eq!(deserialized, expected);
            }

            #[test]
            fn test_valid_serialization() {
                let encoded_hash = "$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$fRsRY9PAt5H+qAKuXRzL0/6JbFShsCd62W5aHzESk/c";
                let hash = PasswordHash::try_from(encoded_hash).unwrap();
                let serialized: String = serde_json::to_string(&hash).unwrap();
                assert_eq!(serialized, format!("\"{encoded_hash}\""));

                let encoded_hash = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$fRsRY9PAt5H+qAKuXRzL0/6JbFShsCd62W5aHzESk/c";
                let hash = PasswordHash::try_from(encoded_hash).unwrap();
                let serialized: String = serde_json::to_string(&hash).unwrap();
                assert_eq!(serialized, format!("\"{encoded_hash}\""));
            }
        }
    }

    #[cfg(feature = "safe_api")]
    mod test_verify {
        use super::*;

        // Migration logic from orion::pwhash (0.17 -> 0.18)
        // to ensure this hazardous P-H-C implementation can
        // be used during migrationn.
        // These tests were part of orion::pwhash in 0.17.
        mod migration {
            use super::*;
            use hex;

            #[test]
            fn test_encoding_and_verify_1() {
                let password = b"password";
                let raw_hash =
                    hex::decode("7d1b1163d3c0b791fea802ae5d1ccbd3fe896c54a1b0277ad96e5a1f311293f7")
                        .unwrap();
                let encoded_hash = "$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$fRsRY9PAt5H+qAKuXRzL0/6JbFShsCd62W5aHzESk/c";

                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                assert_eq!(expected.data.hash, &raw_hash[..]);
                assert_eq!(expected.unprotected_as_ref(), encoded_hash.as_bytes());
                assert!(
                    Argon2::<I, Sequential>::verify_encoded(&expected, password, None, None)
                        .is_ok()
                );
            }

            #[test]
            fn test_encoding_and_verify_2() {
                let password = b"passwordPASSWORDPassword";
                let raw_hash =
                    hex::decode("ed4b0fd657e165f9ffe90f66ff315fbec878e629f03b2d6468d4b17a50c796aa")
                        .unwrap();
                let encoded_hash = "$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$7UsP1lfhZfn/6Q9m/zFfvsh45inwOy1kaNSxelDHlqo";

                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                assert_eq!(expected.data.hash, &raw_hash[..]);
                assert_eq!(expected.unprotected_as_ref(), encoded_hash.as_bytes());
                assert!(
                    Argon2::<I, Sequential>::verify_encoded(&expected, password, None, None)
                        .is_ok()
                );
            }

            #[test]
            fn test_encoding_and_verify_3() {
                // Different salt from test 2
                let password = b"passwordPASSWORDPassword";
                let raw_hash =
                    hex::decode("fa9ea96fecd0998251d698c1303edda4df3889a39bfa87cd5e7b8656ef61b510")
                        .unwrap();
                let encoded_hash = "$argon2i$v=19$m=65536,t=3,p=1$U29tZVNhbHRTb21lU2FsdA$+p6pb+zQmYJR1pjBMD7dpN84iaOb+ofNXnuGVu9htRA";

                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                assert_eq!(expected.data.hash, &raw_hash[..]);
                assert_eq!(expected.unprotected_as_ref(), encoded_hash.as_bytes());
                assert!(
                    Argon2::<I, Sequential>::verify_encoded(&expected, password, None, None)
                        .is_ok()
                );
            }

            #[test]
            fn test_encoding_and_verify_4() {
                let password = b"passwordPASSWORDPassword";
                let raw_hash =
                    hex::decode("fb3e0cdf7b10970bf6711c151861851566006f8986c9109ba2cdd5d98f9ca9d7")
                        .unwrap();
                let encoded_hash = "$argon2i$v=19$m=256,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$+z4M33sQlwv2cRwVGGGFFWYAb4mGyRCbos3V2Y+cqdc";

                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                assert_eq!(expected.data.hash, &raw_hash[..]);
                assert_eq!(expected.unprotected_as_ref(), encoded_hash.as_bytes());
                assert!(
                    Argon2::<I, Sequential>::verify_encoded(&expected, password, None, None)
                        .is_ok()
                );
            }

            #[test]
            fn test_encoding_and_verify_5() {
                let password = b"passwordPASSWORDPassword";
                let raw_hash =
                    hex::decode("9b134c4c1c34e66170d1088c18be3a8e0f4a1837d4c069703ce62f85248b1e8f")
                        .unwrap();
                let encoded_hash = "$argon2i$v=19$m=256,t=4,p=1$c29tZXNhbHRzb21lc2FsdA$mxNMTBw05mFw0QiMGL46jg9KGDfUwGlwPOYvhSSLHo8";

                let expected = PasswordHash::try_from(encoded_hash).unwrap();
                assert_eq!(expected.data.hash, &raw_hash[..]);
                assert_eq!(expected.unprotected_as_ref(), encoded_hash.as_bytes());
                assert!(
                    Argon2::<I, Sequential>::verify_encoded(&expected, password, None, None)
                        .is_ok()
                );
            }
        }

        #[test]
        #[cfg(feature = "safe_api")]
        fn test_variant_mismatch_fails_verify() {
            use crate::util;

            let mut salt = [0u8; 16];
            util::secure_rand_bytes(&mut salt).unwrap();

            let h_i = Argon2::<I, Sequential>::derive_key_encoded(
                b"password",
                &salt,
                &CostParams::new(1, 1 << 8, 2).unwrap(),
                None,
                None,
                32,
            )
            .unwrap();

            let h_id = Argon2::<ID, Sequential>::derive_key_encoded(
                b"password",
                &salt,
                &CostParams::new(1, 1 << 8, 2).unwrap(),
                None,
                None,
                32,
            )
            .unwrap();

            assert!(
                Argon2::<I, Sequential>::verify_encoded(&h_i, b"password", None, None,).is_ok()
            );
            assert!(
                Argon2::<I, Sequential>::verify_encoded(&h_id, b"password", None, None,).is_err()
            );
            assert!(
                Argon2::<ID, Sequential>::verify_encoded(&h_i, b"password", None, None,).is_err()
            );
            assert!(
                Argon2::<ID, Sequential>::verify_encoded(&h_id, b"password", None, None,).is_ok()
            );
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_same_input_verify_true(
            hlen: u32,
            kib: u32,
            p: u8,
            pass: Vec<u8>,
            s: Vec<u8>,
            k: Vec<u8>,
            x: Vec<u8>,
        ) -> bool {
            let parallelism = if p > 4 || p == 0 { 1 } else { p };
            let passes = 1;
            let mem = if !(8..=4096).contains(&kib) {
                1024
            } else {
                kib
            };
            let salt = if s.len() < 8 { alloc::vec![37u8; 8] } else { s };

            let mut dst_out = if !(4..=512).contains(&hlen) {
                alloc::vec![0u8; 32]
            } else {
                alloc::vec![0u8; hlen as usize]
            };

            let cost = CostParams::new(passes, mem, parallelism as u32).unwrap();

            let mut dst_out_verify = dst_out.clone();
            Argon2::<I, Sequential>::derive_key(
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                &mut dst_out,
            )
            .unwrap();

            let argin2i_result = Argon2::<I, Sequential>::verify(
                &dst_out,
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                &mut dst_out_verify,
            )
            .is_ok();

            Argon2::<ID, Sequential>::derive_key(
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                &mut dst_out,
            )
            .unwrap();

            let argin2id_result = Argon2::<ID, Sequential>::verify(
                &dst_out,
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                &mut dst_out_verify,
            )
            .is_ok();

            argin2i_result && argin2id_result
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_same_input_verify_encoded_true(
            hlen: u32,
            kib: u32,
            p: u8,
            pass: Vec<u8>,
            s: Vec<u8>,
            k: Vec<u8>,
            x: Vec<u8>,
        ) -> bool {
            let parallelism = if p > 4 || p == 0 { 1 } else { p };
            let passes = 1;
            let mem = if !(8..=4096).contains(&kib) {
                1024
            } else {
                kib
            };
            let salt = if s.len() < 8 { alloc::vec![37u8; 8] } else { s };

            let hlen = if !(4..=512).contains(&hlen) { 32 } else { hlen };
            let cost = CostParams::new(passes, mem, parallelism as u32).unwrap();

            let h = Argon2::<I, Sequential>::derive_key_encoded(
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                hlen as usize,
            )
            .unwrap();

            let argin2i_result =
                Argon2::<I, Sequential>::verify_encoded(&h, &pass, Some(&k), Some(&x)).is_ok();

            let h = Argon2::<ID, Sequential>::derive_key_encoded(
                &pass,
                &salt,
                &cost,
                Some(&k),
                Some(&x),
                hlen as usize,
            )
            .unwrap();

            let argin2id_result =
                Argon2::<ID, Sequential>::verify_encoded(&h, &pass, Some(&k), Some(&x)).is_ok();

            argin2i_result && argin2id_result
        }
    }

    mod test_derive_key {
        use super::*;

        #[test]
        fn test_dst_out() {
            let mut dst_out_less = [0u8; 3];
            let mut dst_out_exact = [0u8; 4];
            let mut dst_out_above = [0u8; 5];
            let cost = CostParams::new(1, 8, 1).unwrap();
            assert!(
                Argon2::<I, Sequential>::derive_key(
                    &[],
                    &[0u8; 8],
                    &cost,
                    None,
                    None,
                    &mut dst_out_less
                )
                .is_err()
            );
            assert!(
                Argon2::<I, Sequential>::derive_key(
                    &[],
                    &[0u8; 8],
                    &cost,
                    None,
                    None,
                    &mut dst_out_exact
                )
                .is_ok()
            );
            assert!(
                Argon2::<I, Sequential>::derive_key(
                    &[],
                    &[0u8; 8],
                    &cost,
                    None,
                    None,
                    &mut dst_out_above
                )
                .is_ok()
            );
        }

        #[test]
        fn test_some_or_none_same_result() {
            let mut dst_one = [0u8; 32];
            let mut dst_two = [0u8; 32];
            let cost = CostParams::new(1, 8, 1).unwrap();
            Argon2::<I, Sequential>::derive_key(
                &[255u8; 16],
                &[1u8; 16],
                &cost,
                None,
                None,
                &mut dst_one,
            )
            .unwrap();
            Argon2::<I, Sequential>::derive_key(
                &[255u8; 16],
                &[1u8; 16],
                &cost,
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
            Argon2::<I, Sequential>::derive_key(
                &p,
                &s,
                &CostParams::new(passes, mem, 1).unwrap(),
                Some(&k),
                Some(&x),
                &mut actual,
            )
            .unwrap();

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
            Argon2::<I, Sequential>::derive_key(
                &p,
                &s,
                &CostParams::new(passes, mem, 1).unwrap(),
                Some(&k),
                Some(&x),
                &mut actual,
            )
            .unwrap();

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
            Argon2::<I, Sequential>::derive_key(
                &p,
                &s,
                &CostParams::new(passes, mem, 1).unwrap(),
                Some(&k),
                Some(&x),
                &mut actual,
            )
            .unwrap();

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
            Argon2::<I, Sequential>::derive_key(
                &p,
                &s,
                &CostParams::new(passes, mem, 1).unwrap(),
                Some(&k),
                Some(&x),
                &mut actual,
            )
            .unwrap();

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
            Argon2::<I, Sequential>::derive_key(
                &p,
                &s,
                &CostParams::new(passes, mem, 1).unwrap(),
                Some(&k),
                Some(&x),
                &mut actual,
            )
            .unwrap();

            assert_eq!(expected.len(), actual.len());
            assert_eq!(expected.as_ref(), &actual[..]);
        }
    }
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
    use super::*;

    mod test_initial_hash_argon2i {
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
            let actual = initial_hash(
                ARGON2_VERSION_19,
                1,
                ARGON2_I_VARIANT,
                hlen,
                kib,
                passes,
                &p,
                &s,
                &k,
                &x,
            )
            .unwrap();
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
            let actual = initial_hash(
                ARGON2_VERSION_19,
                1,
                ARGON2_I_VARIANT,
                hlen,
                kib,
                passes,
                &p,
                &s,
                &k,
                &x,
            )
            .unwrap();
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
            let actual = initial_hash(
                ARGON2_VERSION_19,
                1,
                ARGON2_I_VARIANT,
                hlen,
                kib,
                passes,
                &p,
                &s,
                &k,
                &x,
            )
            .unwrap();
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
            let first = initial_hash(
                ARGON2_VERSION_19,
                1,
                ARGON2_I_VARIANT,
                hlen,
                kib,
                passes,
                &p,
                &s,
                &k,
                &x,
            )
            .unwrap();
            let second = initial_hash(
                ARGON2_VERSION_19,
                1,
                ARGON2_I_VARIANT,
                hlen,
                kib,
                passes,
                &p,
                &s,
                &k,
                &x,
            )
            .unwrap();

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
            if out.len() < 4 {
                return true;
            }

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
            if out.len() < 4 {
                return true;
            }

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
