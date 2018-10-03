// MIT License

// Copyright 2016 chacha20-poly1305-aead Developers
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

//! # Parameters:
//!
//! # Exceptions:
//! An exception will be thrown if:
//! - `one_time_key` is not 32 bytes
//! - `msg_block` is not 16 bytes
//! - `final_msg_block` is greater than 16 bytes
//! - `finalize()` is called twice without a `reset()` in between
//! - `update()` is called after `finalize()` without a `reset()` in between
//! - `message` is empty
//!
//! # Security:
//!
//! # Example:
//! ```
//! ```

use byteorder::{ByteOrder, LittleEndian};
use hazardous::constants::{Poly1305Tag, POLY1305_BLOCKSIZE};
use seckey::zero;
use utilities::{errors::*, util};

pub struct Poly1305 {
    a: [u32; 5],
    r: [u32; 5],
    s: [u32; 4],
    is_finalized: bool,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        zero(&mut self.a);
        zero(&mut self.r);
        zero(&mut self.s)
    }
}

impl Poly1305 {
    #[inline(never)]
    fn accumulate(&mut self, n0: u32, n1: u32, n2: u32, n3: u32, n4: u32) {
        self.a[0] += n0;
        self.a[1] += n1;
        self.a[2] += n2;
        self.a[3] += n3;
        self.a[4] += n4;
        self.mul_r_mod_p();
    }

    #[inline(never)]
    fn mul_r_mod_p(&mut self) {
        // t = r * a; high limbs multiplied by 5 and added to low limbs
        let mut t = [0; 5];

        t[0] += self.r[0] as u64 * self.a[0] as u64;
        t[1] += self.r[0] as u64 * self.a[1] as u64;
        t[2] += self.r[0] as u64 * self.a[2] as u64;
        t[3] += self.r[0] as u64 * self.a[3] as u64;
        t[4] += self.r[0] as u64 * self.a[4] as u64;

        t[0] += (5 * self.r[1]) as u64 * self.a[4] as u64;
        t[1] += self.r[1] as u64 * self.a[0] as u64;
        t[2] += self.r[1] as u64 * self.a[1] as u64;
        t[3] += self.r[1] as u64 * self.a[2] as u64;
        t[4] += self.r[1] as u64 * self.a[3] as u64;

        t[0] += (5 * self.r[2]) as u64 * self.a[3] as u64;
        t[1] += (5 * self.r[2]) as u64 * self.a[4] as u64;
        t[2] += self.r[2] as u64 * self.a[0] as u64;
        t[3] += self.r[2] as u64 * self.a[1] as u64;
        t[4] += self.r[2] as u64 * self.a[2] as u64;

        t[0] += (5 * self.r[3]) as u64 * self.a[2] as u64;
        t[1] += (5 * self.r[3]) as u64 * self.a[3] as u64;
        t[2] += (5 * self.r[3]) as u64 * self.a[4] as u64;
        t[3] += self.r[3] as u64 * self.a[0] as u64;
        t[4] += self.r[3] as u64 * self.a[1] as u64;

        t[0] += (5 * self.r[4]) as u64 * self.a[1] as u64;
        t[1] += (5 * self.r[4]) as u64 * self.a[2] as u64;
        t[2] += (5 * self.r[4]) as u64 * self.a[3] as u64;
        t[3] += (5 * self.r[4]) as u64 * self.a[4] as u64;
        t[4] += self.r[4] as u64 * self.a[0] as u64;

        // propagate carries
        t[1] += t[0] >> 26;
        t[2] += t[1] >> 26;
        t[3] += t[2] >> 26;
        t[4] += t[3] >> 26;

        // mask out carries
        self.a[0] = t[0] as u32 & 0x03ffffff;
        self.a[1] = t[1] as u32 & 0x03ffffff;
        self.a[2] = t[2] as u32 & 0x03ffffff;
        self.a[3] = t[3] as u32 & 0x03ffffff;
        self.a[4] = t[4] as u32 & 0x03ffffff;

        // propagate high limb carry
        self.a[0] += (t[4] >> 26) as u32 * 5;
        self.a[1] += self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;

        // A carry of at most 1 bit has been left in self.a[1]
    }

    #[inline(never)]
    fn propagate_carries(&mut self) {
        // propagate carries
        self.a[2] += self.a[1] >> 26;
        self.a[3] += self.a[2] >> 26;
        self.a[4] += self.a[3] >> 26;
        self.a[0] += (self.a[4] >> 26) * 5;
        self.a[1] += self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;
        self.a[1] &= 0x03ffffff;
        self.a[2] &= 0x03ffffff;
        self.a[3] &= 0x03ffffff;
        self.a[4] &= 0x03ffffff;
    }

    #[inline(never)]
    fn reduce_mod_p(&mut self) {
        self.propagate_carries();

        let mut t = self.a;

        // t = a - p
        t[0] += 5;
        t[4] = t[4].wrapping_sub(1 << 26);

        // propagate carries
        t[1] += t[0] >> 26;
        t[2] += t[1] >> 26;
        t[3] += t[2] >> 26;
        t[4] = t[4].wrapping_add(t[3] >> 26);

        // mask out carries
        t[0] &= 0x03ffffff;
        t[1] &= 0x03ffffff;
        t[2] &= 0x03ffffff;
        t[3] &= 0x03ffffff;

        // constant-time select between (a - p) if non-negative, (a) otherwise
        let mask = (t[4] >> 31).wrapping_sub(1);
        self.a[0] = t[0] & mask | self.a[0] & !mask;
        self.a[1] = t[1] & mask | self.a[1] & !mask;
        self.a[2] = t[2] & mask | self.a[2] & !mask;
        self.a[3] = t[3] & mask | self.a[3] & !mask;
        self.a[4] = t[4] & mask | self.a[4] & !mask;
    }

    #[inline(never)]
    /// Generate a non-serialzed tag.
    fn generate_tag(&mut self) -> [u32; 4] {
        self.reduce_mod_p();

        // convert from 5x26-bit to 4x32-bit
        let a = [
            self.a[0] | self.a[1] << 26,
            self.a[1] >> 6 | self.a[2] << 20,
            self.a[2] >> 12 | self.a[3] << 14,
            self.a[3] >> 18 | self.a[4] << 8,
        ];

        // t = a + s
        let mut tag = [
            a[0] as u64 + self.s[0] as u64,
            a[1] as u64 + self.s[1] as u64,
            a[2] as u64 + self.s[2] as u64,
            a[3] as u64 + self.s[3] as u64,
        ];

        // propagate carries
        tag[1] += tag[0] >> 32;
        tag[2] += tag[1] >> 32;
        tag[3] += tag[2] >> 32;

        // mask out carries
        [
            (tag[0] as u32).to_le(),
            (tag[1] as u32).to_le(),
            (tag[2] as u32).to_le(),
            (tag[3] as u32).to_le(),
        ]
    }

    #[inline(always)]
    /// The Poly1305 function to clamp `r`.
    fn clamp(&mut self, key: &[u8]) -> Result<(), UnknownCryptoError> {
        if key.len() != 32 {
            return Err(UnknownCryptoError);
        }
        // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.r[0] = (LittleEndian::read_u32(&key[0..4])) & 0x3ffffff;
        self.r[1] = (LittleEndian::read_u32(&key[3..7]) >> 2) & 0x3ffff03;
        self.r[2] = (LittleEndian::read_u32(&key[6..10]) >> 4) & 0x3ffc0ff;
        self.r[3] = (LittleEndian::read_u32(&key[9..13]) >> 6) & 0x3f03fff;
        self.r[4] = (LittleEndian::read_u32(&key[12..16]) >> 8) & 0x00fffff;

        Ok(())
    }
    #[inline(always)]
    /// Read `s` from a given key.
    fn read_s(&mut self, key: &[u8]) -> Result<(), UnknownCryptoError> {
        if key.len() != 32 {
            return Err(UnknownCryptoError);
        }

        self.s[0] = LittleEndian::read_u32(&key[16..20]);
        self.s[1] = LittleEndian::read_u32(&key[20..24]);
        self.s[2] = LittleEndian::read_u32(&key[24..28]);
        self.s[3] = LittleEndian::read_u32(&key[28..32]);

        Ok(())
    }
    #[inline(always)]
    /// Reset to `init()` state.
    pub fn reset(&mut self) {
        if self.is_finalized {
            self.a = [0u32; 5];
            self.is_finalized = false;
        } else {
            ()
        }
    }
    #[inline(always)]
    /// Update with a message block of `POLY1305_BLOCKSIZE` length.
    fn update_message_block(&mut self, msg_block: &[u8]) -> Result<(), UnknownCryptoError> {
        if msg_block.len() != POLY1305_BLOCKSIZE {
            return Err(UnknownCryptoError);
        }

        self.accumulate(
            LittleEndian::read_u32(&msg_block[0..4]) & 0x03ffffff,
            LittleEndian::read_u32(&msg_block[3..7]) >> 2 & 0x03ffffff,
            LittleEndian::read_u32(&msg_block[6..10]) >> 4 & 0x03ffffff,
            LittleEndian::read_u32(&msg_block[9..13]) >> 6 & 0x03ffffff,
            LittleEndian::read_u32(&msg_block[12..16]) >> 8 | (1 << 24),
        );

        Ok(())
    }
    #[inline(always)]
    /// Update with the last message block that is `<= POLY1305_BLOCKSIZE` length.
    fn update_final_message_block(
        &mut self,
        final_msg_block: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        if final_msg_block.len() > POLY1305_BLOCKSIZE {
            return Err(UnknownCryptoError);
        }

        let mut buf = [0u8; 17];
        buf[..final_msg_block.len()].clone_from_slice(final_msg_block);
        buf[final_msg_block.len()] = 1;

        self.accumulate(
            LittleEndian::read_u32(&buf[0..4]) & 0x03ffffff,
            LittleEndian::read_u32(&buf[3..7]) >> 2 & 0x03ffffff,
            LittleEndian::read_u32(&buf[6..10]) >> 4 & 0x03ffffff,
            LittleEndian::read_u32(&buf[9..13]) >> 6 & 0x03ffffff,
            LittleEndian::read_u32(&buf[13..17]),
        );

        Ok(())
    }
    #[inline(always)]
    /// Update state with a message block that is 16 bytes. This can be called multiple times.
    pub fn update(&mut self, msg_block: &[u8]) -> Result<(), FinalizationCryptoError> {
        if self.is_finalized {
            return Err(FinalizationCryptoError);
        }

        self.update_message_block(msg_block).unwrap();

        Ok(())
    }
    #[inline(always)]
    /// Retrive a Poly1305 tag with the last message block.
    pub fn finalize(
        &mut self,
        final_msg_block: &[u8],
    ) -> Result<Poly1305Tag, FinalizationCryptoError> {
        if self.is_finalized {
            return Err(FinalizationCryptoError);
        }

        self.is_finalized = true;
        let mut serialized_tag: Poly1305Tag = [0u8; 16];

        if final_msg_block.is_empty() {
            LittleEndian::write_u32_into(&self.generate_tag(), &mut serialized_tag);
        } else {
            self.update_final_message_block(final_msg_block).unwrap();
            LittleEndian::write_u32_into(&self.generate_tag(), &mut serialized_tag);
        }

        Ok(serialized_tag)
    }
}

/// Initialize `Poly1305` struct with a given one-time key.
pub fn init(one_time_key: &[u8]) -> Result<Poly1305, UnknownCryptoError> {
    if one_time_key.len() != 32 {
        return Err(UnknownCryptoError);
    }

    let mut poly_1305 = Poly1305 {
        a: [0u32; 5],
        r: [0u32; 5],
        s: [0u32; 4],
        is_finalized: false,
    };

    poly_1305.clamp(one_time_key).unwrap();
    poly_1305.read_s(one_time_key).unwrap();

    Ok(poly_1305)
}

/// One-shot function for generating a Poly1305 tag of a message.
pub fn poly1305(one_time_key: &[u8], message: &[u8]) -> Result<Poly1305Tag, UnknownCryptoError> {
    if message.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut poly_1305_state = init(one_time_key).unwrap();
    let mut poly_1305_tag: Poly1305Tag = [0u8; 16];

    for message_chunk in message.chunks(POLY1305_BLOCKSIZE) {
        if message_chunk.len() == POLY1305_BLOCKSIZE {
            poly_1305_state.update(message_chunk).unwrap();
        } else {
            poly_1305_tag = poly_1305_state.finalize(message_chunk).unwrap();
        }
    }

    Ok(poly_1305_tag)
}

/// Verify a Poly1305 tag in constant time.
pub fn verify(
    expected: &[u8],
    one_time_key: &[u8],
    message: &[u8],
) -> Result<bool, ValidationCryptoError> {
    let tag = poly1305(one_time_key, message).unwrap();

    if util::compare_ct(&tag, expected).is_err() {
        Err(ValidationCryptoError)
    } else {
        Ok(true)
    }
}


#[test]
fn test_init_wrong_key_len() {
    assert!(init(&[0u8; 31]).is_err());
    assert!(init(&[0u8; 33]).is_err());
    assert!(init(&[0u8; 32]).is_ok());
}

#[test]
#[should_panic]
fn test_update_wrong_block_len_greater() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 17]).unwrap();
}

#[test]
#[should_panic]
fn test_update_wrong_block_len_greater_less() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 15]).unwrap();
}

#[test]
#[should_panic]
fn test_finalize_wrong_block_len_greater() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 17]).unwrap();
}

#[test]
fn test_poly1305_oneshot_ok() {
    assert!(poly1305(&[0u8; 32], &[0u8; 16]).is_ok());
}

#[test]
#[should_panic]
fn test_poly1305_oneshot_bad_key_err_less() {
    poly1305(&[0u8; 31], &[0u8; 16]).unwrap();
}

#[test]
#[should_panic]
fn test_poly1305_oneshot_bad_key_err_greater() {
    poly1305(&[0u8; 33], &[0u8; 16]).unwrap();
}

#[test]
#[should_panic]
fn test_poly1305_oneshot_bad_msg_err() {
    poly1305(&[0u8; 32], &[0u8; 0]).unwrap();
}

#[test]
#[should_panic]
fn double_finalize_err() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
}

#[test]
fn double_finalize_with_reset_ok() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
    poly1305_state.reset();
    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
}

#[test]
fn double_finalize_with_reset_no_update_ok() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
    poly1305_state.reset();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
}

#[test]
#[should_panic]
fn update_after_finalize_err() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
    poly1305_state.update(&[0u8; 16]).unwrap();
}

#[test]
fn update_after_finalize_with_reset_ok() {
    let mut poly1305_state = init(&[0u8; 32]).unwrap();

    poly1305_state.update(&[0u8; 16]).unwrap();
    poly1305_state.finalize(&[0u8; 11]).unwrap();
    poly1305_state.reset();
    poly1305_state.update(&[0u8; 16]).unwrap();
}
