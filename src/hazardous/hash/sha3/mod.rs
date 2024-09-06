// MIT License

// Copyright (c) 2023-2024 The orion Developers

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

/// SHA3-224 as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod sha3_224;

/// SHA3-256 as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod sha3_256;

/// SHA3-384 as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod sha3_384;

/// SHA3-512 as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod sha3_512;

/// SHAKE-128 XOF as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod shake128;

/// SHAKE-256 XOF as specified in the [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf).
pub mod shake256;

use crate::errors::UnknownCryptoError;
use core::fmt::Debug;
use zeroize::Zeroize;

/// Round constants. See NIST intermediate test vectors for source.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rho offsets. See NIST intermediate test vectors for source.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Indices precomputed based on spec of Pi.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccakf<const ROUNDS: usize>(state: &mut [u64; 25]) {
    for round in 0..ROUNDS {
        let mut buf = [0u64; 5];

        theta(state, &mut buf);
        rho_and_pi(state, &mut buf);
        chi(state, &mut buf);
        iota(state, round);
    }
}

#[allow(clippy::erasing_op)]
#[allow(clippy::identity_op)]
// Theta (θ).
fn theta(state: &mut [u64; 25], buf: &mut [u64; 5]) {
    buf[0] ^= state[0 + (0 * 5)];
    buf[0] ^= state[0 + (1 * 5)];
    buf[0] ^= state[0 + (2 * 5)];
    buf[0] ^= state[0 + (3 * 5)];
    buf[0] ^= state[0 + (4 * 5)];

    buf[1] ^= state[1 + (0 * 5)];
    buf[1] ^= state[1 + (1 * 5)];
    buf[1] ^= state[1 + (2 * 5)];
    buf[1] ^= state[1 + (3 * 5)];
    buf[1] ^= state[1 + (4 * 5)];

    buf[2] ^= state[2 + (0 * 5)];
    buf[2] ^= state[2 + (1 * 5)];
    buf[2] ^= state[2 + (2 * 5)];
    buf[2] ^= state[2 + (3 * 5)];
    buf[2] ^= state[2 + (4 * 5)];

    buf[3] ^= state[3 + (0 * 5)];
    buf[3] ^= state[3 + (1 * 5)];
    buf[3] ^= state[3 + (2 * 5)];
    buf[3] ^= state[3 + (3 * 5)];
    buf[3] ^= state[3 + (4 * 5)];

    buf[4] ^= state[4 + (0 * 5)];
    buf[4] ^= state[4 + (1 * 5)];
    buf[4] ^= state[4 + (2 * 5)];
    buf[4] ^= state[4 + (3 * 5)];
    buf[4] ^= state[4 + (4 * 5)];

    state[(0 * 5) + 0] ^= buf[(0 + 4) % 5] ^ buf[(0 + 1) % 5].rotate_left(1);
    state[(1 * 5) + 0] ^= buf[(0 + 4) % 5] ^ buf[(0 + 1) % 5].rotate_left(1);
    state[(2 * 5) + 0] ^= buf[(0 + 4) % 5] ^ buf[(0 + 1) % 5].rotate_left(1);
    state[(3 * 5) + 0] ^= buf[(0 + 4) % 5] ^ buf[(0 + 1) % 5].rotate_left(1);
    state[(4 * 5) + 0] ^= buf[(0 + 4) % 5] ^ buf[(0 + 1) % 5].rotate_left(1);

    state[(0 * 5) + 1] ^= buf[(1 + 4) % 5] ^ buf[(1 + 1) % 5].rotate_left(1);
    state[(1 * 5) + 1] ^= buf[(1 + 4) % 5] ^ buf[(1 + 1) % 5].rotate_left(1);
    state[(2 * 5) + 1] ^= buf[(1 + 4) % 5] ^ buf[(1 + 1) % 5].rotate_left(1);
    state[(3 * 5) + 1] ^= buf[(1 + 4) % 5] ^ buf[(1 + 1) % 5].rotate_left(1);
    state[(4 * 5) + 1] ^= buf[(1 + 4) % 5] ^ buf[(1 + 1) % 5].rotate_left(1);

    state[(0 * 5) + 2] ^= buf[(2 + 4) % 5] ^ buf[(2 + 1) % 5].rotate_left(1);
    state[(1 * 5) + 2] ^= buf[(2 + 4) % 5] ^ buf[(2 + 1) % 5].rotate_left(1);
    state[(2 * 5) + 2] ^= buf[(2 + 4) % 5] ^ buf[(2 + 1) % 5].rotate_left(1);
    state[(3 * 5) + 2] ^= buf[(2 + 4) % 5] ^ buf[(2 + 1) % 5].rotate_left(1);
    state[(4 * 5) + 2] ^= buf[(2 + 4) % 5] ^ buf[(2 + 1) % 5].rotate_left(1);

    state[(0 * 5) + 3] ^= buf[(3 + 4) % 5] ^ buf[(3 + 1) % 5].rotate_left(1);
    state[(1 * 5) + 3] ^= buf[(3 + 4) % 5] ^ buf[(3 + 1) % 5].rotate_left(1);
    state[(2 * 5) + 3] ^= buf[(3 + 4) % 5] ^ buf[(3 + 1) % 5].rotate_left(1);
    state[(3 * 5) + 3] ^= buf[(3 + 4) % 5] ^ buf[(3 + 1) % 5].rotate_left(1);
    state[(4 * 5) + 3] ^= buf[(3 + 4) % 5] ^ buf[(3 + 1) % 5].rotate_left(1);

    state[(0 * 5) + 4] ^= buf[(4 + 4) % 5] ^ buf[(4 + 1) % 5].rotate_left(1);
    state[(1 * 5) + 4] ^= buf[(4 + 4) % 5] ^ buf[(4 + 1) % 5].rotate_left(1);
    state[(2 * 5) + 4] ^= buf[(4 + 4) % 5] ^ buf[(4 + 1) % 5].rotate_left(1);
    state[(3 * 5) + 4] ^= buf[(4 + 4) % 5] ^ buf[(4 + 1) % 5].rotate_left(1);
    state[(4 * 5) + 4] ^= buf[(4 + 4) % 5] ^ buf[(4 + 1) % 5].rotate_left(1);
}

// Rho (ρ) & Pi (π).
fn rho_and_pi(state: &mut [u64; 25], buf: &mut [u64; 5]) {
    let mut prev = state[1];

    buf[0] = state[PI[0]];
    state[PI[0]] = prev.rotate_left(RHO[0]);
    prev = buf[0];

    buf[0] = state[PI[1]];
    state[PI[1]] = prev.rotate_left(RHO[1]);
    prev = buf[0];

    buf[0] = state[PI[2]];
    state[PI[2]] = prev.rotate_left(RHO[2]);
    prev = buf[0];

    buf[0] = state[PI[3]];
    state[PI[3]] = prev.rotate_left(RHO[3]);
    prev = buf[0];

    buf[0] = state[PI[4]];
    state[PI[4]] = prev.rotate_left(RHO[4]);
    prev = buf[0];

    buf[0] = state[PI[5]];
    state[PI[5]] = prev.rotate_left(RHO[5]);
    prev = buf[0];

    buf[0] = state[PI[6]];
    state[PI[6]] = prev.rotate_left(RHO[6]);
    prev = buf[0];

    buf[0] = state[PI[7]];
    state[PI[7]] = prev.rotate_left(RHO[7]);
    prev = buf[0];

    buf[0] = state[PI[8]];
    state[PI[8]] = prev.rotate_left(RHO[8]);
    prev = buf[0];

    buf[0] = state[PI[9]];
    state[PI[9]] = prev.rotate_left(RHO[9]);
    prev = buf[0];

    buf[0] = state[PI[10]];
    state[PI[10]] = prev.rotate_left(RHO[10]);
    prev = buf[0];

    buf[0] = state[PI[11]];
    state[PI[11]] = prev.rotate_left(RHO[11]);
    prev = buf[0];

    buf[0] = state[PI[12]];
    state[PI[12]] = prev.rotate_left(RHO[12]);
    prev = buf[0];

    buf[0] = state[PI[13]];
    state[PI[13]] = prev.rotate_left(RHO[13]);
    prev = buf[0];

    buf[0] = state[PI[14]];
    state[PI[14]] = prev.rotate_left(RHO[14]);
    prev = buf[0];

    buf[0] = state[PI[15]];
    state[PI[15]] = prev.rotate_left(RHO[15]);
    prev = buf[0];

    buf[0] = state[PI[16]];
    state[PI[16]] = prev.rotate_left(RHO[16]);
    prev = buf[0];

    buf[0] = state[PI[17]];
    state[PI[17]] = prev.rotate_left(RHO[17]);
    prev = buf[0];

    buf[0] = state[PI[18]];
    state[PI[18]] = prev.rotate_left(RHO[18]);
    prev = buf[0];

    buf[0] = state[PI[19]];
    state[PI[19]] = prev.rotate_left(RHO[19]);
    prev = buf[0];

    buf[0] = state[PI[20]];
    state[PI[20]] = prev.rotate_left(RHO[20]);
    prev = buf[0];

    buf[0] = state[PI[21]];
    state[PI[21]] = prev.rotate_left(RHO[21]);
    prev = buf[0];

    buf[0] = state[PI[22]];
    state[PI[22]] = prev.rotate_left(RHO[22]);
    prev = buf[0];

    buf[0] = state[PI[23]];
    state[PI[23]] = prev.rotate_left(RHO[23]);
}

#[allow(clippy::identity_op)]
// Chi (χ).
fn chi(state: &mut [u64; 25], buf: &mut [u64; 5]) {
    buf[0] = state[0 + 0];
    buf[1] = state[0 + 1];
    buf[2] = state[0 + 2];
    buf[3] = state[0 + 3];
    buf[4] = state[0 + 4];

    state[0 + 0] = buf[0] ^ ((!buf[(0 + 1) % 5]) & (buf[(0 + 2) % 5]));
    state[0 + 1] = buf[1] ^ ((!buf[(1 + 1) % 5]) & (buf[(1 + 2) % 5]));
    state[0 + 2] = buf[2] ^ ((!buf[(2 + 1) % 5]) & (buf[(2 + 2) % 5]));
    state[0 + 3] = buf[3] ^ ((!buf[(3 + 1) % 5]) & (buf[(3 + 2) % 5]));
    state[0 + 4] = buf[4] ^ ((!buf[(4 + 1) % 5]) & (buf[(4 + 2) % 5]));

    buf[0] = state[5 + 0];
    buf[1] = state[5 + 1];
    buf[2] = state[5 + 2];
    buf[3] = state[5 + 3];
    buf[4] = state[5 + 4];

    state[5 + 0] = buf[0] ^ ((!buf[(0 + 1) % 5]) & (buf[(0 + 2) % 5]));
    state[5 + 1] = buf[1] ^ ((!buf[(1 + 1) % 5]) & (buf[(1 + 2) % 5]));
    state[5 + 2] = buf[2] ^ ((!buf[(2 + 1) % 5]) & (buf[(2 + 2) % 5]));
    state[5 + 3] = buf[3] ^ ((!buf[(3 + 1) % 5]) & (buf[(3 + 2) % 5]));
    state[5 + 4] = buf[4] ^ ((!buf[(4 + 1) % 5]) & (buf[(4 + 2) % 5]));

    buf[0] = state[10 + 0];
    buf[1] = state[10 + 1];
    buf[2] = state[10 + 2];
    buf[3] = state[10 + 3];
    buf[4] = state[10 + 4];

    state[10 + 0] = buf[0] ^ ((!buf[(0 + 1) % 5]) & (buf[(0 + 2) % 5]));
    state[10 + 1] = buf[1] ^ ((!buf[(1 + 1) % 5]) & (buf[(1 + 2) % 5]));
    state[10 + 2] = buf[2] ^ ((!buf[(2 + 1) % 5]) & (buf[(2 + 2) % 5]));
    state[10 + 3] = buf[3] ^ ((!buf[(3 + 1) % 5]) & (buf[(3 + 2) % 5]));
    state[10 + 4] = buf[4] ^ ((!buf[(4 + 1) % 5]) & (buf[(4 + 2) % 5]));

    buf[0] = state[15 + 0];
    buf[1] = state[15 + 1];
    buf[2] = state[15 + 2];
    buf[3] = state[15 + 3];
    buf[4] = state[15 + 4];

    state[15 + 0] = buf[0] ^ ((!buf[(0 + 1) % 5]) & (buf[(0 + 2) % 5]));
    state[15 + 1] = buf[1] ^ ((!buf[(1 + 1) % 5]) & (buf[(1 + 2) % 5]));
    state[15 + 2] = buf[2] ^ ((!buf[(2 + 1) % 5]) & (buf[(2 + 2) % 5]));
    state[15 + 3] = buf[3] ^ ((!buf[(3 + 1) % 5]) & (buf[(3 + 2) % 5]));
    state[15 + 4] = buf[4] ^ ((!buf[(4 + 1) % 5]) & (buf[(4 + 2) % 5]));

    buf[0] = state[20 + 0];
    buf[1] = state[20 + 1];
    buf[2] = state[20 + 2];
    buf[3] = state[20 + 3];
    buf[4] = state[20 + 4];

    state[20 + 0] = buf[0] ^ ((!buf[(0 + 1) % 5]) & (buf[(0 + 2) % 5]));
    state[20 + 1] = buf[1] ^ ((!buf[(1 + 1) % 5]) & (buf[(1 + 2) % 5]));
    state[20 + 2] = buf[2] ^ ((!buf[(2 + 1) % 5]) & (buf[(2 + 2) % 5]));
    state[20 + 3] = buf[3] ^ ((!buf[(3 + 1) % 5]) & (buf[(3 + 2) % 5]));
    state[20 + 4] = buf[4] ^ ((!buf[(4 + 1) % 5]) & (buf[(4 + 2) % 5]));
}

// Iota (ι).
fn iota(state: &mut [u64; 25], round: usize) {
    debug_assert!(round <= 24);
    state[0] ^= RC[round];
}

// <https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt>
#[test]
fn test_full_round() {
    let mut state = [0u64; 25];
    let expected_state_from_zero = [
        0xF1258F7940E1DDE7,
        0x84D5CCF933C0478A,
        0xD598261EA65AA9EE,
        0xBD1547306F80494D,
        0x8B284E056253D057,
        0xFF97A42D7F8E6FD4,
        0x90FEE5A0A44647C4,
        0x8C5BDA0CD6192E76,
        0xAD30A6F71B19059C,
        0x30935AB7D08FFC64,
        0xEB5AA93F2317D635,
        0xA9A6E6260D712103,
        0x81A57C16DBCF555F,
        0x43B831CD0347C826,
        0x01F22F1A11A5569F,
        0x05E5635A21D9AE61,
        0x64BEFEF28CC970F2,
        0x613670957BC46611,
        0xB87C5A554FD00ECB,
        0x8C3EE88A1CCF32C8,
        0x940C7922AE3A2614,
        0x1841F924A2C509E4,
        0x16F53526E70465C2,
        0x75F644E97F30A13B,
        0xEAF1FF7B5CECA249,
    ];
    let expected_state_rerun = [
        0x2D5C954DF96ECB3C,
        0x6A332CD07057B56D,
        0x093D8D1270D76B6C,
        0x8A20D9B25569D094,
        0x4F9C4F99E5E7F156,
        0xF957B9A2DA65FB38,
        0x85773DAE1275AF0D,
        0xFAF4F247C3D810F7,
        0x1F1B9EE6F79A8759,
        0xE4FECC0FEE98B425,
        0x68CE61B6B9CE68A1,
        0xDEEA66C4BA8F974F,
        0x33C43D836EAFB1F5,
        0xE00654042719DBD9,
        0x7CF8A9F009831265,
        0xFD5449A6BF174743,
        0x97DDAD33D8994B40,
        0x48EAD5FC5D0BE774,
        0xE3B8C8EE55B7B03C,
        0x91A0226E649E42E9,
        0x900E3129E7BADD7B,
        0x202A9EC5FAA3CCE8,
        0x5B3402464E1C3DB6,
        0x609F4E62A44C1059,
        0x20D06CD26A8FBF5C,
    ];

    keccakf::<24>(&mut state);
    assert_eq!(&state, &expected_state_from_zero);
    keccakf::<24>(&mut state);
    assert_eq!(&state, &expected_state_rerun);
}

#[derive(Clone)]
/// SHA3 streaming state.
pub(crate) struct Sha3<const RATE: usize> {
    pub(crate) state: [u64; 25],
    pub(crate) buffer: [u8; RATE],
    pub(crate) capacity: usize,
    leftover: usize,
    is_finalized: bool,
}

impl<const RATE: usize> Drop for Sha3<RATE> {
    fn drop(&mut self) {
        self.state.iter_mut().zeroize();
        self.buffer.iter_mut().zeroize();
        self.leftover.zeroize();
    }
}

impl<const RATE: usize> Debug for Sha3<RATE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "State {{ state: [***OMITTED***], buffer: [***OMITTED***], capacity: {:?}, leftover: {:?}, \
            is_finalized: {:?} }}",
            self.capacity, self.leftover, self.is_finalized
        )
    }
}

impl<const RATE: usize> Sha3<RATE> {
    /// Initialize a new state.
    /// `capacity` should be in bytes.
    pub(crate) fn _new(capacity: usize) -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; RATE],
            capacity,
            leftover: 0,
            is_finalized: false,
        }
    }

    /// Process data in `self.buffer` or optionally `data`.
    pub(crate) fn process_block(&mut self, data: Option<&[u8]>) {
        // If `data.is_none()` then we want to process leftover data within `self.buffer`.
        let data_block = match data {
            Some(bytes) => {
                debug_assert_eq!(bytes.len(), RATE);
                bytes
            }
            None => &self.buffer,
        };

        debug_assert_eq!(data_block.len() % 8, 0);

        // We process data in terms of bitrate, but we need to XOR in an entire Keccak state.
        // So the 25 - bitrate values will be zero. That's the same as not XORing those values
        // so we leave it be as this.
        for (b, s) in data_block
            .chunks_exact(size_of::<u64>())
            .zip(self.state.iter_mut())
        {
            *s ^= u64::from_le_bytes(b.try_into().unwrap());
        }

        keccakf::<24>(&mut self.state);
    }

    /// Reset to `new()` state.
    pub(crate) fn _reset(&mut self) {
        self.state = [0u64; 25];
        self.buffer = [0u8; RATE];
        self.leftover = 0;
        self.is_finalized = false;
    }

    /// Update state with `data`. This can be called multiple times.
    pub(crate) fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }
        if data.is_empty() {
            return Ok(());
        }

        let mut bytes = data;

        if self.leftover != 0 {
            debug_assert!(self.leftover <= RATE);

            let mut want = RATE - self.leftover;
            if want > bytes.len() {
                want = bytes.len();
            }

            for (idx, itm) in bytes.iter().enumerate().take(want) {
                self.buffer[self.leftover + idx] = *itm;
            }

            bytes = &bytes[want..];
            self.leftover += want;

            if self.leftover < RATE {
                return Ok(());
            }

            self.process_block(None);
            self.leftover = 0;
        }

        while bytes.len() >= RATE {
            self.process_block(Some(bytes[..RATE].as_ref()));
            bytes = &bytes[RATE..];
        }

        if !bytes.is_empty() {
            debug_assert_eq!(self.leftover, 0);
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.leftover = bytes.len();
        }

        Ok(())
    }

    /// Finalize the hash and put the final digest into `dest`.
    pub(crate) fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }

        self.is_finalized = true;
        // self.leftover should not be greater than SHA3(256/384/512)_RATE
        // as that would have been processed in the update call
        debug_assert!(self.leftover < RATE);
        // Set padding byte and pad with zeroes after
        self.buffer[self.leftover] = 0x06;
        self.leftover += 1;
        for itm in self.buffer.iter_mut().skip(self.leftover) {
            *itm = 0;
        }

        self.buffer[self.buffer.len() - 1] |= 0x80;
        self.process_block(None);

        // The reason we can't work with chunks_exact here is that for SHA3-224
        // the `dest` is not evenly divisible by 8/`core::mem::size_of::<u64>()`.
        for (out_chunk, state_value) in dest.chunks_mut(size_of::<u64>()).zip(self.state.iter()) {
            // We need to slice the state value in bytes here for same reason as mentioned
            // above.
            out_chunk.copy_from_slice(&state_value.to_le_bytes()[..out_chunk.len()]);
        }

        Ok(())
    }

    #[cfg(test)]
    /// Compare two Sha3 state objects to check if their fields
    /// are the same.
    pub(crate) fn compare_state_to_other(&self, other: &Self) {
        for idx in 0..25 {
            assert_eq!(self.state[idx], other.state[idx]);
        }
        assert_eq!(self.buffer, other.buffer);
        assert_eq!(self.capacity, other.capacity);
        assert_eq!(self.leftover, other.leftover);
        assert_eq!(self.is_finalized, other.is_finalized);
    }
}

#[derive(Clone)]
/// SHAKE streaming state.
pub(crate) struct Shake<const RATE: usize> {
    pub(crate) state: [u64; 25],
    pub(crate) buffer: [u8; RATE],
    pub(crate) capacity: usize,
    // There is a difference in the state handling here for SHAKE compared
    // to the rest of the hashing/streaming states in Orion. This is
    // because we're dealing with a XOF, enabling many calls to squeeze()
    // data from the internal state, which is not possible with other
    // streaming states in Orion, at the time of writing.
    //
    // What normally is called `self.leftover` has here been named to
    // `self.until_absorb` to indicate a tracker, that counts how many
    // bytes we can copy into `self.buffer`, before we need to XOR into
    // internal state and permute. `self.until_absorb == RATE` time to XOR in
    // `self.buffer`. The logic behind this tracker is exactly as before
    // it was renamed.
    //
    // A new tracker is `self.to_squeeze` that indicates how many bytes
    // are left to be squeezed out of the sponge. This is relevant when calling
    // squeeze() multiple times, requesting data amounts that aren't a mulitple
    // of the `RATE`. As soon as `RATE` amount of bytes have been squeezed(),
    // we have to permute the internal state, before we can output more bytes
    // `self.to_squeeze() == 0` indicates we need to permute again...
    until_absorb: usize,
    to_squeeze: usize,
    // ... Lastly, `self.is_finalized` doesn't indicate no further operations
    // on this instance are possible (`reset()` is always possible), but instead that
    // we are finished `absorbing()`ing data.
    //
    // I dislike these similar-looking states and their management be equal but
    // now having variables mean different things. A TODO would be to come up with a
    // better design for this.
    is_finalized: bool,
}

impl<const RATE: usize> Drop for Shake<RATE> {
    fn drop(&mut self) {
        self.state.iter_mut().zeroize();
        self.buffer.iter_mut().zeroize();
        self.until_absorb.zeroize();
        self.to_squeeze.zeroize();
    }
}

impl<const RATE: usize> Debug for Shake<RATE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "State {{ state: [***OMITTED***], buffer: [***OMITTED***], capacity: {:?}, until_absorb: {:?}, \
            to_squeeze: {:?}, is_finalized: {:?} }}",
            self.capacity, self.until_absorb, self.to_squeeze, self.is_finalized
        )
    }
}

impl<const RATE: usize> Shake<RATE> {
    /// Initialize a new state.
    /// `capacity` should be in bytes.
    pub(crate) fn _new(capacity: usize) -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; RATE],
            capacity,
            until_absorb: 0,
            to_squeeze: 0,
            is_finalized: false,
        }
    }

    /// Process data in `self.buffer` or optionally `data`.
    pub(crate) fn process_block(&mut self, data: Option<&[u8]>) {
        // If `data.is_none()` then we want to process to_absorb data within `self.buffer`.
        let data_block = match data {
            Some(bytes) => {
                debug_assert_eq!(bytes.len(), RATE);
                bytes
            }
            None => &self.buffer,
        };

        debug_assert_eq!(data_block.len() % 8, 0);

        // We process data in terms of bitrate, but we need to XOR in an entire Keccak state.
        // So the 25 - bitrate values will be zero. That's the same as not XORing those values
        // so we leave it be as this.
        for (b, s) in data_block
            .chunks_exact(size_of::<u64>())
            .zip(self.state.iter_mut())
        {
            *s ^= u64::from_le_bytes(b.try_into().unwrap());
        }

        keccakf::<24>(&mut self.state);
    }

    /// Reset to `new()` state.
    pub(crate) fn _reset(&mut self) {
        self.state = [0u64; 25];
        self.buffer = [0u8; RATE];
        self.until_absorb = 0;
        self.to_squeeze = 0;
        self.is_finalized = false;
    }

    /// Update state with `data`. This can be called multiple times.
    pub(crate) fn _absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }
        if data.is_empty() {
            return Ok(());
        }

        let mut bytes = data;

        if self.until_absorb != 0 {
            debug_assert!(self.until_absorb <= RATE);

            let mut want = RATE - self.until_absorb;
            if want > bytes.len() {
                want = bytes.len();
            }

            for (idx, itm) in bytes.iter().enumerate().take(want) {
                self.buffer[self.until_absorb + idx] = *itm;
            }

            bytes = &bytes[want..];
            self.until_absorb += want;

            if self.until_absorb < RATE {
                return Ok(());
            }

            self.process_block(None);
            self.until_absorb = 0;
        }

        while bytes.len() >= RATE {
            self.process_block(Some(bytes[..RATE].as_ref()));
            bytes = &bytes[RATE..];
        }

        if !bytes.is_empty() {
            debug_assert_eq!(self.until_absorb, 0);
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.until_absorb = bytes.len();
        }

        Ok(())
    }

    /// Finalize the hash and put the final digest into `dest`.
    pub(crate) fn _squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
        // We have to do padding first time we switch from absorbing => squeezing
        if !self.is_finalized {
            // self.to_absorb should not be greater than SHA3(256/384/512)_RATE
            // as that would have been processed in the update call
            debug_assert!(self.until_absorb < RATE);
            // Set padding byte and pad with zeroes after
            self.buffer[self.until_absorb] = 0x1f;
            self.until_absorb += 1;
            for itm in self.buffer.iter_mut().skip(self.until_absorb) {
                *itm = 0;
            }

            self.buffer[self.buffer.len() - 1] |= 0x80;
            self.process_block(None);

            // Skip padding next time.
            self.is_finalized = true;
        } else {
            keccakf::<24>(&mut self.state);
        }

        // The reason we can't work with chunks_exact here is that for SHA3-224
        // the `dest` is not evenly divisible by 8/`core::mem::size_of::<u64>()`.
        for (out_chunk, state_value) in dest.chunks_mut(size_of::<u64>()).zip(self.state.iter()) {
            // We need to slice the state value in bytes here for same reason as mentioned
            // above.
            out_chunk.copy_from_slice(&state_value.to_le_bytes()[..out_chunk.len()]);
        }

        Ok(())
    }

    #[cfg(test)]
    /// Compare two Shake state objects to check if their fields
    /// are the same.
    pub(crate) fn compare_state_to_other(&self, other: &Self) {
        for idx in 0..25 {
            assert_eq!(self.state[idx], other.state[idx]);
        }
        assert_eq!(self.buffer, other.buffer);
        assert_eq!(self.capacity, other.capacity);
        assert_eq!(self.until_absorb, other.until_absorb);
        assert_eq!(self.is_finalized, other.is_finalized);
    }
}
