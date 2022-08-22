// MIT License

// Copyright (c) 2022 The orion Developers

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

// TODO:
// - See if we can make this `const`

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
const RO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Indices precomputed based on spec of Pi.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccakf<const ROUNDS: usize>(state: &mut [u64; 25]) {
    for round in 0..ROUNDS {
        theta(state);
        rho_and_pi(state);
        chi(state);
        iota(state, round);
    }
}

// Theta (θ).
fn theta(state: &mut [u64; 25]) {
    let mut buf = [0u64; 5];

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
fn rho_and_pi(state: &mut [u64; 25]) {
    let mut buf = [0u64; 5];
    let mut prev = state[1];

    /*
           unroll24!(x, {
               array[0] = state[PI[x]];
               state[PI[x]] = last.rotate_left(RHO[x]);
               last = array[0];
           });
    */

    // NOTE: If these fail test vectors it might require an additional iteration ( the last one )

    buf[0] = state[PI[0]];
    state[PI[0]] = prev.rotate_left(RO[0]);
    prev = buf[0];

    buf[0] = state[PI[1]];
    state[PI[1]] = prev.rotate_left(RO[1]);
    prev = buf[0];

    buf[0] = state[PI[2]];
    state[PI[2]] = prev.rotate_left(RO[2]);
    prev = buf[0];

    buf[0] = state[PI[3]];
    state[PI[3]] = prev.rotate_left(RO[3]);
    prev = buf[0];

    buf[0] = state[PI[4]];
    state[PI[4]] = prev.rotate_left(RO[4]);
    prev = buf[0];

    buf[0] = state[PI[5]];
    state[PI[5]] = prev.rotate_left(RO[5]);
    prev = buf[0];

    buf[0] = state[PI[6]];
    state[PI[6]] = prev.rotate_left(RO[6]);
    prev = buf[0];

    buf[0] = state[PI[7]];
    state[PI[7]] = prev.rotate_left(RO[7]);
    prev = buf[0];

    buf[0] = state[PI[8]];
    state[PI[8]] = prev.rotate_left(RO[8]);
    prev = buf[0];

    buf[0] = state[PI[9]];
    state[PI[9]] = prev.rotate_left(RO[9]);
    prev = buf[0];

    buf[0] = state[PI[10]];
    state[PI[10]] = prev.rotate_left(RO[10]);
    prev = buf[0];

    buf[0] = state[PI[11]];
    state[PI[11]] = prev.rotate_left(RO[11]);
    prev = buf[0];

    buf[0] = state[PI[12]];
    state[PI[12]] = prev.rotate_left(RO[12]);
    prev = buf[0];

    buf[0] = state[PI[13]];
    state[PI[13]] = prev.rotate_left(RO[13]);
    prev = buf[0];

    buf[0] = state[PI[14]];
    state[PI[14]] = prev.rotate_left(RO[14]);
    prev = buf[0];

    buf[0] = state[PI[15]];
    state[PI[15]] = prev.rotate_left(RO[15]);
    prev = buf[0];

    buf[0] = state[PI[16]];
    state[PI[16]] = prev.rotate_left(RO[16]);
    prev = buf[0];

    buf[0] = state[PI[17]];
    state[PI[17]] = prev.rotate_left(RO[17]);
    prev = buf[0];

    buf[0] = state[PI[18]];
    state[PI[18]] = prev.rotate_left(RO[18]);
    prev = buf[0];

    buf[0] = state[PI[19]];
    state[PI[19]] = prev.rotate_left(RO[19]);
    prev = buf[0];

    buf[0] = state[PI[20]];
    state[PI[20]] = prev.rotate_left(RO[20]);
    prev = buf[0];

    buf[0] = state[PI[21]];
    state[PI[21]] = prev.rotate_left(RO[21]);
    prev = buf[0];

    buf[0] = state[PI[22]];
    state[PI[22]] = prev.rotate_left(RO[22]);
    prev = buf[0];

    buf[0] = state[PI[23]];
    state[PI[23]] = prev.rotate_left(RO[23]);
    prev = buf[0];
}

// Chi (χ).
fn chi(state: &mut [u64; 25]) {
    let mut buf = [0u64; 5];

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
