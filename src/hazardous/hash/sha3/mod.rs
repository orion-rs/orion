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

// Rho (ρ).
fn rho(state: &mut [u64; 25]) {
    todo!();
}

// Phi (π).
fn phi(state: &mut [u64; 25]) {
    todo!();
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
fn iota(state: &mut [u64; 25]) {
    todo!();
}
