// MIT License

// Copyright (c) 2026 The orion Developers

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

use core::fmt::Debug;

mod fe;
mod sampling;

const fn bitlen(a: u32) -> u32 {
    u32::BITS - a.leading_zeros()
}

#[test]
fn test_bitlen() {
    assert_eq!(bitlen(32), 6);
    assert_eq!(bitlen(31), 5);

    assert_eq!(MlDsa44::GAMMA_1_BITLEN, 17);
    assert_eq!(MlDsa65::GAMMA_1_BITLEN, 19);
    assert_eq!(MlDsa87::GAMMA_1_BITLEN, 19);
}

pub trait MlDsaParameters: Debug {
    const Q: u32 = 8380417;
    const N: usize = 256;

    /// "# of ±1’s in polynomial c"
    const TAU: usize;
    /// "collision strength of c ̃"
    const LAMBDA: usize;
    /// "private key range"
    const ETA: usize;
    /// "dimensions of A"
    const DIM_K: usize;
    const DIM_L: usize;
    /// "coefficient range of y"
    const GAMMA_1: u32;
    /// "low-order rounding range"
    const GAMMA_2: u32;
    /// `bitlen (γ1 − 1)`
    const GAMMA_1_BITLEN: u32 = bitlen(Self::GAMMA_1 - 1);

    const PRIVATE_KEY_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-44.
pub struct MlDsa44;

impl MlDsaParameters for MlDsa44 {
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const ETA: usize = 2;
    const DIM_K: usize = 4;
    const DIM_L: usize = 4;
    const GAMMA_1: u32 = 1 << 17;
    const GAMMA_2: u32 = (Self::Q - 1) / 88;

    const PRIVATE_KEY_SIZE: usize = 2560;
    const PUBLIC_KEY_SIZE: usize = 1312;
    const SIGNATURE_SIZE: usize = 2420;
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-65.
pub struct MlDsa65;

impl MlDsaParameters for MlDsa65 {
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const ETA: usize = 4;
    const DIM_K: usize = 6;
    const DIM_L: usize = 5;
    const GAMMA_1: u32 = 1 << 19;
    const GAMMA_2: u32 = (Self::Q - 1) / 32;

    const PRIVATE_KEY_SIZE: usize = 4032;
    const PUBLIC_KEY_SIZE: usize = 1952;
    const SIGNATURE_SIZE: usize = 3309;
}

#[derive(Debug, PartialEq, Clone)]
/// ML-DSA-87.
pub struct MlDsa87;

impl MlDsaParameters for MlDsa87 {
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const ETA: usize = 2;
    const DIM_K: usize = 8;
    const DIM_L: usize = 7;
    const GAMMA_1: u32 = 1 << 19;
    const GAMMA_2: u32 = (Self::Q - 1) / 32;

    const PRIVATE_KEY_SIZE: usize = 4896;
    const PUBLIC_KEY_SIZE: usize = 2592;
    const SIGNATURE_SIZE: usize = 4627;
}
