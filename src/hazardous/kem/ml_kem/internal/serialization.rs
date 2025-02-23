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

use super::fe::{barrett_reduce, FieldElement};

#[cfg(test)]
/// FIPS-203, Algorithm 3.
/// Little-endian order.
fn bits_to_bytes(bits: &[u8], bytes: &mut [u8]) {
    debug_assert_eq!(bits.len() / 8, bytes.len());
    debug_assert!(bits.iter().all(|x| *x == 0 || *x == 1));
    debug_assert!(bytes.iter().all(|x| *x == 0));

    for (i, bit) in bits.iter().enumerate() {
        // floor(i/8) <=> i >> 3
        let byte_idx = i >> 3;
        // i mod 8 <=> i & 7
        // 2^{..} <=> 1 << (i & 7)
        bytes[byte_idx] += bit * (1 << (i & 7));
    }
}

/// FIPS-203, Algorithm 4.
/// Little-endian order.
pub fn bytes_to_bits(bytes: &[u8], bits: &mut [u8]) {
    debug_assert_eq!(bytes.len() * 8, bits.len());

    for (by, bi) in bytes.iter().zip(bits.chunks_exact_mut(u8::BITS as usize)) {
        for (idx, exact_bit) in bi.iter_mut().enumerate() {
            *exact_bit = (by >> idx) & 1;
        }
    }

    debug_assert!(bits.iter().all(|x| *x == 0 || *x == 1));
}

/// Encoding to an from FieldElements/bytes.
pub struct ByteSerialization;

impl ByteSerialization {
    /// FIPS-203, Algorithm 5.
    /// d = 1.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_1(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(8).zip(out.iter_mut()) {
            let mut byte: u8 = 0;
            byte |= (scalar[0].0 as u8 & 0x1).overflowing_shl(7 - 7).0;
            byte |= (scalar[1].0 as u8 & 0x1).overflowing_shl(7 - 6).0;
            byte |= (scalar[2].0 as u8 & 0x1).overflowing_shl(7 - 5).0;
            byte |= (scalar[3].0 as u8 & 0x1).overflowing_shl(7 - 4).0;
            byte |= (scalar[4].0 as u8 & 0x1).overflowing_shl(7 - 3).0;
            byte |= (scalar[5].0 as u8 & 0x1).overflowing_shl(7 - 2).0;
            byte |= (scalar[6].0 as u8 & 0x1).overflowing_shl(7 - 1).0;
            byte |= (scalar[7].0 as u8 & 0x1).overflowing_shl(7 - 0).0;

            *b = byte;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// d = 1.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_1(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.iter().zip(out.chunks_exact_mut(8)) {
            s[0].0 = ((b & 0x01) >> (7 - 7) as u16) as i32;
            s[1].0 = ((b & 0x02) >> (7 - 6) as u16) as i32;
            s[2].0 = ((b & 0x04) >> (7 - 5) as u16) as i32;
            s[3].0 = ((b & 0x08) >> (7 - 4) as u16) as i32;
            s[4].0 = ((b & 0x10) >> (7 - 3) as u16) as i32;
            s[5].0 = ((b & 0x20) >> (7 - 2) as u16) as i32;
            s[6].0 = ((b & 0x40) >> (7 - 1) as u16) as i32;
            s[7].0 = ((b & 0x80) >> (7 - 0) as u16) as i32;
        }
    }

    /// FIPS-203, Algorithm 5.
    /// d = 4.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_4(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(2).zip(out.iter_mut()) {
            let mut byte: u8 = 0;
            byte |= (scalar[0].0 as u8).overflowing_shl(4 * 0).0;
            byte |= (scalar[1].0 as u8).overflowing_shl(4 * 1).0;

            *b = byte;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// d = 4.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_4(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.iter().zip(out.chunks_exact_mut(2)) {
            s[0].0 = ((b & 0xF) as u16) as i32;
            s[1].0 = ((b >> 4) as u16) as i32;
        }
    }

    /// FIPS-203, Algorithm 5.
    /// d = 5.
    /// Encode coeffs into 5-bit bytes, segmenting 8 coeffs into 5 full bytes.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_5(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(8).zip(out.chunks_exact_mut(5)) {
            let mut bits: u64 = 0;
            bits |= (scalar[0].0 as u64).overflowing_shl(5 * 0).0;
            bits |= (scalar[1].0 as u64).overflowing_shl(5 * 1).0;
            bits |= (scalar[2].0 as u64).overflowing_shl(5 * 2).0;
            bits |= (scalar[3].0 as u64).overflowing_shl(5 * 3).0;
            bits |= (scalar[4].0 as u64).overflowing_shl(5 * 4).0;
            bits |= (scalar[5].0 as u64).overflowing_shl(5 * 5).0;
            bits |= (scalar[6].0 as u64).overflowing_shl(5 * 6).0;
            bits |= (scalar[7].0 as u64).overflowing_shl(5 * 7).0;

            b[0] = (bits >> (8 * 0)) as u8;
            b[1] = (bits >> (8 * 1)) as u8;
            b[2] = (bits >> (8 * 2)) as u8;
            b[3] = (bits >> (8 * 3)) as u8;
            b[4] = (bits >> (8 * 4)) as u8;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// d = 5.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_5(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.chunks(5).zip(out.chunks_exact_mut(8)) {
            let mut bits: u64 = 0;
            bits |= (b[0] as u64) << (8 * (4 - 4));
            bits |= (b[1] as u64) << (8 * (4 - 3));
            bits |= (b[2] as u64) << (8 * (4 - 2));
            bits |= (b[3] as u64) << (8 * (4 - 1));
            bits |= (b[4] as u64) << (8 * (4 - 0));

            s[0].0 = (((bits >> (5 * (7 - 7))) & 0x1F) as u16) as i32;
            s[1].0 = (((bits >> (5 * (7 - 6))) & 0x1F) as u16) as i32;
            s[2].0 = (((bits >> (5 * (7 - 5))) & 0x1F) as u16) as i32;
            s[3].0 = (((bits >> (5 * (7 - 4))) & 0x1F) as u16) as i32;
            s[4].0 = (((bits >> (5 * (7 - 3))) & 0x1F) as u16) as i32;
            s[5].0 = (((bits >> (5 * (7 - 2))) & 0x1F) as u16) as i32;
            s[6].0 = (((bits >> (5 * (7 - 1))) & 0x1F) as u16) as i32;
            s[7].0 = (((bits >> (5 * (7 - 0))) & 0x1F) as u16) as i32;
        }
    }

    /// FIPS-203, Algorithm 5.
    /// d = 10.
    /// Encode coeffs, segmenting 10 coeffs into 5 full bytes.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_10(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(4).zip(out.chunks_exact_mut(5)) {
            let mut bits: u64 = 0;
            bits |= (scalar[0].0 as u64).overflowing_shl(10 * 0).0;
            bits |= (scalar[1].0 as u64).overflowing_shl(10 * 1).0;
            bits |= (scalar[2].0 as u64).overflowing_shl(10 * 2).0;
            bits |= (scalar[3].0 as u64).overflowing_shl(10 * 3).0;

            b[0] = (bits >> (8 * 0)) as u8;
            b[1] = (bits >> (8 * 1)) as u8;
            b[2] = (bits >> (8 * 2)) as u8;
            b[3] = (bits >> (8 * 3)) as u8;
            b[4] = (bits >> (8 * 4)) as u8;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// d = 10.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_10(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.chunks(5).zip(out.chunks_exact_mut(4)) {
            let mut bits: u64 = 0;
            bits |= (b[0] as u64) << (8 * (4 - 4));
            bits |= (b[1] as u64) << (8 * (4 - 3));
            bits |= (b[2] as u64) << (8 * (4 - 2));
            bits |= (b[3] as u64) << (8 * (4 - 1));
            bits |= (b[4] as u64) << (8 * (4 - 0));

            s[0].0 = (((bits >> (10 * (3 - 3))) & 0x3FF) as u16) as i32;
            s[1].0 = (((bits >> (10 * (3 - 2))) & 0x3FF) as u16) as i32;
            s[2].0 = (((bits >> (10 * (3 - 1))) & 0x3FF) as u16) as i32;
            s[3].0 = (((bits >> (10 * (3 - 0))) & 0x3FF) as u16) as i32;
        }
    }

    /// FIPS-203, Algorithm 5.
    /// d = 11.
    /// Encode coeffs, segmenting 8 coeffs into 11 full bytes.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_11(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(8).zip(out.chunks_exact_mut(11)) {
            let mut bits: u128 = 0;
            bits |= (scalar[0].0 as u128).overflowing_shl(11 * 0).0;
            bits |= (scalar[1].0 as u128).overflowing_shl(11 * 1).0;
            bits |= (scalar[2].0 as u128).overflowing_shl(11 * 2).0;
            bits |= (scalar[3].0 as u128).overflowing_shl(11 * 3).0;
            bits |= (scalar[4].0 as u128).overflowing_shl(11 * 4).0;
            bits |= (scalar[5].0 as u128).overflowing_shl(11 * 5).0;
            bits |= (scalar[6].0 as u128).overflowing_shl(11 * 6).0;
            bits |= (scalar[7].0 as u128).overflowing_shl(11 * 7).0;

            b[0] = (bits >> (8 * 0)) as u8;
            b[1] = (bits >> (8 * 1)) as u8;
            b[2] = (bits >> (8 * 2)) as u8;
            b[3] = (bits >> (8 * 3)) as u8;
            b[4] = (bits >> (8 * 4)) as u8;
            b[5] = (bits >> (8 * 5)) as u8;
            b[6] = (bits >> (8 * 6)) as u8;
            b[7] = (bits >> (8 * 7)) as u8;
            b[8] = (bits >> (8 * 8)) as u8;
            b[9] = (bits >> (8 * 9)) as u8;
            b[10] = (bits >> (8 * 10)) as u8;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// d = 11.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_11(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.chunks(11).zip(out.chunks_exact_mut(8)) {
            let mut bits: u128 = 0;
            bits |= (b[0] as u128) << (8 * (10 - 10));
            bits |= (b[1] as u128) << (8 * (10 - 9));
            bits |= (b[2] as u128) << (8 * (10 - 8));
            bits |= (b[3] as u128) << (8 * (10 - 7));
            bits |= (b[4] as u128) << (8 * (10 - 6));
            bits |= (b[5] as u128) << (8 * (10 - 5));
            bits |= (b[6] as u128) << (8 * (10 - 4));
            bits |= (b[7] as u128) << (8 * (10 - 3));
            bits |= (b[8] as u128) << (8 * (10 - 2));
            bits |= (b[9] as u128) << (8 * (10 - 1));
            bits |= (b[10] as u128) << (8 * (10 - 0));

            s[0].0 = (((bits >> (11 * (7 - 7))) & 0x7FF) as u16) as i32;
            s[1].0 = (((bits >> (11 * (7 - 6))) & 0x7FF) as u16) as i32;
            s[2].0 = (((bits >> (11 * (7 - 5))) & 0x7FF) as u16) as i32;
            s[3].0 = (((bits >> (11 * (7 - 4))) & 0x7FF) as u16) as i32;
            s[4].0 = (((bits >> (11 * (7 - 3))) & 0x7FF) as u16) as i32;
            s[5].0 = (((bits >> (11 * (7 - 2))) & 0x7FF) as u16) as i32;
            s[6].0 = (((bits >> (11 * (7 - 1))) & 0x7FF) as u16) as i32;
            s[7].0 = (((bits >> (11 * (7 - 0))) & 0x7FF) as u16) as i32;
        }
    }

    /// FIPS-203, Algorithm 5.
    /// d = 12.
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn encode_12(coefficients: &[FieldElement], out: &mut [u8]) {
        for (scalar, b) in coefficients.chunks(2).zip(out.chunks_exact_mut(3)) {
            let s1: u16 = (scalar[0].0 as u16) & 0xFFF;
            let s2: u16 = (scalar[1].0 as u16) & 0xFFF;
            let bits: u32 = ((s2 as u32) << 12) | s1 as u32;

            b[0] = (bits >> (8 * 0)) as u8;
            b[1] = (bits >> (8 * 1)) as u8;
            b[2] = (bits >> (8 * 2)) as u8;
        }
    }

    /// FIPS-203, Algorithm 6.
    /// bytes => integer modulo m, d = 12.
    ///
    /// "Specifically, ByteDecode12 converts each 12-bit
    /// segment of its input into an integer modulo 2^{12} = 4096
    /// and then reduces the result modulo q."
    #[allow(clippy::identity_op, clippy::eq_op, clippy::erasing_op)]
    pub fn decode_12(inbytes: &[u8], out: &mut [FieldElement]) {
        for (b, s) in inbytes.chunks(3).zip(out.chunks_exact_mut(2)) {
            let mut bits: u32 = 0;
            bits |= (b[0] as u32) << (8 * (2 - 2));
            bits |= (b[1] as u32) << (8 * (2 - 1));
            bits |= (b[2] as u32) << (8 * (2 - 0));

            let s1: u16 = (bits & 0xFFF) as u16;
            let s2: u16 = ((bits >> 12) & 0xFFF) as u16;

            s[0].0 = barrett_reduce(s1 as i32);
            s[1].0 = barrett_reduce(s2 as i32);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hazardous::kem::ml_kem::internal::fe::KYBER_Q;

    use super::*;

    #[test]
    fn test_bits_to_bytes() {
        for i in 0..=u16::MAX {
            assert_eq!(i % 8, i & 7);
            assert_eq!(2u32.pow(i as u32 % 8), (1 << (i & 7) as u32));
        }

        let bits: [u8; 8] = [0, 1, 0, 1, 0, 1, 0, 0];
        let mut byte = [0u8; 1];
        bits_to_bytes(&bits, &mut byte);
        assert_eq!(byte[0], 42);

        // From FIPS-203:
        // "As an example, the 8-bit string 11010001 corresponds to the byte 2^0 + 2^1 + 2^3 + 2^7 = 139."
        let bits: [u8; 8] = [1, 1, 0, 1, 0, 0, 0, 1];
        let mut byte = [0u8; 1];
        bits_to_bytes(&bits, &mut byte);
        assert_eq!(byte[0], 139);
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_bit_byte_conversions() {
        use rand::prelude::*;

        let mut rng = rand::rng();

        const MAX_POLYCBD_SIZE: usize = 64 * 3;
        for size in 0..MAX_POLYCBD_SIZE {
            let mut bytes_actual = vec![0u8; size];
            let mut bytes_ref = vec![0u8; size];
            rng.fill_bytes(&mut bytes_ref);

            let mut bits = vec![0u8; size * 8];

            bytes_to_bits(&bytes_ref, &mut bits);
            bits_to_bytes(&bits, &mut bytes_actual);

            assert_eq!(bytes_ref, bytes_actual);
        }
    }

    #[test]
    fn test_bytedecode12_performs_mod() {
        let mut polynomial = [FieldElement::zero(); 256];
        for fe in polynomial.iter_mut() {
            fe.0 = KYBER_Q; // Decoding this should mod-wrap around back to 0.
        }

        let mut out_enc_12 = [0u8; 384];
        let mut polynomial_dst = [FieldElement::new(KYBER_Q / 2); 256];

        ByteSerialization::encode_12(&polynomial, &mut out_enc_12);
        ByteSerialization::decode_12(&out_enc_12, &mut polynomial_dst);
        assert_eq!(polynomial_dst, [FieldElement::zero(); 256]);

        for fe in polynomial.iter_mut() {
            fe.0 = KYBER_Q + 1; // Decoding this should mod-wrap around back to 1.
        }

        ByteSerialization::encode_12(&polynomial, &mut out_enc_12);
        ByteSerialization::decode_12(&out_enc_12, &mut polynomial_dst);
        assert_eq!(polynomial_dst, [FieldElement::new(1); 256]);
    }

    #[cfg(feature = "safe_api")]
    #[test]
    fn test_serialization_roundtrip() {
        let polynomial: Vec<FieldElement> = (0..256).map(|_| FieldElement::random()).collect();
        let mut polynomial_dst: Vec<FieldElement> =
            (0..256).map(|_| FieldElement::zero()).collect();

        debug_assert_eq!(polynomial.len(), 256);

        let mut out_enc_1 = [0u8; 32];
        let mut out_enc_4 = [0u8; 128];
        let mut out_enc_5 = [0u8; 160];
        let mut out_enc_10 = [0u8; 320];
        let mut out_enc_11 = [0u8; 352];
        let mut out_enc_12 = [0u8; 384];

        // d = 1
        let mut expected_decoded: Vec<FieldElement> = polynomial.clone();
        for fe in expected_decoded.iter_mut() {
            fe.0 %= 1 << 1;
        }
        ByteSerialization::encode_1(&expected_decoded, &mut out_enc_1);
        ByteSerialization::decode_1(&out_enc_1, &mut polynomial_dst);
        assert_eq!(polynomial_dst, expected_decoded);

        // d = 4
        let mut expected_decoded: Vec<FieldElement> = polynomial.clone();
        for fe in expected_decoded.iter_mut() {
            fe.0 %= 1 << 4;
        }
        ByteSerialization::encode_4(&expected_decoded, &mut out_enc_4);
        ByteSerialization::decode_4(&out_enc_4, &mut polynomial_dst);
        assert_eq!(polynomial_dst, expected_decoded);

        // d = 5
        let mut expected_decoded: Vec<FieldElement> = polynomial.clone();
        for fe in expected_decoded.iter_mut() {
            fe.0 %= 1 << 5;
        }
        ByteSerialization::encode_5(&expected_decoded, &mut out_enc_5);
        ByteSerialization::decode_5(&out_enc_5, &mut polynomial_dst);
        assert_eq!(polynomial_dst, expected_decoded);

        // d = 10
        let mut expected_decoded: Vec<FieldElement> = polynomial.clone();
        for fe in expected_decoded.iter_mut() {
            fe.0 %= 1 << 10;
        }
        ByteSerialization::encode_10(&expected_decoded, &mut out_enc_10);
        ByteSerialization::decode_10(&out_enc_10, &mut polynomial_dst);
        assert_eq!(polynomial_dst, expected_decoded);

        // d = 11
        let mut expected_decoded: Vec<FieldElement> = polynomial.clone();
        for fe in expected_decoded.iter_mut() {
            fe.0 %= 1 << 11;
        }
        ByteSerialization::encode_11(&expected_decoded, &mut out_enc_11);
        ByteSerialization::decode_11(&out_enc_11, &mut polynomial_dst);
        assert_eq!(polynomial_dst, expected_decoded);

        // d = 12 (already all mod m = q)
        ByteSerialization::encode_12(&polynomial, &mut out_enc_12);
        ByteSerialization::decode_12(&out_enc_12, &mut polynomial_dst);
        assert_eq!(polynomial_dst, polynomial);
    }
}
