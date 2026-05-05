// MIT License

// Copyright (c) 2019-2026 The orion Developers

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

use crate::{errors::UnknownCryptoError, hazardous::stream::chacha20::CHACHA_BLOCKSIZE};
use core::marker::PhantomData;

#[cfg(all(feature = "alloc", not(feature = "safe_api")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "safe_api")))]
use alloc::vec::Vec;

pub trait TestableStreamCipher: Sized + Clone {
    const MAX_KEYSTREAM_BYTES: u64;

    fn _new(sk: &[u8], n: &[u8]) -> Self;

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    fn _random() -> Self;

    fn _next_producible(&self) -> Result<(), UnknownCryptoError>;

    fn _keystream_remaining(&self) -> u64;

    fn _is_exhausted(&self) -> bool;

    fn _set_position(&mut self, blockctr: u32);

    fn _set_byte_position(&mut self, pos: u64) -> Result<(), UnknownCryptoError>;

    fn _position(&self) -> u32;

    fn _byte_position(&mut self) -> u64;

    fn _xor_keystream_into(&mut self, bytes: &mut [u8]) -> Result<(), UnknownCryptoError>;
}

#[derive(Debug)]
pub struct StreamcipherTester<SC: TestableStreamCipher> {
    ctx: PhantomData<SC>,
}

impl<SC: TestableStreamCipher> StreamcipherTester<SC> {
    pub fn run_tests<const BS: usize, const MAX_POSITION: u32, const MAX_BYTES: u64>(
        sk: &[u8],
        n: &[u8],
        plaintext: Option<&[u8]>,
        expected_ct: Option<&[u8]>,
    ) {
        if expected_ct.is_some() {
            assert!(
                plaintext.is_some(),
                "cannot have expected ciphertext without plaintext"
            );
        }

        let ctx = SC::_new(sk, n);

        Self::next_producable_ok_max::<MAX_POSITION>(&mut ctx.clone());
        Self::xor_keystream_empty_ok(&mut ctx.clone());
        Self::last_keystream_block_exhausts::<BS, MAX_POSITION>(&mut ctx.clone());
        Self::bytes_pos_keystream_rem::<MAX_BYTES>(&mut ctx.clone());
        Self::set_bytes_pos_err_past_max::<MAX_BYTES>(&mut ctx.clone());

        #[cfg(any(feature = "alloc", feature = "safe_api"))]
        {
            Self::return_err_if_next_overflows::<BS, MAX_POSITION>(&mut ctx.clone());
            Self::xor_keystream_seek_ahead::<BS>(&mut ctx.clone());
            Self::test_xor_keystream_non_blocksize_aligned::<BS>(&mut ctx.clone());
            Self::test_xor_keystream_last_two_full_blocks::<BS, MAX_POSITION>(&mut ctx.clone());

            if let Some(pt) = plaintext {
                Self::xor_keystream_roundtrip(&mut ctx.clone(), pt);
            }
        }

        #[cfg(feature = "safe_api")]
        {
            if let (Some(pt), Some(expected)) = (plaintext, expected_ct) {
                Self::xor_keystream_produces_expected(&mut ctx.clone(), pt, expected);
            }
        }

        #[cfg(all(feature = "safe_api", test))]
        Self::test_diff_params_diff_output();
    }

    #[cfg(feature = "safe_api")]
    /// Given an input length `a` find out how many times
    /// the initial counter on encrypt()/decrypt() would
    /// increase.
    fn counter_increase_times(a: f32) -> u32 {
        // Otherwise a overflowing subtraction would happen
        if a <= 64f32 {
            return 0;
        }

        let check_with_floor = (a / 64f32).floor();
        let actual = a / 64f32;

        assert!(actual >= check_with_floor);
        // Subtract one because the first 64 in length
        // the counter does not increase
        if actual > check_with_floor {
            (actual.ceil() as u32) - 1
        } else {
            (actual as u32) - 1
        }
    }

    fn xor_keystream_empty_ok(ctx: &mut SC) {
        assert!(ctx._xor_keystream_into(&mut [0u8; 0]).is_ok());
    }

    fn bytes_pos_keystream_rem<const MAX_BYTES: u64>(ctx: &mut SC) {
        assert_eq!(ctx._keystream_remaining() + ctx._byte_position(), MAX_BYTES);
    }

    fn set_bytes_pos_err_past_max<const MAX_BYTES: u64>(ctx: &mut SC) {
        assert!(ctx._set_byte_position(MAX_BYTES + 1).is_err());
        assert!(ctx._set_byte_position(MAX_BYTES).is_err()); // 0-indexed
        assert!(ctx._set_byte_position(MAX_BYTES - 1).is_ok());
    }

    fn next_producable_ok_max<const MAX: u32>(ctx: &mut SC) {
        ctx._set_position(MAX - 2);
        assert!(ctx._next_producible().is_ok());
        ctx._set_position(MAX - 1);
        assert!(ctx._next_producible().is_ok());
        ctx._set_position(MAX);
        assert!(ctx._next_producible().is_ok());
        // only after keystream_block() has generated the last
        // block is the state exhausted and cannot produce any more.
        let mut block = [0u8; CHACHA_BLOCKSIZE];
        ctx._xor_keystream_into(&mut block).unwrap();
        assert!(ctx._next_producible().is_err());
    }

    #[cfg(any(feature = "alloc", feature = "safe_api"))]
    fn xor_keystream_roundtrip(ctx: &mut SC, input: &[u8]) {
        assert_eq!(ctx._position(), 0);
        let mut inputdst = input.to_vec();
        ctx._xor_keystream_into(&mut inputdst).unwrap();

        if !input.is_empty() {
            assert_ne!(&inputdst, &input);
        }

        ctx._set_position(0);
        ctx._xor_keystream_into(&mut inputdst).unwrap();
        assert_eq!(&inputdst, &input);
        assert_eq!(ctx._byte_position() as usize, input.len());
    }

    #[cfg(feature = "safe_api")]
    fn xor_keystream_produces_expected(ctx: &mut SC, pt: &[u8], expected: &[u8]) {
        let mut ct_actual = pt.to_vec();
        let mut pt_actual = expected.to_vec();
        assert_eq!(ct_actual.len(), pt_actual.len());

        let mut enc_ctx = ctx.clone();
        let mut dec_ctx = ctx.clone();
        assert_eq!(enc_ctx._position(), 0);
        assert_eq!(dec_ctx._position(), 0);

        enc_ctx._xor_keystream_into(&mut ct_actual).unwrap();
        dec_ctx._xor_keystream_into(&mut pt_actual).unwrap();

        assert_eq!(ct_actual, expected);
        assert_eq!(pt_actual, pt);

        assert_eq!(
            Self::counter_increase_times(ct_actual.len() as f32),
            enc_ctx._position()
        );
        assert_eq!(
            Self::counter_increase_times(pt_actual.len() as f32),
            dec_ctx._position()
        );
    }

    fn last_keystream_block_exhausts<const BS: usize, const MAX: u32>(ctx: &mut SC) {
        ctx._set_position(MAX);
        assert!(!ctx._is_exhausted());

        let mut block = [123u8; BS];

        // OK: Generate the very last keystream block.
        let prepos = ctx._position();
        assert!(ctx._xor_keystream_into(&mut block).is_ok());
        // (internally the streampos hasn't moved because it would wrap-around)
        assert_eq!(prepos, ctx._position());
        assert!(ctx._is_exhausted());
        assert!(ctx._next_producible().is_err());
        assert_eq!(ctx._keystream_remaining(), 0);

        // ERR: Generate the last block again, even with BS size dst.
        assert!(ctx._xor_keystream_into(&mut block).is_err());
        assert_eq!(prepos, ctx._position());
        assert!(ctx._is_exhausted());
        assert!(ctx._next_producible().is_err());
        assert_eq!(ctx._keystream_remaining(), 0);

        // Should not be recoverable from exhausted state even with position.
        ctx._set_position(0);
        assert!(ctx._xor_keystream_into(&mut block).is_err());
        assert!(ctx._is_exhausted());
        assert!(ctx._next_producible().is_err()); // should also check self.exhausted
        assert_eq!(ctx._keystream_remaining(), 0);
    }

    #[cfg(any(feature = "alloc", feature = "safe_api"))]
    fn return_err_if_next_overflows<const BS: usize, const MAX: u32>(ctx: &mut SC) {
        ctx._set_position(MAX);
        assert!(!ctx._is_exhausted());

        let mut block = vec![123u8; BS + 8];
        assert!(ctx._xor_keystream_into(&mut block).is_err());
        // Generating the last block exhausted
        assert!(ctx._is_exhausted());

        // the last possible block is produced and acutally written to output
        assert_ne!(&block[..BS], &[123u8; BS]);
        // the last bytes are left untouched
        assert_eq!(&block[BS..], &[123u8; 8]);
    }

    #[cfg(any(feature = "alloc", feature = "safe_api"))]
    fn xor_keystream_seek_ahead<const BS: usize>(ctx: &mut SC) {
        let mut blocks = vec![0u8; BS * 10];

        ctx._set_position(0);
        ctx._xor_keystream_into(&mut blocks).unwrap();
        assert_eq!(ctx._position(), 10);

        ctx._set_position(0);
        let mut block = [0u8; BS];
        ctx._xor_keystream_into(&mut block).unwrap();
        assert_eq!(&block, &blocks[..BS]);
        assert_eq!(ctx._position(), 1);

        ctx._set_position(1);
        let mut block = [0u8; BS];
        ctx._xor_keystream_into(&mut block).unwrap();
        assert_eq!(&block, &blocks[BS..BS * 2]);
        assert_eq!(ctx._position(), 2);

        ctx._set_position(2);
        let mut block = [0u8; BS];
        ctx._xor_keystream_into(&mut block).unwrap();
        assert_eq!(&block, &blocks[BS * 2..BS * 3]);
        assert_eq!(ctx._position(), 3);

        ctx._set_position(9);
        let mut block = [0u8; BS];
        ctx._xor_keystream_into(&mut block).unwrap();
        assert_eq!(&block, &blocks[blocks.len() - BS..]);
        assert_eq!(ctx._position(), 10);
    }

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    /// Test that encrypting using different secret-key/nonce/initial-counter combinations yields different
    /// ciphertexts.
    fn test_diff_params_diff_output() {
        let input = &[0u8; 16];

        let mut ctx1 = SC::_random();
        let mut ctx2 = SC::_random();

        let mut dst1 = vec![0u8; input.len()];
        let mut dst2 = vec![0u8; input.len()];

        ctx1._xor_keystream_into(&mut dst1).unwrap();
        ctx2._xor_keystream_into(&mut dst2).unwrap();
        assert_ne!(&dst1, &input);
        assert_ne!(&dst2, &input);
        assert_ne!(&dst1, &dst2);

        ctx1._set_position(0);
        ctx2._set_position(0);

        ctx1._xor_keystream_into(&mut dst1).unwrap();
        ctx2._xor_keystream_into(&mut dst2).unwrap();
        assert_eq!(&dst1, &input);
        assert_eq!(&dst2, &input);
        assert_eq!(&dst1, &dst2);
    }

    #[cfg(any(feature = "alloc", feature = "safe_api"))]
    fn test_xor_keystream_last_two_full_blocks<const BS: usize, const MAX: u32>(ctx: &mut SC) {
        assert_eq!(ctx._position(), 0);
        assert!(!ctx._is_exhausted());

        // Use u32::MAX to fill the last half block
        let mut wctx = ctx.clone();
        wctx._set_position(MAX - 1);
        let mut twoblocks_min = vec![0u8; BS + (BS / 2)];
        assert!(wctx._xor_keystream_into(&mut twoblocks_min).is_ok());
        assert!(wctx._is_exhausted());
        // Still has 32 bytes leftover from the last block.
        assert_eq!(wctx._keystream_remaining(), (BS / 2) as u64);
        let mut consume_leftover = vec![0u8; BS / 2];
        assert!(wctx._xor_keystream_into(&mut consume_leftover).is_ok());
        assert!(wctx._is_exhausted());
        // Consume the leftover keystream of the last block.
        assert_eq!(wctx._keystream_remaining(), 0);
        let mut err = [0u8; 1];
        assert!(wctx._xor_keystream_into(&mut err).is_err());

        // Use u32::MAX to fill the full last blocks
        let mut wctx = ctx.clone();
        wctx._set_position(MAX - 1);
        let mut twoblocks_mid = vec![0u8; BS * 2];
        assert!(wctx._xor_keystream_into(&mut twoblocks_mid).is_ok());
        assert!(wctx._is_exhausted());
        assert_eq!(wctx._keystream_remaining(), 0);

        // ERR: Do not move past two full blocks
        let mut wctx = ctx.clone();
        wctx._set_position(u32::MAX - 1);
        let mut twoblocks_max = vec![0u8; (BS * 2) + 1];
        assert!(wctx._xor_keystream_into(&mut twoblocks_max).is_err());
        assert!(wctx._is_exhausted());
        assert_eq!(wctx._keystream_remaining(), 0);

        assert_eq!(&twoblocks_min, &twoblocks_mid[..twoblocks_min.len()]);
        assert_eq!(&twoblocks_mid, &twoblocks_max[..twoblocks_mid.len()]);
        assert_eq!(twoblocks_max[twoblocks_max.len() - 1], 0);
    }

    #[cfg(any(feature = "alloc", feature = "safe_api"))]
    /// This test should be identical in intention to the
    /// `StreamingContextConsistencyTester::incremental_processing_with_leftover()`
    fn test_xor_keystream_non_blocksize_aligned<const BS: usize>(ctx: &mut SC) {
        assert_eq!(ctx._position(), 0);

        for len in 0..BS * 4 {
            let mut data = vec![0u8; len];
            let mut state = ctx.clone();
            let mut other_data: Vec<u8> = Vec::new();

            other_data.extend_from_slice(&data);
            state._xor_keystream_into(&mut data).unwrap();

            if data.len() > BS {
                let data_prelen = data.len();
                data.extend_from_slice(b"");
                state._xor_keystream_into(&mut data[data_prelen..]).unwrap();
                other_data.extend_from_slice(b"");
            }
            if data.len() > BS * 2 {
                let data_prelen = data.len();
                data.extend_from_slice(b"Extra");
                state._xor_keystream_into(&mut data[data_prelen..]).unwrap();
                other_data.extend_from_slice(b"Extra");
            }
            if data.len() > BS * 3 {
                let data_prelen = data.len();
                data.extend_from_slice(&[0u8; 256]);
                state._xor_keystream_into(&mut data[data_prelen..]).unwrap();
                other_data.extend_from_slice(&[0u8; 256]);
            }

            let mut one_shot = ctx.clone();
            one_shot._xor_keystream_into(&mut other_data).unwrap();

            assert_eq!(data, other_data);
            assert_eq!(state._is_exhausted(), one_shot._is_exhausted());
            assert_eq!(state._position(), one_shot._position());
            assert_eq!(
                state._keystream_remaining(),
                one_shot._keystream_remaining()
            );
            assert_eq!(
                state._keystream_remaining(),
                SC::MAX_KEYSTREAM_BYTES - data.len() as u64,
            );
            assert_eq!(
                one_shot._keystream_remaining(),
                SC::MAX_KEYSTREAM_BYTES - other_data.len() as u64,
            );

            if !data.is_empty() {
                assert_eq!(state._byte_position() as usize, data.len());
                assert_eq!(one_shot._byte_position() as usize, other_data.len());
            } else {
                assert_eq!(state._byte_position() as usize, 0);
                assert_eq!(one_shot._byte_position() as usize, 0);
            }
        }
    }
}
