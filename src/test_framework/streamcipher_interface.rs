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

pub trait TestableStreamCipher: Sized + Clone {
    fn _new(sk: &[u8], n: &[u8]) -> Self;

    #[cfg(test)]
    #[cfg(feature = "safe_api")]
    fn _random() -> Self;

    fn _next_producible(&self) -> Result<(), UnknownCryptoError>;

    fn _keystream_remaining(&self) -> u64;

    fn _is_exhausted(&self) -> bool;

    fn _set_position(&mut self, blockctr: u32);

    fn _position(&self) -> u32;

    fn _xor_keystream_into(&mut self, bytes: &mut [u8]) -> Result<(), UnknownCryptoError>;
}

#[derive(Debug)]
pub struct StreamcipherTester<SC: TestableStreamCipher> {
    ctx: PhantomData<SC>,
}

impl<SC: TestableStreamCipher> StreamcipherTester<SC> {
    pub fn run_tests<const BS: usize, const MAX_POSITION: u32>(
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

        #[cfg(any(feature = "alloc", feature = "safe_api"))]
        {
            Self::return_err_if_next_overflows::<BS, MAX_POSITION>(&mut ctx.clone());
            Self::xor_keystream_seek_ahead::<BS>(&mut ctx.clone());

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
}
