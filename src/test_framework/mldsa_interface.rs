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

use crate::errors::UnknownCryptoError;
use alloc::vec::Vec;

pub trait TestableDsa {
    const SIGNATURE_SIZE: usize;

    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn keygen_rng() -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    fn sign_deterministic(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<Vec<u8>, UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn sign_with_rnd(
        sk: &[u8],
        m: &[u8],
        ctx: &[u8],
        rnd: &[u8],
    ) -> Result<Vec<u8>, UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn sign_randomized(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<Vec<u8>, UnknownCryptoError>;

    fn verify(vk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn init_sign(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn init_verify(&mut self, ctx: &[u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn update_sign(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn update_verify(&mut self, m: &[u8]) -> Result<(), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn finalize_sign(&mut self, rnd: &[u8]) -> Result<Vec<u8>, UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn finalize_verify(&mut self, sig: &[u8]) -> Result<(), UnknownCryptoError>;
}

#[derive(Debug)]
pub struct DsaTester<T> {
    _initial_context: T,
}

impl<T: TestableDsa + Clone> DsaTester<T> {
    pub fn new(streaming_context: T) -> Self {
        Self {
            _initial_context: streaming_context,
        }
    }

    pub fn run_all_tests(&self, seed: &[u8], msg: &[u8]) {
        Self::keygen_is_deterministic(seed);
        Self::keygen_is_diff_modified_seed(seed);
        Self::sign_verify_roundtrip(seed, msg);
        Self::sign_is_deterministic(seed, msg);
        Self::sign_verify_err_bad_ctx(seed, msg);
        Self::sign_verify_err_bad_msg(seed);
        Self::verify_err_bad_sig(seed, msg);
        Self::verify_err_trunncated_sig(seed, msg);

        #[cfg(feature = "safe_api")]
        {
            Self::keygen_rnd_is_different();
            Self::sign_rnd_is_different(seed, msg);
            Self::verify_err_different_public(msg);

            #[cfg(all(test, feature = "safe_api"))]
            {
                let (rnd, ctx) = Self::test_values_rnd_and_ctx();
                self.consistency_sign(msg, &ctx, &rnd);
                self.consistency_verify(seed, msg, &ctx, &rnd);
                self.test_iuf_combinations(seed, msg, &ctx, &rnd);
            }
        }
    }

    // rand is dev-dep only
    #[cfg(all(test, feature = "safe_api"))]
    fn test_values_rnd_and_ctx() -> (Vec<u8>, Vec<u8>) {
        use rand::{prelude::*, rng};
        let mut rng = rng();

        let ctxsize = rng.random_range(0..=255usize);
        let mut ctx = vec![0u8; ctxsize];
        rng.fill_bytes(&mut ctx);

        let mut rnd = vec![0u8; 32];
        rng.fill_bytes(&mut rnd);

        (rnd, ctx)
    }

    fn keygen_is_deterministic(seed: &[u8]) {
        let (sk1, vk1) = T::keygen(seed).unwrap();
        let (sk2, vk2) = T::keygen(seed).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);
    }

    fn keygen_is_diff_modified_seed(seed: &[u8]) {
        let (sk1, vk1) = T::keygen(seed).unwrap();
        let (sk2, vk2) = T::keygen(seed).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);

        for idx in 0..seed.len() {
            let mut seed_mod = seed.to_vec();
            seed_mod[idx] ^= 1;
            let (sk3, vk3) = T::keygen(&seed_mod).unwrap();
            assert_ne!(sk2, sk3);
            assert_ne!(vk2, vk3);
        }
    }

    #[cfg(feature = "safe_api")]
    fn keygen_rnd_is_different() {
        let (sk1, vk1) = T::keygen_rng().unwrap();
        let (sk2, vk2) = T::keygen_rng().unwrap();
        assert_ne!(sk1, sk2);
        assert_ne!(vk1, vk2);
    }

    fn sign_verify_roundtrip(seed: &[u8], msg: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let sig = T::sign_deterministic(&sk, msg, &[]).unwrap();
        assert_eq!(sig.len(), T::SIGNATURE_SIZE);
        assert!(T::verify(&vk, msg, &[], &sig).is_ok());
    }

    fn sign_is_deterministic(seed: &[u8], msg: &[u8]) {
        let (sk, _) = T::keygen(seed).unwrap();

        let sig0 = T::sign_deterministic(&sk, msg, &[]).unwrap();
        let sig1 = T::sign_deterministic(&sk, msg, &[]).unwrap();
        assert_eq!(sig0.len(), T::SIGNATURE_SIZE);
        assert_eq!(sig1.len(), T::SIGNATURE_SIZE);
        assert_eq!(sig0, sig1);
    }

    #[cfg(feature = "safe_api")]
    fn sign_rnd_is_different(seed: &[u8], msg: &[u8]) {
        let (sk, _) = T::keygen(seed).unwrap();

        let sig0 = T::sign_randomized(&sk, msg, &[]).unwrap();
        let sig1 = T::sign_randomized(&sk, msg, &[]).unwrap();
        assert_eq!(sig0.len(), T::SIGNATURE_SIZE);
        assert_eq!(sig1.len(), T::SIGNATURE_SIZE);
        assert_ne!(sig0, sig1);
    }

    fn sign_verify_err_bad_ctx(seed: &[u8], msg: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let sig = T::sign_deterministic(&sk, msg, &[]).unwrap();
        let sig_mod = T::sign_deterministic(&sk, msg, &[0u8; 1]).unwrap();

        assert_ne!(sig, sig_mod);
        assert!(T::verify(&vk, msg, &[], &sig).is_ok());
        assert!(T::verify(&vk, msg, &[0u8; 1], &sig).is_err());

        assert!(T::verify(&vk, msg, &[], &sig_mod).is_err());
        assert!(T::verify(&vk, msg, &[0u8; 1], &sig_mod).is_ok());
    }

    fn sign_verify_err_bad_msg(seed: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let sig = T::sign_deterministic(&sk, b"Message", &[]).unwrap();
        let sig_mod = T::sign_deterministic(&sk, b"message", &[]).unwrap();

        assert_ne!(sig, sig_mod);
        assert!(T::verify(&vk, b"Message", &[], &sig).is_ok());
        assert!(T::verify(&vk, b"message", &[], &sig).is_err());

        assert!(T::verify(&vk, b"Message", &[], &sig_mod).is_err());
        assert!(T::verify(&vk, b"message", &[], &sig_mod).is_ok());
    }

    fn verify_err_bad_sig(seed: &[u8], msg: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let sig = T::sign_deterministic(&sk, msg, &[]).unwrap();
        assert!(T::verify(&vk, msg, &[], &sig).is_ok());

        for idx in 0..T::SIGNATURE_SIZE {
            let mut sig_mod = sig.clone();
            sig_mod[idx] ^= 1;

            assert!(T::verify(&vk, msg, &[], &sig_mod).is_err());
        }
    }

    #[cfg(feature = "safe_api")]
    fn verify_err_different_public(msg: &[u8]) {
        let (sk, vk) = T::keygen_rng().unwrap();
        let (_, vk_mod) = T::keygen_rng().unwrap();
        let sig = T::sign_deterministic(&sk, msg, &[]).unwrap();
        assert!(T::verify(&vk, msg, &[], &sig).is_ok());
        assert!(T::verify(&vk_mod, msg, &[], &sig).is_err());
    }

    fn verify_err_trunncated_sig(seed: &[u8], msg: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let (_, vk_mod) = T::keygen(seed).unwrap();
        let sig = T::sign_deterministic(&sk, msg, &[]).unwrap();
        assert!(T::verify(&vk, msg, &[], &sig).is_ok());
        assert!(T::verify(&vk_mod, msg, &[], &sig[..sig.len() - 1]).is_err());
    }

    #[cfg(all(test, feature = "safe_api"))]
    /// Related bug: https://github.com/orion-rs/orion/issues/46
    /// Testing different usage combinations of new(), update(),
    /// finalize() and reset() produce the same output.
    ///
    /// It is important to ensure this is also called with empty
    /// `data`.
    ///
    /// NOTE(brycx): This is copied from incremental_interface.rs
    /// wehre in this case: init() == reset().
    fn consistency_sign(&self, data: &[u8], ctx: &[u8], rnd: &[u8]) {
        // new(), update(), finalize()
        let mut state_1 = self._initial_context.clone();
        state_1.init_sign(ctx).unwrap();
        state_1.update_sign(data).unwrap();
        let res_1 = state_1.finalize_sign(rnd).unwrap();

        // new(), reset(), update(), finalize()
        let mut state_2 = self._initial_context.clone();
        state_2.init_sign(ctx).unwrap();
        state_2.init_sign(ctx).unwrap();
        state_2.update_sign(data).unwrap();
        let res_2 = state_2.finalize_sign(rnd).unwrap();

        // new(), update(), reset(), update(), finalize()
        let mut state_3 = self._initial_context.clone();
        state_3.init_sign(ctx).unwrap();
        state_3.update_sign(data).unwrap();
        state_3.init_sign(ctx).unwrap();
        state_3.update_sign(data).unwrap();
        let res_3 = state_3.finalize_sign(rnd).unwrap();

        // new(), update(), finalize(), reset(), update(), finalize()
        let mut state_4 = self._initial_context.clone();
        state_4.init_sign(ctx).unwrap();
        state_4.update_sign(data).unwrap();
        let _ = state_4.finalize_sign(rnd).unwrap();
        state_4.init_sign(ctx).unwrap();
        state_4.update_sign(data).unwrap();
        let res_4 = state_4.finalize_sign(rnd).unwrap();

        assert_eq!(res_1, res_2);
        assert_eq!(res_2, res_3);
        assert_eq!(res_3, res_4);

        // Tests for the assumption that returning Ok() on empty update() calls
        // with streaming APIs, gives the correct result. This is done by testing
        // the reasoning that if update() is empty, returns Ok(), it is the same as
        // calling new() -> finalize(). i.e not calling update() at all.
        if data.is_empty() {
            // new(), finalize()
            let mut state_5 = self._initial_context.clone();
            state_5.init_sign(ctx).unwrap();
            let res_5 = state_5.finalize_sign(rnd).unwrap();

            // new(), reset(), finalize()
            let mut state_6 = self._initial_context.clone();
            state_6.init_sign(ctx).unwrap();
            state_6.init_sign(ctx).unwrap();
            let res_6 = state_6.finalize_sign(rnd).unwrap();

            // new(), update(), reset(), finalize()
            let mut state_7 = self._initial_context.clone();
            state_7.init_sign(ctx).unwrap();
            state_7.update_sign(b"WRONG DATA").unwrap();
            state_7.init_sign(ctx).unwrap();
            let res_7 = state_7.finalize_sign(rnd).unwrap();

            assert_eq!(res_4, res_5);
            assert_eq!(res_5, res_6);
            assert_eq!(res_6, res_7);
        }
    }

    #[cfg(all(test, feature = "safe_api"))]
    fn consistency_verify(&self, seed: &[u8], data: &[u8], ctx: &[u8], rnd: &[u8]) {
        let (sk, _) = T::keygen(seed).unwrap();
        let sigma = T::sign_with_rnd(&sk, data, ctx, rnd).unwrap();

        // new(), update(), finalize()
        let mut state_1 = self._initial_context.clone();
        state_1.init_verify(ctx).unwrap();
        state_1.update_verify(data).unwrap();
        let res_1 = state_1.finalize_verify(&sigma).is_ok();

        // new(), reset(), update(), finalize()
        let mut state_2 = self._initial_context.clone();
        state_2.init_verify(ctx).unwrap();
        state_2.init_verify(ctx).unwrap();
        state_2.update_verify(data).unwrap();
        let res_2 = state_2.finalize_verify(&sigma).is_ok();

        // new(), update(), reset(), update(), finalize()
        let mut state_3 = self._initial_context.clone();
        state_3.init_verify(ctx).unwrap();
        state_3.update_verify(data).unwrap();
        state_3.init_verify(ctx).unwrap();
        state_3.update_verify(data).unwrap();
        let res_3 = state_3.finalize_verify(&sigma).is_ok();

        // new(), update(), finalize(), reset(), update(), finalize()
        let mut state_4 = self._initial_context.clone();
        state_4.init_verify(ctx).unwrap();
        state_4.update_verify(data).unwrap();
        let _ = state_4.finalize_verify(&sigma).is_ok();
        state_4.init_verify(ctx).unwrap();
        state_4.update_verify(data).unwrap();
        let res_4 = state_4.finalize_verify(&sigma).is_ok();

        assert_eq!(res_1, res_2);
        assert_eq!(res_2, res_3);
        assert_eq!(res_3, res_4);

        // Tests for the assumption that returning Ok() on empty update() calls
        // with streaming APIs, gives the correct result. This is done by testing
        // the reasoning that if update() is empty, returns Ok(), it is the same as
        // calling new() -> finalize(). i.e not calling update() at all.
        if data.is_empty() {
            // new(), finalize()
            let mut state_5 = self._initial_context.clone();
            state_5.init_verify(ctx).unwrap();
            let res_5 = state_5.finalize_verify(&sigma).is_ok();

            // new(), reset(), finalize()
            let mut state_6 = self._initial_context.clone();
            state_6.init_verify(ctx).unwrap();
            state_6.init_verify(ctx).unwrap();
            let res_6 = state_6.finalize_verify(&sigma).is_ok();

            // new(), update(), reset(), finalize()
            let mut state_7 = self._initial_context.clone();
            state_7.init_verify(ctx).unwrap();
            state_7.update_verify(b"WRONG DATA").unwrap();
            state_7.init_verify(ctx).unwrap();
            let res_7 = state_7.finalize_verify(&sigma).is_ok();

            assert_eq!(res_4, res_5);
            assert_eq!(res_5, res_6);
            assert_eq!(res_6, res_7);
        }
    }

    #[cfg(all(test, feature = "safe_api"))]
    fn test_iuf_combinations(&self, seed: &[u8], data: &[u8], ctx: &[u8], rnd: &[u8]) {
        let (sk, _) = T::keygen(seed).unwrap();
        let sigma = T::sign_with_rnd(&sk, &[], ctx, rnd).unwrap();

        // no init() -> update(): ERR
        assert!(self._initial_context.clone().update_sign(data).is_err());
        assert!(self._initial_context.clone().update_verify(data).is_err());

        // no init() -> finalize(): ERR
        assert!(self._initial_context.clone().finalize_sign(rnd).is_err());
        assert!(
            self._initial_context
                .clone()
                .finalize_verify(&sigma)
                .is_err()
        );

        // finalize() -> update(): ERR
        let mut stream_ctx = self._initial_context.clone();
        stream_ctx.init_sign(ctx).unwrap();
        stream_ctx.finalize_sign(rnd).unwrap();
        assert!(stream_ctx.update_sign(data).is_err());

        let mut stream_ctx = self._initial_context.clone();
        stream_ctx.init_verify(ctx).unwrap();
        stream_ctx.update_verify(&[]).unwrap(); // must match sigma
        stream_ctx.finalize_verify(&sigma).unwrap();
        assert!(stream_ctx.update_verify(&[]).is_err());

        // init() -> finalize(): OK
        let mut stream_ctx = self._initial_context.clone();
        stream_ctx.init_sign(ctx).unwrap();
        assert!(stream_ctx.finalize_sign(rnd).is_ok());

        let mut stream_ctx = self._initial_context.clone();
        stream_ctx.init_verify(ctx).unwrap();
        assert!(stream_ctx.finalize_verify(&sigma).is_ok());
    }
}
