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

use core::marker::PhantomData;

use crate::errors::UnknownCryptoError;

pub trait TestableDsa {
    const SIGNATURE_SIZE: usize;

    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn keygen_rng() -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    fn sign_deterministic(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<Vec<u8>, UnknownCryptoError>;

    #[cfg(feature = "safe_api")]
    fn sign_randomized(sk: &[u8], m: &[u8], ctx: &[u8]) -> Result<Vec<u8>, UnknownCryptoError>;

    fn verify(vk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), UnknownCryptoError>;
}

#[derive(Debug)]
pub struct DsaTester<T> {
    _dsa: PhantomData<T>,
}

impl<T: TestableDsa> DsaTester<T> {
    pub fn run_all_tests(seed: &[u8], msg: &[u8]) {
        Self::keygen_is_deterministic(seed);
        Self::keygen_is_diff_modified_seed(seed);
        Self::sign_verify_roundtrip(seed, msg);
        Self::sign_is_deterministic(seed, msg);
        Self::sign_verify_err_bad_ctx(seed, msg);
        Self::sign_verify_err_bad_msg(seed);
        Self::verify_err_bad_sig(seed, msg);
        Self::verify_err_different_public(seed, msg);
        Self::verify_err_trunncated_sig(seed, msg);

        #[cfg(feature = "safe_api")]
        {
            Self::keygen_rnd_is_different();
            Self::sign_rnd_is_different(seed, msg);
        }
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
        let sig_mod = T::sign_deterministic(&sk, b"message", &[0u8; 1]).unwrap();

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

    fn verify_err_different_public(seed: &[u8], msg: &[u8]) {
        let (sk, vk) = T::keygen(seed).unwrap();
        let (_, vk_mod) = T::keygen(seed).unwrap();
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
}
