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

#![allow(non_snake_case)]

use crate::errors::UnknownCryptoError;
use crate::{Public, Secret, generics::TypeSpec};
use core::marker::PhantomData;

#[cfg(any(feature = "safe_api", feature = "alloc"))]
use crate::hazardous::stream::chacha20::CHACHA_BLOCKSIZE;
use core::fmt::Debug;

#[cfg(all(feature = "alloc", not(feature = "safe_api")))]
use alloc::vec;

pub trait TestableAead: Debug {
    type Key: TypeSpec;
    type Nonce: TypeSpec;
    type Tag: TypeSpec + Clone;

    fn _seal_inplace(
        sk: &Secret<Self::Key>,
        n: &Public<Self::Nonce>,
        ad: Option<&[u8]>,
        bytes: &mut [u8],
    ) -> Result<Secret<Self::Tag>, UnknownCryptoError>;

    fn _open_inplace(
        sk: &Secret<Self::Key>,
        n: &Public<Self::Nonce>,
        tag: &Secret<Self::Tag>,
        ad: Option<&[u8]>,
        bytes: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn _seal(
        sk: &Secret<Self::Key>,
        n: &Public<Self::Nonce>,
        plaintext: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;

    fn _open(
        sk: &Secret<Self::Key>,
        n: &Public<Self::Nonce>,
        ciphertext_with_tag: &[u8],
        ad: Option<&[u8]>,
        dst_out: &mut [u8],
    ) -> Result<(), UnknownCryptoError>;
}

#[derive(Debug)]
/// KS: Key-size
/// NS: Nonce-size.
/// TS: Tag-size.
pub struct AeadTestRunner<Aead: TestableAead, const KS: usize, const NS: usize, const TS: usize> {
    _aead: PhantomData<Aead>,
}

impl<Aead: TestableAead, const KS: usize, const NS: usize, const TS: usize>
    AeadTestRunner<Aead, KS, NS, TS>
{
    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    pub fn run_with_testvector(
        sk: &[u8],
        n: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        expected_ct: &[u8],
        expected_tag: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        let default_aad = if aad.is_empty() { None } else { Some(aad) };

        let sk = Secret::<Aead::Key>::try_from(sk)?;
        let n = Public::<Aead::Nonce>::try_from(n)?;
        let tag = Secret::<Aead::Tag>::try_from(expected_tag)?;

        let mut dst_out_ct = vec![0u8; plaintext.len() + TS];
        Aead::_seal(&sk, &n, plaintext, default_aad, &mut dst_out_ct)?;
        assert_eq!(&dst_out_ct[..plaintext.len()], expected_ct);
        assert_eq!(
            &dst_out_ct[plaintext.len()..plaintext.len() + TS],
            expected_tag
        );

        let mut dst_out_ct_inplace = plaintext.to_vec();
        let actual_tag = Aead::_seal_inplace(&sk, &n, default_aad, &mut dst_out_ct_inplace)?;
        assert_eq!(&dst_out_ct_inplace, expected_ct);
        assert_eq!(actual_tag, expected_tag);

        let mut dst_out_pt = vec![0u8; plaintext.len()];
        Aead::_open(&sk, &n, &dst_out_ct, default_aad, &mut dst_out_pt)?;
        assert_eq!(&dst_out_pt, plaintext);

        Aead::_open_inplace(&sk, &n, &tag, default_aad, &mut dst_out_ct_inplace)?;
        assert_eq!(&dst_out_ct_inplace, plaintext);

        Ok(())
    }

    #[allow(unused_variables)] // input is not used on pure --no-default-features.
    pub fn run_all_tests(input: &[u8]) {
        Self::test_seal_zero_length_input_is_ok();

        #[cfg(any(feature = "safe_api", feature = "alloc"))]
        {
            Self::test_seal_open_not_using_out_bytes();
            Self::test_wrong_aad_fails();
            Self::test_wrong_nonce_fails();
            Self::test_wrong_key_fails();
            Self::test_wrong_tag_fails();
            Self::test_none_or_empty_some_aad_same_result();
            Self::test_lengths_ad();
            Self::test_lengths_pt_ct();
            Self::test_inplace_buffered_interop(input);
            Self::test_wrong_ciphertext_fails();
        }

        #[cfg(all(feature = "safe_api", test))]
        {
            Self::test_rng_nonce_or_key_different_ciphertext();
        }
    }

    fn secret_key_nonce() -> (Secret<Aead::Key>, Public<Aead::Nonce>) {
        #[cfg(all(feature = "safe_api", test))]
        {
            // safe_api + test gives us dev-dep rand
            use rand::Rng;
            let mut rng = rand::rng();

            let mut skbytes = [0u8; KS];
            let mut nbytes = [0u8; NS];
            rng.fill_bytes(&mut skbytes);
            rng.fill_bytes(&mut nbytes);

            let sk = Secret::<Aead::Key>::try_from(&skbytes).unwrap();
            let n = Public::<Aead::Nonce>::try_from(&nbytes).unwrap();

            (sk, n)
        }

        #[cfg(not(all(feature = "safe_api", test)))]
        {
            let sk = Secret::<Aead::Key>::try_from(&[0u8; KS]).unwrap();
            let n = Public::<Aead::Nonce>::try_from(&[0u8; NS]).unwrap();

            (sk, n)
        }
    }

    // seal()/seal_inplace() should accept zero-length input and produce a authentication tag over this.
    fn test_seal_zero_length_input_is_ok() {
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out = [0u8; TS];
        let mut bytes = [0u8; 0];

        // seal requires space for Tag
        assert!(Aead::_seal(&sk, &n, b"", None, &mut bytes).is_err());
        assert!(Aead::_seal(&sk, &n, b"", None, &mut dst_out).is_ok());
        let tag = Aead::_seal_inplace(&sk, &n, None, &mut bytes)
            .expect("failed to accept zero-len input seal_inplace()");
        assert_eq!(tag, &dst_out);
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_lengths_ad() {
        // Tests different lengths in relation to the padding to Poly1305 blocksize that happens
        const LENGHTS: [usize; 5] = [0, 1, 15, 16, 17];
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out = vec![0u8; 32 + TS];
        let mut dst_out_pt = [0u8; 32];
        let mut bytes = [123u8; 32];
        for len in LENGHTS {
            let ad = vec![1u8; len];
            Aead::_seal(&sk, &n, &[123u8; 32], Some(&ad), &mut dst_out).unwrap();
            Aead::_open(&sk, &n, &dst_out, Some(&ad), &mut dst_out_pt).unwrap();
            assert_eq!(&dst_out_pt, &[123u8; 32]);

            let t = Aead::_seal_inplace(&sk, &n, Some(&ad), &mut bytes).unwrap();
            assert_eq!(&dst_out[..32], &bytes);
            assert_eq!(t, &dst_out[32..]);
            Aead::_open_inplace(&sk, &n, &t, Some(&ad), &mut bytes).unwrap();
            assert_eq!(&bytes, &[123u8; 32]);
        }
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    /// Related bug: <https://github.com/orion-rs/orion/issues/52>
    /// Test input sizes when using seal()/open().
    fn test_lengths_pt_ct() {
        // Tests different lengths in relation to the padding to Poly1305 blocksize that happens
        // and ChaCha blocksize.
        const LENGHTS: [usize; 10] = [0, 1, 15, 16, 17, 32, 63, 64, 65, 128];
        let (sk, n) = Self::secret_key_nonce();

        for len in LENGHTS {
            let plaintext = vec![121u8; len];
            let mut dst_out = vec![0u8; len + TS];
            let mut dst_out_pt = vec![0u8; len];
            let mut bytes = plaintext.to_vec();

            Aead::_seal(&sk, &n, &plaintext, None, &mut dst_out).unwrap();
            Aead::_open(&sk, &n, &dst_out, None, &mut dst_out_pt).unwrap();
            assert_eq!(&dst_out_pt, &plaintext);

            // Test bytes provided too little, too much.
            let mut dst_out_pt_save = vec![0u8; len];
            if len != 0 {
                assert!(
                    Aead::_open(
                        &sk,
                        &n,
                        &dst_out[..len + TS - 1],
                        None,
                        &mut dst_out_pt_save
                    )
                    .is_err()
                );
                let mut dst_out_dropped_ct = dst_out.clone();
                dst_out_dropped_ct.remove(0);
                assert!(
                    Aead::_open(&sk, &n, &dst_out_dropped_ct, None, &mut dst_out_pt_save).is_err()
                );
                assert!(
                    Aead::_open(&sk, &n, &dst_out, None, &mut dst_out_pt_save[..len - 1]).is_err()
                );
            }
            let mut dst_out_more = dst_out.clone();
            dst_out_more.push(1u8);
            assert!(Aead::_open(&sk, &n, &dst_out_more, None, &mut dst_out_pt_save).is_err());
            dst_out_pt_save.push(1u8);
            assert!(Aead::_open(&sk, &n, &dst_out, None, &mut dst_out_pt_save).is_ok());

            // NOTE: This one is only applicable for seal() as inplace() doesn't take btho in/out parameters.
            // Test too small, perfect and larger for outsize (https://github.com/orion-rs/orion/issues/52)
            let mut dst_out_ct_more = vec![0u8; plaintext.len() + (TS + 1)];
            assert!(Aead::_seal(&sk, &n, &plaintext, None, &mut dst_out_ct_more).is_ok());
            let mut dst_out_ct_more_double = vec![0u8; plaintext.len() + (TS * 2)];
            assert!(Aead::_seal(&sk, &n, &plaintext, None, &mut dst_out_ct_more_double).is_ok());
            let mut dst_out_ct_less = vec![0u8; plaintext.len() + (TS - 1)];
            assert!(Aead::_seal(&sk, &n, &plaintext, None, &mut dst_out_ct_less).is_err());

            let t = Aead::_seal_inplace(&sk, &n, None, &mut bytes).unwrap();
            let mut bytes_ct_save = bytes.clone();
            assert_eq!(&dst_out[..len], &bytes);
            assert_eq!(t, &dst_out[len..len + TS]);
            Aead::_open_inplace(&sk, &n, &t, None, &mut bytes).unwrap();
            assert_eq!(&bytes, &plaintext);

            // Test bytes provided too little, too much.
            if len != 0 {
                assert!(
                    Aead::_open_inplace(&sk, &n, &t, None, &mut bytes_ct_save[..len - 1]).is_err()
                );
            }
            bytes_ct_save.push(1u8);
            // This cannot, comapred to open() be too large! This is because it needs to contain the entire
            // ciphertext and only that, in order to authenticate it fully.
            assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes_ct_save).is_err());
        }
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_wrong_aad_fails() {
        let (sk, n) = Self::secret_key_nonce();
        let ad = Some("Additional context".as_bytes());

        let mut dst_out_ct = vec![0u8; (CHACHA_BLOCKSIZE * 3) + TS];
        let mut dst_out_pt = [0u8; CHACHA_BLOCKSIZE * 3];
        let mut bytes = [123u8; CHACHA_BLOCKSIZE * 3];

        Aead::_seal(&sk, &n, &[123u8; CHACHA_BLOCKSIZE * 3], ad, &mut dst_out_ct).unwrap();
        let t = Aead::_seal_inplace(&sk, &n, ad, &mut bytes).unwrap();
        // Capital starting letter differs in AD:
        assert!(
            Aead::_open(
                &sk,
                &n,
                &dst_out_ct,
                Some("additional context".as_bytes()),
                &mut dst_out_pt
            )
            .is_err()
        );
        assert!(
            Aead::_open_inplace(
                &sk,
                &n,
                &t,
                Some("additional context".as_bytes()),
                &mut bytes
            )
            .is_err()
        );
        // SECURITY: Check that nothing was altered on failing verification,
        // in terms of output (partial plaintext release).
        assert_eq!(&dst_out_pt, &[0u8; CHACHA_BLOCKSIZE * 3]);
        assert_eq!(bytes.as_slice(), &dst_out_ct[..dst_out_ct.len() - TS]);

        assert!(Aead::_open(&sk, &n, &dst_out_ct, ad, &mut dst_out_pt).is_ok());
        assert!(Aead::_open_inplace(&sk, &n, &t, ad, &mut bytes).is_ok());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_wrong_nonce_fails() {
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out_ct = vec![0u8; (CHACHA_BLOCKSIZE * 3) + TS];
        let mut dst_out_pt = [0u8; CHACHA_BLOCKSIZE * 3];
        let mut bytes = [123u8; CHACHA_BLOCKSIZE * 3];

        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE * 3],
            None,
            &mut dst_out_ct,
        )
        .unwrap();
        let t = Aead::_seal_inplace(&sk, &n, None, &mut bytes).unwrap();
        let n_prime = Public::<Aead::Nonce>::try_from(&[1u8; NS]).unwrap();
        assert!(Aead::_open(&sk, &n_prime, &dst_out_ct, None, &mut dst_out_pt).is_err());
        assert!(Aead::_open_inplace(&sk, &n_prime, &t, None, &mut bytes).is_err());
        // SECURITY: Check that nothing was altered on failing verification,
        // in terms of output (partial plaintext release).
        assert_eq!(&dst_out_pt, &[0u8; CHACHA_BLOCKSIZE * 3]);
        assert_eq!(bytes.as_slice(), &dst_out_ct[..dst_out_ct.len() - TS]);

        assert!(Aead::_open(&sk, &n, &dst_out_ct, None, &mut dst_out_pt).is_ok());
        assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes).is_ok());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_wrong_key_fails() {
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out_ct = vec![0u8; (CHACHA_BLOCKSIZE * 3) + TS];
        let mut dst_out_pt = [0u8; CHACHA_BLOCKSIZE * 3];
        let mut bytes = [123u8; CHACHA_BLOCKSIZE * 3];

        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE * 3],
            None,
            &mut dst_out_ct,
        )
        .unwrap();
        let t = Aead::_seal_inplace(&sk, &n, None, &mut bytes).unwrap();
        let sk_prime = Secret::<Aead::Key>::try_from(&[1u8; KS]).unwrap();
        assert!(Aead::_open(&sk_prime, &n, &dst_out_ct, None, &mut dst_out_pt).is_err());
        assert!(Aead::_open_inplace(&sk_prime, &n, &t, None, &mut bytes).is_err());
        // SECURITY: Check that nothing was altered on failing verification,
        // in terms of output (partial plaintext release).
        assert_eq!(&dst_out_pt, &[0u8; CHACHA_BLOCKSIZE * 3]);
        assert_eq!(bytes.as_slice(), &dst_out_ct[..dst_out_ct.len() - TS]);

        assert!(Aead::_open(&sk, &n, &dst_out_ct, None, &mut dst_out_pt).is_ok());
        assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes).is_ok());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_wrong_ciphertext_fails() {
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out_ct = vec![0u8; (CHACHA_BLOCKSIZE * 3) + TS];
        let mut dst_out_pt = [0u8; CHACHA_BLOCKSIZE * 3];
        let mut bytes = [123u8; CHACHA_BLOCKSIZE * 3];

        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE * 3],
            None,
            &mut dst_out_ct,
        )
        .unwrap();
        let t = Aead::_seal_inplace(&sk, &n, None, &mut bytes).unwrap();
        let mut dst_out_ct_mod = dst_out_ct.clone();
        let mut bytes_ct_mod = bytes;
        dst_out_ct_mod[0] ^= 1;
        bytes_ct_mod[0] ^= 1;

        assert!(Aead::_open(&sk, &n, &dst_out_ct_mod, None, &mut dst_out_pt).is_err());
        assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes_ct_mod).is_err());
        // SECURITY: Check that nothing was altered on failing verification,
        // in terms of output (partial plaintext release).
        assert_eq!(&dst_out_pt, &[0u8; CHACHA_BLOCKSIZE * 3]);
        assert_eq!(
            bytes_ct_mod.as_slice(),
            &dst_out_ct_mod[..dst_out_ct_mod.len() - TS]
        );

        assert!(Aead::_open(&sk, &n, &dst_out_ct, None, &mut dst_out_pt).is_ok());
        assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes).is_ok());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_wrong_tag_fails() {
        let (sk, n) = Self::secret_key_nonce();

        let mut dst_out_ct = vec![0u8; (CHACHA_BLOCKSIZE * 3) + TS];
        let mut dst_out_pt = [0u8; CHACHA_BLOCKSIZE * 3];
        let mut bytes = [123u8; CHACHA_BLOCKSIZE * 3];

        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE * 3],
            None,
            &mut dst_out_ct,
        )
        .unwrap();
        let dst_out_ct_original = dst_out_ct.clone();

        let t = Aead::_seal_inplace(&sk, &n, None, &mut bytes).unwrap();
        dst_out_ct[CHACHA_BLOCKSIZE * 3] ^= 1;
        let mut t_prime = t.unprotected_as_ref().to_vec();
        t_prime[0] ^= 1;
        let t_prime = Secret::<Aead::Tag>::try_from(&t_prime).unwrap();
        assert!(Aead::_open(&sk, &n, &dst_out_ct, None, &mut dst_out_pt).is_err());
        assert!(Aead::_open_inplace(&sk, &n, &t_prime, None, &mut bytes).is_err());
        // SECURITY: Check that nothing was altered on failing verification,
        // in terms of output (partial plaintext release).
        assert_eq!(&dst_out_pt, &[0u8; CHACHA_BLOCKSIZE * 3]);
        assert_eq!(
            bytes.as_slice(),
            &dst_out_ct_original[..dst_out_ct_original.len() - TS]
        );

        assert!(Aead::_open(&sk, &n, &dst_out_ct_original, None, &mut dst_out_pt).is_ok());
        assert!(Aead::_open_inplace(&sk, &n, &t, None, &mut bytes).is_ok());
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_inplace_buffered_interop(input: &[u8]) {
        let (sk, n) = Self::secret_key_nonce();
        let ad = b"Additional context";

        let mut dst_out_ct = vec![0u8; input.len() + TS];
        let mut dst_out_pt = vec![0u8; input.len()];
        let mut inplace_buffer = input.to_vec();

        Aead::_seal(&sk, &n, input, Some(ad), &mut dst_out_ct).unwrap();
        let tag = Aead::_seal_inplace(&sk, &n, Some(ad), &mut inplace_buffer).unwrap();

        // Use inplace and separate tag for non-inplace and vice versa
        inplace_buffer.extend_from_slice(tag.unprotected_as_ref());
        assert!(Aead::_open(&sk, &n, &inplace_buffer, Some(ad), &mut dst_out_pt).is_ok());
        assert_eq!(&dst_out_pt, input);

        let tag =
            Secret::<Aead::Tag>::try_from(&dst_out_ct[input.len()..input.len() + TS]).unwrap();
        dst_out_ct.truncate(input.len());
        assert!(Aead::_open_inplace(&sk, &n, &tag, Some(ad), &mut dst_out_ct).is_ok());
        assert_eq!(&dst_out_ct, input);
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    /// Ensure that seal()/open() are not expecting `dst_out` bytes to be 0.
    /// Not applicable to *_inplace() because they XOR the bytes directly, so the mutable
    /// destination is the input.
    fn test_seal_open_not_using_out_bytes() {
        let sk = Secret::<Aead::Key>::try_from(&[0u8; KS]).unwrap();
        let n = Public::<Aead::Nonce>::try_from(&[0u8; NS]).unwrap();

        // seal()/open()
        let mut dst_out_0 = vec![0u8; CHACHA_BLOCKSIZE + TS];
        let mut dst_out_255 = vec![255u8; CHACHA_BLOCKSIZE + TS];
        Aead::_seal(&sk, &n, &[123u8; CHACHA_BLOCKSIZE], None, &mut dst_out_0).unwrap();
        Aead::_seal(&sk, &n, &[123u8; CHACHA_BLOCKSIZE], None, &mut dst_out_255).unwrap();
        assert_eq!(dst_out_0, dst_out_255);

        let mut rt_dst_out_0 = [0u8; CHACHA_BLOCKSIZE];
        let mut rt_dst_out_255 = [255u8; CHACHA_BLOCKSIZE];
        Aead::_open(&sk, &n, &dst_out_0, None, &mut rt_dst_out_0).unwrap();
        Aead::_open(&sk, &n, &dst_out_255, None, &mut rt_dst_out_255).unwrap();
        assert_eq!(&rt_dst_out_0, &[123u8; CHACHA_BLOCKSIZE]);
        assert_eq!(&rt_dst_out_255, &[123u8; CHACHA_BLOCKSIZE]);
    }

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    fn test_none_or_empty_some_aad_same_result() {
        let sk = Secret::<Aead::Key>::try_from(&[0u8; KS]).unwrap();
        let n = Public::<Aead::Nonce>::try_from(&[0u8; NS]).unwrap();

        let mut dst_out_none = vec![0u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2) + TS];
        let mut dst_out_some = vec![0u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2) + TS];
        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)],
            None,
            &mut dst_out_none,
        )
        .unwrap();
        Aead::_seal(
            &sk,
            &n,
            &[123u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)],
            Some(&[]),
            &mut dst_out_some,
        )
        .unwrap();
        assert_eq!(dst_out_none, dst_out_some);

        let mut bytes_none = vec![123u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)];
        let mut bytes_some = vec![123u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)];
        let t_none = Aead::_seal_inplace(&sk, &n, None, &mut bytes_none).unwrap();
        let t_some = Aead::_seal_inplace(&sk, &n, Some(&[]), &mut bytes_some).unwrap();
        assert_eq!(bytes_none, bytes_some);

        let mut dst_out_none_pt = vec![0u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)];
        let mut dst_out_some_pt = vec![0u8; CHACHA_BLOCKSIZE + (CHACHA_BLOCKSIZE / 2)];
        Aead::_open(&sk, &n, &dst_out_none, None, &mut dst_out_none_pt).unwrap();
        Aead::_open(&sk, &n, &dst_out_some, Some(&[]), &mut dst_out_some_pt).unwrap();
        assert_eq!(dst_out_none_pt, dst_out_some_pt);

        Aead::_open_inplace(&sk, &n, &t_none, None, &mut bytes_none).unwrap();
        Aead::_open_inplace(&sk, &n, &t_some, None, &mut bytes_some).unwrap();
        assert_eq!(bytes_none, bytes_some);
    }

    #[cfg(all(feature = "safe_api", test))]
    fn test_rng_nonce_or_key_different_ciphertext() {
        // safe_api + test gives us dev-dep rand
        use rand::{Rng, RngExt};
        let mut rng = rand::rng();

        let inlen: usize = rng.random_range(0..1024);
        let adlen: usize = rng.random_range(0..512);
        let mut input = vec![0u8; inlen];
        let mut ad = vec![0u8; adlen];
        let mut skbytes = [0u8; KS];
        let mut nbytes = [0u8; NS];
        rng.fill_bytes(&mut skbytes);
        rng.fill_bytes(&mut nbytes);
        rng.fill_bytes(&mut input);
        rng.fill_bytes(&mut ad);

        let sk = Secret::<Aead::Key>::try_from(&skbytes).unwrap();
        let n = Public::<Aead::Nonce>::try_from(&nbytes).unwrap();

        let ref_input = input.clone();
        let ref_tag = Aead::_seal_inplace(&sk, &n, Some(&ad), &mut input).unwrap();
        let ref_ct = input.clone();

        input = ref_input.clone();
        rng.fill_bytes(&mut skbytes);
        let diff_sk = Secret::<Aead::Key>::try_from(&skbytes).unwrap();
        let diff_tag = Aead::_seal_inplace(&diff_sk, &n, Some(&ad), &mut input).unwrap();
        assert_ne!(diff_tag, ref_tag);
        if input.len() >= 4 {
            // avoid hitting equal for low input sizes randomly
            assert_ne!(input, ref_ct);
        }

        input = ref_input.clone();
        rng.fill_bytes(&mut nbytes);
        let diff_n = Public::<Aead::Nonce>::try_from(&nbytes).unwrap();
        let diff_tag = Aead::_seal_inplace(&sk, &diff_n, Some(&ad), &mut input).unwrap();
        assert_ne!(diff_tag, ref_tag);
        if input.len() >= 4 {
            // avoid hitting equal for low input sizes randomly
            assert_ne!(input, ref_ct);
        }

        if !ad.is_empty() {
            input = ref_input.clone();
            rng.fill_bytes(&mut ad);
            let diff_tag = Aead::_seal_inplace(&sk, &n, Some(&ad), &mut input).unwrap();
            assert_ne!(diff_tag, ref_tag);
            // AD-difference only changes the Tag, not the ciphertext. If empty, always Eq.
            assert_eq!(input, ref_ct);
        }
    }
}

// The following is from before seal_inplace()/open_inplace()
// was supported. These tests are for buffered-only interfaces.

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "safe_api")]
/// Test runner for AEADs.
pub fn BufferedOnlyAeadTestRunner<Sealer, Opener, Key, Nonce>(
    sealer: Sealer,
    opener: Opener,
    key: Key,
    nonce: Nonce,
    input: &[u8],
    expected_ct_with_tag: Option<&[u8]>,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    seal_dst_out_length(&sealer, &key, &nonce, input, tag_size, aad);
    open_dst_out_length(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_tag_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_ciphertext_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    open_modified_aad_err(&sealer, &opener, &key, &nonce, input, tag_size, aad);
    none_or_empty_some_aad_same_result(&sealer, &opener, &key, &nonce, input, tag_size);
    seal_open_equals_expected(
        &sealer,
        &opener,
        &key,
        &nonce,
        input,
        expected_ct_with_tag,
        tag_size,
        aad,
    );
    seal_plaintext_length(&sealer, &key, &nonce, tag_size, aad);
    open_ciphertext_with_tag_length(&sealer, &opener, &key, &nonce, tag_size, aad);
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test dst_out mutable array sizes when using seal().
fn seal_dst_out_length<Sealer, Key, Nonce>(
    sealer: &Sealer,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct).is_ok());

    let mut dst_out_ct_more = vec![0u8; input.len() + (tag_size + 1)];
    // Related bug: #52
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_more).is_ok());

    let mut dst_out_ct_more_double = vec![0u8; input.len() + (tag_size * 2)];
    // Related bug: #52
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_more_double).is_ok());

    let mut dst_out_ct_less = vec![0u8; input.len() + (tag_size - 1)];
    assert!(sealer(key, nonce, input, default_aad, &mut dst_out_ct_less).is_err());
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test input sizes when using seal().
fn seal_plaintext_length<Sealer, Key, Nonce>(
    sealer: &Sealer,
    key: &Key,
    nonce: &Nonce,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let input_0 = vec![0u8; 0];
    let mut dst_out_ct_0 = vec![0u8; input_0.len() + tag_size];
    assert!(sealer(key, nonce, &input_0, default_aad, &mut dst_out_ct_0).is_ok());

    let input_1 = vec![0u8; 1];
    let mut dst_out_ct_1 = vec![0u8; input_1.len() + tag_size];
    assert!(sealer(key, nonce, &input_1, default_aad, &mut dst_out_ct_1).is_ok());

    let input_128 = vec![0u8; 128];
    let mut dst_out_ct_128 = vec![0u8; input_128.len() + tag_size];
    assert!(sealer(key, nonce, &input_128, default_aad, &mut dst_out_ct_128).is_ok());
}

#[cfg(feature = "safe_api")]
/// Related bug: <https://github.com/orion-rs/orion/issues/52>
/// Test dst_out mutable array sizes when using open().
fn open_dst_out_length<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();

    let mut dst_out_pt = vec![0u8; input.len()];
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_ok());

    let mut dst_out_pt_0 = [0u8; 0];
    let empty_out_res = opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_0);
    if input.is_empty() {
        assert!(empty_out_res.is_ok());
    } else {
        assert!(empty_out_res.is_err());
    }

    if !input.is_empty() {
        let mut dst_out_pt_less = vec![0u8; input.len() - 1];
        assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_less).is_err());
    }

    let mut dst_out_pt_more = vec![0u8; input.len() + 1];
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt_more).is_ok());
}

#[cfg(feature = "safe_api")]
/// Test input sizes when using open().
fn open_ciphertext_with_tag_length<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };
    let mut dst_out_pt = vec![0u8; tag_size];

    assert!(opener(key, nonce, &[0u8; 0], default_aad, &mut dst_out_pt).is_err());

    assert!(
        opener(
            key,
            nonce,
            &vec![0u8; tag_size - 1],
            default_aad,
            &mut dst_out_pt
        )
        .is_err()
    );

    let mut dst_out_ct = vec![0u8; tag_size];
    sealer(key, nonce, &[0u8; 0], default_aad, &mut dst_out_ct).unwrap();

    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_ok());
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "safe_api")]
/// Test that sealing and opening produces the expected ciphertext.
fn seal_open_equals_expected<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    expected_ct_with_tag: Option<&[u8]>,
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    if let Some(expected) = expected_ct_with_tag {
        assert_eq!(expected, &dst_out_ct[..]);
    }

    let mut dst_out_pt = input.to_vec();
    opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).unwrap();
    assert_eq!(input, &dst_out_pt[..]);
    if let Some(expected) = expected_ct_with_tag {
        opener(key, nonce, expected, default_aad, &mut dst_out_pt).unwrap();
        assert_eq!(input, &dst_out_pt[..]);
    }
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with a modified tag, an error should be returned.
fn open_modified_tag_err<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    // Modify the first byte of the authentication tag.
    dst_out_ct[input.len() + 1] ^= 1;

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with a modified ciphertext, an error should be returned.
fn open_modified_ciphertext_err<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let mut input = input;
    if input.is_empty() {
        input = &[0u8; 1];
    }
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();
    // Modify the first byte of the ciphertext.
    dst_out_ct[0] ^= 1;

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, default_aad, &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// When opening sealed data with modified aad, an error should be returned.
fn open_modified_aad_err<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
    aad: &[u8],
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let default_aad = if aad.is_empty() { None } else { Some(aad) };

    let mut dst_out_ct = vec![0u8; input.len() + tag_size];
    sealer(key, nonce, input, default_aad, &mut dst_out_ct).unwrap();

    let mut dst_out_pt = input.to_vec();
    assert!(opener(key, nonce, &dst_out_ct, Some(b"BAD AAD"), &mut dst_out_pt).is_err());
}

#[cfg(feature = "safe_api")]
/// Using None or Some with empty slice should produce the exact same result.
fn none_or_empty_some_aad_same_result<Sealer, Opener, Key, Nonce>(
    sealer: &Sealer,
    opener: &Opener,
    key: &Key,
    nonce: &Nonce,
    input: &[u8],
    tag_size: usize,
) where
    Sealer: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
    Opener: Fn(&Key, &Nonce, &[u8], Option<&[u8]>, &mut [u8]) -> Result<(), UnknownCryptoError>,
{
    let mut dst_out_ct_none = vec![0u8; input.len() + tag_size];
    let mut dst_out_ct_some_empty = vec![0u8; input.len() + tag_size];

    sealer(key, nonce, input, None, &mut dst_out_ct_none).unwrap();
    sealer(
        key,
        nonce,
        input,
        Some(&[0u8; 0]),
        &mut dst_out_ct_some_empty,
    )
    .unwrap();

    assert_eq!(dst_out_ct_none, dst_out_ct_some_empty);

    let mut dst_out_pt = vec![0u8; input.len()];
    assert!(
        opener(
            key,
            nonce,
            &dst_out_ct_none,
            Some(&[0u8; 0]),
            &mut dst_out_pt
        )
        .is_ok()
    );
    assert!(opener(key, nonce, &dst_out_ct_some_empty, None, &mut dst_out_pt).is_ok());
}
