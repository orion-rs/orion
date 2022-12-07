// MIT License

// Copyright (c) 2018-2022 The orion Developers

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

//! # Parameters:
//! - `secret_key`: The secret key.
//! - `nonce`: The nonce value.
//! - `initial_counter`: The initial counter value. In most cases, this is `0`.
//! - `ciphertext`: The encrypted data.
//! - `plaintext`: The data to be encrypted.
//! - `dst_out`: Destination array that will hold the ciphertext/plaintext after
//!   encryption/decryption.
//!
//! `nonce`: "Counters and LFSRs are both acceptable ways of generating unique
//! nonces, as is encrypting a counter using a block cipher with a 64-bit block
//! size such as DES.  Note that it is not acceptable to use a truncation of a
//! counter encrypted with block ciphers with 128-bit or 256-bit blocks,
//! because such a truncation may repeat after a short time." See [RFC]
//! for more information.
//!
//! `dst_out`: The output buffer may have a capacity greater than the input. If this is the case,
//! only the first input length amount of bytes in `dst_out` are modified, while the rest remain untouched.
//!
//! # Errors:
//! An error will be returned if:
//! - The length of `dst_out` is less than `plaintext` or `ciphertext`.
//! - `plaintext` or `ciphertext` is empty.
//! - The `initial_counter` is high enough to cause a potential overflow.
//!
//! Even though `dst_out` is allowed to be of greater length than `plaintext`,
//! the `ciphertext` produced by `chacha20`/`xchacha20` will always be of the
//! same length as the `plaintext`.
//!
//! # Panics:
//! A panic will occur if:
//! - More than `2^32-1` keystream blocks are processed or more than `2^32-1 * 64`
//!   bytes of data are processed.
//!
//! # Security:
//! - It is critical for security that a given nonce is not re-used with a given
//!   key. Should this happen, the security of all data that has been encrypted
//!   with that given key is compromised.
//! - Functions herein do not provide any data integrity. If you need
//!   data integrity, which is nearly ***always the case***, you should use an
//!   AEAD construction instead. See the [`aead`](super::aead) module for this.
//! - Only a nonce for XChaCha20 is big enough to be randomly generated using a CSPRNG.
//! - To securely generate a strong key, use [`SecretKey::generate()`].
//!
//! # Recommendation:
//! - It is recommended to use [`XChaCha20Poly1305`] when possible.
//!
//! # Example:
//! ```rust
//! # #[cfg(feature = "safe_api")] {
//! use orion::hazardous::stream::chacha20;
//!
//! let secret_key = chacha20::SecretKey::generate();
//!
//! // WARNING: This nonce is only meant for demonstration and should not
//! // be repeated. Please read the security section.
//! let nonce = chacha20::Nonce::from([0u8; 12]);
//! let message = "Data to protect".as_bytes();
//!
//! // The length of this message is 15.
//!
//! let mut dst_out_pt = [0u8; 15];
//! let mut dst_out_ct = [0u8; 15];
//!
//! chacha20::encrypt(&secret_key, &nonce, 0, message, &mut dst_out_ct)?;
//!
//! chacha20::decrypt(&secret_key, &nonce, 0, &dst_out_ct, &mut dst_out_pt)?;
//!
//! assert_eq!(dst_out_pt, message);
//! # }
//! # Ok::<(), orion::errors::UnknownCryptoError>(())
//! ```
//! [`SecretKey::generate()`]: chacha20::SecretKey::generate()
//! [`XChaCha20Poly1305`]: super::aead::xchacha20poly1305
//! [RFC]: https://tools.ietf.org/html/rfc8439
use crate::errors::UnknownCryptoError;
use crate::util::endianness::load_u32_le;
use crate::util::u32x4::U32x4;
use zeroize::{Zeroize, Zeroizing};

/// The key size for ChaCha20.
pub const CHACHA_KEYSIZE: usize = 32;
/// The nonce size for IETF ChaCha20.
pub const IETF_CHACHA_NONCESIZE: usize = 12;
/// The blocksize which ChaCha20 operates on.
pub(crate) const CHACHA_BLOCKSIZE: usize = 64;
/// The size of the subkey that HChaCha20 returns.
const HCHACHA_OUTSIZE: usize = 32;
/// The nonce size for HChaCha20.
pub(crate) const HCHACHA_NONCESIZE: usize = 16;

construct_secret_key! {
    /// A type to represent the `SecretKey` that Chacha20, XChaCha20, ChaCha20-Poly1305 and
    /// XChaCha20-Poly1305 use.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 32 bytes.
    ///
    /// # Panics:
    /// A panic will occur if:
    /// - Failure to generate random bytes securely.
    (SecretKey, test_secret_key, CHACHA_KEYSIZE, CHACHA_KEYSIZE, CHACHA_KEYSIZE)
}

impl_from_trait!(SecretKey, CHACHA_KEYSIZE);

construct_public! {
    /// A type that represents a `Nonce` that ChaCha20 and ChaCha20-Poly1305 use.
    ///
    /// # Errors:
    /// An error will be returned if:
    /// - `slice` is not 12 bytes.
    (Nonce, test_nonce, IETF_CHACHA_NONCESIZE, IETF_CHACHA_NONCESIZE)
}

impl_from_trait!(Nonce, IETF_CHACHA_NONCESIZE);

macro_rules! ROUND {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr) => {
        $r0 = $r0.wrapping_add($r1);
        $r3 = ($r3 ^ $r0).rotate_left(16);

        $r2 = $r2.wrapping_add($r3);
        $r1 = ($r1 ^ $r2).rotate_left(12);

        $r0 = $r0.wrapping_add($r1);
        $r3 = ($r3 ^ $r0).rotate_left(8);

        $r2 = $r2.wrapping_add($r3);
        $r1 = ($r1 ^ $r2).rotate_left(7);
    };
}

macro_rules! DOUBLE_ROUND {
    ($r0:expr, $r1:expr, $r2:expr, $r3:expr) => {
        ROUND!($r0, $r1, $r2, $r3);

        // Shuffle
        $r1 = $r1.shl_1();
        $r2 = $r2.shl_2();
        $r3 = $r3.shl_3();

        ROUND!($r0, $r1, $r2, $r3);

        // Unshuffle
        $r1 = $r1.shl_3();
        $r2 = $r2.shl_2();
        $r3 = $r3.shl_1();
    };
}
pub(crate) struct ChaCha20 {
    state: [U32x4; 4],
    internal_counter: u32,
    is_ietf: bool,
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.state.iter_mut().zeroize();
    }
}

impl ChaCha20 {
    #[allow(clippy::unreadable_literal)]
    /// Initialize either a ChaCha or HChaCha state with a `secret_key` and
    /// `nonce`.
    pub(crate) fn new(sk: &[u8], n: &[u8], is_ietf: bool) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(sk.len(), CHACHA_KEYSIZE);
        if (n.len() != IETF_CHACHA_NONCESIZE) && is_ietf {
            return Err(UnknownCryptoError);
        }
        if (n.len() != HCHACHA_NONCESIZE) && !is_ietf {
            return Err(UnknownCryptoError);
        }

        // Row 0 with constants.
        let r0 = U32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);

        // Row 1 and 2 with secret key.
        let r1 = U32x4(
            load_u32_le(&sk[0..4]),
            load_u32_le(&sk[4..8]),
            load_u32_le(&sk[8..12]),
            load_u32_le(&sk[12..16]),
        );

        let r2 = U32x4(
            load_u32_le(&sk[16..20]),
            load_u32_le(&sk[20..24]),
            load_u32_le(&sk[24..28]),
            load_u32_le(&sk[28..32]),
        );

        // Row 3 with counter and nonce if IETF,
        // but only nonce if HChaCha20.
        let r3 = if is_ietf {
            U32x4(
                0, // Default counter
                load_u32_le(&n[0..4]),
                load_u32_le(&n[4..8]),
                load_u32_le(&n[8..12]),
            )
        } else {
            U32x4(
                load_u32_le(&n[0..4]),
                load_u32_le(&n[4..8]),
                load_u32_le(&n[8..12]),
                load_u32_le(&n[12..16]),
            )
        };

        Ok(Self {
            state: [r0, r1, r2, r3],
            internal_counter: 0,
            is_ietf,
        })
    }

    /// Check that we can produce one more keystream block, given the current state.
    ///
    /// If the internal counter would overflow, we return an error.
    pub(crate) fn next_produceable(&self) -> Result<(), UnknownCryptoError> {
        if self.internal_counter.checked_add(1).is_none() {
            Err(UnknownCryptoError)
        } else {
            Ok(())
        }
    }

    /// Process the next keystream and copy into destination array.
    pub(crate) fn keystream_block(&mut self, block_counter: u32, inplace: &mut [u8]) {
        debug_assert!(if self.is_ietf {
            inplace.len() == CHACHA_BLOCKSIZE
        } else {
            inplace.len() == HCHACHA_OUTSIZE
        });

        if self.is_ietf {
            self.state[3].0 = block_counter;
        }

        // If this panics, max amount of keystream blocks
        // have been retrieved.
        self.internal_counter = self.internal_counter.checked_add(1).unwrap();

        let mut wr0 = self.state[0];
        let mut wr1 = self.state[1];
        let mut wr2 = self.state[2];
        let mut wr3 = self.state[3];

        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);
        DOUBLE_ROUND!(wr0, wr1, wr2, wr3);

        let mut iter = inplace.chunks_exact_mut(16);

        if self.is_ietf {
            wr0 = wr0.wrapping_add(self.state[0]);
            wr1 = wr1.wrapping_add(self.state[1]);
            wr2 = wr2.wrapping_add(self.state[2]);
            wr3 = wr3.wrapping_add(self.state[3]);

            wr0.store_into_le(iter.next().unwrap());
            wr1.store_into_le(iter.next().unwrap());
            wr2.store_into_le(iter.next().unwrap());
            wr3.store_into_le(iter.next().unwrap());
        } else {
            wr0.store_into_le(iter.next().unwrap());
            wr3.store_into_le(iter.next().unwrap());
        }
    }
}

/// XOR keystream into destination array using a temporary buffer for each keystream block.
pub(crate) fn xor_keystream(
    ctx: &mut ChaCha20,
    initial_counter: u32,
    tmp_block: &mut [u8],
    bytes: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    debug_assert_eq!(tmp_block.len(), CHACHA_BLOCKSIZE);
    if bytes.is_empty() {
        return Err(UnknownCryptoError);
    }

    for (ctr, out_block) in bytes.chunks_mut(CHACHA_BLOCKSIZE).enumerate() {
        match initial_counter.checked_add(ctr as u32) {
            Some(counter) => {
                ctx.keystream_block(counter, tmp_block);
                xor_slices!(tmp_block, out_block);
            }
            None => return Err(UnknownCryptoError),
        }
    }

    Ok(())
}

/// In-place IETF ChaCha20 encryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub(crate) fn encrypt_in_place(
    secret_key: &SecretKey,
    nonce: &Nonce,
    initial_counter: u32,
    bytes: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if bytes.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut ctx = ChaCha20::new(secret_key.unprotected_as_bytes(), nonce.as_ref(), true)?;
    let mut keystream_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);
    xor_keystream(&mut ctx, initial_counter, keystream_block.as_mut(), bytes)
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// IETF ChaCha20 encryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn encrypt(
    secret_key: &SecretKey,
    nonce: &Nonce,
    initial_counter: u32,
    plaintext: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    if dst_out.len() < plaintext.len() {
        return Err(UnknownCryptoError);
    }
    if plaintext.is_empty() {
        return Err(UnknownCryptoError);
    }

    let mut ctx = ChaCha20::new(secret_key.unprotected_as_bytes(), nonce.as_ref(), true)?;
    let mut keystream_block = Zeroizing::new([0u8; CHACHA_BLOCKSIZE]);

    for (ctr, (p_block, c_block)) in plaintext
        .chunks(CHACHA_BLOCKSIZE)
        .zip(dst_out.chunks_mut(CHACHA_BLOCKSIZE))
        .enumerate()
    {
        match initial_counter.checked_add(ctr as u32) {
            Some(counter) => {
                // See https://github.com/orion-rs/orion/issues/308
                ctx.next_produceable()?;

                ctx.keystream_block(counter, keystream_block.as_mut());
                xor_slices!(p_block, keystream_block.as_mut());
                c_block[..p_block.len()]
                    .copy_from_slice(&keystream_block.as_ref()[..p_block.len()]);
            }
            None => return Err(UnknownCryptoError),
        }
    }

    Ok(())
}

#[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
/// IETF ChaCha20 decryption as specified in the [RFC 8439](https://tools.ietf.org/html/rfc8439).
pub fn decrypt(
    secret_key: &SecretKey,
    nonce: &Nonce,
    initial_counter: u32,
    ciphertext: &[u8],
    dst_out: &mut [u8],
) -> Result<(), UnknownCryptoError> {
    encrypt(secret_key, nonce, initial_counter, ciphertext, dst_out)
}

/// HChaCha20 as specified in the [draft-RFC](https://github.com/bikeshedders/xchacha-rfc/blob/master).
pub(super) fn hchacha20(
    secret_key: &SecretKey,
    nonce: &[u8],
) -> Result<[u8; HCHACHA_OUTSIZE], UnknownCryptoError> {
    let mut chacha_state = ChaCha20::new(secret_key.unprotected_as_bytes(), nonce, false)?;
    let mut keystream_block = [0u8; HCHACHA_OUTSIZE];
    chacha_state.keystream_block(0, &mut keystream_block);

    Ok(keystream_block)
}

// Testing public functions in the module.
#[cfg(test)]
mod public {
    use super::*;

    #[cfg(feature = "safe_api")]
    #[test]
    // See https://github.com/orion-rs/orion/issues/308
    fn test_plaintext_left_in_dst_out() {
        let k = SecretKey::generate();
        let n = Nonce::from_slice(&[0u8; 12]).unwrap();
        let ic: u32 = u32::MAX - 1;

        let text = [b'x'; 128 + 4];
        let mut dst_out = [0u8; 128 + 4];

        let _err = encrypt(&k, &n, ic, &text, &mut dst_out).unwrap_err();

        assert_ne!(&[b'x'; 4], &dst_out[dst_out.len() - 4..]);
    }

    #[cfg(feature = "safe_api")]
    mod test_encrypt_decrypt {
        use super::*;
        use crate::test_framework::streamcipher_interface::*;

        impl TestingRandom for SecretKey {
            fn gen() -> Self {
                Self::generate()
            }
        }

        impl TestingRandom for Nonce {
            fn gen() -> Self {
                let mut n = [0u8; IETF_CHACHA_NONCESIZE];
                crate::util::secure_rand_bytes(&mut n).unwrap();
                Self::from_slice(&n).unwrap()
            }
        }

        #[quickcheck]
        fn prop_streamcipher_interface(input: Vec<u8>, counter: u32) -> bool {
            let secret_key = SecretKey::generate();
            let nonce = Nonce::from_slice(&[0u8; IETF_CHACHA_NONCESIZE]).unwrap();
            StreamCipherTestRunner(encrypt, decrypt, secret_key, nonce, counter, &input, None);
            test_diff_params_diff_output(&encrypt, &decrypt);

            true
        }
    }

    // hex crate uses Vec<u8>, so we need std.
    mod test_hchacha20 {
        use super::*;

        use hex::decode;

        #[test]
        fn test_nonce_length() {
            assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16],).is_ok());
            assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 17],).is_err());
            assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 15],).is_err());
            assert!(hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 0],).is_err());
        }

        #[test]
        fn test_diff_keys_diff_output() {
            let keystream1 =
                hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16]).unwrap();

            let keystream2 =
                hchacha20(&SecretKey::from_slice(&[1u8; 32]).unwrap(), &[0u8; 16]).unwrap();

            assert_ne!(keystream1, keystream2);
        }

        #[test]
        fn test_diff_nonce_diff_output() {
            let keystream1 =
                hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[0u8; 16]).unwrap();

            let keystream2 =
                hchacha20(&SecretKey::from_slice(&[0u8; 32]).unwrap(), &[1u8; 16]).unwrap();

            assert_ne!(keystream1, keystream2);
        }

        pub fn hchacha_test_runner(key: &str, nonce: &str, output_expected: &str) {
            let actual: [u8; 32] = hchacha20(
                &SecretKey::from_slice(&decode(key).unwrap()).unwrap(),
                &decode(nonce).unwrap(),
            )
            .unwrap();

            assert_eq!(&actual, &decode(output_expected).unwrap()[..]);
        }

        // Testing against Monocypher-generated test vectors
        // https://github.com/LoupVaillant/Monocypher/tree/master/tests/gen
        // Pulled at commit: https://github.com/LoupVaillant/Monocypher/commit/39b164a5bf715d1a62689203b059144df76d98e2

        #[test]
        fn test_case_0() {
            let key = "e4e4c4054fe35a75d9c0f679ad8770d8227e68e4c1e68ce67ee88e6be251a207";
            let nonce = "48b3753cff3a6d990163e6b60da1e4e5";
            let expected_output =
                "d805447c583fd97a07a2b7ab66be621ad0fa32d63d86ac20588da90b87c1907b";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_1() {
            let key = "d6a2df78c16c96a52d4fb01ea4ecf70e81ac001b08d6577bd91ce991c4c45c46";
            let nonce = "bc84d5465fc9139bf17042ae7313181f";
            let expected_output =
                "66d1fd5e89a564b55ccf0c339455449c20dfbc9d17081c85fbb430a157777be9";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_2() {
            let key = "7afb217bd1eceeac1e133aaa9edb441fa88ea3ae0eaa06cb9911b6d218570f92";
            let nonce = "4a70a7e992b43e0b18578e892e954c40";
            let expected_output =
                "41119e28a00a9d3f24b1910495f3058f9db83cbcf12889de84a2fcd7de8dc31b";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_3() {
            let key = "a51abdb5a85d300c32f391c45d6ef4db043ddcf4214f24ea6ef6b181071f299a";
            let nonce = "a254a4606ab6a058e0c6fb5598218db7";
            let expected_output =
                "04c2f31fdcc7013ac7d10ec82e8d3628c9ab23b08bbf95d6d77ad2dec7e865d6";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_4() {
            let key = "1deb473f7d04c152e7e857736715dc7b788aca39a3c96a878019e8999c815c57";
            let nonce = "23dbfbde05e6c71f118afc0dedb5b9f8";
            let expected_output =
                "75e9a94daf28b6b8634823325c61cdcb2beeb17a8f7554cc6d5b1b1d2e3592cf";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_5() {
            let key = "dea398b2d764bca68dfc023a9821939d389e38a072cf1b413bb1517c3fe83abe";
            let nonce = "bb1cdf3a218abb1b0c01da64c24f59ee";
            let expected_output =
                "65a20993e8e69de41d38e94c0796cb7baccd6d80a6e4084e65d0d574fbcb7311";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_6() {
            let key = "d19cfb8cb3940aba546f0be57895e2cc869fe55aab069c5abcf9e7ba6444a846";
            let nonce = "e5d73f1c8c5376c1220ff3d9d53eeb65";
            let expected_output =
                "a345f5f10ec20b4a744634fbb94e94c9425699b4d57ffeab5403b8fbfb85bae7";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_7() {
            let key = "cc53599f40d6c8348c353b00172655236cddcd1879ca1f04b35f91adab70b81f";
            let nonce = "504035fc169964a5ae985e6c11b0b7bb";
            let expected_output =
                "11dda56dce88c92641177e2a6e21b11c5ca794912b3bceb9ccb375c87bcc7968";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_8() {
            let key = "18a51fd77fbffd722aa220efdd8947ca5a5c7fb1c2ebdb9ad1f603801ff22e80";
            let nonce = "314f716af9c22022fa159dbb4b4d3153";
            let expected_output =
                "14759f0e978a9f45a4696739fecb590b4ba6f06536384225333cccba074c8a68";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_9() {
            let key = "f999b20ab4769eb1d01c057c5295ed042b4536561dce32478b113adb5b605cac";
            let nonce = "75bcfcacb5e3e811b78e72e398fdd118";
            let expected_output =
                "564eb6b2ac2b92270af7c0b054cc7a721313e4ed3651b0970db9dfcdfda27220";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_10() {
            let key = "bf04c6a7ed0756a3533e3dca02109e1830b739210bd8bffe6a8a542980bd73e9";
            let nonce = "ca43cdd4eb7173476862df6d2458d6c7";
            let expected_output =
                "4f8975d01fb3525a60de55c61190471e86b95cb3e835374d58b003f55eb9819a";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_11() {
            let key = "4739a0ad2169b9c89edd74e16fbcecc748c25dc338041fc34af0f1bda20eaf3f";
            let nonce = "ff7b372aa801eb98a1298bc610280737";
            let expected_output =
                "06ccde41d10d6466859927bfc9a476dbc84064838ec721261cb548c18bd14c67";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_12() {
            let key = "50831c8cb43cd6822bf3f6fae0801cb6c843d8066b07346635365fb7d6ee54e5";
            let nonce = "c9cd6f05d76b2bd4caec8d80b58235cb";
            let expected_output =
                "6ed040d7721395fb2c74c8afe252a169ded78e6f2f889e8fb0ec1490533a8154";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_13() {
            let key = "4268543ab0eb865a948cc5b5f6e31f05f8146bd9495acc459d6d200005ee72c3";
            let nonce = "bc3e4ae3badfd79adfe46b2ae1045f78";
            let expected_output =
                "19b839a6d3424cf2a52d301e70e76cb77368cf9f60945bf43ce4c657aeb1d157";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_14() {
            let key = "382e04c969df1a2d6a963a79c58401770a383248b5d70bb4adedcbe520fed634";
            let nonce = "f513b8c2ea6ab37fe633ba7302a5db6c";
            let expected_output =
                "fd0739819bae6c98cbde7cb50a80e8d0b359567c50cec1ca7e985745c1cedb3a";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_15() {
            let key = "2aa209e24478fa1bd6f6ffabe98555e034342cbec07364c54d1e407e282ef08e";
            let nonce = "dbfdbde936c9d42df58ae15889f5c939";
            let expected_output =
                "f5047baa0acf9a603415a09b64268d77712ae902c73490e9c53db593765726db";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_16() {
            let key = "a3087eaeac1f2a58e2c2763d01b55744c4a65f4db93adff0078c63f090fb607a";
            let nonce = "90c87defd622e5f55977877cec9ed883";
            let expected_output =
                "1d882fa80248882c6bc311a693ebd06b8c09aa2776e6e90df523d12bfeeed77a";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_17() {
            let key = "12b0411228540cd6dde6e84cd2da59b1871db119e3298e3c12fe8200a47eddf0";
            let nonce = "49c971cd99f694e3b2a5e25fa37aedf0";
            let expected_output =
                "69bb83ccb7bc4deaf60cfe168cb11fad4257222c3523c2d08922564ac0fb74d2";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_18() {
            let key = "1bf32e7c679a3187e22a635d301ce98ad000ca301049f2e891e403250c3358fc";
            let nonce = "2030b227bb96e93b88f419afe9f9d660";
            let expected_output =
                "d0ed414a875a81db1e4cff7609afdbb2ffcdd575ebc17543fb92de53c6487efb";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_19() {
            let key = "e013761228051ec5a8f0c093b33fc60e2cd7a9c845434e95d4319d79d1bdaa8f";
            let nonce = "73853fbd9958e9ffc23a0ecbb7b48dbb";
            let expected_output =
                "e3f6c6da6c0300103d665dd877a8b62e23b1361bf3af5bbc2310502131d69be8";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_20() {
            let key = "a63672d582bb83d92249800324cbc9a6e5b37d36887e7c79093f58ef8f1a0015";
            let nonce = "85321bfee1714260dd6130cc768d20b1";
            let expected_output =
                "97e05360aca70058389d93be38d49fa26df01a4d3b4c4f10c3ec31e0ed64f08e";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_21() {
            let key = "4d3850f0eec0f8f349110e751c16cdb5ed05516df17479937d942c90eb1fb181";
            let nonce = "3062bd3f3f6b7668cd8fd3afce0cc752";
            let expected_output =
                "77513195542b2ab157cb2e6870c5b1ba143a8423ad276a64152ab923c6f54c06";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_22() {
            let key = "9b87dfc58eceb951e1e53d9e94793329199c42d004bc0f0dab3adf0cd702e99e";
            let nonce = "fa5ef6e59d3b201680f8e2d5a4ef7f23";
            let expected_output =
                "56a208bd87c5b486b5de50fbe4c1c476532f874147eba529cbb0cbeae8f09b94";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_23() {
            let key = "f1b6a8e102670a3829a995ae23fbc3a5639e028cd2b5f71bb90c7a1e4a8a0501";
            let nonce = "7d26e3afc3a88541f6c3f45d71f8a3cc";
            let expected_output =
                "a02140057f889e7ab36b4a5066e376dff248d13bd8072c384e23bd8fe4bf7047";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_24() {
            let key = "31a063ea4aad1b4d00db6f5228e9b9b1561a7f61812b8b79e6af4292580d02ea";
            let nonce = "4f6266d04244303304510272e383eaa5";
            let expected_output =
                "d610d44b8b3c14c7d3782f73405637fd14b7fada717665a9acbd4df6daa89adc";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_25() {
            let key = "1a8ea7099a74bafa3375b210653a0d2f40b15afd725cf5065066be1cb803dc15";
            let nonce = "8865ed8d7cca72dcf2b7c6b5d0d045bf";
            let expected_output =
                "f10cce296197a056bedbee166183ad6aaa56bdb21c3459296ca54c0bb78317d1";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_26() {
            let key = "32b063d3da484ba1843e071b61c49ce7f30ba18a4f7ef2730ecd785494839966";
            let nonce = "f593168e17311913753c59593fc66cb6";
            let expected_output =
                "f18115a9568724c25184728f563b65b737219cb0df1b3ce19a8bdcbdf7b8b2be";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_27() {
            let key = "64c1572251132fc28bf37fd8e96f2327cf7948a1126fd37175a91f483d6b3ad9";
            let nonce = "2308df7e6daa8bf3efde75f80ad72a49";
            let expected_output =
                "06a24cb90abe94cf3ee8e429d8197bc42bc769fbe81119156274f9692aa017a2";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_28() {
            let key = "ae0794009e21ad33fa4141fe5fa79fed12f6a20f51614dc130f45598e92549b1";
            let nonce = "13ed6185724507e7fa5a7e8a75b2c7a3";
            let expected_output =
                "51d1aec8d64d20e448a377bfa83ccbf71a73a3ad00d062bf6b83c549a7296ef1";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_29() {
            let key = "ad700919f36a46ea0ffa680857e30188f8a03c7c4b6c11bc39aececec2668723";
            let nonce = "3682d31887277028e2fd286f2654c681";
            let expected_output =
                "a24610a94968df2dc9d197cd0bc55cab08c9dabd444c0efcd2a47fd37016382e";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_30() {
            let key = "efd9e7ed6b340874e897337d4dcc672811a6cf4b69086e0a57c266424dc1d10e";
            let nonce = "cbaf0c822cce9e4f17b19e0ece39c180";
            let expected_output =
                "6f94a0f8ed7f3fe5ebaa3b8caba016ab64373ffc3c7b1c86e6787f31b4a905ec";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_31() {
            let key = "a4c756c03c19900280ff6cdebe5174d507c6e0860c38c3537176c58965b74a56";
            let nonce = "c52b3151bb8a149cf4f82158d57c823f";
            let expected_output =
                "50ea3d4f6a45e4a062b2d966e63cac51e093dfb6ab9df6d16bb109bc177b0a38";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_32() {
            let key = "3a90c6b427912226ff604d9abee1fb8c8d35530a0cd5808e53e308ac580f7318";
            let nonce = "fe2ab2a4933b5d90db718aa3440fbe9b";
            let expected_output =
                "2b57adcc5d26060383c87ef7e055f9aca4addcb2646cbf2cff4edc3f17b72ad5";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_33() {
            let key = "a17f09716219bdffc93a189e410a6a3e6477fbb05c7c35956c3c0c5f342355fa";
            let nonce = "0850307998642501c025e3873ebac3cc";
            let expected_output =
                "d3a58c49e9fe1ecf2eca169f4d4131cde27279053d562d0429a08ec701aaa39e";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_34() {
            let key = "d749d8379ae6d830f785ec104897bd723d34ad20c9d36bfe371df46aebc6d459";
            let nonce = "5d490a770bee4dd0be6a5a0b5e95645c";
            let expected_output =
                "c278c0079bd656f1dadf3dec692f19f25339c6557542181716d2a41379740bf2";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_35() {
            let key = "7dcbc03c27010df3320fe75b0a3ecc8983ad94217e80348fd0f3f54e54b95bb5";
            let nonce = "48dc2225a264443732b41b861590358d";
            let expected_output =
                "b244c408c74f3dcb8bcb72f834a054c554edad0363d761847003dab003ac6848";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_36() {
            let key = "543894006b73f3d70fc04b15d0c2a5dfa650be5044fb5061811b866be7f9d623";
            let nonce = "fcb077ee19421610aeb263c57faef006";
            let expected_output =
                "fb20ea177cb7225c87122f285d92faf0c2033e2497575f74505255b6d3dfcb96";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_37() {
            let key = "62d424c07a7aa5005068b262251c0667a4e2e4b12f5df7f509564517887e370b";
            let nonce = "425fabab1ce9e733ab2911b42074414e";
            let expected_output =
                "3a5eb5552cdd267c05c1e4fe936ce8f0eaf7279ff328ed9a42d6d83f7b30416c";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_38() {
            let key = "387d7247fa5055489bbd4b7d4de256de723566c1c2d3ecee8c10e7d98233dbef";
            let nonce = "90494951ec91a843f6701f8216a7326b";
            let expected_output =
                "8c4bc60a1e05004ec93aef4ae162aeff43d679ea1ba048739c700d6a168bc6cc";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_39() {
            let key = "241fd57f32e09976de4054797b9aee820e0de381d02852ac13f511918267b703";
            let nonce = "7330e60ba1c5875a0275f8ccc75cbe98";
            let expected_output =
                "9e724c5b0321e2528278a501108f1ae8a14dffaea9b6b138eacef3bd8d4dda41";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_40() {
            let key = "7c12457eb5614f87f1fdc40118906d02c602059d48ae05ae62d3d607d6bf63c6";
            let nonce = "760b802483b0e3aaa9dd4f79c6c5e93e";
            let expected_output =
                "e5b86f76fbc1f488c44e4d7f304736b752ab6cfb99fcf6910668eeefa4b67c2a";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_41() {
            let key = "6b51da45018c6bde108f81f9abfa23640b83cfe3fed34bcf6640bf0baf647daf";
            let nonce = "e9bc99acee972b5a152efa3e69e50f34";
            let expected_output =
                "1032b5d539b1c8cd6e0be96db443a08fc759bea8988384435c03b5f00b6e485f";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_42() {
            let key = "3bc12887fec8e70db73b4b48dce564d83786aca4c6b7e224163ea928771fde37";
            let nonce = "78c453b35d98deced812fc5685843565";
            let expected_output =
                "2279b063dab4c73a96abe02175e694662c65d09eb5889234293c7a1f2911e13d";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_43() {
            let key = "b73d097601d3558278bd9d7327de5fdaa2b842050b370e837ef811a496169d5f";
            let nonce = "f768878766c08c45561fdc2aad6469c1";
            let expected_output =
                "a8e85a6ab627f08ad415649a9cf9998f4b1065030f3c844e31c8185036af7558";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_44() {
            let key = "1380c3d3f873c7233c541ea4c43824ecd8bf7e11ac8486208fb685218d46736e";
            let nonce = "51103d1fae0e8e368f25480ee7328381";
            let expected_output =
                "9b84e50804449b594a54240741e21d75d31050d2612f4cbc651fea2f25bd9c1f";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_45() {
            let key = "c2f8b252a18a29c44dbfbb62cbe6c3dfd4db55378734d8110b8f20f1d1ada6dd";
            let nonce = "d4da48fb09c06580eb46bbc5ca62bfab";
            let expected_output =
                "315c3fe1009e438762a72f27e7a68b8ccb2c0b60bf79cb6e48123db0c42d4aeb";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_46() {
            let key = "40b184271b73b710d40cb63435042c9b526d1e5c3a77bfc516a2bcb4cc27ecae";
            let nonce = "b3451318590c84e311dd1e876f527d81";
            let expected_output =
                "cbbde3a3412504c1f684aa273ee691159edc9f44e306360278d63d4ee2f1faa4";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_47() {
            let key = "ec81df06c7e426b729aebb02be30c846eb228490df4a0e6c688aaaa6bf05d144";
            let nonce = "28335f2652926bfdfe32dfd789173ba8";
            let expected_output =
                "522b522e4cf9aa1e80126a446ed7b9665af3e781a3d5afdce43a5fe0cdbd4351";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_48() {
            let key = "60fa0114802ee333d7c49ccaad8108db470c882514716592e57aba26bb75049b";
            let nonce = "75db088bd1a89c6a67fb76b96c987478";
            let expected_output =
                "e004cc12dfdb74268e59958385e2a1c6ff31e31664838971629f5bbf88f4ed51";
            hchacha_test_runner(key, nonce, expected_output);
        }
        #[test]
        fn test_case_49() {
            let key = "bfba2449a607f3cca1c911d3b7d9cb972bcd84b0246189c7820032e031949f1e";
            let nonce = "97e8ad5eb5a75cc805900850969de48e";
            let expected_output =
                "19faebfbb954552fcfbf9b91f271c9397a15c641733c394a9cb731c286c68645";
            hchacha_test_runner(key, nonce, expected_output);
        }
    }
}

// Testing private functions in the module.
#[cfg(test)]
mod private {
    use super::*;

    mod test_init_state {
        use super::*;

        #[test]
        fn test_nonce_length() {
            assert!(ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; 15], true).is_err());
            assert!(ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; 10], true).is_err());
            assert!(
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; IETF_CHACHA_NONCESIZE], true).is_ok()
            );

            assert!(ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; 15], false).is_err());
            assert!(ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; 17], false).is_err());
            assert!(
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; HCHACHA_NONCESIZE], false).is_ok()
            );
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        fn prop_test_nonce_length_ietf(nonce: Vec<u8>) -> bool {
            if nonce.len() == IETF_CHACHA_NONCESIZE {
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &nonce[..], true).is_ok()
            } else {
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &nonce[..], true).is_err()
            }
        }

        #[quickcheck]
        #[cfg(feature = "safe_api")]
        // Always fail to initialize state while the nonce is not
        // the correct length. If it is correct length, never panic.
        fn prop_test_nonce_length_hchacha(nonce: Vec<u8>) -> bool {
            if nonce.len() == HCHACHA_NONCESIZE {
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &nonce, false).is_ok()
            } else {
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &nonce, false).is_err()
            }
        }
    }

    mod test_encrypt_in_place {
        use super::*;

        #[test]
        #[should_panic]
        #[cfg(debug_assertions)]
        fn test_xor_keystream_err_bad_tmp() {
            let mut ctx =
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; IETF_CHACHA_NONCESIZE], true).unwrap();
            let mut tmp = [0u8; CHACHA_BLOCKSIZE - 1];
            let mut out = [0u8; CHACHA_BLOCKSIZE];
            xor_keystream(&mut ctx, 0, &mut tmp, &mut out).unwrap();
        }

        #[test]
        fn test_xor_keystream_err_empty_input() {
            let mut ctx =
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; IETF_CHACHA_NONCESIZE], true).unwrap();
            let mut tmp = [0u8; CHACHA_BLOCKSIZE];
            let mut out = [0u8; 0];
            assert!(xor_keystream(&mut ctx, 0, &mut tmp, &mut out).is_err());
        }

        #[test]
        fn test_enc_in_place_err_empty_input() {
            let n = Nonce::from([0u8; IETF_CHACHA_NONCESIZE]);
            let sk = SecretKey::from([0u8; CHACHA_KEYSIZE]);
            let mut out = [0u8; 0];
            assert!(encrypt_in_place(&sk, &n, 0, &mut out).is_err());
        }
    }

    mod test_keystream_block {
        use super::*;

        #[test]
        fn test_xor_keystream_block_ignore_counter_when_hchacha() {
            let mut chacha_state_hchacha =
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; HCHACHA_NONCESIZE], false).unwrap();

            let mut hchacha_keystream_block_zero = [0u8; HCHACHA_OUTSIZE];
            let mut hchacha_keystream_block_max = [0u8; HCHACHA_OUTSIZE];

            chacha_state_hchacha.keystream_block(0, &mut hchacha_keystream_block_zero);
            chacha_state_hchacha.keystream_block(u32::MAX, &mut hchacha_keystream_block_max);

            assert_eq!(hchacha_keystream_block_zero, hchacha_keystream_block_max);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic]
        fn test_xor_keystream_block_invalid_blocksize_ietf() {
            let mut chacha_state_ietf =
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; IETF_CHACHA_NONCESIZE], true).unwrap();

            let mut ietf_keystream_block = [0u8; CHACHA_BLOCKSIZE];
            let mut hchacha_keystream_block = [0u8; HCHACHA_OUTSIZE];

            chacha_state_ietf.keystream_block(0, &mut ietf_keystream_block);
            chacha_state_ietf.keystream_block(0, &mut hchacha_keystream_block);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic]
        fn test_xor_keystream_block_invalid_blocksize_hchacha() {
            let mut chacha_state_hchacha =
                ChaCha20::new(&[0u8; CHACHA_KEYSIZE], &[0u8; HCHACHA_NONCESIZE], false).unwrap();

            let mut ietf_keystream_block = [0u8; CHACHA_BLOCKSIZE];
            let mut hchacha_keystream_block = [0u8; HCHACHA_OUTSIZE];

            chacha_state_hchacha.keystream_block(0, &mut hchacha_keystream_block);
            chacha_state_hchacha.keystream_block(0, &mut ietf_keystream_block);
        }

        #[test]
        #[should_panic]
        fn test_xor_keystream_panic_on_too_much_keystream_data_ietf() {
            let mut chacha_state_ietf = ChaCha20 {
                state: [
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                ],
                internal_counter: (u32::MAX - 128),
                is_ietf: true,
            };

            let mut keystream_block = [0u8; CHACHA_BLOCKSIZE];

            for amount in 0..(128 + 1) {
                chacha_state_ietf.keystream_block(amount, &mut keystream_block);
            }
        }

        #[test]
        #[should_panic]
        fn test_xor_keystream_panic_on_too_much_keystream_data_hchacha() {
            let mut chacha_state_ietf = ChaCha20 {
                state: [
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                ],
                internal_counter: (u32::MAX - 128),
                is_ietf: false,
            };

            let mut keystream_block = [0u8; HCHACHA_OUTSIZE];

            for _ in 0..(128 + 1) {
                chacha_state_ietf.keystream_block(0, &mut keystream_block);
            }
        }

        #[test]
        fn test_error_if_internal_counter_would_overflow() {
            let mut chacha_state = ChaCha20 {
                state: [
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                    U32x4(0, 0, 0, 0),
                ],
                internal_counter: (u32::MAX - 2),
                is_ietf: false,
            };

            assert!(chacha_state.next_produceable().is_ok());
            chacha_state.internal_counter += 1;
            assert!(chacha_state.next_produceable().is_ok());
            chacha_state.internal_counter += 1;
            assert!(chacha_state.next_produceable().is_err());
        }
    }
}

// Testing any test vectors that aren't put into library's /tests folder.
#[cfg(test)]
mod test_vectors {
    use super::*;

    // NOTE: These PartialEq implementation should only be available in testing.
    #[cfg(test)]
    impl PartialEq for U32x4 {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3
        }
    }

    // Convenience function for testing.
    fn init(key: &[u8], nonce: &[u8]) -> Result<ChaCha20, UnknownCryptoError> {
        ChaCha20::new(key, nonce, true)
    }
    #[test]
    fn rfc8439_chacha20_block_results() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        let expected_init = [
            U32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
            U32x4(0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c),
            U32x4(0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c),
            U32x4(0x00000001, 0x09000000, 0x4a000000, 0x00000000),
        ];
        // Test initial key-setup
        let mut state = init(&key, &nonce).unwrap();
        // Set block counter
        state.state[3].0 = 1;
        assert!(state.state[..] == expected_init[..]);

        let mut kb = [0u8; 64];
        state.keystream_block(1, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_chacha20_block_test_1() {
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut kb = [0u8; 64];
        state.keystream_block(0, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_chacha20_block_test_2() {
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a, 0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d,
            0x08, 0x0d, 0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69, 0x12, 0xc6, 0x53, 0x3e,
            0x32, 0xee, 0x7a, 0xed, 0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43, 0xd5, 0x71,
            0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5, 0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
            0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut kb = [0u8; 64];
        state.keystream_block(1, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_chacha20_block_test_3() {
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x3a, 0xeb, 0x52, 0x24, 0xec, 0xf8, 0x49, 0x92, 0x9b, 0x9d, 0x82, 0x8d, 0xb1, 0xce,
            0xd4, 0xdd, 0x83, 0x20, 0x25, 0xe8, 0x01, 0x8b, 0x81, 0x60, 0xb8, 0x22, 0x84, 0xf3,
            0xc9, 0x49, 0xaa, 0x5a, 0x8e, 0xca, 0x00, 0xbb, 0xb4, 0xa7, 0x3b, 0xda, 0xd1, 0x92,
            0xb5, 0xc4, 0x2f, 0x73, 0xf2, 0xfd, 0x4e, 0x27, 0x36, 0x44, 0xc8, 0xb3, 0x61, 0x25,
            0xa6, 0x4a, 0xdd, 0xeb, 0x00, 0x6c, 0x13, 0xa0,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut kb = [0u8; 64];
        state.keystream_block(1, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_chacha20_block_test_4() {
        let key = [
            0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x72, 0xd5, 0x4d, 0xfb, 0xf1, 0x2e, 0xc4, 0x4b, 0x36, 0x26, 0x92, 0xdf, 0x94, 0x13,
            0x7f, 0x32, 0x8f, 0xea, 0x8d, 0xa7, 0x39, 0x90, 0x26, 0x5e, 0xc1, 0xbb, 0xbe, 0xa1,
            0xae, 0x9a, 0xf0, 0xca, 0x13, 0xb2, 0x5a, 0xa2, 0x6c, 0xb4, 0xa6, 0x48, 0xcb, 0x9b,
            0x9d, 0x1b, 0xe6, 0x5b, 0x2c, 0x09, 0x24, 0xa6, 0x6c, 0x54, 0xd5, 0x45, 0xec, 0x1b,
            0x73, 0x74, 0xf4, 0x87, 0x2e, 0x99, 0xf0, 0x96,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut kb = [0u8; 64];
        state.keystream_block(2, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_chacha20_block_test_5() {
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let expected = [
            0xc2, 0xc6, 0x4d, 0x37, 0x8c, 0xd5, 0x36, 0x37, 0x4a, 0xe2, 0x04, 0xb9, 0xef, 0x93,
            0x3f, 0xcd, 0x1a, 0x8b, 0x22, 0x88, 0xb3, 0xdf, 0xa4, 0x96, 0x72, 0xab, 0x76, 0x5b,
            0x54, 0xee, 0x27, 0xc7, 0x8a, 0x97, 0x0e, 0x0e, 0x95, 0x5c, 0x14, 0xf3, 0xa8, 0x8e,
            0x74, 0x1b, 0x97, 0xc2, 0x86, 0xf7, 0x5f, 0x8f, 0xc2, 0x99, 0xe8, 0x14, 0x83, 0x62,
            0xfa, 0x19, 0x8a, 0x39, 0x53, 0x1b, 0xed, 0x6d,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut kb = [0u8; 64];
        state.keystream_block(0, &mut kb);

        assert_eq!(kb[..], expected[..]);
    }

    #[test]
    fn rfc8439_key_schedule() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        // First block setup expected
        let first_state = [
            U32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
            U32x4(0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c),
            U32x4(0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c),
            U32x4(0x00000001, 0x00000000, 0x4a000000, 0x00000000),
        ];
        // Second block setup expected
        let second_state = [
            U32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
            U32x4(0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c),
            U32x4(0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c),
            U32x4(0x00000002, 0x00000000, 0x4a000000, 0x00000000),
        ];

        // Expected keystream
        let expected_keystream = [
            0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63,
            0x1d, 0xed, 0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2, 0x7e, 0x4f, 0xca, 0xec,
            0x9e, 0xf3, 0xcf, 0x78, 0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 0xb5, 0x79,
            0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34, 0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
            0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7, 0x69, 0xa6, 0x74, 0x9f, 0x3f, 0x63,
            0x0f, 0x41, 0x22, 0xca, 0xfe, 0x28, 0xec, 0x4d, 0xc4, 0x7e, 0x26, 0xd4, 0x34, 0x6d,
            0x70, 0xb9, 0x8c, 0x73, 0xf3, 0xe9, 0xc5, 0x3a, 0xc4, 0x0c, 0x59, 0x45, 0x39, 0x8b,
            0x6e, 0xda, 0x1a, 0x83, 0x2c, 0x89, 0xc1, 0x67, 0xea, 0xcd, 0x90, 0x1d, 0x7e, 0x2b,
            0xf3, 0x63,
        ];

        let mut state = init(&key, &nonce).unwrap();
        let mut actual_keystream = [0u8; 128];

        state.keystream_block(1, &mut actual_keystream[..64]);
        assert!(first_state == state.state);

        state.keystream_block(2, &mut actual_keystream[64..]);
        assert!(second_state == state.state);

        assert_eq!(
            actual_keystream[..expected_keystream.len()].as_ref(),
            expected_keystream.as_ref()
        );
    }
}
