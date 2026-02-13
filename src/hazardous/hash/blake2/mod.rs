// MIT License

// Copyright (c) 2018-2026 The orion Developers

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

/// BLAKE2b as specified in the [RFC 7693](https://tools.ietf.org/html/rfc7693).
pub mod blake2b;

pub(crate) mod blake2b_core {

    /// The blocksize for the hash function BLAKE2b.
    pub(crate) const BLAKE2B_BLOCKSIZE: usize = 128;
    /// The maximum key size for the hash function BLAKE2b when used in keyed mode.
    pub(crate) const BLAKE2B_KEYSIZE: usize = 64;
    /// The maximum output size for the hash function BLAKE2b.
    pub(crate) const BLAKE2B_OUTSIZE: usize = 64;

    use crate::errors::UnknownCryptoError;
    use crate::util::endianness::load_u64_into_le;
    use crate::util::u64x4::U64x4;

    #[allow(clippy::unreadable_literal)]
    /// The BLAKE2b initialization vector as defined in the RFC 7693.
    pub(crate) const IV: [U64x4; 2] = [
        U64x4(
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
        ),
        U64x4(
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ),
    ];

    /// BLAKE2b SIGMA as defined in the RFC 7693.
    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    /// Quarter round on the BLAKE2b internal matrix.
    macro_rules! QROUND {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $s_idx:expr, $rconst1:expr, $rconst2:expr) => {
            $v0 = $v0.wrapping_add($v1).wrapping_add($s_idx);
            $v3 = ($v3 ^ $v0).rotate_right($rconst1);
            $v2 = $v2.wrapping_add($v3);
            $v1 = ($v1 ^ $v2).rotate_right($rconst2);
        };
    }

    /// Perform a single round based on a message schedule selection.
    macro_rules! ROUND {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr, $s_idx:expr, $m:expr) => {
            let s_indexed = U64x4($m[$s_idx[0]], $m[$s_idx[2]], $m[$s_idx[4]], $m[$s_idx[6]]);
            QROUND!($v0, $v1, $v2, $v3, s_indexed, 32, 24);
            let s_indexed = U64x4($m[$s_idx[1]], $m[$s_idx[3]], $m[$s_idx[5]], $m[$s_idx[7]]);
            QROUND!($v0, $v1, $v2, $v3, s_indexed, 16, 63);

            // Shuffle
            $v1 = $v1.shl_1();
            $v2 = $v2.shl_2();
            $v3 = $v3.shl_3();

            let s_indexed = U64x4(
                $m[$s_idx[8]],
                $m[$s_idx[10]],
                $m[$s_idx[12]],
                $m[$s_idx[14]],
            );
            QROUND!($v0, $v1, $v2, $v3, s_indexed, 32, 24);
            let s_indexed = U64x4(
                $m[$s_idx[9]],
                $m[$s_idx[11]],
                $m[$s_idx[13]],
                $m[$s_idx[15]],
            );
            QROUND!($v0, $v1, $v2, $v3, s_indexed, 16, 63);

            // Unshuffle
            $v1 = $v1.shl_3();
            $v2 = $v2.shl_2();
            $v3 = $v3.shl_1();
        };
    }

    #[derive(Clone)]
    /// BLAKE2b streaming state.
    pub(crate) struct State {
        pub(crate) init_state: [U64x4; 2],
        pub(crate) internal_state: [U64x4; 2],
        pub(crate) buffer: [u8; BLAKE2B_BLOCKSIZE],
        pub(crate) leftover: usize,
        pub(crate) t: [u64; 2],
        pub(crate) f: [u64; 2],
        pub(crate) is_finalized: bool,
        pub(crate) is_keyed: bool,
        pub(crate) size: usize,
    }

    impl Drop for State {
        #[cfg(feature = "zeroize")]
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.init_state.iter_mut().zeroize();
            self.internal_state.iter_mut().zeroize();
            self.buffer.zeroize();
        }
    }

    impl core::fmt::Debug for State {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "State {{ init_state: [***OMITTED***], internal_state: [***OMITTED***], buffer: \
             [***OMITTED***], leftover: {:?}, t: {:?}, f: {:?}, is_finalized: {:?}, is_keyed: \
             {:?}, size: {:?} }}",
                self.leftover, self.t, self.f, self.is_finalized, self.is_keyed, self.size
            )
        }
    }

    impl State {
        /// Increment the internal states offset value `t`.
        pub(crate) fn _increment_offset(&mut self, value: u64) {
            let (res, was_overflow) = self.t[0].overflowing_add(value);
            self.t[0] = res;
            if was_overflow {
                // If this panics size limit is reached.
                self.t[1] = self.t[1].checked_add(1).unwrap();
            }
        }

        /// The compression function f.
        pub(crate) fn _compress_f(&mut self, data: Option<&[u8]>) {
            let mut m_vec = [0u64; 16];
            match data {
                Some(bytes) => {
                    debug_assert!(bytes.len() == BLAKE2B_BLOCKSIZE);
                    load_u64_into_le(bytes, &mut m_vec);
                }
                None => load_u64_into_le(&self.buffer, &mut m_vec),
            }

            let mut v0 = self.internal_state[0];
            let mut v1 = self.internal_state[1];
            let mut v2 = IV[0];
            let mut v3 = U64x4(
                self.t[0] ^ IV[1].0,
                self.t[1] ^ IV[1].1,
                self.f[0] ^ IV[1].2,
                self.f[1] ^ IV[1].3,
            );

            ROUND!(v0, v1, v2, v3, SIGMA[0], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[1], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[2], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[3], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[4], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[5], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[6], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[7], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[8], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[9], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[10], m_vec);
            ROUND!(v0, v1, v2, v3, SIGMA[11], m_vec);

            self.internal_state[0] ^= v0 ^ v2;
            self.internal_state[1] ^= v1 ^ v3;
        }

        #[allow(clippy::unreadable_literal)]
        /// Initialize a `State` struct with a given size a key and optional key.
        /// An empty `secret_key` equals non-MAC mode.
        pub(crate) fn _new(sk: &[u8], size: usize) -> Result<Self, UnknownCryptoError> {
            if !(1..=BLAKE2B_OUTSIZE).contains(&size) {
                return Err(UnknownCryptoError);
            }
            let is_keyed = match sk.len() {
                0 => false,
                1..=BLAKE2B_KEYSIZE => true,
                _ => return Err(UnknownCryptoError),
            };

            let mut context = Self {
                init_state: [U64x4::default(); 2],
                internal_state: IV,
                buffer: [0u8; BLAKE2B_BLOCKSIZE],
                leftover: 0,
                t: [0u64; 2],
                f: [0u64; 2],
                is_finalized: false,
                is_keyed,
                size,
            };

            if is_keyed {
                context.is_keyed = true;
                let klen = sk.len();
                context.internal_state[0].0 ^= 0x01010000 ^ ((klen as u64) << 8) ^ (size as u64);
                context.init_state.copy_from_slice(&context.internal_state);
                context._update(sk)?;
                // The state needs updating with the secret key padded to blocksize length
                let pad = [0u8; BLAKE2B_BLOCKSIZE];
                let rem = BLAKE2B_BLOCKSIZE - klen;
                context._update(pad[..rem].as_ref())?;
            } else {
                context.internal_state[0].0 ^= 0x01010000 ^ (size as u64);
                context.init_state.copy_from_slice(&context.internal_state);
            }

            Ok(context)
        }

        /// Reset to `_new()` state.
        pub(crate) fn _reset(&mut self, sk: &[u8]) -> Result<(), UnknownCryptoError> {
            // Disallow re-setting without a key if initialized with one and vice versa
            match (sk.len(), self.is_keyed) {
                // new with key, reset with none
                (0, true) => return Err(UnknownCryptoError),
                (0, false) => (),
                // reset with key, new with none
                (1..=BLAKE2B_KEYSIZE, false) => return Err(UnknownCryptoError),
                (1..=BLAKE2B_KEYSIZE, true) => (),
                (_, _) => return Err(UnknownCryptoError),
            }

            self.internal_state.copy_from_slice(&self.init_state);
            self.buffer = [0u8; BLAKE2B_BLOCKSIZE];
            self.leftover = 0;
            self.t = [0u64; 2];
            self.f = [0u64; 2];
            self.is_finalized = false;

            if self.is_keyed {
                self._update(sk)?;
                // The state needs updating with the secret key padded to blocksize length
                let pad = [0u8; BLAKE2B_BLOCKSIZE];
                let rem = BLAKE2B_BLOCKSIZE - sk.len();
                self._update(pad[..rem].as_ref())?;
            }

            Ok(())
        }

        /// Update state with `data`. This can be called multiple times.
        pub(crate) fn _update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            if self.is_finalized {
                return Err(UnknownCryptoError);
            }
            if data.is_empty() {
                return Ok(());
            }

            let mut bytes = data;

            if self.leftover != 0 {
                debug_assert!(self.leftover <= BLAKE2B_BLOCKSIZE);

                let fill = BLAKE2B_BLOCKSIZE - self.leftover;

                if bytes.len() <= fill {
                    self.buffer[self.leftover..(self.leftover + bytes.len())]
                        .copy_from_slice(bytes);
                    self.leftover += bytes.len();
                    return Ok(());
                }

                self.buffer[self.leftover..(self.leftover + fill)].copy_from_slice(&bytes[..fill]);
                self._increment_offset(BLAKE2B_BLOCKSIZE as u64);
                self._compress_f(None);
                self.leftover = 0;
                bytes = &bytes[fill..];
            }

            while bytes.len() > BLAKE2B_BLOCKSIZE {
                self._increment_offset(BLAKE2B_BLOCKSIZE as u64);
                self._compress_f(Some(bytes[..BLAKE2B_BLOCKSIZE].as_ref()));
                bytes = &bytes[BLAKE2B_BLOCKSIZE..];
            }

            if !bytes.is_empty() {
                debug_assert!(self.leftover == 0);
                self.buffer[..bytes.len()].copy_from_slice(bytes);
                self.leftover += bytes.len();
            }

            Ok(())
        }

        /// Finalize the hash and put the final digest into `dest`.
        /// NOTE: Writes the full hash (as if `self.size == BLAKE2B_OUTSIZE`) into `dest`. Must be truncated
        /// to `self.size` later.
        pub(crate) fn _finalize(
            &mut self,
            dest: &mut [u8; BLAKE2B_OUTSIZE],
        ) -> Result<(), UnknownCryptoError> {
            debug_assert!(self.size <= BLAKE2B_OUTSIZE);
            if self.is_finalized {
                return Err(UnknownCryptoError);
            }

            self.is_finalized = true;

            let in_buffer_len = self.leftover;
            self._increment_offset(in_buffer_len as u64);
            // Mark that it is the last block of data to be processed
            self.f[0] = !0;

            for leftover_block in self.buffer.iter_mut().skip(in_buffer_len) {
                *leftover_block = 0;
            }
            self._compress_f(None);

            self.internal_state[0].store_into_le(dest[..32].as_mut());
            self.internal_state[1].store_into_le(dest[32..].as_mut());

            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn compare_blake2b_states(state_1: &State, state_2: &State) {
        assert!(state_1.init_state == state_2.init_state);
        assert!(state_1.internal_state == state_2.internal_state);
        assert_eq!(state_1.buffer[..], state_2.buffer[..]);
        assert_eq!(state_1.leftover, state_2.leftover);
        assert_eq!(state_1.t, state_2.t);
        assert_eq!(state_1.f, state_2.f);
        assert_eq!(state_1.is_finalized, state_2.is_finalized);
        assert_eq!(state_1.is_keyed, state_2.is_keyed);
        assert_eq!(state_1.size, state_2.size);
    }
}

#[cfg(test)]
mod private {
    use crate::hazardous::hash::blake2::blake2b_core::BLAKE2B_KEYSIZE;

    use super::blake2b_core::State;

    #[test]
    #[cfg(feature = "safe_api")]
    fn test_debug_impl() {
        let initial_state = State::_new(&[], 64).unwrap();
        let debug = format!("{initial_state:?}");
        let expected = "State { init_state: [***OMITTED***], internal_state: [***OMITTED***], buffer: [***OMITTED***], leftover: 0, t: [0, 0], f: [0, 0], is_finalized: false, is_keyed: false, size: 64 }";
        assert_eq!(debug, expected);
    }

    #[test]
    fn test_sk_len() {
        assert!(State::_new(&[0u8; 0], 64).is_ok());
        assert!(State::_new(&[0u8; 1], 64).is_ok());
        assert!(State::_new(&[0u8; BLAKE2B_KEYSIZE], 64).is_ok());
        assert!(State::_new(&[0u8; BLAKE2B_KEYSIZE + 1], 64).is_err());

        let mut ctx = State::_new(&[], 64).unwrap();
        assert!(ctx._reset(&[]).is_ok());
        assert!(ctx._reset(&[0u8; BLAKE2B_KEYSIZE + 1]).is_err());
    }

    #[test]
    fn test_switching_keyed_modes_fails() {
        let mut tmp = [0u8; 64];

        let mut state_keyed = State::_new(&[0u8; 64], 64).unwrap();
        state_keyed._update(b"Tests").unwrap();
        state_keyed._finalize(&mut tmp).unwrap();
        assert!(state_keyed._reset(&[]).is_err());
        assert!(state_keyed._reset(&[0u8; 64]).is_ok());

        let mut state = State::_new(&[], 64).unwrap();
        state._update(b"Tests").unwrap();
        state_keyed._finalize(&mut tmp).unwrap();
        assert!(state._reset(&[0u8; 64]).is_err());
        assert!(state._reset(&[]).is_ok());
    }

    mod test_increment_offset {
        use crate::hazardous::hash::blake2::blake2b_core::{State, BLAKE2B_BLOCKSIZE, IV};
        use crate::util::u64x4::U64x4;

        #[test]
        fn test_offset_increase_values() {
            let mut context = State {
                init_state: [U64x4::default(); 2],
                internal_state: IV,
                buffer: [0u8; BLAKE2B_BLOCKSIZE],
                leftover: 0,
                t: [0u64; 2],
                f: [0u64; 2],
                is_finalized: false,
                is_keyed: false,
                size: 1,
            };

            context._increment_offset(1);
            assert_eq!(context.t, [1u64, 0u64]);
            context._increment_offset(17);
            assert_eq!(context.t, [18u64, 0u64]);
            context._increment_offset(12);
            assert_eq!(context.t, [30u64, 0u64]);
            // Overflow
            context._increment_offset(u64::MAX);
            assert_eq!(context.t, [29u64, 1u64]);
        }

        #[test]
        #[should_panic]
        fn test_panic_on_second_overflow() {
            let mut context = State {
                init_state: [U64x4::default(); 2],
                internal_state: IV,
                buffer: [0u8; BLAKE2B_BLOCKSIZE],
                leftover: 0,
                t: [1u64, u64::MAX],
                f: [0u64; 2],
                is_finalized: false,
                is_keyed: false,
                size: 1,
            };

            context._increment_offset(u64::MAX);
        }
    }
}
