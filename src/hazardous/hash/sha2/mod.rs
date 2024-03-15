// MIT License

// Copyright (c) 2020-2024 The orion Developers

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

/// SHA256 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha256;

/// SHA384 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha384;

/// SHA512 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha512;

pub(crate) mod sha2_core {
    use crate::errors::UnknownCryptoError;
    use core::fmt::Debug;
    use core::marker::PhantomData;
    use core::ops::*;
    use zeroize::Zeroize;

    /// Word used within the SHA2 internal state.
    pub(crate) trait Word:
        Sized
        + BitOr<Output = Self>
        + BitAnd<Output = Self>
        + BitXor<Output = Self>
        + Shr<Self>
        + Default
        + Div<Output = Self>
        + From<usize>
        + Copy
        + Debug
        + PartialEq<Self>
        + Zeroize
    {
        const MAX: Self;

        fn wrapping_add(&self, rhs: Self) -> Self;

        fn overflowing_add(&self, rhs: Self) -> (Self, bool);

        fn checked_add(&self, rhs: Self) -> Option<Self>;

        fn checked_mul(&self, rhs: Self) -> Option<Self>;

        fn rotate_right(&self, rhs: u32) -> Self;

        fn one() -> Self;

        fn size_of() -> usize;

        fn as_be(&self, dest: &mut [u8]);

        fn from_be(src: &[u8]) -> Self;

        #[allow(clippy::wrong_self_convention)]
        fn as_be_bytes(src: &[Self], dest: &mut [u8]);

        fn from_be_bytes(src: &[u8], dest: &mut [Self]);

        #[cfg(any(debug_assertions, test))]
        fn less_than_or_equal(&self, rhs: Self) -> bool;
    }

    /// Trait to define a specific SHA2 variant.
    pub(crate) trait Variant<W: Word, const N_CONSTS: usize>: Clone {
        /// The constants as defined in FIPS 180-4.
        const K: [W; N_CONSTS];

        /// The initial hash value H(0) as defined in FIPS 180-4.
        const H0: [W; 8];

        // Because it's currently not possible to use type parameters
        // in const expressions (see #![feature(const_evaluatable_checked)]),
        // we can't have this trait define the blocksize or output size
        // of the hash function, since array-sizes are defined by these.
        // This can be accomplished once full const-generics support lands,
        // and should remove the need for the const parameters in the state struct.

        fn big_sigma_0(x: W) -> W;

        fn big_sigma_1(x: W) -> W;

        fn small_sigma_0(x: W) -> W;

        fn small_sigma_1(x: W) -> W;
    }

    /// The Ch function as specified in FIPS 180-4 section 4.1.3.
    fn ch<W: Word>(x: W, y: W, z: W) -> W {
        z ^ (x & (y ^ z))
    }

    /// The Maj function as specified in FIPS 180-4 section 4.1.3.
    fn maj<W: Word>(x: W, y: W, z: W) -> W {
        (x & y) | (z & (x | y))
    }

    #[derive(Clone)]
    /// Core SHA2 state.
    pub(crate) struct State<
        W,
        T,
        const BLOCKSIZE: usize,
        const OUTSIZE: usize,
        const N_CONSTS: usize,
    >
    where
        W: Word,
        T: Variant<W, { N_CONSTS }>,
    {
        _variant: PhantomData<T>,
        pub(crate) working_state: [W; 8],
        pub(crate) buffer: [u8; BLOCKSIZE],
        pub(crate) leftover: usize,
        pub(crate) message_len: [W; 2],
        pub(crate) is_finalized: bool,
    }

    impl<
            W: Word,
            T: Variant<W, { N_CONSTS }>,
            const BLOCKSIZE: usize,
            const OUTSIZE: usize,
            const N_CONSTS: usize,
        > Drop for State<W, T, BLOCKSIZE, OUTSIZE, N_CONSTS>
    {
        fn drop(&mut self) {
            self.working_state.iter_mut().zeroize();
            self.buffer.iter_mut().zeroize();
            self.message_len.iter_mut().zeroize();
            self.leftover.zeroize();
            self.is_finalized.zeroize();
        }
    }

    impl<
            W: Word,
            T: Variant<W, { N_CONSTS }>,
            const BLOCKSIZE: usize,
            const OUTSIZE: usize,
            const N_CONSTS: usize,
        > Debug for State<W, T, BLOCKSIZE, OUTSIZE, N_CONSTS>
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "State {{ working_state: [***OMITTED***], buffer: [***OMITTED***], leftover: {:?}, \
             message_len: {:?}, is_finalized: {:?} }}",
                self.leftover, self.message_len, self.is_finalized
            )
        }
    }

    impl<
            W: Word,
            T: Variant<W, { N_CONSTS }>,
            const BLOCKSIZE: usize,
            const OUTSIZE: usize,
            const N_CONSTS: usize,
        > State<W, T, BLOCKSIZE, OUTSIZE, N_CONSTS>
    {
        /// Increment the message length during processing of data.
        pub(crate) fn increment_mlen(&mut self, length: &W) {
            #[cfg(any(debug_assertions, test))]
            debug_assert!(length.less_than_or_equal(W::MAX / W::from(8)));

            // Length in bits
            let len: W = match length.checked_mul(W::from(8)) {
                Some(bitlen) => bitlen,
                // Should be impossible for a user to trigger, because update() processes
                // in SHA(256/384/512)_BLOCKSIZE chunks.
                None => unreachable!(),
            };

            let (res, was_overflow) = self.message_len[1].overflowing_add(len);
            self.message_len[1] = res;

            if was_overflow {
                // If this panics, then size limit is reached.
                self.message_len[0] = self.message_len[0].checked_add(W::one()).unwrap();
            }
        }

        #[allow(clippy::many_single_char_names)]
        #[allow(clippy::too_many_arguments)]
        /// Message compression adopted from [mbed
        /// TLS](https://github.com/ARMmbed/mbedtls/blob/master/library/sha512.c).
        pub(crate) fn compress(
            a: W,
            b: W,
            c: W,
            d: &mut W,
            e: W,
            f: W,
            g: W,
            h: &mut W,
            x: W,
            ki: W,
        ) {
            let temp1 = h
                .wrapping_add(T::big_sigma_1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(ki)
                .wrapping_add(x);

            let temp2 = T::big_sigma_0(a).wrapping_add(maj(a, b, c));

            *d = d.wrapping_add(temp1);
            *h = temp1.wrapping_add(temp2);
        }

        #[rustfmt::skip]
        #[allow(clippy::many_single_char_names)]
        /// Process data in `self.buffer` or optionally `data`.
        pub(crate) fn process(&mut self, data: Option<&[u8]>) {
            let mut w = [W::default(); N_CONSTS];
            // If `data.is_none()` then we want to process leftover data within `self.buffer`.
            match data {
                Some(bytes) => {
                    debug_assert_eq!(bytes.len(), BLOCKSIZE);
                    W::from_be_bytes(bytes, &mut w[..16]);
                }
                None => W::from_be_bytes(&self.buffer, &mut w[..16]),
            }

            for t in 16..T::K.len() {
                w[t] = T::small_sigma_1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(T::small_sigma_0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let mut a = self.working_state[0];
            let mut b = self.working_state[1];
            let mut c = self.working_state[2];
            let mut d = self.working_state[3];
            let mut e = self.working_state[4];
            let mut f = self.working_state[5];
            let mut g = self.working_state[6];
            let mut h = self.working_state[7];

            let mut t = 0;
            while t < T::K.len() {
                Self::compress(a, b, c, &mut d, e, f, g, &mut h, w[t], T::K[t]); t += 1;
                Self::compress(h, a, b, &mut c, d, e, f, &mut g, w[t], T::K[t]); t += 1;
                Self::compress(g, h, a, &mut b, c, d, e, &mut f, w[t], T::K[t]); t += 1;
                Self::compress(f, g, h, &mut a, b, c, d, &mut e, w[t], T::K[t]); t += 1;
                Self::compress(e, f, g, &mut h, a, b, c, &mut d, w[t], T::K[t]); t += 1;
                Self::compress(d, e, f, &mut g, h, a, b, &mut c, w[t], T::K[t]); t += 1;
                Self::compress(c, d, e, &mut f, g, h, a, &mut b, w[t], T::K[t]); t += 1;
                Self::compress(b, c, d, &mut e, f, g, h, &mut a, w[t], T::K[t]); t += 1;
            }

            self.working_state[0] = self.working_state[0].wrapping_add(a);
            self.working_state[1] = self.working_state[1].wrapping_add(b);
            self.working_state[2] = self.working_state[2].wrapping_add(c);
            self.working_state[3] = self.working_state[3].wrapping_add(d);
            self.working_state[4] = self.working_state[4].wrapping_add(e);
            self.working_state[5] = self.working_state[5].wrapping_add(f);
            self.working_state[6] = self.working_state[6].wrapping_add(g);
            self.working_state[7] = self.working_state[7].wrapping_add(h);
        }

        /// Initialize a new state.
        pub(crate) fn _new() -> Self {
            Self {
                _variant: PhantomData::<T>,
                working_state: T::H0,
                buffer: [0u8; BLOCKSIZE],
                leftover: 0,
                message_len: [W::default(); 2],
                is_finalized: false,
            }
        }

        /// Reset to `new()` state.
        pub(crate) fn _reset(&mut self) {
            self.working_state = T::H0;
            self.buffer = [0u8; BLOCKSIZE];
            self.leftover = 0;
            self.message_len = [W::default(); 2];
            self.is_finalized = false;
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
                debug_assert!(self.leftover <= BLOCKSIZE);

                let mut want = BLOCKSIZE - self.leftover;
                if want > bytes.len() {
                    want = bytes.len();
                }

                for (idx, itm) in bytes.iter().enumerate().take(want) {
                    self.buffer[self.leftover + idx] = *itm;
                }

                bytes = &bytes[want..];
                self.leftover += want;
                self.increment_mlen(&W::from(want));

                if self.leftover < BLOCKSIZE {
                    return Ok(());
                }

                self.process(None);
                self.leftover = 0;
            }

            while bytes.len() >= BLOCKSIZE {
                self.process(Some(bytes[..BLOCKSIZE].as_ref()));
                self.increment_mlen(&W::from(BLOCKSIZE));
                bytes = &bytes[BLOCKSIZE..];
            }

            if !bytes.is_empty() {
                debug_assert_eq!(self.leftover, 0);
                self.buffer[..bytes.len()].copy_from_slice(bytes);
                self.leftover = bytes.len();
                self.increment_mlen(&W::from(bytes.len()));
            }

            Ok(())
        }

        /// Finalize the hash and put the final digest into `dest`.
        pub(crate) fn _finalize(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
            // NOTE: We need to support less than OUTSIZE in HKDF through HMAC.
            // debug_assert_eq!(dest.len(), OUTSIZE);
            if self.is_finalized {
                return Err(UnknownCryptoError);
            }

            self.is_finalized = true;
            // self.leftover should not be greater than SHA(256/384/512)_BLOCKSIZE
            // as that would have been processed in the update call
            debug_assert!(self.leftover < BLOCKSIZE);
            self.buffer[self.leftover] = 0x80;
            self.leftover += 1;

            for itm in self.buffer.iter_mut().skip(self.leftover) {
                *itm = 0;
            }

            let lenpad = W::size_of();
            // Check for available space for length padding
            if (BLOCKSIZE - self.leftover) < lenpad * 2 {
                self.process(None);
                for itm in self.buffer.iter_mut().take(self.leftover) {
                    *itm = 0;
                }
            }

            self.message_len[0]
                .as_be(&mut self.buffer[BLOCKSIZE - (lenpad * 2)..BLOCKSIZE - lenpad]);
            self.message_len[1].as_be(&mut self.buffer[BLOCKSIZE - lenpad..BLOCKSIZE]);
            self.process(None);

            let to_use = OUTSIZE / W::size_of();
            W::as_be_bytes(&self.working_state[..to_use], &mut dest[..OUTSIZE]);

            Ok(())
        }

        #[cfg(test)]
        /// Compare two Sha2 state objects to check if their fields
        /// are the same.
        pub(crate) fn compare_state_to_other(&self, other: &Self) {
            for idx in 0..8 {
                assert_eq!(self.working_state[idx], other.working_state[idx]);
            }
            assert_eq!(self.buffer, other.buffer);
            assert_eq!(self.leftover, other.leftover);
            assert_eq!(self.message_len[0], other.message_len[0]);
            assert_eq!(self.message_len[1], other.message_len[1]);
            assert_eq!(self.is_finalized, other.is_finalized);
        }
    }
}

pub(crate) mod w32 {
    use core::convert::{From, TryFrom, TryInto};
    use core::ops::*;
    use zeroize::Zeroize;

    #[derive(Debug, PartialEq, Copy, Clone, Default)]
    pub(crate) struct WordU32(pub(crate) u32);

    impl Zeroize for WordU32 {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    impl BitOr for WordU32 {
        type Output = Self;

        fn bitor(self, rhs: Self) -> Self::Output {
            Self(self.0 | rhs.0)
        }
    }

    impl BitAnd for WordU32 {
        type Output = Self;

        fn bitand(self, rhs: Self) -> Self::Output {
            Self(self.0 & rhs.0)
        }
    }

    impl BitXor for WordU32 {
        type Output = Self;

        fn bitxor(self, rhs: Self) -> Self::Output {
            Self(self.0 ^ rhs.0)
        }
    }

    impl From<usize> for WordU32 {
        fn from(value: usize) -> Self {
            // NOTE: Should never panic
            Self(u32::try_from(value).unwrap())
        }
    }

    impl From<u32> for WordU32 {
        fn from(value: u32) -> Self {
            Self(value)
        }
    }

    impl Div<Self> for WordU32 {
        type Output = Self;

        fn div(self, rhs: Self) -> Self::Output {
            Self(self.0 / rhs.0)
        }
    }

    impl Shr<WordU32> for WordU32 {
        type Output = Self;

        fn shr(self, Self(rhs): Self) -> Self::Output {
            let Self(lhs) = self;
            Self(lhs >> rhs)
        }
    }

    impl super::sha2_core::Word for WordU32 {
        const MAX: Self = Self(u32::MAX);

        #[inline]
        fn wrapping_add(&self, rhs: Self) -> Self {
            Self(self.0.wrapping_add(rhs.0))
        }

        #[inline]
        fn overflowing_add(&self, rhs: Self) -> (Self, bool) {
            let (res, did_overflow) = self.0.overflowing_add(rhs.0);

            (Self(res), did_overflow)
        }

        #[inline]
        fn checked_add(&self, rhs: Self) -> Option<Self> {
            self.0.checked_add(rhs.0).map(Self)
        }

        #[inline]
        fn checked_mul(&self, rhs: Self) -> Option<Self> {
            self.0.checked_mul(rhs.0).map(Self)
        }

        #[inline]
        fn rotate_right(&self, rhs: u32) -> Self {
            Self(self.0.rotate_right(rhs))
        }

        #[inline]
        fn one() -> Self {
            Self(1u32)
        }

        #[inline]
        fn size_of() -> usize {
            core::mem::size_of::<u32>()
        }

        #[inline]
        fn as_be(&self, dest: &mut [u8]) {
            debug_assert_eq!(dest.len(), Self::size_of());
            dest.copy_from_slice(&self.0.to_be_bytes());
        }

        #[inline]
        fn from_be(src: &[u8]) -> Self {
            Self(u32::from_be_bytes(src.try_into().unwrap()))
        }

        #[inline]
        fn as_be_bytes(src: &[Self], dest: &mut [u8]) {
            debug_assert_eq!(dest.len(), src.len() * Self::size_of());
            for (src_elem, dst_chunk) in src.iter().zip(dest.chunks_exact_mut(Self::size_of())) {
                src_elem.as_be(dst_chunk);
            }
        }

        #[inline]
        fn from_be_bytes(src: &[u8], dest: &mut [Self]) {
            debug_assert_eq!(dest.len(), src.len() / Self::size_of());
            for (src_chunk, dst_elem) in src.chunks_exact(Self::size_of()).zip(dest.iter_mut()) {
                *dst_elem = Self::from_be(src_chunk);
            }
        }

        #[cfg(any(debug_assertions, test))]
        fn less_than_or_equal(&self, rhs: Self) -> bool {
            self.0 <= rhs.0
        }
    }
}

pub(crate) mod w64 {
    use core::convert::{From, TryFrom, TryInto};
    use core::ops::*;
    use zeroize::Zeroize;

    #[derive(Debug, PartialEq, Copy, Clone, Default)]
    pub(crate) struct WordU64(pub(crate) u64);

    impl Zeroize for WordU64 {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    impl BitOr for WordU64 {
        type Output = Self;

        fn bitor(self, rhs: Self) -> Self::Output {
            Self(self.0 | rhs.0)
        }
    }

    impl BitAnd for WordU64 {
        type Output = Self;

        fn bitand(self, rhs: Self) -> Self::Output {
            Self(self.0 & rhs.0)
        }
    }

    impl BitXor for WordU64 {
        type Output = Self;

        fn bitxor(self, rhs: Self) -> Self::Output {
            Self(self.0 ^ rhs.0)
        }
    }

    impl From<usize> for WordU64 {
        fn from(value: usize) -> Self {
            // NOTE: Should never panic
            Self(u64::try_from(value).unwrap())
        }
    }

    impl From<u64> for WordU64 {
        fn from(value: u64) -> Self {
            Self(value)
        }
    }

    impl Div<Self> for WordU64 {
        type Output = Self;

        fn div(self, rhs: Self) -> Self::Output {
            Self(self.0 / rhs.0)
        }
    }

    impl Shr<WordU64> for WordU64 {
        type Output = Self;

        fn shr(self, Self(rhs): Self) -> Self::Output {
            let Self(lhs) = self;
            Self(lhs >> rhs)
        }
    }

    impl super::sha2_core::Word for WordU64 {
        const MAX: Self = Self(u64::MAX);

        #[inline]
        fn wrapping_add(&self, rhs: Self) -> Self {
            Self(self.0.wrapping_add(rhs.0))
        }

        #[inline]
        fn overflowing_add(&self, rhs: Self) -> (Self, bool) {
            let (res, did_overflow) = self.0.overflowing_add(rhs.0);

            (Self(res), did_overflow)
        }

        #[inline]
        fn checked_add(&self, rhs: Self) -> Option<Self> {
            self.0.checked_add(rhs.0).map(Self)
        }

        #[inline]
        fn checked_mul(&self, rhs: Self) -> Option<Self> {
            self.0.checked_mul(rhs.0).map(Self)
        }

        #[inline]
        fn rotate_right(&self, rhs: u32) -> Self {
            Self(self.0.rotate_right(rhs))
        }

        #[inline]
        fn one() -> Self {
            Self(1u64)
        }

        #[inline]
        fn size_of() -> usize {
            core::mem::size_of::<u64>()
        }

        #[inline]
        fn as_be(&self, dest: &mut [u8]) {
            debug_assert_eq!(dest.len(), Self::size_of());
            dest.copy_from_slice(&self.0.to_be_bytes());
        }

        #[inline]
        fn from_be(src: &[u8]) -> Self {
            Self(u64::from_be_bytes(src.try_into().unwrap()))
        }

        #[inline]
        fn as_be_bytes(src: &[Self], dest: &mut [u8]) {
            debug_assert_eq!(dest.len(), src.len() * Self::size_of());
            for (src_elem, dst_chunk) in src.iter().zip(dest.chunks_exact_mut(Self::size_of())) {
                src_elem.as_be(dst_chunk);
            }
        }

        #[inline]
        fn from_be_bytes(src: &[u8], dest: &mut [Self]) {
            debug_assert_eq!(dest.len(), src.len() / Self::size_of());
            for (src_chunk, dst_elem) in src.chunks_exact(Self::size_of()).zip(dest.iter_mut()) {
                *dst_elem = Self::from_be(src_chunk);
            }
        }

        #[cfg(any(debug_assertions, test))]
        fn less_than_or_equal(&self, rhs: Self) -> bool {
            self.0 <= rhs.0
        }
    }
}

#[cfg(test)]
mod test_word {
    use super::sha2_core::Word;
    use super::w32::WordU32;
    use super::w64::WordU64;

    #[test]
    #[should_panic]
    #[cfg(target_pointer_width = "64")]
    // We can only test this on 64-bit platforms.
    // On 32-bit platforms, due to the on-by-default #[deny(arithmetic_overflow)]
    // this won't compile because of `(u32::MAX as usize) + 1)`, not the from call.
    fn w32_panic_on_above_from() {
        let _ = WordU32::from((u32::MAX as usize) + 1);
    }

    #[test]
    #[should_panic]
    #[cfg(target_pointer_width = "128")]
    // See above note.
    fn w64_panic_on_above_from() {
        WordU64::from((u64::MAX as usize) + 1);
    }

    #[test]
    fn equiv_max() {
        assert_eq!(WordU32::MAX.0, u32::MAX);
        assert_eq!(WordU64::MAX.0, u64::MAX);
    }

    #[test]
    fn equiv_sizeof() {
        assert_eq!(WordU32::size_of(), core::mem::size_of::<u32>());
        assert_eq!(WordU64::size_of(), core::mem::size_of::<u64>());
    }

    #[test]
    fn equiv_one() {
        assert_eq!(WordU32::one(), WordU32::from(1usize));
        assert_eq!(WordU64::one(), WordU64::from(1usize));
    }

    #[test]
    fn equiv_default() {
        assert_eq!(WordU32::default().0, u32::default());
        assert_eq!(WordU64::default().0, u64::default());
    }

    #[test]
    fn test_results_store_and_load_u32_into_be() {
        let input_0: [WordU32; 2] = [WordU32::from(777190791u32), WordU32::from(1465409568u32)];
        let input_1: [WordU32; 4] = [
            WordU32::from(3418616323u32),
            WordU32::from(2289579672u32),
            WordU32::from(172726903u32),
            WordU32::from(1048927929u32),
        ];
        let input_2: [WordU32; 6] = [
            WordU32::from(84693101u32),
            WordU32::from(443297962u32),
            WordU32::from(3962861724u32),
            WordU32::from(3081916164u32),
            WordU32::from(4167874952u32),
            WordU32::from(3982893227u32),
        ];
        let input_3: [WordU32; 8] = [
            WordU32::from(2761719494u32),
            WordU32::from(242571916u32),
            WordU32::from(3097304063u32),
            WordU32::from(3924274282u32),
            WordU32::from(1553851098u32),
            WordU32::from(3673278295u32),
            WordU32::from(3531531406u32),
            WordU32::from(2347852690u32),
        ];

        let expected_0: [u8; 8] = [46, 82, 253, 135, 87, 88, 96, 32];
        let expected_1: [u8; 16] = [
            203, 195, 242, 3, 136, 120, 54, 152, 10, 75, 154, 119, 62, 133, 94, 185,
        ];
        let expected_2: [u8; 24] = [
            5, 12, 80, 109, 26, 108, 48, 170, 236, 52, 120, 156, 183, 178, 79, 4, 248, 108, 185,
            136, 237, 102, 32, 171,
        ];
        let expected_3: [u8; 32] = [
            164, 156, 126, 198, 14, 117, 90, 140, 184, 157, 27, 255, 233, 231, 172, 106, 92, 157,
            226, 218, 218, 241, 199, 87, 210, 126, 228, 142, 139, 241, 99, 146,
        ];

        let mut actual_bytes_0 = [0u8; 8];
        let mut actual_bytes_1 = [0u8; 16];
        let mut actual_bytes_2 = [0u8; 24];
        let mut actual_bytes_3 = [0u8; 32];

        WordU32::as_be_bytes(&input_0, &mut actual_bytes_0);
        WordU32::as_be_bytes(&input_1, &mut actual_bytes_1);
        WordU32::as_be_bytes(&input_2, &mut actual_bytes_2);
        WordU32::as_be_bytes(&input_3, &mut actual_bytes_3);

        assert_eq!(actual_bytes_0, expected_0);
        assert_eq!(actual_bytes_1, expected_1);
        assert_eq!(actual_bytes_2, expected_2);
        assert_eq!(actual_bytes_3, expected_3);

        let mut actual_nums_0 = [WordU32::default(); 2];
        let mut actual_nums_1 = [WordU32::default(); 4];
        let mut actual_nums_2 = [WordU32::default(); 6];
        let mut actual_nums_3 = [WordU32::default(); 8];

        WordU32::from_be_bytes(&actual_bytes_0, &mut actual_nums_0);
        WordU32::from_be_bytes(&actual_bytes_1, &mut actual_nums_1);
        WordU32::from_be_bytes(&actual_bytes_2, &mut actual_nums_2);
        WordU32::from_be_bytes(&actual_bytes_3, &mut actual_nums_3);

        assert_eq!(actual_nums_0, input_0);
        assert_eq!(actual_nums_1, input_1);
        assert_eq!(actual_nums_2, input_2);
        assert_eq!(actual_nums_3, input_3);
    }

    #[test]
    fn test_results_store_and_load_u64_into_be() {
        let input_0: [WordU64; 2] = [
            WordU64::from(588679683042986719u64),
            WordU64::from(14213404201893491922u64),
        ];
        let input_1: [WordU64; 4] = [
            WordU64::from(11866671478157678302u64),
            WordU64::from(12365793902795026927u64),
            WordU64::from(3777757590820648064u64),
            WordU64::from(6594491344853184185u64),
        ];
        let input_2: [WordU64; 6] = [
            WordU64::from(2101516190274184922u64),
            WordU64::from(7904425905466803755u64),
            WordU64::from(16590119592260157258u64),
            WordU64::from(6043085125584392657u64),
            WordU64::from(292831874581513482u64),
            WordU64::from(1878340435767862001u64),
        ];
        let input_3: [WordU64; 8] = [
            WordU64::from(10720360125345046831u64),
            WordU64::from(12576204976780952869u64),
            WordU64::from(2183760329755932840u64),
            WordU64::from(12806242450747917237u64),
            WordU64::from(17861362669514295908u64),
            WordU64::from(4901620135335484985u64),
            WordU64::from(3014680565865559727u64),
            WordU64::from(5106077179490460734u64),
        ];

        let expected_0: [u8; 16] = [
            8, 43, 105, 13, 130, 68, 74, 223, 197, 64, 39, 208, 214, 231, 244, 210,
        ];
        let expected_1: [u8; 32] = [
            164, 174, 226, 214, 73, 217, 22, 222, 171, 156, 32, 9, 173, 201, 241, 239, 52, 109, 74,
            131, 112, 102, 116, 128, 91, 132, 86, 240, 100, 92, 174, 185,
        ];
        let expected_2: [u8; 48] = [
            29, 42, 21, 215, 59, 6, 102, 218, 109, 178, 41, 123, 72, 190, 134, 43, 230, 59, 241,
            222, 245, 234, 63, 74, 83, 221, 89, 231, 113, 231, 145, 209, 4, 16, 89, 9, 215, 87,
            197, 10, 26, 17, 52, 172, 169, 50, 34, 241,
        ];
        let expected_3: [u8; 64] = [
            148, 198, 94, 188, 47, 116, 33, 47, 174, 135, 167, 203, 119, 135, 69, 37, 30, 78, 70,
            115, 41, 177, 56, 168, 177, 184, 233, 168, 152, 91, 131, 181, 247, 224, 78, 182, 224,
            210, 138, 100, 68, 6, 13, 139, 14, 146, 222, 57, 41, 214, 76, 0, 143, 176, 182, 175,
            70, 220, 110, 36, 63, 65, 228, 62,
        ];

        let mut actual_bytes_0 = [0u8; 16];
        let mut actual_bytes_1 = [0u8; 32];
        let mut actual_bytes_2 = [0u8; 48];
        let mut actual_bytes_3 = [0u8; 64];

        WordU64::as_be_bytes(&input_0, &mut actual_bytes_0);
        WordU64::as_be_bytes(&input_1, &mut actual_bytes_1);
        WordU64::as_be_bytes(&input_2, &mut actual_bytes_2);
        WordU64::as_be_bytes(&input_3, &mut actual_bytes_3);

        assert_eq!(actual_bytes_0, expected_0);
        assert_eq!(actual_bytes_1, expected_1);
        assert_eq!(actual_bytes_2.as_ref(), expected_2.as_ref());
        assert_eq!(actual_bytes_3.as_ref(), expected_3.as_ref());

        let mut actual_nums_0 = [WordU64::default(); 2];
        let mut actual_nums_1 = [WordU64::default(); 4];
        let mut actual_nums_2 = [WordU64::default(); 6];
        let mut actual_nums_3 = [WordU64::default(); 8];

        WordU64::from_be_bytes(&actual_bytes_0, &mut actual_nums_0);
        WordU64::from_be_bytes(&actual_bytes_1, &mut actual_nums_1);
        WordU64::from_be_bytes(&actual_bytes_2, &mut actual_nums_2);
        WordU64::from_be_bytes(&actual_bytes_3, &mut actual_nums_3);

        assert_eq!(actual_nums_0, input_0);
        assert_eq!(actual_nums_1, input_1);
        assert_eq!(actual_nums_2, input_2);
        assert_eq!(actual_nums_3, input_3);
    }

    #[cfg(feature = "safe_api")]
    mod proptests {
        use super::*;

        #[quickcheck]
        #[rustfmt::skip]
        fn equiv_from(n: u32, m: u64) -> bool {
            // Implicitly assume there's no panic
            if WordU32::from(n).0 != n { return false; }
            if WordU64::from(m).0 != m { return false; }

            true
        }

        #[quickcheck]
        #[rustfmt::skip]
        fn equiv_ops(n1: u32, n2: u32, m1: u64, m2: u64) -> bool {
            // WordU32
            let w32n1 = WordU32::from(n1);
            let w32n2 = WordU32::from(n2);

            if (w32n1 | w32n2).0 != n1 | n2  { return false; }
            if (w32n1 & w32n2).0 != n1 & n2  { return false; }
            if (w32n1 ^ w32n2).0 != n1 ^ n2  { return false; }
            // Test only specific values used with Shr (in sigma functions)
            if (w32n1 >> WordU32::from(10usize)).0 != n1 >> 10 { return false; }
            if (w32n1 >> WordU32::from(3usize)).0 != n1 >> 3  { return false; }
            if w32n2.0 != 0 && ((w32n1 / w32n2).0 != n1 / n2) { return false }

            // WordU64
            let w64m1 = WordU64::from(m1);
            let w64m2 = WordU64::from(m2);

            if (w64m1 | w64m2).0 != m1 | m2  { return false; }
            if (w64m1 & w64m2).0 != m1 & m2  { return false; }
            if (w64m1 ^ w64m2).0 != m1 ^ m2  { return false; }
            // Test only specific values used with Shr (in sigma functions)
            if (w64m1 >> WordU64::from(7usize)).0 != m1 >> 7 { return false; }
            if (w64m1 >> WordU64::from(6usize)).0 != m1 >> 6 { return false; }
            if w64m2.0 != 0 && ((w64m1 / w64m2).0 != m1 / m2) { return false }

            true
        }

        #[quickcheck]
        fn equiv_wrapping_add(n1: u32, n2: u32, m1: u64, m2: u64) -> bool {
            let w32n1 = WordU32::from(n1);
            let w32n2 = WordU32::from(n2);
            let ret32 = w32n1.wrapping_add(w32n2).0 == n1.wrapping_add(n2);

            let w64m1 = WordU64::from(m1);
            let w64m2 = WordU64::from(m2);
            let ret64 = w64m1.wrapping_add(w64m2).0 == m1.wrapping_add(m2);

            ret32 && ret64
        }

        #[quickcheck]
        fn equiv_overflowing_add(n1: u32, n2: u32, m1: u64, m2: u64) -> bool {
            let w32n1 = WordU32::from(n1);
            let w32n2 = WordU32::from(n2);
            let ret32: bool = match (w32n1.overflowing_add(w32n2), n1.overflowing_add(n2)) {
                ((w32, true), (n, true)) => w32.0 == n,
                ((w32, false), (n, false)) => w32.0 == n,
                _ => false,
            };

            let w64m1 = WordU64::from(m1);
            let w64m2 = WordU64::from(m2);
            let ret64: bool = match (w64m1.overflowing_add(w64m2), m1.overflowing_add(m2)) {
                ((w64, true), (n, true)) => w64.0 == n,
                ((w64, false), (n, false)) => w64.0 == n,
                _ => false,
            };

            ret32 && ret64
        }

        #[quickcheck]
        fn equiv_checked_add(n1: u32, n2: u32, m1: u64, m2: u64) -> bool {
            let w32n1 = WordU32::from(n1);
            let w32n2 = WordU32::from(n2);
            let ret32: bool = match (w32n1.checked_add(w32n2), n1.checked_add(n2)) {
                (Some(w32), Some(n)) => w32.0 == n,
                (None, None) => true,
                _ => false,
            };

            let w64m1 = WordU64::from(m1);
            let w64m2 = WordU64::from(m2);
            let ret64: bool = match (w64m1.checked_add(w64m2), m1.checked_add(m2)) {
                (Some(w64), Some(n)) => w64.0 == n,
                (None, None) => true,
                _ => false,
            };

            ret32 && ret64
        }

        #[quickcheck]
        fn equiv_checked_mul(n: u32, m: u64, x: u32, y: u64) -> bool {
            let w32n = WordU32::from(n);
            let ret32: bool = match (w32n.checked_mul(WordU32::from(x)), n.checked_mul(x)) {
                (Some(w32), Some(n1)) => w32.0 == n1,
                (None, None) => true,
                _ => false,
            };

            let w64m = WordU64::from(m);
            let ret64: bool = match (w64m.checked_mul(WordU64::from(y)), m.checked_mul(y)) {
                (Some(w64), Some(n1)) => w64.0 == n1,
                (None, None) => true,
                _ => false,
            };

            ret32 && ret64
        }

        #[quickcheck]
        #[rustfmt::skip]
        fn equiv_rotate_right(n: u32, m: u64, x: u32) -> bool {
            let w32n = WordU32::from(n);
            let w64m = WordU64::from(m);

            if w32n.rotate_right(x).0 != n.rotate_right(x) { return false; }
            if w64m.rotate_right(x).0 != m.rotate_right(x) { return false; }

            true
        }

        #[quickcheck]
        #[rustfmt::skip]
        fn equiv_into_from_be(n: u32, m: u64) -> bool {

            let w32n = WordU32::from(n);
            let w64m = WordU64::from(m);

            let mut dest32 = [0u8; core::mem::size_of::<u32>()];
            let mut dest64 = [0u8; core::mem::size_of::<u64>()];
            w32n.as_be(&mut dest32);
            w64m.as_be(&mut dest64);

            if dest32 != n.to_be_bytes() { return false; }
            if dest64 != m.to_be_bytes() { return false; }


            if w32n.0 != u32::from_be_bytes(dest32) { return false; }
            if w64m.0 != u64::from_be_bytes(dest64) { return false; }

            true
        }

        #[cfg(debug_assertions)]
        #[quickcheck]
        #[rustfmt::skip]
        /// Word::less_than_or_equal() is only used for debug_assertions.
        fn equiv_less_than_or_equal(n1: u32, n2: u32, m1: u64, m2: u64) -> bool {
            let w32n1 = WordU32::from(n1);
            let w32n2 = WordU32::from(n2);
            let w64m1 = WordU64::from(m1);
            let w64m2 = WordU64::from(m2);

            if w32n1.less_than_or_equal(w32n2) != (n1 <= n2) { return false; }
            if w64m1.less_than_or_equal(w64m2) != (m1 <= m2) { return false; }

            true
        }
    }
}
