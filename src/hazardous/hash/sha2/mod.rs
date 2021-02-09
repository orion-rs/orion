// MIT License

// Copyright (c) 2020-2021 The orion Developers

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

use core::ops::{BitAnd, BitOr, BitXor};

/// The Ch function as specified in FIPS 180-4 section 4.1.3.
pub(crate) fn ch<T>(x: T, y: T, z: T) -> T
where
    T: BitXor<Output = T> + BitAnd<Output = T> + Copy,
{
    z ^ (x & (y ^ z))
}

/// The Maj function as specified in FIPS 180-4 section 4.1.3.
pub(crate) fn maj<T>(x: T, y: T, z: T) -> T
where
    T: BitOr<Output = T> + BitAnd<Output = T> + Copy,
{
    (x & y) | (z & (x | y))
}

macro_rules! func_update (($blocksize:expr, $primitive:ident) => (
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Update state with `data`. This can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        if self.is_finalized {
            return Err(UnknownCryptoError);
        }
        if data.is_empty() {
            return Ok(());
        }

        let mut bytes = data;

        if self.leftover != 0 {
            debug_assert!(self.leftover <= $blocksize);

            let mut want = $blocksize - self.leftover;
            if want > bytes.len() {
                want = bytes.len();
            }

            for (idx, itm) in bytes.iter().enumerate().take(want) {
                self.buffer[self.leftover + idx] = *itm;
            }

            bytes = &bytes[want..];
            self.leftover += want;
            self.increment_mlen(want as $primitive);

            if self.leftover < $blocksize {
                return Ok(());
            }

            self.process(None);
            self.leftover = 0;
        }

        while bytes.len() >= $blocksize {
            self.process(Some(bytes[..$blocksize].as_ref()));
            self.increment_mlen($blocksize as $primitive);
            bytes = &bytes[$blocksize..];
        }

        if !bytes.is_empty() {
            debug_assert!(self.leftover == 0);
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.leftover = bytes.len();
            self.increment_mlen(bytes.len() as $primitive);
        }

        Ok(())
    }
));

macro_rules! func_compress_and_process (($blocksize:expr, $primitive:ident, $default_prim_value:expr, $to_be_func:expr, $w_size:expr) => (
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_arguments)]
    /// Message compression adopted from [mbed
    /// TLS](https://github.com/ARMmbed/mbedtls/blob/master/library/sha512.c).
    fn compress(
        a: $primitive,
        b: $primitive,
        c: $primitive,
        d: &mut $primitive,
        e: $primitive,
        f: $primitive,
        g: $primitive,
        h: &mut $primitive,
        x: $primitive,
        ki: $primitive,
    ) {
        let temp1 = h
            .wrapping_add(big_sigma_1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(ki)
            .wrapping_add(x);

        let temp2 = big_sigma_0(a).wrapping_add(maj(a, b, c));

        *d = d.wrapping_add(temp1);
        *h = temp1.wrapping_add(temp2);
    }

    #[rustfmt::skip]
	#[allow(clippy::many_single_char_names)]
    /// Process data in `self.buffer` or optionally `data`.
    fn process(&mut self, data: Option<&[u8]>) {
        let mut w = [$default_prim_value; $w_size];
		match data {
			Some(bytes) => {
                debug_assert!(bytes.len() == $blocksize);
				$to_be_func(bytes, &mut w[..16]);
			}
			None => $to_be_func(&self.buffer, &mut w[..16]),
		}

		for t in 16..$w_size {
			w[t] = small_sigma_1(w[t - 2])
				.wrapping_add(w[t - 7])
				.wrapping_add(small_sigma_0(w[t - 15]))
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
		while t < $w_size {
			Self::compress(a, b, c, &mut d, e, f, g, &mut h, w[t], K[t]); t += 1;
			Self::compress(h, a, b, &mut c, d, e, f, &mut g, w[t], K[t]); t += 1;
			Self::compress(g, h, a, &mut b, c, d, e, &mut f, w[t], K[t]); t += 1;
			Self::compress(f, g, h, &mut a, b, c, d, &mut e, w[t], K[t]); t += 1;
			Self::compress(e, f, g, &mut h, a, b, c, &mut d, w[t], K[t]); t += 1;
			Self::compress(d, e, f, &mut g, h, a, b, &mut c, w[t], K[t]); t += 1;
			Self::compress(c, d, e, &mut f, g, h, a, &mut b, w[t], K[t]); t += 1;
			Self::compress(b, c, d, &mut e, f, g, h, &mut a, w[t], K[t]); t += 1;
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
));

/// SHA256 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha256;

/// SHA384 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha384;

/// SHA512 as specified in the [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub mod sha512;
