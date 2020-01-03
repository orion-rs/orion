// MIT License

// Copyright (c) 2018-2019 The orion Developers

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

#[derive(Clone, Copy)]
pub(crate) struct U64x4(
	pub(crate) u64,
	pub(crate) u64,
	pub(crate) u64,
	pub(crate) u64,
);

impl core::ops::BitXor for U64x4 {
	type Output = Self;

	#[must_use]
	#[inline(always)]
	fn bitxor(self, _rhs: Self) -> Self::Output {
		Self(
			self.0 ^ _rhs.0,
			self.1 ^ _rhs.1,
			self.2 ^ _rhs.2,
			self.3 ^ _rhs.3,
		)
	}
}

impl core::ops::BitXorAssign for U64x4 {
	#[inline(always)]
	fn bitxor_assign(&mut self, _rhs: Self) {
		self.0 ^= _rhs.0;
		self.1 ^= _rhs.1;
		self.2 ^= _rhs.2;
		self.3 ^= _rhs.3;
	}
}

impl Default for U64x4 {
	fn default() -> Self {
		Self(0, 0, 0, 0)
	}
}

#[cfg(test)]
impl PartialEq<U64x4> for U64x4 {
	fn eq(&self, other: &Self) -> bool {
		(self.0 == other.0 && self.1 == other.1 && self.2 == other.2 && self.3 == other.3)
	}
}

impl U64x4 {
	#[must_use]
	#[inline(always)]
	pub(crate) const fn wrapping_add(self, _rhs: Self) -> Self {
		Self(
			self.0.wrapping_add(_rhs.0),
			self.1.wrapping_add(_rhs.1),
			self.2.wrapping_add(_rhs.2),
			self.3.wrapping_add(_rhs.3),
		)
	}

	#[must_use]
	#[inline(always)]
	pub(crate) const fn shl_1(self) -> Self {
		Self(self.1, self.2, self.3, self.0)
	}

	#[must_use]
	#[inline(always)]
	pub(crate) const fn shl_2(self) -> Self {
		Self(self.2, self.3, self.0, self.1)
	}

	#[must_use]
	#[inline(always)]
	pub(crate) const fn shl_3(self) -> Self {
		Self(self.3, self.0, self.1, self.2)
	}

	#[must_use]
	#[inline(always)]
	pub(crate) const fn rotate_right(self, n: u32) -> Self {
		Self(
			self.0.rotate_right(n),
			self.1.rotate_right(n),
			self.2.rotate_right(n),
			self.3.rotate_right(n),
		)
	}

	#[inline(always)]
	pub(crate) fn store_into_le(self, dst: &mut [u8]) {
		debug_assert!(dst.len() == core::mem::size_of::<u64>() * 4);
		dst[0..8].copy_from_slice(&self.0.to_le_bytes());
		dst[8..16].copy_from_slice(&self.1.to_le_bytes());
		dst[16..24].copy_from_slice(&self.2.to_le_bytes());
		dst[24..32].copy_from_slice(&self.3.to_le_bytes());
	}
}
