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

use core::mem;

macro_rules! impl_store {
    ($(#[$meta:meta])*
    ($type_alias: ty, $conv_function: ident, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[$type_alias], dst: &mut [u8]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((type_alias_len * src.len()) == dst.len());

            for (src_elem, dst_chunk) in src.iter().zip(dst.chunks_exact_mut(type_alias_len)) {
                dst_chunk.copy_from_slice(&src_elem.$conv_function());
            }
        }
	);
}

macro_rules! impl_load {
    ($(#[$meta:meta])*
    ($type_alias: ty, $type_alias_expr: ident, $conv_function: ident, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[u8], dst: &mut [$type_alias]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((dst.len() * type_alias_len) == src.len());

            let mut tmp = [0u8; mem::size_of::<$type_alias>()];

            for (src_chunk, dst_elem) in src.chunks_exact(type_alias_len).zip(dst.iter_mut()) {
                tmp.copy_from_slice(src_chunk);
                *dst_elem = $type_alias_expr::$conv_function(tmp);
            }
        }
    );
}

#[rustfmt::skip]
impl_load!(
	/// Load bytes in `src` into `dst` in little-endian byte order.
	///
	/// # Parameters:
	/// - `dst`: Destination buffer.
	/// - `src`: Source buffer.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `dst.len() != src.len() / 4`
	///
	/// # Example:
	/// ```
	/// use orion::util::endianness;
	///
	/// let mut dst = [0u32; 16];
	///
	/// endianness::load_u32_into_le(&[125u8; 64], &mut dst);
	/// ```
	(u32, u32, from_le_bytes, load_u32_into_le)
);

#[rustfmt::skip]
impl_load!(
	/// Load bytes in `src` into `dst` in little-endian byte order.
	///
	/// # Parameters:
	/// - `dst`: Destination buffer.
	/// - `src`: Source buffer.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `dst.len() != src.len() / 8`
	///
	/// # Example:
	/// ```
	/// use orion::util::endianness;
	///
	/// let mut dst = [0u64; 8];
	///
	/// endianness::load_u64_into_le(&[125u8; 64], &mut dst);
	/// ```
	(u64, u64, from_le_bytes, load_u64_into_le)
);

#[rustfmt::skip]
impl_load!(
    /// Load bytes in `src` into `dst` in big-endian byte order.
    ///
    /// # Parameters:
    /// - `dst`: Destination buffer.
    /// - `src`: Source buffer.
    ///
    /// # Exceptions:
    /// An exception will be thrown if:
    /// - `dst.len() != src.len() / 4`
    ///
    /// # Example:
    /// ```
    /// use orion::util::endianness;
    ///
    /// let mut dst = [0u32; 16];
    ///
    /// endianness::load_u32_into_be(&[125u8; 64], &mut dst);
    /// ```
    (u32, u32, from_be_bytes, load_u32_into_be)
);

#[rustfmt::skip]
impl_load!(
    /// Load bytes in `src` into `dst` in big-endian byte order.
    ///
    /// # Parameters:
    /// - `dst`: Destination buffer.
    /// - `src`: Source buffer. 
    ///
    /// # Exceptions:
    /// An exception will be thrown if:
    /// - `dst.len() != src.len() / 8`
    ///
    /// # Example:
    /// ```
    /// use orion::util::endianness;
    ///
    /// let mut dst = [0u64; 8];
    ///
    /// endianness::load_u64_into_be(&[125u8; 64], &mut dst);
    /// ```
    (u64, u64, from_be_bytes, load_u64_into_be)
);

#[rustfmt::skip]
impl_store!(
    /// Store bytes `src` in `dst` in little-endian byte order.
    ///
    /// # Parameters:
    /// - `dst`: Destination buffer.
    /// - `src`: Source buffer.
    ///
    /// # Exceptions:
    /// An exception will be thrown if:
    /// - `dst.len() != src.len() * 4`
    ///
    /// # Example:
    /// ```
    /// use orion::util::endianness;
    ///
    /// let mut dst = [0u8; 64];
    ///
    /// endianness::store_u32_into_le(&[5u32; 16], &mut dst);
    /// ```
    (u32, to_le_bytes, store_u32_into_le)
);

#[rustfmt::skip]
impl_store!(
	/// Store bytes in `src` into `dst` in little-endian byte order.
	///
	/// # Parameters:
	/// - `dst`: Destination buffer.
	/// - `src`: Source buffer.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `dst.len() != src.len() * 8`
	///
	/// # Example:
	/// ```
	/// use orion::util::endianness;
	///
	/// let mut dst = [0u8; 64];
	///
	/// endianness::store_u64_into_le(&[5u64; 8], &mut dst);
	/// ```
	(u64, to_le_bytes, store_u64_into_le)
);

#[rustfmt::skip]
impl_store!(
	/// Store bytes in `src` into `dst` in big-endian byte order.
	///
	/// # Parameters:
	/// - `dst`: Destination buffer.
	/// - `src`: Source buffer.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `dst.len() != src.len() * 4`
	///
	/// # Example:
	/// ```
	/// use orion::util::endianness;
	///
	/// let mut dst = [0u8; 64];
	///
	/// endianness::store_u32_into_be(&[5u32; 16], &mut dst);
	/// ```
	(u32, to_be_bytes, store_u32_into_be)
);

#[rustfmt::skip]
impl_store!(
	/// Store bytes in `src` into `dst` in big-endian byte order.
	///
	/// # Parameters:
	/// - `dst`: Destination buffer.
	/// - `src`: Source buffer.
	///
	/// # Exceptions:
	/// An exception will be thrown if:
	/// - `dst.len() != src.len() * 8`
	///
	/// # Example:
	/// ```
	/// use orion::util::endianness;
	///
	/// let mut dst = [0u8; 64];
	///
	/// endianness::store_u64_into_be(&[5u64; 8], &mut dst);
	/// ```
	(u64, to_be_bytes, store_u64_into_be)
);

// Testing public functions in the module.
#[cfg(test)]
mod public {
	use super::*;

	macro_rules! test_empty_src_panic {
		($test_name:ident, $src_val:expr, $dst_val:expr, $func_to_test:expr) => {
			#[test]
			#[should_panic]
			fn $test_name() {
				let mut dst_load = $dst_val;
				$func_to_test($src_val, &mut dst_load);
			}
		};
	}

	macro_rules! test_dst_length_panic {
		($test_name:ident, $src_val:expr, $dst_val:expr, $func_to_test:expr) => {
			#[test]
			#[should_panic]
			fn $test_name() {
				let mut dst_load = $dst_val;
				$func_to_test($src_val, &mut dst_load);
			}
		};
	}

	macro_rules! test_dst_length_ok {
		($test_name:ident, $src_val:expr, $dst_val:expr, $func_to_test:expr) => {
			#[test]
			fn $test_name() {
				let mut dst_load = $dst_val;
				$func_to_test($src_val, &mut dst_load);
			}
		};
	}

	test_empty_src_panic! {test_panic_empty_load_u32_into_le, &[0u8; 0], [0u32; 4], load_u32_into_le}
	test_empty_src_panic! {test_panic_empty_load_u32_into_be, &[0u8; 0], [0u32; 4], load_u32_into_be}
	test_empty_src_panic! {test_panic_empty_load_u64_into_le, &[0u8; 0], [0u64; 4], load_u64_into_le}
	test_empty_src_panic! {test_panic_empty_load_u64_into_be, &[0u8; 0], [0u64; 4], load_u64_into_be}

	test_empty_src_panic! {test_panic_empty_store_u32_into_le, &[0u32; 0], [0u8; 24], store_u32_into_le}
	test_empty_src_panic! {test_panic_empty_store_u32_into_be, &[0u32; 0], [0u8; 24], store_u32_into_be}
	test_empty_src_panic! {test_panic_empty_store_u64_into_le, &[0u64; 0], [0u8; 24], store_u64_into_le}
	test_empty_src_panic! {test_panic_empty_store_u64_into_be, &[0u64; 0], [0u8; 24], store_u64_into_be}

	// -1 too low
	test_dst_length_panic! {test_dst_length_load_u32_into_le_low, &[0u8; 64], [0u32; 15], load_u32_into_le}
	test_dst_length_panic! {test_dst_length_load_u32_into_be_low, &[0u8; 64], [0u32; 15], load_u32_into_be}
	test_dst_length_panic! {test_dst_length_load_u64_into_le_low, &[0u8; 64], [0u64; 7], load_u64_into_le}
	test_dst_length_panic! {test_dst_length_load_u64_into_be_low, &[0u8; 64], [0u64; 7], load_u64_into_be}

	test_dst_length_panic! {test_dst_length_store_u32_into_le_low, &[0u32; 15], [0u8; 64], store_u32_into_le}
	test_dst_length_panic! {test_dst_length_store_u32_into_be_low, &[0u32; 15], [0u8; 64], store_u32_into_be}
	test_dst_length_panic! {test_dst_length_store_u64_into_le_low, &[0u64; 7], [0u8; 64], store_u64_into_le}
	test_dst_length_panic! {test_dst_length_store_u64_into_be_low, &[0u64; 7], [0u8; 64], store_u64_into_be}
	// +1 too high
	test_dst_length_panic! {test_dst_length_load_u32_into_le_high, &[0u8; 64], [0u32; 17], load_u32_into_le}
	test_dst_length_panic! {test_dst_length_load_u32_into_be_high, &[0u8; 64], [0u32; 17], load_u32_into_be}
	test_dst_length_panic! {test_dst_length_load_u64_into_le_high, &[0u8; 64], [0u64; 9], load_u64_into_le}
	test_dst_length_panic! {test_dst_length_load_u64_into_be_high, &[0u8; 64], [0u64; 9], load_u64_into_be}

	test_dst_length_panic! {test_dst_length_store_u32_into_le_high, &[0u32; 17], [0u8; 64], store_u32_into_le}
	test_dst_length_panic! {test_dst_length_store_u32_into_be_high, &[0u32; 17], [0u8; 64], store_u32_into_be}
	test_dst_length_panic! {test_dst_length_store_u64_into_le_high, &[0u64; 9], [0u8; 64], store_u64_into_le}
	test_dst_length_panic! {test_dst_length_store_u64_into_be_high, &[0u64; 9], [0u8; 64], store_u64_into_be}
	// Ok
	test_dst_length_ok! {test_dst_length_load_u32_into_le_ok, &[0u8; 64], [0u32; 16], load_u32_into_le}
	test_dst_length_ok! {test_dst_length_load_u32_into_be_ok, &[0u8; 64], [0u32; 16], load_u32_into_be}
	test_dst_length_ok! {test_dst_length_load_u64_into_le_ok, &[0u8; 64], [0u64; 8], load_u64_into_le}
	test_dst_length_ok! {test_dst_length_load_u64_into_be_ok, &[0u8; 64], [0u64; 8], load_u64_into_be}

	test_dst_length_ok! {test_dst_length_store_u32_into_le_ok, &[0u32; 16], [0u8; 64], store_u32_into_le}
	test_dst_length_ok! {test_dst_length_store_u32_into_be_ok, &[0u32; 16], [0u8; 64], store_u32_into_be}
	test_dst_length_ok! {test_dst_length_store_u64_into_le_ok, &[0u64; 8], [0u8; 64], store_u64_into_le}
	test_dst_length_ok! {test_dst_length_store_u64_into_be_ok, &[0u64; 8], [0u8; 64], store_u64_into_be}

	// Proptests. Only exectued when NOT testing no_std.
	#[cfg(feature = "safe_api")]
	mod proptest {
		use super::*;

		quickcheck! {
			/// Load and store should not change the result.
			fn prop_load_store_u32_le(src: Vec<u8>) -> bool {
				if !src.is_empty() && src.len() % 4 == 0 {
					let mut dst_load = vec![0u32; src.len() / 4];
					load_u32_into_le(&src[..], &mut dst_load);
					let mut dst_store = src.clone();
					store_u32_into_le(&dst_load[..], &mut dst_store);

					(dst_store == src)
				} else {
					// if not, it panics
					true
				}
			}
		}

		quickcheck! {
			/// Load and store should not change the result.
			fn prop_load_store_u32_be(src: Vec<u8>) -> bool {
				if !src.is_empty() && src.len() % 4 == 0 {
					let mut dst_load = vec![0u32; src.len() / 4];
					load_u32_into_be(&src[..], &mut dst_load);
					let mut dst_store = src.clone();
					store_u32_into_be(&dst_load[..], &mut dst_store);

					(dst_store == src)
				} else {
					// if not, it panics
					true
				}
			}
		}

		quickcheck! {
			/// Load and store should not change the result.
			fn prop_load_store_u64_le(src: Vec<u8>) -> bool {
				if !src.is_empty() && src.len() % 8 == 0 {
					let mut dst_load = vec![0u64; src.len() / 8];
					load_u64_into_le(&src[..], &mut dst_load);
					let mut dst_store = src.clone();
					store_u64_into_le(&dst_load[..], &mut dst_store);

					(dst_store == src)
				} else {
					// if not, it panics
					true
				}
			}
		}

		quickcheck! {
			/// Load and store should not change the result.
			fn prop_load_store_u64_be(src: Vec<u8>) -> bool {
				if !src.is_empty() && src.len() % 8 == 0 {
					let mut dst_load = vec![0u64; src.len() / 8];
					load_u64_into_be(&src[..], &mut dst_load);
					let mut dst_store = src.clone();
					store_u64_into_be(&dst_load[..], &mut dst_store);

					(dst_store == src)
				} else {
					// if not, it panics
					true
				}
			}
		}

		quickcheck! {
			/// Store and load should not change the result.
			fn prop_store_load_u32_le(src: Vec<u32>) -> bool {

				let mut dst_store = vec![0u8; src.len() * 4];
				store_u32_into_le(&src[..], &mut dst_store);
				let mut dst_load = src.clone();
				load_u32_into_le(&dst_store[..], &mut dst_load);

				(dst_load == src)
			}
		}

		quickcheck! {
			 /// Store and load should not change the result.
			fn prop_store_load_u32_be(src: Vec<u32>) -> bool {

				let mut dst_store = vec![0u8; src.len() * 4];
				store_u32_into_be(&src[..], &mut dst_store);
				let mut dst_load = src.clone();
				load_u32_into_be(&dst_store[..], &mut dst_load);

				(dst_load == src)
			}
		}

		quickcheck! {
			 /// Store and load should not change the result.
			fn prop_store_load_u64_le(src: Vec<u64>) -> bool {

				let mut dst_store = vec![0u8; src.len() * 8];
				store_u64_into_le(&src[..], &mut dst_store);
				let mut dst_load = src.clone();
				load_u64_into_le(&dst_store[..], &mut dst_load);

				(dst_load == src)
			}
		}

		quickcheck! {
			 /// Store and load should not change the result.
			fn prop_store_load_u64_be(src: Vec<u64>) -> bool {

				let mut dst_store = vec![0u8; src.len() * 8];
				store_u64_into_be(&src[..], &mut dst_store);
				let mut dst_load = src.clone();
				load_u64_into_be(&dst_store[..], &mut dst_load);

				(dst_load == src)
			}
		}
	}
}
