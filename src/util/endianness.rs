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

macro_rules! impl_store_le {
    ($(#[$meta:meta])*
    ($type_alias: ty, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[$type_alias], dst: &mut [u8]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((type_alias_len * src.len()) == dst.len());
            
            for (src_elem, dst_chunk) in src.iter().zip(dst.chunks_exact_mut(type_alias_len)) {
                dst_chunk.copy_from_slice(&src_elem.to_le_bytes());
            }
        }
	);
}

macro_rules! impl_store_be {
    ($(#[$meta:meta])*
    ($type_alias: ty, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[$type_alias], dst: &mut [u8]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((type_alias_len * src.len()) == dst.len());
            
            for (src_elem, dst_chunk) in src.iter().zip(dst.chunks_exact_mut(type_alias_len)) {
                dst_chunk.copy_from_slice(&src_elem.to_be_bytes());
            }
        }
	);
}

macro_rules! impl_load_le {
    ($(#[$meta:meta])*
    ($type_alias: ty, $type_alias_expr: ident, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[u8], dst: &mut [$type_alias]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((type_alias_len * dst.len()) == src.len());
            
            let mut tmp = [0u8; mem::size_of::<$type_alias>()];
            
            for (src_chunk, dst_elem) in src.chunks_exact(type_alias_len).zip(dst.iter_mut()) {
                tmp.copy_from_slice(src_chunk);
                *dst_elem = $type_alias_expr::from_le_bytes(tmp);
            }
        }
    );
}

macro_rules! impl_load_be {
    ($(#[$meta:meta])*
    ($type_alias: ty, $type_alias_expr: ident, $func_name: ident)) => (
        #[inline]
        $(#[$meta])*
		///
        pub fn $func_name(src: &[u8], dst: &mut [$type_alias]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            assert!((type_alias_len * dst.len()) == src.len());
            
            let mut tmp = [0u8; mem::size_of::<$type_alias>()];
            
            for (src_chunk, dst_elem) in src.chunks_exact(type_alias_len).zip(dst.iter_mut()) {
                tmp.copy_from_slice(src_chunk);
                *dst_elem = $type_alias_expr::from_be_bytes(tmp);
            }
        }

    );
}

impl_store_le!(
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
	(u32, store_u32_into_le)
);

impl_store_le!(
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
	(u64, store_u64_into_le)
);

impl_store_be!(
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
	(u32, store_u32_into_be)
);

impl_store_be!(
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
	(u64, store_u64_into_be)
);

impl_load_le!(
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
	(u32, u32, load_u32_into_le)
);

impl_load_le!(
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
	(u64, u64, load_u64_into_le)
);

impl_load_be!(
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
	(u32, u32, load_u32_into_be)
);

impl_load_be!(
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
	(u64, u64, load_u64_into_be)
);