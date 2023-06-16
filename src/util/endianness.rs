// MIT License

// Copyright (c) 2019-2023 The orion Developers

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

use core::convert::TryInto;
use core::mem;

macro_rules! impl_store_into {
    ($type_alias:ty, $conv_function:ident, $func_name:ident) => {
        /// Store bytes in `src` in `dst`.
        pub fn $func_name(src: &[$type_alias], dst: &mut [u8]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            // The length of src must be evenly divisible with the length of dst,
            // making sure .chunks_exact() leaves no remainder.
            assert_eq!(mem::size_of_val(src), dst.len());

            for (src_elem, dst_chunk) in src.iter().zip(dst.chunks_exact_mut(type_alias_len)) {
                dst_chunk.copy_from_slice(&src_elem.$conv_function());
            }
        }
    };
}

macro_rules! impl_load_into {
    ($type_alias:ty, $type_alias_expr:ident, $conv_function:ident, $func_name:ident) => {
        /// Load bytes in `src` into `dst`.
        pub fn $func_name(src: &[u8], dst: &mut [$type_alias]) {
            let type_alias_len = mem::size_of::<$type_alias>();
            // The length of src must be evenly divisible with the length of dst,
            // making sure .chunks_exact() leaves no remainder.
            assert_eq!(mem::size_of_val(dst), src.len());

            for (src_chunk, dst_elem) in src.chunks_exact(type_alias_len).zip(dst.iter_mut()) {
                // The above assert and this debug assert should prove that .unwrap()
                // cannot panic using TryInto.
                debug_assert_eq!(src_chunk.len(), type_alias_len);
                *dst_elem = $type_alias_expr::$conv_function(src_chunk.try_into().unwrap());
            }
        }
    };
}

macro_rules! impl_load {
    ($type_alias:ty, $type_alias_expr:ident, $conv_function:ident, $func_name:ident) => {
        /// Convert bytes in `src` to a given primitive.
        pub fn $func_name(src: &[u8]) -> $type_alias {
            // Satisfying this assert should prove that using TryInto
            // cannot panic.
            assert_eq!(mem::size_of::<$type_alias>(), src.len());
            $type_alias_expr::$conv_function(src.try_into().unwrap())
        }
    };
}

impl_load!(u32, u32, from_le_bytes, load_u32_le);

#[cfg(test)]
impl_load_into!(u32, u32, from_le_bytes, load_u32_into_le);

impl_load_into!(u64, u64, from_le_bytes, load_u64_into_le);

impl_store_into!(u32, to_le_bytes, store_u32_into_le);

#[cfg(any(feature = "safe_api", feature = "alloc", test))]
impl_store_into!(u64, to_le_bytes, store_u64_into_le);

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

    test_empty_src_panic! {test_panic_empty_load_u32_le, &[0u8; 0], [0u32; 4], load_u32_into_le}
    test_empty_src_panic! {test_panic_empty_load_u64_le, &[0u8; 0], [0u64; 4], load_u64_into_le}

    test_empty_src_panic! {test_panic_empty_store_u32_le, &[0u32; 0], [0u8; 24], store_u32_into_le}
    test_empty_src_panic! {test_panic_empty_store_u64_le, &[0u64; 0], [0u8; 24], store_u64_into_le}

    // -1 too low
    test_dst_length_panic! {test_dst_length_load_u32_le_low, &[0u8; 64], [0u32; 15], load_u32_into_le}
    test_dst_length_panic! {test_dst_length_load_u64_le_low, &[0u8; 64], [0u64; 7], load_u64_into_le}

    test_dst_length_panic! {test_dst_length_store_u32_le_low, &[0u32; 15], [0u8; 64], store_u32_into_le}
    test_dst_length_panic! {test_dst_length_store_u64_le_low, &[0u64; 7], [0u8; 64], store_u64_into_le}

    // +1 too high
    test_dst_length_panic! {test_dst_length_load_u32_le_high, &[0u8; 64], [0u32; 17], load_u32_into_le}
    test_dst_length_panic! {test_dst_length_load_u64_le_high, &[0u8; 64], [0u64; 9], load_u64_into_le}

    test_dst_length_panic! {test_dst_length_store_u32_le_high, &[0u32; 17], [0u8; 64], store_u32_into_le}
    test_dst_length_panic! {test_dst_length_store_u64_le_high, &[0u64; 9], [0u8; 64], store_u64_into_le}

    // Ok
    test_dst_length_ok! {test_dst_length_load_u32_le_ok, &[0u8; 64], [0u32; 16], load_u32_into_le}
    test_dst_length_ok! {test_dst_length_load_u64_le_ok, &[0u8; 64], [0u64; 8], load_u64_into_le}

    test_dst_length_ok! {test_dst_length_store_u32_le_ok, &[0u32; 16], [0u8; 64], store_u32_into_le}
    test_dst_length_ok! {test_dst_length_store_u64_le_ok, &[0u64; 8], [0u8; 64], store_u64_into_le}

    #[test]
    #[should_panic]
    fn test_load_single_src_high() {
        load_u32_le(&[0u8; 5]);
    }

    #[test]
    #[should_panic]
    fn test_load_single_src_low() {
        load_u32_le(&[0u8; 3]);
    }

    #[test]
    fn test_load_single_src_ok() {
        load_u32_le(&[0u8; 4]);
    }

    #[test]
    fn test_results_store_and_load_u32_into_le() {
        let input_0: [u32; 2] = [777190791, 1465409568];
        let input_1: [u32; 4] = [3418616323, 2289579672, 172726903, 1048927929];
        let input_2: [u32; 6] = [
            84693101, 443297962, 3962861724, 3081916164, 4167874952, 3982893227,
        ];
        let input_3: [u32; 8] = [
            2761719494, 242571916, 3097304063, 3924274282, 1553851098, 3673278295, 3531531406,
            2347852690,
        ];

        let expected_0: [u8; 8] = [135, 253, 82, 46, 32, 96, 88, 87];
        let expected_1: [u8; 16] = [
            3, 242, 195, 203, 152, 54, 120, 136, 119, 154, 75, 10, 185, 94, 133, 62,
        ];
        let expected_2: [u8; 24] = [
            109, 80, 12, 5, 170, 48, 108, 26, 156, 120, 52, 236, 4, 79, 178, 183, 136, 185, 108,
            248, 171, 32, 102, 237,
        ];
        let expected_3: [u8; 32] = [
            198, 126, 156, 164, 140, 90, 117, 14, 255, 27, 157, 184, 106, 172, 231, 233, 218, 226,
            157, 92, 87, 199, 241, 218, 142, 228, 126, 210, 146, 99, 241, 139,
        ];

        let mut actual_bytes_0 = [0u8; 8];
        let mut actual_bytes_1 = [0u8; 16];
        let mut actual_bytes_2 = [0u8; 24];
        let mut actual_bytes_3 = [0u8; 32];

        store_u32_into_le(&input_0, &mut actual_bytes_0);
        store_u32_into_le(&input_1, &mut actual_bytes_1);
        store_u32_into_le(&input_2, &mut actual_bytes_2);
        store_u32_into_le(&input_3, &mut actual_bytes_3);

        assert_eq!(actual_bytes_0, expected_0);
        assert_eq!(actual_bytes_1, expected_1);
        assert_eq!(actual_bytes_2, expected_2);
        assert_eq!(actual_bytes_3, expected_3);

        let mut actual_nums_0 = [0u32; 2];
        let mut actual_nums_1 = [0u32; 4];
        let mut actual_nums_2 = [0u32; 6];
        let mut actual_nums_3 = [0u32; 8];

        load_u32_into_le(&actual_bytes_0, &mut actual_nums_0);
        load_u32_into_le(&actual_bytes_1, &mut actual_nums_1);
        load_u32_into_le(&actual_bytes_2, &mut actual_nums_2);
        load_u32_into_le(&actual_bytes_3, &mut actual_nums_3);

        assert_eq!(actual_nums_0, input_0);
        assert_eq!(actual_nums_1, input_1);
        assert_eq!(actual_nums_2, input_2);
        assert_eq!(actual_nums_3, input_3);
    }

    #[test]
    fn test_results_store_and_load_u64_into_le() {
        let input_0: [u64; 2] = [3449173576222258260, 2574723713182514848];
        let input_1: [u64; 4] = [
            18418572897904167042,
            8576666536239673655,
            11410394363908906546,
            7465319841649779999,
        ];
        let input_2: [u64; 6] = [
            9356732802025012686,
            185726711773006573,
            11478604380402216982,
            11229612629557120299,
            2892361689551487626,
            11014300370630005317,
        ];
        let input_3: [u64; 8] = [
            9519534723912119720,
            6001603601558183532,
            8164850737304360888,
            571607234094878696,
            4752095875230140457,
            13190954815003641110,
            16657196750477544576,
            10329042493888204415,
        ];

        let expected_0: [u8; 16] = [
            84, 52, 100, 211, 23, 237, 221, 47, 160, 190, 4, 95, 147, 65, 187, 35,
        ];
        let expected_1: [u8; 32] = [
            130, 8, 55, 1, 119, 234, 155, 255, 55, 177, 139, 9, 198, 112, 6, 119, 50, 222, 232, 23,
            56, 221, 89, 158, 31, 229, 53, 208, 215, 36, 154, 103,
        ];
        let expected_2: [u8; 48] = [
            206, 61, 242, 202, 232, 202, 217, 129, 237, 10, 136, 216, 117, 213, 147, 2, 22, 240,
            29, 35, 222, 49, 76, 159, 43, 13, 254, 133, 48, 153, 215, 155, 138, 66, 170, 219, 161,
            187, 35, 40, 69, 210, 218, 176, 212, 167, 218, 152,
        ];
        let expected_3: [u8; 64] = [
            168, 53, 199, 13, 101, 46, 28, 132, 108, 158, 148, 129, 173, 250, 73, 83, 184, 215, 28,
            129, 124, 96, 79, 113, 232, 207, 68, 59, 192, 193, 238, 7, 41, 8, 177, 85, 5, 214, 242,
            65, 22, 69, 133, 252, 131, 175, 15, 183, 128, 76, 1, 226, 48, 64, 42, 231, 127, 14, 31,
            46, 108, 33, 88, 143,
        ];

        let mut actual_bytes_0 = [0u8; 16];
        let mut actual_bytes_1 = [0u8; 32];
        let mut actual_bytes_2 = [0u8; 48];
        let mut actual_bytes_3 = [0u8; 64];

        store_u64_into_le(&input_0, &mut actual_bytes_0);
        store_u64_into_le(&input_1, &mut actual_bytes_1);
        store_u64_into_le(&input_2, &mut actual_bytes_2);
        store_u64_into_le(&input_3, &mut actual_bytes_3);

        assert_eq!(actual_bytes_0, expected_0);
        assert_eq!(actual_bytes_1, expected_1);
        assert_eq!(actual_bytes_2.as_ref(), expected_2.as_ref());
        assert_eq!(actual_bytes_3.as_ref(), expected_3.as_ref());

        let mut actual_nums_0 = [0u64; 2];
        let mut actual_nums_1 = [0u64; 4];
        let mut actual_nums_2 = [0u64; 6];
        let mut actual_nums_3 = [0u64; 8];

        load_u64_into_le(&actual_bytes_0, &mut actual_nums_0);
        load_u64_into_le(&actual_bytes_1, &mut actual_nums_1);
        load_u64_into_le(&actual_bytes_2, &mut actual_nums_2);
        load_u64_into_le(&actual_bytes_3, &mut actual_nums_3);

        assert_eq!(actual_nums_0, input_0);
        assert_eq!(actual_nums_1, input_1);
        assert_eq!(actual_nums_2, input_2);
        assert_eq!(actual_nums_3, input_3);
    }

    #[test]
    fn test_results_load_u32() {
        let input_0: [u8; 4] = [203, 12, 195, 63];
        let expected_0: u32 = 1069747403;

        assert_eq!(load_u32_le(&input_0), expected_0);
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Load and store should not change the result.
    fn prop_load_store_u32_le(src: Vec<u8>) -> bool {
        if !src.is_empty() && src.len() % 4 == 0 {
            let mut dst_load = vec![0u32; src.len() / 4];
            load_u32_into_le(&src[..], &mut dst_load);
            // Test that loading a single also is working correctly
            dst_load[0] = load_u32_le(&src[..4]);
            let mut dst_store = src.clone();
            store_u32_into_le(&dst_load[..], &mut dst_store);

            dst_store == src
        } else {
            // Otherwise above functions panic.
            true
        }
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Load and store should not change the result.
    fn prop_load_store_u64_le(src: Vec<u8>) -> bool {
        if !src.is_empty() && src.len() % 8 == 0 {
            let mut dst_load = vec![0u64; src.len() / 8];
            load_u64_into_le(&src[..], &mut dst_load);
            let mut dst_store = src.clone();
            store_u64_into_le(&dst_load[..], &mut dst_store);

            dst_store == src
        } else {
            // Otherwise above functions panic.
            true
        }
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Store and load should not change the result.
    fn prop_store_load_u32_le(src: Vec<u32>) -> bool {
        let mut dst_store = vec![0u8; src.len() * 4];
        store_u32_into_le(&src[..], &mut dst_store);
        let mut dst_load = src.clone();
        load_u32_into_le(&dst_store[..], &mut dst_load);
        if dst_store.len() >= 4 {
            // Test that loading a single also is working correctly
            dst_load[0] = load_u32_le(&dst_store[..4]);
        }

        dst_load == src
    }

    #[quickcheck]
    #[cfg(feature = "safe_api")]
    /// Store and load should not change the result.
    fn prop_store_load_u64_le(src: Vec<u64>) -> bool {
        let mut dst_store = vec![0u8; src.len() * 8];
        store_u64_into_le(&src[..], &mut dst_store);
        let mut dst_load = src.clone();
        load_u64_into_le(&dst_store[..], &mut dst_load);

        dst_load == src
    }
}
