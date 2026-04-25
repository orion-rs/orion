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

use crate::generics::{GenerateSecret, Secret, TypeSpec};

#[cfg(feature = "alloc")]
use alloc::vec;

#[derive(Debug)]
pub struct SecretNewtype {}

impl SecretNewtype {
    pub fn test_with_generate<
        const MIN: usize,
        const MAX: usize,
        const GEN_SIZE: usize,
        S: TypeSpec + GenerateSecret,
    >() {
        test_try_from::<MIN, MAX, S>();
        test_partial_eq::<MIN, MAX, S>();
        test_as_bytes::<MIN, MAX, S>();

        #[cfg(feature = "safe_api")]
        {
            test_generate::<GEN_SIZE, S>();
            test_omitted_debug::<MIN, MAX, S>();
        }
    }

    pub fn test_no_generate<const MIN: usize, const MAX: usize, S: TypeSpec>() {
        test_try_from::<MIN, MAX, S>();
        test_partial_eq::<MIN, MAX, S>();
        test_as_bytes::<MIN, MAX, S>();

        #[cfg(feature = "safe_api")]
        {
            test_omitted_debug::<MIN, MAX, S>();
        }
    }
}

pub fn test_try_from<const MIN: usize, const MAX: usize, S: TypeSpec>() {
    // All types ought to implement:
    // - TryFrom<&[u8]>
    // - TryFrom<&[u8; N]>
    // - TryFrom<&Vec<u8>>
    // We test both 0 and MAX to indicate these tests are meant for abritrarily valid byte sequences.
    // If this is not the case, such a type needs more specialized testing than this.

    assert!(Secret::<S>::try_from([0u8; MAX].as_slice()).is_ok()); // TryFrom<&[u8]>
    assert!(Secret::<S>::try_from(&[0u8; MAX]).is_ok()); // TryFrom<&[u8; N]>
    assert!(Secret::<S>::try_from([u8::MAX; MAX].as_slice()).is_ok()); // TryFrom<&[u8]>
    assert!(Secret::<S>::try_from(&[u8::MAX; MAX]).is_ok()); // TryFrom<&[u8; N]>

    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    {
        assert!(Secret::<S>::try_from(&vec![0u8; MAX]).is_ok()); // TryFrom<&Vec<u8>>
        assert!(Secret::<S>::try_from(&vec![u8::MAX; MAX]).is_ok()); // TryFrom<&Vec<u8>>
    }
}
pub fn test_partial_eq<const MIN: usize, const MAX: usize, S: TypeSpec>() {
    // PartialEq<Self>
    assert_eq!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        Secret::<S>::try_from(&[0u8; MAX]).unwrap()
    );
    assert_ne!(
        Secret::<S>::try_from(&[0u8; MIN]).unwrap(),
        Secret::<S>::try_from(&[1u8; MAX]).unwrap()
    );

    // If we want to compare with Primitive, which is what will be most useful
    // for all impls, we need to apply the same S::parse_bytes() as try_from([u8])
    // will, otherwise we're not guaranteed to have the same repr (like X25519 public key)
    // where some processing of the bytes happen so it doesn't map over 1-1.
    let arr_primitve_zero: [u8; MAX] = S::parse_bytes(&[0u8; MAX])
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    let arr_primitve_one: [u8; MAX] = S::parse_bytes(&[1u8; MAX])
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();

    // PartialEq<&[Primitive]>
    assert_eq!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        arr_primitve_zero.as_slice()
    );
    assert_ne!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        arr_primitve_one.as_slice()
    );

    // PartialEq<&[Primitive; N]>
    assert_eq!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        &arr_primitve_zero
    );
    assert_ne!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        &arr_primitve_one
    );

    // NOTE: It's possible to override the internal PartialEq,
    // and we otherwise rely on `subtle` to check and abort
    // early on length, mismtach, so we test this happens here
    // so we don't forget if we override and allow indexing panics.
    assert_ne!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        arr_primitve_one.as_slice()[..MAX / 2]
    );
    assert_ne!(
        Secret::<S>::try_from(&[0u8; MAX]).unwrap(),
        arr_primitve_one.as_slice()[..0]
    );
}

pub fn test_as_bytes<const MIN: usize, const MAX: usize, S: TypeSpec>() {
    let test_upper = Secret::<S>::try_from(&[0u8; MAX]).unwrap();
    let test_lower = Secret::<S>::try_from(&[0u8; MIN]).unwrap();

    assert_eq!(test_upper.unprotected_as_ref().len(), test_upper.len());
    assert_eq!(test_upper.len(), MAX);

    assert_eq!(test_lower.unprotected_as_ref().len(), test_lower.len());
    assert_eq!(test_lower.len(), MIN);

    assert!(!test_upper.is_empty());
    assert!(!test_lower.is_empty());

    // Test non-fixed-length definitions
    #[cfg(any(feature = "safe_api", feature = "alloc"))]
    {
        if MIN != MAX {
            let test_upper = Secret::<S>::try_from(&vec![0u8; MAX - 1]).unwrap();
            let test_lower = Secret::<S>::try_from(&vec![0u8; MIN + 1]).unwrap();

            assert_eq!(test_upper.unprotected_as_ref().len(), test_upper.len());
            assert_eq!(test_upper.len(), MAX - 1);

            assert_eq!(test_lower.unprotected_as_ref().len(), test_lower.len());
            assert_eq!(test_lower.len(), MIN + 1);

            assert!(!test_upper.is_empty());
            assert!(!test_lower.is_empty());
        }
    }
}

#[cfg(feature = "safe_api")]
pub fn test_generate<const GEN_SIZE: usize, S: TypeSpec + GenerateSecret>() {
    assert!(Secret::<S>::generate().is_ok());

    let test_zero = Secret::<S>::try_from(&vec![0u8; GEN_SIZE]).unwrap();

    // - A random one should never be all 0's.
    // - A random generated one should always be GEN_SIZE in length.
    let test_rand = Secret::<S>::generate().unwrap();
    assert_ne!(&test_zero, &test_rand);
    assert_eq!(test_rand.len(), GEN_SIZE);
    assert_ne!(Secret::<S>::generate().unwrap(), test_rand);

    // Because we can overload T::parse_slice() on newtypes, meaning parsing
    // logic changes, we want to test that if that ever happens, the `GenerateSecret`
    // logic still agrees with what is expected from an arbitrary slice.
    // In other words: T::try_from(T::generate().as_ref()) should ALWAYS pass when no getrandom failure.
    assert!(Secret::<S>::try_from(test_rand.unprotected_as_ref()).is_ok());
}

#[cfg(feature = "safe_api")] // format! is only available with std
fn test_omitted_debug<const MIN: usize, const MAX: usize, S: TypeSpec>() {
    let ser = format!("{:?}", [u8::MAX; MAX].as_ref());
    let test_debug_contents = format!("{:?}", Secret::<S>::try_from(&[u8::MAX; MAX]).unwrap());
    assert!(!test_debug_contents.contains(&ser));
    assert!(test_debug_contents.contains(&"{***OMITTED***}".to_string()));
    assert!(test_debug_contents.starts_with(S::NAME));
}
