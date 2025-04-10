// MIT License

// Copyright (c) 2025 The orion Developers

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

use crate::errors::UnknownCryptoError;
use core::marker::PhantomData;

pub trait TestableKem<K: PartialEq, C: PartialEq + AsRef<[u8]>> {
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UnknownCryptoError>;

    fn ciphertext_from_bytes(b: &[u8]) -> Result<C, UnknownCryptoError>;

    fn encap(ek: &[u8]) -> Result<(K, C), UnknownCryptoError>;

    fn decap(dk: &[u8], c: &C) -> Result<K, UnknownCryptoError>;
}

pub struct KemTester<T, K, C> {
    _kem: PhantomData<T>,
    _return_type_k: PhantomData<K>,
    _return_type_c: PhantomData<C>,
}

impl<T, K, C> KemTester<T, K, C>
where
    T: TestableKem<K, C>,
    K: PartialEq + core::fmt::Debug,
    C: PartialEq + core::fmt::Debug + AsRef<[u8]>,
{
    pub fn run_all_tests(seed: &[u8]) {
        Self::keygen_encap_decap_rountrip(seed);
        Self::decap_wrong_key_implicit_reject(seed);
        Self::encap_twice_then_decap(seed);
        Self::decap_wrong_cipertext_implicit_reject(seed);
    }

    fn keygen_encap_decap_rountrip(seed: &[u8]) {
        let (ek1, dk1) = T::keygen(seed).unwrap();

        for _ in 0..100 {
            let (k, c) = T::encap(&ek1).unwrap();
            let k_prime = T::decap(&dk1, &c).unwrap();

            assert_eq!(k, k_prime);
        }
    }

    fn decap_wrong_key_implicit_reject(seed: &[u8]) {
        let (ek1, _) = T::keygen(seed).unwrap();

        let mut seed_mod = seed.to_vec();
        seed_mod[0] ^= 1;
        let (_, dk2) = T::keygen(&seed_mod).unwrap();

        let (k, c) = T::encap(&ek1).unwrap();
        let k_prime = T::decap(&dk2, &c).unwrap();
        assert_ne!(k, k_prime);
    }

    fn decap_wrong_cipertext_implicit_reject(seed: &[u8]) {
        let (ek1, dk1) = T::keygen(seed).unwrap();

        let (k, c) = T::encap(&ek1).unwrap();
        let mut c_mod = c.as_ref().to_vec();
        c_mod[0] ^= 1;

        let k_prime = T::decap(&dk1, &T::ciphertext_from_bytes(&c_mod).unwrap()).unwrap();
        assert_ne!(k, k_prime);
    }

    fn encap_twice_then_decap(seed: &[u8]) {
        let (ek1, dk1) = T::keygen(seed).unwrap();
        let (k1, c1) = T::encap(&ek1).unwrap();
        let (k2, c2) = T::encap(&ek1).unwrap();
        assert_ne!(k1, k2);
        assert_ne!(c1, c2);

        let k1_prime = T::decap(&dk1, &c1).unwrap();
        let k2_prime = T::decap(&dk1, &c2).unwrap();
        assert_ne!(k1_prime, k2_prime);
        // Repeat decap() to ensure the's no bad internal state-management.
        assert_eq!(k1_prime, T::decap(&dk1, &c1).unwrap());
        assert_eq!(k2_prime, T::decap(&dk1, &c2).unwrap());
    }
}
