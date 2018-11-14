// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

macro_rules! impl_partialeq_trait (($name:ident) => (
    impl PartialEq for $name {
        fn eq(&self, other: &$name) -> bool {
            use util;
            util::compare_ct(
                &self.unprotected_as_bytes(),
                &other.unprotected_as_bytes(),
            ).unwrap()
        }
    }
));

macro_rules! impl_debug_trait (($name:ident) => (
    impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "{} {{***OMITTED***}}", stringify!($name))
        }
    }
));

macro_rules! impl_drop_trait (($name:ident) => (
    impl Drop for $name {
        fn drop(&mut self) {
            use seckey::zero;
            zero(&mut self.value)
        }
    }
));

macro_rules! func_from_slice (($name:ident, $size:expr) => (
    #[must_use]
    /// Make an object from a given byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<$name, UnknownCryptoError> {

        if slice.len() != $size {
            return Err(UnknownCryptoError);
        }

        let mut value = [0u8; $size];
        value.copy_from_slice(slice);

        Ok($name { value: value })

    }
));

macro_rules! func_unprotected_as_bytes (($name:ident, $size:expr) => (
    #[must_use]
    /// Return the object as byte slice. __**WARNING**__: Should not be used unless strictly
    /// needed. This breaks protections such as protection against insecure comparison methods,
    /// that can leave an application vulnerable to timing attacks.
    pub fn unprotected_as_bytes(&self) -> [u8; $size] {
        self.value
    }
));

macro_rules! func_as_bytes (($name:ident, $size:expr) => (
    #[must_use]
    /// Return the object as byte slice.
    pub fn as_bytes(&self) -> [u8; $size] {
        self.value
    }
));

macro_rules! func_generate (($name:ident, $size:expr) => (
    #[must_use]
    #[cfg(feature = "safe_api")]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate() -> $name {
        use util;
        let mut value = [0u8; $size];
        util::gen_rand_key(&mut value).unwrap();

        $name { value: value }
    }
));

macro_rules! construct_secret_key (($name:ident, $size:expr) => (
    #[must_use]
    /// A secret key type.
    pub struct $name { value: [u8; $size] }

    impl_debug_trait!($name);
    impl_drop_trait!($name);
    impl_partialeq_trait!($name);

    impl $name {
        func_from_slice!($name, $size);
        func_unprotected_as_bytes!($name, $size);
        func_generate!($name, $size);
    }
));

macro_rules! construct_nonce_no_generator(($name:ident, $size:expr) => (
    #[must_use]
    /// A nonce type.
    pub struct $name { value: [u8; $size] }

    impl $name {
        func_from_slice!($name, $size);
        func_as_bytes!($name, $size);
    }
));

macro_rules! construct_nonce_with_generator(($name:ident, $size:expr) => (
    #[must_use]
    /// A nonce type.
    pub struct $name { value: [u8; $size] }

    impl $name {
        func_from_slice!($name, $size);
        func_as_bytes!($name, $size);
        func_generate!($name, $size);
    }
));

macro_rules! construct_tag(($name:ident, $size:expr) => (
    #[must_use]
    /// A tag type.
    pub struct $name { value: [u8; $size] }

    impl_partialeq_trait!($name);

    impl $name {
        func_from_slice!($name, $size);
        func_unprotected_as_bytes!($name, $size);
    }
));
