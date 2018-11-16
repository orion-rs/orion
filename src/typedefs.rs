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

/// Macro that implements the `PartialEq` trait on a object called `$name`.
/// This `PartialEq` will perform eq in constant time.
macro_rules! impl_partialeq_trait (($name:ident) => (
    impl PartialEq for $name {
        fn eq(&self, other: &$name) -> bool {
            use subtle::ConstantTimeEq;
             self.unprotected_as_bytes()
                .ct_eq(&other.unprotected_as_bytes())
                .unwrap_u8() == 1
        }
    }
));

/// Macro that implements the `Debug` trait on a object called `$name`.
/// This `Debug` will omit any fields of object `$name` to avoid them being
/// written to logs.
macro_rules! impl_debug_trait (($name:ident) => (
    impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "{} {{***OMITTED***}}", stringify!($name))
        }
    }
));

/// Macro that implements the `Drop` trait on a object called `$name` which as a field `value`.
/// This `Drop` will zero out the field `value` when the objects destructor is called.
macro_rules! impl_drop_trait (($name:ident) => (
    impl Drop for $name {
        fn drop(&mut self) {
            use seckey::zero;
            zero(&mut self.value)
        }
    }
));

/// Macro to implement a `from_slice()` function. Returns `UnknownCryptoError` if the slice
/// is not of length `$size`.
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

/// Macro to implement a `unprotected_as_bytes()` function for objects that implement extra protections.
/// Typically used on objects that implement `Drop`, `Debug` and/or `PartialEq`.
macro_rules! func_unprotected_as_bytes (($name:ident) => (
    #[must_use]
    /// Return the object as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.value.as_ref()
    }
));

/// Macro to implement a `as_bytes()` function for objects that don't implement extra protections.
macro_rules! func_as_bytes (($name:ident) => (
    #[must_use]
    /// Return the object as byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_ref()
    }
));

/// Macro to implement a `generate()` function for objects that benefit from having a CSPRNG available
/// to generate data of a recommended length. For exmaple symmetric keys for AEADs.
macro_rules! func_generate (($name:ident, $size:expr) => (
    #[must_use]
    #[cfg(feature = "safe_api")]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate() -> $name {
        use util;
        let mut value = [0u8; $size];
        util::secure_rand_bytes(&mut value).unwrap();

        $name { value: value }
    }
));

/// Macro to construct a type containing sensitive data.
macro_rules! construct_secret_key {
    ($(#[$meta:meta])*
    ($name:ident, $size:expr)) => (
        #[must_use]
        $(#[$meta])*
        ///
        /// # Security:
        /// This implements `PartialEq` and thus prevents users from accidentally using non constant-time
        /// comparisons. However, `unprotected_as_bytes()` lets the user return the secret key
        /// without such a protection. Avoid using `unprotected_as_bytes()` whenever possible.
        pub struct $name { value: [u8; $size] }

        impl_debug_trait!($name);
        impl_drop_trait!($name);
        impl_partialeq_trait!($name);

        impl $name {
            func_from_slice!($name, $size);
            func_unprotected_as_bytes!($name);
            func_generate!($name, $size);
        }
    );
}

/// Macro to construct a nonce where a random generator is not applicable.
macro_rules! construct_nonce_no_generator {
    ($(#[$meta:meta])*
    ($name:ident, $size:expr)) => (
        #[must_use]
        $(#[$meta])*
        pub struct $name { value: [u8; $size] }

        impl $name {
            func_from_slice!($name, $size);
            func_as_bytes!($name);
        }
    );
}

/// Macro to construct a nonce where a random generator is applicable.
macro_rules! construct_nonce_with_generator {
    ($(#[$meta:meta])*
    ($name:ident, $size:expr)) => (
        #[must_use]
        $(#[$meta])*
        pub struct $name { value: [u8; $size] }

        impl $name {
            func_from_slice!($name, $size);
            func_as_bytes!($name);
            func_generate!($name, $size);
        }
    );
}

/// Macro to construct a tag type that MACs return.
macro_rules! construct_tag {
    ($(#[$meta:meta])*
    ($name:ident, $size:expr)) => (
        #[must_use]
        #[derive(Clone, Copy)]
        $(#[$meta])*
        ///
        /// # Security:
        /// This implements `PartialEq` and thus prevents users from accidentally using non constant-time
        /// comparisons. However, `unprotected_as_bytes()` lets the user return the tag
        /// __**without such a protection**__. __**Avoid using**__ `unprotected_as_bytes()` whenever possible.
        pub struct $name { value: [u8; $size] }

        impl_partialeq_trait!($name);

        impl $name {
            func_from_slice!($name, $size);
            func_unprotected_as_bytes!($name);
        }
    );
}

/// Macro to construct a secret key used for HMAC. This pre-pads the given key to the required length
/// specified by the HMAC specifications.
macro_rules! construct_hmac_key {
    ($(#[$meta:meta])*
    ($name:ident, $size:expr)) => (
        #[must_use]
        $(#[$meta])*
        ///
        /// # Security:
        /// This implements `PartialEq` and thus prevents users from accidentally using non constant-time
        /// comparisons. However, `unprotected_as_bytes()` lets the user return the secret key
        /// without such a protection. Avoid using `unprotected_as_bytes()` whenever possible.
        pub struct $name { value: [u8; $size] }

        impl_debug_trait!($name);
        impl_drop_trait!($name);
        impl_partialeq_trait!($name);

        impl $name {
            #[must_use]
            /// Make an object from a given byte slice.
            pub fn from_slice(slice: &[u8]) -> $name {
                use sha2::{Digest, Sha512};
                use hazardous::constants::HLEN;

                let mut secret_key = [0u8; $size];

                let slice_len = slice.len();

                if slice_len > $size {
                    secret_key[..HLEN].copy_from_slice(&Sha512::digest(slice));
                } else {
                    secret_key[..slice_len].copy_from_slice(slice);
                }

                $name { value: secret_key }
            }

            func_unprotected_as_bytes!($name);
            func_generate!($name, $size);
        }
    );
}