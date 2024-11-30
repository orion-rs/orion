// MIT License

// Copyright (c) 2018-2024 The orion Developers

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

// Trait implementation macros

#[cfg(feature = "safe_api")]
/// Macro that implements the `Default` trait using a CSPRNG.
macro_rules! impl_default_trait (($name:ident, $size:expr) => (
    impl Default for $name {
        #[cfg(feature = "safe_api")]
        /// Randomly generate using a CSPRNG with recommended size. Not available in `no_std` context.
        fn default() -> $name {
            let mut value = vec![0u8; $size];
            crate::util::secure_rand_bytes(&mut value).unwrap();

            $name { value, original_length: $size }
        }
    }
));

/// Macro that implements the `PartialEq` trait on a object called `$name` that
/// provides a given $bytes_function to return a slice. This `PartialEq` will
/// execute in constant-time.
///
/// This also provides an empty `Eq` implementation.
macro_rules! impl_ct_partialeq_trait (($name:ident, $bytes_function:ident) => (
    impl PartialEq<$name> for $name {
        fn eq(&self, other: &$name) -> bool {
            use subtle::ConstantTimeEq;

            (self.$bytes_function()
                .ct_eq(other.$bytes_function())).into()
        }
    }

    impl Eq for $name {}

    impl PartialEq<&[u8]> for $name {
        fn eq(&self, other: &&[u8]) -> bool {
            use subtle::ConstantTimeEq;

            (self.$bytes_function()
                .ct_eq(*other)).into()
        }
    }
));

/// Macro that implements the `Debug` trait on a object called `$name`.
/// This `Debug` will omit any fields of object `$name` to avoid them being
/// written to logs.
macro_rules! impl_omitted_debug_trait (($name:ident) => (
    impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{} {{***OMITTED***}}", stringify!($name))
        }
    }
));

/// Macro that implements the `Debug` trait on a object called `$name`.
macro_rules! impl_normal_debug_trait (($name:ident) => (
    impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{} {:?}", stringify!($name), &self.value[..])
        }
    }
));

/// Macro that implements the `serde::{Serialize, Deserialize}` traits.
#[cfg(feature = "serde")]
macro_rules! impl_serde_traits (($name:ident, $bytes_function:ident) => (

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// This type tries to serialize as a `&[u8]` would. Note that the serialized
    /// type likely does not have the same protections that Orion provides, such
    /// as constant-time operations. A good rule of thumb is to only serialize
    /// these types for storage. Don't operate on the serialized types.
    impl serde::Serialize for $name {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            let bytes: &[u8] = &self.$bytes_function();
            bytes.serialize(serializer)
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// This type tries to deserialize as a `Vec<u8>` would. If it succeeds, the digest
    /// will be built using `Self::from_slice`.
    ///
    /// Note that **this allocates** once to store the referenced bytes on the heap.
    impl<'de> serde::Deserialize<'de> for $name {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            std::convert::TryFrom::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
        }
    }
));

/// Macro that implements the `Drop` trait on a object called `$name` which has
/// a field `value`. This `Drop` will zero out the field `value` when the
/// objects destructor is called.
macro_rules! impl_drop_trait (($name:ident) => (
    impl Drop for $name {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.value.iter_mut().zeroize();
        }
    }
));

/// Macro that implements the `AsRef<[u8]>` trait on a object called `$name`
/// which has fields `value` and `original_length`. This will return the inner
/// `value` as a byte slice, and should only be implemented on public types
/// which don't have any special protections.
macro_rules! impl_asref_trait (($name:ident) => (
    impl AsRef<[u8]> for $name {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            self.value[..self.original_length].as_ref()
        }
    }
));

/// Macro that implements the `From<[T]>` trait on a object called `$name`
/// which has fields `value` and `original_length`. It implements From
/// based on `$size` and this macro should, in most cases, only be used for
/// types which have a fixed-length.
macro_rules! impl_from_trait (($name:ident, $size:expr) => (
    impl From<[u8; $size]> for $name {
        #[inline]
        /// Make an object from a byte array.
        fn from(bytes: [u8; $size]) -> $name {
            $name {
                value: bytes,
                original_length: $size
            }
        }
    }
));

/// Macro that implements `TryFrom<&[u8]>` on an object called `$name` that
/// implements the method `from_slice`.
macro_rules! impl_try_from_trait (($name:ident) => (
    /// Delegates to `from_slice` implementation
    impl TryFrom<&[u8]> for $name {
        type Error = UnknownCryptoError;
        fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
            Self::from_slice(slice)
        }
    }
));

// Function implementation macros

/// Macro to implement a `from_slice()` function. Returns `UnknownCryptoError`
/// if the slice length is not accepted.
/// $lower_bound and $upper_bound is the inclusive range of which a slice might
/// be acceptable in length. If a slice may only be a fixed size, $lower_bound
/// and $upper_bound should be the same. The `value` field will always be allocated with
/// a size of $upper_bound.
macro_rules! func_from_slice (($name:ident, $lower_bound:expr, $upper_bound:expr) => (
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Construct from a given byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<$name, UnknownCryptoError> {

        let slice_len = slice.len();

        if !($lower_bound..=$upper_bound).contains(&slice_len) {
            return Err(UnknownCryptoError);
        }

        let mut value = [0u8; $upper_bound];
        value[..slice_len].copy_from_slice(slice);

        Ok($name { value, original_length: slice_len })
    }
));

#[cfg(feature = "safe_api")]
/// Macro to implement a `from_slice()` function. Returns `UnknownCryptoError`
/// if the slice is empty.
macro_rules! func_from_slice_variable_size (($name:ident) => (
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    #[cfg(feature = "safe_api")]
    /// Construct from a given byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<$name, UnknownCryptoError> {
        // See issue on `isize` limit: https://github.com/orion-rs/orion/issues/130
        if slice.is_empty() || slice.len() > (isize::MAX as usize) {
            return Err(UnknownCryptoError);
        }

        Ok($name { value: Vec::from(slice), original_length: slice.len() })
    }
));

/// Macro to implement a `unprotected_as_bytes()` function for objects that
/// implement extra protections. Typically used on objects that implement
/// `Drop`.
macro_rules! func_unprotected_as_bytes (() => (
    #[inline]
    /// Return the object as byte slice. __**Warning**__: Should not be used unless strictly
    /// needed. This __**breaks protections**__ that the type implements.
    pub fn unprotected_as_bytes(&self) -> &[u8] {
        self.value[..self.original_length].as_ref()
    }
));

/// Macro to implement a `len()` function which will return the original_length
/// field. Meaning the amount of bytes the newtype was created from.
macro_rules! func_len (() => (
    #[inline]
    /// Return the length of the object.
    pub fn len(&self) -> usize {
        self.original_length
    }
));

/// Macro to implement an `is_empty()` function which will return `true` if `self.len() == 0`.
macro_rules! func_is_empty (() => (
    #[inline]
    /// Return `true` if this object does not hold any data, `false` otherwise.
    ///
    /// __NOTE__: This method should always return `false`, since there shouldn't be a way
    /// to create an empty instance of this object.
    pub fn is_empty(&self) -> bool {
        self.original_length == 0
    }
));

/// Macro to implement a `generate()` function for objects that benefit from
/// having a CSPRNG available to generate data of a fixed length $gen_length.
macro_rules! func_generate (($name:ident, $upper_bound:expr, $gen_length:expr) => (
    #[cfg(feature = "safe_api")]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate() -> $name {
        let mut value = [0u8; $upper_bound];
        // This will not panic on size, unless the newtype has been defined with $upper_bound
        // or $gen_length equal to 0.
        crate::util::secure_rand_bytes(&mut value[..$gen_length]).unwrap();

        $name { value, original_length: $gen_length }
    }
));

#[cfg(feature = "safe_api")]
/// Macro to implement a `generate()` function for objects that benefit from
/// having a CSPRNG available to generate data of a variable length.
macro_rules! func_generate_variable_size (($name:ident) => (
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    #[cfg(feature = "safe_api")]
    /// Randomly generate using a CSPRNG. Not available in `no_std` context.
    pub fn generate(length: usize) -> Result<$name, UnknownCryptoError> {
        // See issue on `isize` limit: https://github.com/orion-rs/orion/issues/130
        if length < 1 || length > (isize::MAX as usize) {
            return Err(UnknownCryptoError);
        }

        let mut value = vec![0u8; length];
        // This cannot panic on size input due to above length checks.
        crate::util::secure_rand_bytes(&mut value).unwrap();

        Ok($name { value, original_length: length })
    }
));

///
/// Test implementation macros

#[cfg(test)]
#[cfg(feature = "serde")]
macro_rules! test_serde_impls (($name:ident, $gen_length:expr) => (
    #[test]
    fn test_serde_serialized_equivalence_to_bytes_fn() {
        let bytes = &[38u8; $gen_length][..];
        let orion_type = $name::from_slice(bytes).unwrap();
        let serialized_from_bytes = serde_json::to_value(bytes).unwrap();
        let serialized_from_orion_type = serde_json::to_value(&orion_type).unwrap();
        assert_eq!(serialized_from_bytes, serialized_from_orion_type);
    }

    #[test]
    fn test_serde_deserialized_equivalence_to_bytes_fn() {
        let bytes = &[38u8; $gen_length][..];
        let serialized_from_bytes = serde_json::to_value(bytes).unwrap();
        let orion_type: $name = serde_json::from_value(serialized_from_bytes).unwrap();
        assert_eq!(orion_type, bytes);
    }
));

#[cfg(test)]
macro_rules! test_bound_parameters (($name:ident, $lower_bound:expr, $upper_bound:expr, $gen_length:expr) => (
    #[test]
    fn test_bound_params() {
        // $lower_bound:
        assert!($lower_bound <= $upper_bound);
        // $upper_bound:
        // $gen_length:
        assert!($gen_length <= $upper_bound);
        assert!($gen_length >= $lower_bound);
    }
));

#[cfg(test)]
macro_rules! test_partial_eq (($name:ident, $upper_bound:expr) => (
    #[test]
    fn test_partial_eq() {
        // PartialEq<Self>
        assert_eq!($name::from_slice(&[0u8; $upper_bound]).unwrap(), $name::from_slice(&[0u8; $upper_bound]).unwrap());
        assert_ne!($name::from_slice(&[0u8; $upper_bound]).unwrap(), $name::from_slice(&[1u8; $upper_bound]).unwrap());
        // PartialEq<&[u8]>
        assert_eq!($name::from_slice(&[0u8; $upper_bound]).unwrap(), [0u8; $upper_bound].as_ref());
        assert_ne!($name::from_slice(&[0u8; $upper_bound]).unwrap(), [1u8; $upper_bound].as_ref());
    }
));

#[cfg(test)]
macro_rules! test_from_slice (($name:ident, $lower_bound:expr, $upper_bound:expr) => (
    #[test]
    fn test_from_slice() {
        assert!($name::from_slice(&[0u8; $upper_bound]).is_ok());
        assert!($name::from_slice(&[0u8; $lower_bound]).is_ok());

        assert!($name::from_slice(&[0u8; $upper_bound + 1]).is_err());
        assert!($name::from_slice(&[0u8; $lower_bound - 1]).is_err());
        assert!($name::from_slice(&[0u8; 0]).is_err());

        // Test non-fixed-length definitions
        if $upper_bound != $lower_bound {
            assert!($name::from_slice(&[0u8; $upper_bound - 1]).is_ok());
            assert!($name::from_slice(&[0u8; $lower_bound + 1]).is_ok());
        }
    }
));

#[cfg(test)]
macro_rules! test_as_bytes_and_get_length (($name:ident, $lower_bound:expr, $upper_bound:expr, $bytes_function:ident) => (
    #[test]
    fn test_as_bytes() {
        let test_upper = $name::from_slice(&[0u8; $upper_bound]).unwrap();
        let test_lower = $name::from_slice(&[0u8; $lower_bound]).unwrap();

        assert_eq!(test_upper.$bytes_function().len(), test_upper.len());
        assert_eq!(test_upper.len(), $upper_bound);

        assert_eq!(test_lower.$bytes_function().len(), test_lower.len());
        assert_eq!(test_lower.len(), $lower_bound);

        assert_eq!(test_upper.is_empty(), false);
        assert_eq!(test_lower.is_empty(), false);

        // Test non-fixed-length definitions
        if $lower_bound != $upper_bound {
            let test_upper = $name::from_slice(&[0u8; $upper_bound - 1]).unwrap();
            let test_lower = $name::from_slice(&[0u8; $lower_bound + 1]).unwrap();

            assert_eq!(test_upper.$bytes_function().len(), test_upper.len());
            assert_eq!(test_upper.len(), $upper_bound - 1);

            assert_eq!(test_lower.$bytes_function().len(), test_lower.len());
            assert_eq!(test_lower.len(), $lower_bound + 1);

            assert_eq!(test_upper.is_empty(), false);
            assert_eq!(test_lower.is_empty(), false);
        }
    }
));

#[cfg(test)]
#[cfg(feature = "safe_api")]
macro_rules! test_generate (($name:ident, $gen_length:expr) => (
    #[test]
    #[cfg(feature = "safe_api")]
    fn test_generate() {
        let test_zero = $name::from_slice(&[0u8; $gen_length]).unwrap();
        // A random one should never be all 0's.
        let test_rand = $name::generate();
        assert_ne!(test_zero, test_rand);
        // A random generated one should always be $gen_length in length.
        assert_eq!(test_rand.len(), $gen_length);
    }
));

#[cfg(test)]
#[cfg(feature = "safe_api")]
macro_rules! test_omitted_debug (($name:ident, $upper_bound:expr) => (
    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_omitted_debug() {
        let secret = format!("{:?}", [0u8; $upper_bound].as_ref());
        let test_debug_contents = format!("{:?}", $name::from_slice(&[0u8; $upper_bound]).unwrap());
        assert_eq!(test_debug_contents.contains(&secret), false);
    }
));

#[cfg(test)]
#[cfg(feature = "safe_api")]
macro_rules! test_normal_debug (($name:ident, $upper_bound:expr) => (
    #[test]
    #[cfg(feature = "safe_api")]
    // format! is only available with std
    fn test_normal_debug() {
        let public = format!("{:?}", [0u8; $upper_bound].as_ref());
        let test_debug_contents = format!("{:?}", $name::from_slice(&[0u8; $upper_bound]).unwrap());
        assert_eq!(test_debug_contents.contains(&public), true);
    }
));

#[cfg(test)]
#[cfg(feature = "safe_api")]
macro_rules! test_from_slice_variable (($name:ident) => (
    #[test]
    #[cfg(feature = "safe_api")]
    fn test_from_slice_variable() {
        assert!($name::from_slice(&[0u8; 512]).is_ok());
        assert!($name::from_slice(&[0u8; 256]).is_ok());
        assert!($name::from_slice(&[0u8; 1]).is_ok());
        assert!($name::from_slice(&[0u8; 0]).is_err());
    }
));

#[cfg(test)]
#[cfg(feature = "safe_api")]
macro_rules! test_generate_variable (($name:ident) => (
    #[test]
    #[cfg(feature = "safe_api")]
    fn test_generate_variable() {
        assert!($name::generate(0).is_err());
        assert!($name::generate((isize::MAX as usize) + 1).is_err());
        assert!($name::generate(1).is_ok());
        assert!($name::generate(64).is_ok());

        let test_zero = $name::from_slice(&[0u8; 128]).unwrap();
        // A random one should never be all 0's.
        let test_rand = $name::generate(128).unwrap();
        assert_ne!(test_zero, test_rand);
        assert_eq!(test_rand.len(), 128);
    }
));

// Newtype implementation macros

/// Macro to construct a type containing sensitive data, using a fixed-size
/// array.
///
/// - $name: The name for the newtype.
///
/// - $test_module_name: The name for the newtype's testing module (usually
///   "test_$name").
///
/// - $lower_bound/$upper_bound: An inclusive range that defines what length a
///   secret value might be. Used to validate length of `slice` in from_slice().
///   $upper_bound also defines the `value` field array allocation size.
///
/// - $gen_length: The amount of data to be randomly generated when using
///   generate().
macro_rules! construct_secret_key {
    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $lower_bound:expr, $upper_bound:expr)) => (
        $(#[$meta])*
        ///
        /// # Security:
        /// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
        /// that the type implements.
        ///
        /// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
        /// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
        /// is implemented in such a way that the comparison happens in constant time. Thus, users should
        /// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
        /// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
        /// ```rust
        /// # #[cfg(feature = "safe_api")] {
        /// use orion::hazardous::stream::chacha20::SecretKey;
        ///
        /// // Initialize a secret key with random bytes.
        /// let secret_key = SecretKey::generate();
        ///
        /// // Secure, constant-time comparison with a byte slice
        /// assert_ne!(secret_key, &[0; 32][..]);
        ///
        /// // Secure, constant-time comparison with another SecretKey
        /// assert_ne!(secret_key, SecretKey::generate());
        /// # }
        /// # Ok::<(), orion::errors::UnknownCryptoError>(())
        /// ```
        pub struct $name {
            value: [u8; $upper_bound],
            original_length: usize,
        }

        impl_omitted_debug_trait!($name);
        impl_drop_trait!($name);
        impl_ct_partialeq_trait!($name, unprotected_as_bytes);

        impl $name {
            func_from_slice!($name, $lower_bound, $upper_bound);
            func_unprotected_as_bytes!();
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;

            test_bound_parameters!($name, $lower_bound, $upper_bound, $upper_bound);
            test_from_slice!($name, $lower_bound, $upper_bound);
            test_as_bytes_and_get_length!($name, $lower_bound, $upper_bound, unprotected_as_bytes);
            test_partial_eq!($name, $upper_bound);

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_omitted_debug!($name, $upper_bound);
            }
        }
    );

    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $lower_bound:expr, $upper_bound:expr, $gen_length:expr)) => (
        $(#[$meta])*
        ///
        /// # Security:
        /// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
        /// that the type implements.
        ///
        /// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
        /// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
        /// is implemented in such a way that the comparison happens in constant time. Thus, users should
        /// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
        /// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
        /// ```rust
        /// # #[cfg(feature = "safe_api")] {
        /// use orion::hazardous::stream::chacha20::SecretKey;
        ///
        /// // Initialize a secret key with random bytes.
        /// let secret_key = SecretKey::generate();
        ///
        /// // Secure, constant-time comparison with a byte slice
        /// assert_ne!(secret_key, &[0; 32][..]);
        ///
        /// // Secure, constant-time comparison with another SecretKey
        /// assert_ne!(secret_key, SecretKey::generate());
        /// # }
        /// # Ok::<(), orion::errors::UnknownCryptoError>(())
        /// ```
        pub struct $name {
            value: [u8; $upper_bound],
            original_length: usize,
        }

        impl_omitted_debug_trait!($name);
        impl_drop_trait!($name);
        impl_ct_partialeq_trait!($name, unprotected_as_bytes);

        impl $name {
            func_from_slice!($name, $lower_bound, $upper_bound);
            func_unprotected_as_bytes!();
            func_generate!($name, $upper_bound, $gen_length);
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;

            test_bound_parameters!($name, $lower_bound, $upper_bound, $gen_length);
            test_from_slice!($name, $lower_bound, $upper_bound);
            test_as_bytes_and_get_length!($name, $lower_bound, $upper_bound, unprotected_as_bytes);
            test_partial_eq!($name, $upper_bound);

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_generate!($name, $gen_length);
                test_omitted_debug!($name, $upper_bound);
            }
        }
    );
}

/// Macro to construct a public type containing non-sensitive data, using a
/// fixed-size array.
///
/// - $name: The name for the newtype.
///
/// - $test_module_name: The name for the newtype's testing module (usually
///   "test_$name").
///
/// - $lower_bound/$upper_bound: An inclusive range that defines what length a
///   public value might be. Used to validate length of `slice` in from_slice().
///   $upper_bound also defines the `value` field array allocation size.
///
/// - $gen_length: The amount of data to be randomly generated when using
///   generate(). If not supplied, the public newtype will not have a
///   `generate()` function available.
macro_rules! construct_public {
    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $lower_bound:expr, $upper_bound:expr)) => (
        #[derive(Clone, Copy)]
        $(#[$meta])*
        ///
        pub struct $name {
            pub(crate) value: [u8; $upper_bound],
            original_length: usize,
        }

        impl_ct_partialeq_trait!($name, as_ref);
        impl_normal_debug_trait!($name);
        impl_try_from_trait!($name);
        impl_asref_trait!($name);

        #[cfg(feature = "serde")]
        impl_serde_traits!($name, as_ref);

        impl $name {
            func_from_slice!($name, $lower_bound, $upper_bound);
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;
            // Replace $gen_length with $upper_bound since this doesn't have
            // generate() function.
            test_bound_parameters!($name, $lower_bound, $upper_bound, $upper_bound);
            test_from_slice!($name, $lower_bound, $upper_bound);
            test_as_bytes_and_get_length!($name, $lower_bound, $upper_bound, as_ref);
            test_partial_eq!($name, $upper_bound);

            #[cfg(feature = "serde")]
            test_serde_impls!($name, $upper_bound);

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_normal_debug!($name, $upper_bound);
            }
        }
    );

    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $lower_bound:expr, $upper_bound:expr, $gen_length:expr)) => (
        #[derive(Clone, Copy)]
        $(#[$meta])*
        ///
        pub struct $name {
            pub(crate) value: [u8; $upper_bound],
            original_length: usize,
        }

        impl_ct_partialeq_trait!($name, as_ref);
        impl_normal_debug_trait!($name);
        impl_try_from_trait!($name);
        impl_asref_trait!($name);

        #[cfg(feature = "serde")]
        impl_serde_traits!($name, as_ref);

        impl $name {
            func_from_slice!($name, $lower_bound, $upper_bound);
            func_generate!($name, $upper_bound, $gen_length);
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;
            test_bound_parameters!($name, $lower_bound, $upper_bound, $upper_bound);
            test_from_slice!($name, $lower_bound, $upper_bound);
            test_as_bytes_and_get_length!($name, $lower_bound, $upper_bound, as_ref);
            test_partial_eq!($name, $upper_bound);

            #[cfg(feature = "serde")]
            test_serde_impls!($name, $upper_bound);

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_normal_debug!($name, $upper_bound);
                test_generate!($name, $gen_length);
            }
        }
    );
}

/// Macro to construct a tag type that MACs return.
macro_rules! construct_tag {
    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $lower_bound:expr, $upper_bound:expr)) => (
        #[derive(Clone)]
        $(#[$meta])*
        ///
        /// # Security:
        /// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
        /// that the type implements.
        ///
        /// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
        /// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
        /// is implemented in such a way that the comparison happens in constant time. Thus, users should
        /// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
        /// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
        /// ```rust
        /// use orion::hazardous::mac::hmac::sha512::Tag;
        ///
        /// // Initialize an arbitrary, 64-byte tag.
        /// let tag = Tag::from_slice(&[1; 64])?;
        ///
        /// // Secure, constant-time comparison with a byte slice
        /// assert_eq!(tag, &[1; 64][..]);
        ///
        /// // Secure, constant-time comparison with another Tag
        /// assert_eq!(tag, Tag::from_slice(&[1; 64])?);
        /// # Ok::<(), orion::errors::UnknownCryptoError>(())
        /// ```
        pub struct $name {
            value: [u8; $upper_bound],
            original_length: usize,
        }

        impl_omitted_debug_trait!($name);
        impl_drop_trait!($name);
        impl_ct_partialeq_trait!($name, unprotected_as_bytes);
        impl_try_from_trait!($name);

        #[cfg(feature = "serde")]
        impl_serde_traits!($name, unprotected_as_bytes);

        impl $name {
            func_from_slice!($name, $lower_bound, $upper_bound);
            func_unprotected_as_bytes!();
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;
            // Replace $gen_length with $upper_bound since a tag doesn't have
            // generate() function.
            test_bound_parameters!($name, $lower_bound, $upper_bound, $upper_bound);
            test_from_slice!($name, $lower_bound, $upper_bound);
            test_as_bytes_and_get_length!($name, $lower_bound, $upper_bound, unprotected_as_bytes);
            test_partial_eq!($name, $upper_bound);

            #[cfg(feature = "serde")]
            test_serde_impls!($name, $upper_bound);

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_omitted_debug!($name, $upper_bound);
            }
        }
    );
}

/// Macro to construct a secret key used for HMAC. This pre-pads the given key
/// to the required length specified by the HMAC specifications.
macro_rules! construct_hmac_key {
    ($(#[$meta:meta])*
    ($name:ident, $sha2:ident, $sha2_outsize:expr, $test_module_name:ident, $size:expr)) => (
        $(#[$meta])*
        ///
        /// # Security:
        /// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
        /// that the type implements.
        ///
        /// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
        /// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
        /// is implemented in such a way that the comparison happens in constant time. Thus, users should
        /// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
        /// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
        /// ```rust
        /// # #[cfg(feature = "safe_api")] {
        /// use orion::hazardous::mac::hmac::sha512::SecretKey;
        ///
        /// // Initialize a secret key with random bytes.
        /// let secret_key = SecretKey::generate();
        ///
        /// // Secure, constant-time comparison with a byte slice
        /// assert_ne!(secret_key, &[0; 32][..]);
        ///
        /// // Secure, constant-time comparison with another SecretKey
        /// assert_ne!(secret_key, SecretKey::generate());
        /// # }
        /// # Ok::<(), orion::errors::UnknownCryptoError>(())
        /// ```
        pub struct $name {
            value: [u8; $size],
            original_length: usize,
        }

        impl_omitted_debug_trait!($name);
        impl_drop_trait!($name);
        impl_ct_partialeq_trait!($name, unprotected_as_bytes);

        impl $name {
            #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
            /// Construct from a given byte slice.
            pub fn from_slice(slice: &[u8]) -> Result<$name, UnknownCryptoError> {
                let mut secret_key = [0u8; $size];

                let slice_len = slice.len();

                if slice_len > $size {
                    secret_key[..$sha2_outsize].copy_from_slice(&$sha2::digest(slice)?.as_ref());
                } else {
                    secret_key[..slice_len].copy_from_slice(slice);
                }

                Ok($name { value: secret_key, original_length: $size })
            }

            func_unprotected_as_bytes!();
            func_generate!($name, $size, $size);
            func_len!();
            func_is_empty!();
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;
            test_as_bytes_and_get_length!($name, $size, $size, unprotected_as_bytes);
            test_partial_eq!($name, $size);

            #[test]
            fn test_key_size() {
                assert!($name::from_slice(&[0u8; $size]).is_ok());
                assert!($name::from_slice(&[0u8; $size - $size]).is_ok());
                assert!($name::from_slice(&[0u8; $size + 1]).is_ok());
            }

            #[cfg(test)]
            #[cfg(feature = "safe_api")]
            mod tests_with_std {
                use super::*;

                test_generate!($name, $size);
                test_omitted_debug!($name, $size);
            }
        }
    );
}

#[cfg(feature = "safe_api")]
/// Macro to construct a type containing sensitive data which is stored on the
/// heap.
macro_rules! construct_secret_key_variable_size {
    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $default_size:expr)) => (
        #[cfg(feature = "safe_api")]
        $(#[$meta])*
        ///
        /// # Security:
        /// - __**Avoid using**__ `unprotected_as_bytes()` whenever possible, as it breaks all protections
        /// that the type implements.
        ///
        /// - The trait `PartialEq<&'_ [u8]>` is implemented for this type so that users are not tempted
        /// to call `unprotected_as_bytes` to compare this sensitive value to a byte slice. The trait
        /// is implemented in such a way that the comparison happens in constant time. Thus, users should
        /// prefer `SecretType == &[u8]` over `SecretType.unprotected_as_bytes() == &[u8]`.
        /// Examples are shown below. The examples apply to any type that implements `PartialEq<&'_ [u8]>`.
        /// ```rust
        /// # #[cfg(feature = "safe_api")] {
        /// use orion::pwhash::Password;
        ///
        /// // Initialize a password with 32 random bytes.
        /// let password = Password::generate(32)?;
        ///
        /// // Secure, constant-time comparison with a byte slice
        /// assert_ne!(password, &[0; 32][..]);
        ///
        /// // Secure, constant-time comparison with another Password
        /// assert_ne!(password, Password::generate(32)?);
        /// # }
        /// # Ok::<(), orion::errors::UnknownCryptoError>(())
        /// ```
        pub struct $name {
            pub(crate) value: Vec<u8>,
            original_length: usize,
        }

        impl_omitted_debug_trait!($name);
        impl_drop_trait!($name);
        impl_ct_partialeq_trait!($name, unprotected_as_bytes);
        impl_default_trait!($name, $default_size);

        impl $name {
            func_from_slice_variable_size!($name);
            func_unprotected_as_bytes!();
            func_len!();
            func_is_empty!();
            func_generate_variable_size!($name);
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;

            test_from_slice_variable!($name);
            test_as_bytes_and_get_length!($name, 1, $default_size + 1, unprotected_as_bytes);
            test_generate_variable!($name);
            test_omitted_debug!($name, $default_size);
            test_partial_eq!($name, $default_size);
        }
    );
}

#[cfg(feature = "safe_api")]
/// Macro to construct a type containing non-sensitive which is stored on the
/// heap.
macro_rules! construct_salt_variable_size {
    ($(#[$meta:meta])*
    ($name:ident, $test_module_name:ident, $default_size:expr)) => (
        #[cfg(feature = "safe_api")]
        $(#[$meta])*
        ///
        pub struct $name {
            value: Vec<u8>,
            original_length: usize,
        }

        impl_normal_debug_trait!($name);
        impl_default_trait!($name, $default_size);
        impl_ct_partialeq_trait!($name, as_ref);
        impl_asref_trait!($name);
        impl_try_from_trait!($name);

        #[cfg(feature = "serde")]
        impl_serde_traits!($name, as_ref);

        impl $name {
            func_from_slice_variable_size!($name);
            func_len!();
            func_is_empty!();
            func_generate_variable_size!($name);
        }

        #[cfg(test)]
        mod $test_module_name {
            use super::*;

            test_from_slice_variable!($name);
            test_as_bytes_and_get_length!($name, 1, $default_size + 1, as_ref);
            test_generate_variable!($name);
            test_partial_eq!($name, $default_size);
            test_normal_debug!($name, $default_size);

            #[cfg(feature = "serde")]
            test_serde_impls!($name, $default_size);
        }
    );
}
