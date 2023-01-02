// MIT License

// Copyright (c) 2018-2023 The orion Developers

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

use core::fmt;

#[allow(clippy::derive_partial_eq_without_eq)]
/// Opaque error.
#[derive(Clone, Copy, PartialEq)]
pub struct UnknownCryptoError;

impl fmt::Display for UnknownCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownCryptoError")
    }
}

impl fmt::Debug for UnknownCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownCryptoError")
    }
}

#[cfg(feature = "safe_api")]
impl std::error::Error for UnknownCryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(feature = "safe_api")]
impl From<getrandom::Error> for UnknownCryptoError {
    fn from(_: getrandom::Error) -> Self {
        UnknownCryptoError
    }
}

#[cfg(feature = "safe_api")]
impl From<ct_codecs::Error> for UnknownCryptoError {
    fn from(_: ct_codecs::Error) -> Self {
        UnknownCryptoError
    }
}

impl From<core::num::ParseIntError> for UnknownCryptoError {
    fn from(_: core::num::ParseIntError) -> Self {
        UnknownCryptoError
    }
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_unknown_crypto_error_debug_display() {
    // Tests Debug impl through "{:?}"
    let err = format!("{:?}", UnknownCryptoError);
    assert_eq!(err, "UnknownCryptoError");
    // Tests Display impl through "{}"
    let err = format!("{}", UnknownCryptoError);
    assert_eq!(err, "UnknownCryptoError");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_unknown_crypto_from_getrandom() {
    use core::num::NonZeroU32;
    // Choose some random error code.
    let err_code = NonZeroU32::new(12).unwrap();
    let err_foreign: getrandom::Error = getrandom::Error::from(err_code);

    // Tests Debug impl through "{:?}"
    let err = format!("{:?}", UnknownCryptoError::from(err_foreign));
    assert_eq!(err, "UnknownCryptoError");
    // Tests Display impl through "{}"
    let err = format!("{}", UnknownCryptoError::from(err_foreign));
    assert_eq!(err, "UnknownCryptoError");
}

#[test]
#[cfg(feature = "safe_api")]
fn test_source() {
    use std::error::Error;
    assert!(UnknownCryptoError.source().is_none());
}

#[test]
#[cfg(feature = "safe_api")]
fn test_unknown_crypto_from_decode_error() {
    use ct_codecs::Error;

    let err_one = Error::InvalidInput;
    let err_two = Error::Overflow;

    // Tests Debug impl through "{:?}" and Display impl though "{}"
    let err = format!(
        "{:?}:{}",
        UnknownCryptoError::from(err_one),
        UnknownCryptoError::from(err_one)
    );
    assert_eq!(err, "UnknownCryptoError:UnknownCryptoError");
    let err = format!(
        "{:?}:{}",
        UnknownCryptoError::from(err_two),
        UnknownCryptoError::from(err_two)
    );
    assert_eq!(err, "UnknownCryptoError:UnknownCryptoError");
}

#[test]
#[cfg(feature = "safe_api")]
fn test_unknown_crypto_from_parseint_error() {
    let err_foreign = "j".parse::<u32>().unwrap_err();

    // Tests Debug impl through "{:?}" and Display impl though "{}"
    let err = format!(
        "{:?}:{}",
        UnknownCryptoError::from(err_foreign.clone()),
        UnknownCryptoError::from(err_foreign)
    );
    assert_eq!(err, "UnknownCryptoError:UnknownCryptoError");
}
