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

extern crate core;

use self::core::fmt;
#[cfg(feature = "safe_api")]
use rand_os::rand_core;

/// Opaque error.
#[derive(PartialEq)]
pub struct UnknownCryptoError;

impl fmt::Display for UnknownCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "UnknownCryptoError") }
}

impl fmt::Debug for UnknownCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "UnknownCryptoError") }
}

#[cfg(feature = "safe_api")]
// Required for rand's generators
impl From<rand_core::Error> for UnknownCryptoError {
	fn from(_: rand_core::Error) -> Self { UnknownCryptoError }
}

impl From<FinalizationCryptoError> for UnknownCryptoError {
	fn from(_: FinalizationCryptoError) -> Self { UnknownCryptoError }
}

/// Error for a failed verification.
#[derive(PartialEq)]
pub struct ValidationCryptoError;

impl fmt::Display for ValidationCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "ValidationCryptoError - Failed verification")
	}
}

impl fmt::Debug for ValidationCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "ValidationCryptoError - Failed verification")
	}
}

impl From<UnknownCryptoError> for ValidationCryptoError {
	fn from(_: UnknownCryptoError) -> Self { ValidationCryptoError }
}

/// Error for calling a finalization method on an object that needs to be reset
/// first.
pub struct FinalizationCryptoError;

impl fmt::Display for FinalizationCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "FinalizationCryptoError - Missing reset")
	}
}

impl fmt::Debug for FinalizationCryptoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "FinalizationCryptoError - Missing reset")
	}
}

impl From<UnknownCryptoError> for FinalizationCryptoError {
	fn from(_: UnknownCryptoError) -> Self { FinalizationCryptoError }
}

impl From<FinalizationCryptoError> for ValidationCryptoError {
	fn from(_: FinalizationCryptoError) -> Self { ValidationCryptoError }
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_finalization_crypto_error_debug_display() {
	// Tests Debug impl though "{:?}"
	let err = format!("{:?}", FinalizationCryptoError);
    assert_eq!(err, "FinalizationCryptoError - Missing reset");
	// Tests Display impl though "{:?}"
	let err = format!("{}", FinalizationCryptoError);
    assert_eq!(err, "FinalizationCryptoError - Missing reset");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_finalization_crypto_error_from() {
	let err = format!("{:?}", FinalizationCryptoError::from(UnknownCryptoError));
    assert_eq!(err, "FinalizationCryptoError - Missing reset");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_validation_crypto_error_debug_display() {
	// Tests Debug impl though "{:?}"
	let err = format!("{:?}", ValidationCryptoError);
    assert_eq!(err, "ValidationCryptoError - Failed verification");
	// Tests Display impl though "{:?}"
	let err = format!("{}", ValidationCryptoError);
    assert_eq!(err, "ValidationCryptoError - Failed verification");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_validation_crypto_error_from() {
	let err = format!("{:?}", ValidationCryptoError::from(FinalizationCryptoError));
    assert_eq!(err, "ValidationCryptoError - Failed verification");
	let err = format!("{:?}", ValidationCryptoError::from(UnknownCryptoError));
    assert_eq!(err, "ValidationCryptoError - Failed verification");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_unknown_crypto_error_debug_display() {
	// Tests Debug impl though "{:?}"
	let err = format!("{:?}", UnknownCryptoError);
    assert_eq!(err, "UnknownCryptoError");
	// Tests Display impl though "{:?}"
	let err = format!("{}", UnknownCryptoError);
    assert_eq!(err, "UnknownCryptoError");
}

#[test]
#[cfg(feature = "safe_api")]
// format! is only available with std
fn test_unknown_crypto_error_from() {
	let err = format!("{:?}", UnknownCryptoError::from(rand_core::Error::new(rand_core::ErrorKind::NotReady, "CSPRNG not ready")));
    assert_eq!(err, "UnknownCryptoError");
	let err = format!("{:?}", UnknownCryptoError::from(FinalizationCryptoError));
    assert_eq!(err, "UnknownCryptoError");
}