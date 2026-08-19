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

use crate::{
    errors::UnknownCryptoError,
    generics::sealed::{Data, TryFromBytes},
    hazardous::kdf::{
        argon2::{ARGON2_VERSION_19, I, ID, MAX_SALT_LEN, validate_cost_parameters},
        sealed::Variant,
    },
};
use core::fmt::Debug;
use ct_codecs::{Base64NoPadding, Encoder};
use subtle::ConstantTimeEq;

#[cfg(feature = "safe_api")]
/// Argon2 P-H-C string format.
pub struct Argon2Phc {
    pub(crate) variant: String,
    pub(crate) version: u32,
    pub(crate) memory: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) hash: Vec<u8>,
    pub(crate) phc_string: String,
}
impl crate::generics::sealed::Sealed for Argon2Phc {}

impl PartialEq for Argon2Phc {
    fn eq(&self, other: &Self) -> bool {
        self.variant == other.variant
            && self.version == other.version
            && self.memory == other.memory
            && self.iterations == other.iterations
            && self.parallelism == other.parallelism
            && self.salt == other.salt
            && bool::from(self.hash.ct_eq(&other.hash))
            && bool::from(
                self.phc_string
                    .as_bytes()
                    .ct_eq(other.phc_string.as_bytes()),
            )
    }
}

impl Debug for Argon2Phc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Argon2Phc")
            .field("variant", &self.variant)
            .field("version", &self.version)
            .field("memory", &self.memory)
            .field("iterations", &self.iterations)
            .field("parallelism", &self.parallelism)
            .field("salt", &self.salt)
            .field("hash", &"{{***OMITTED***}}")
            .field("phc_string", &"{{***OMITTED***}}")
            .finish()
    }
}

impl Argon2Phc {
    const VALID_VARIANTS: [&'static str; 2] = [I::PHC_ID, ID::PHC_ID];

    /// Parse a decimal parameter value to a u32. Returns an error on overflow
    /// and if the value has leading zeroes.
    fn parse_decimal_value(value: &str) -> Result<u32, UnknownCryptoError> {
        // See: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#decimal-encoding
        if value.len() > 1 && value.starts_with('0') {
            return Err(UnknownCryptoError);
        }
        // .parse::<T>() detects overflows (in debug and release builds)
        // and rejects empty strings. If the value contains spaces, parsing
        // also fails.
        Ok(value.parse::<u32>()?)
    }

    pub(crate) fn encode_to_phc(&mut self) -> Result<(), UnknownCryptoError> {
        self.phc_string = format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant,
            self.version,
            self.memory,
            self.iterations,
            self.parallelism,
            Base64NoPadding::encode_to_string(&self.salt)?,
            Base64NoPadding::encode_to_string(&self.hash)?,
        );

        Ok(())
    }
}

impl TryFrom<&str> for Argon2Phc {
    type Error = UnknownCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use ct_codecs::{Base64NoPadding, Decoder};

        if value.contains(' ') {
            return Err(UnknownCryptoError);
        }

        let parts_split = value.split('$').collect::<Vec<&str>>();
        if parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut parts = parts_split.into_iter();
        if parts.next() != Some("") {
            return Err(UnknownCryptoError);
        }
        let variant = if let Some(variant) = parts.next() {
            if !Self::VALID_VARIANTS.contains(&variant) {
                return Err(UnknownCryptoError);
            }

            variant
        } else {
            return Err(UnknownCryptoError);
        };
        if parts.next() != Some("v=19") {
            return Err(UnknownCryptoError);
        }

        // Splits as ["m", "X", "t", "Y", "p", "Z"] where m=X, t=Y and p=Z.
        let param_parts_split = parts
            .next()
            .unwrap()
            .split(['=', ','])
            .collect::<Vec<&str>>();
        if param_parts_split.len() != 6 {
            return Err(UnknownCryptoError);
        }
        let mut param_parts = param_parts_split.into_iter();

        if param_parts.next() != Some("m") {
            return Err(UnknownCryptoError);
        }
        let memory = Self::parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("t") {
            return Err(UnknownCryptoError);
        }
        let iterations = Self::parse_decimal_value(param_parts.next().unwrap())?;

        if param_parts.next() != Some("p") {
            return Err(UnknownCryptoError);
        }
        let lanes = Self::parse_decimal_value(param_parts.next().unwrap())?;

        validate_cost_parameters(iterations, memory, lanes)?;
        let salt = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        if salt.len() > MAX_SALT_LEN as usize {
            return Err(UnknownCryptoError);
        }
        let password_hash_raw = Base64NoPadding::decode_to_vec(parts.next().unwrap(), None)?;
        // NOTE(brycx): Not a standards check, one we have had.
        if password_hash_raw.len() < 4 {
            return Err(UnknownCryptoError);
        }

        Ok(Self {
            variant: variant.into(),
            version: ARGON2_VERSION_19,
            memory,
            iterations,
            parallelism: lanes,
            salt,
            hash: password_hash_raw,
            phc_string: value.into(),
        })
    }
}

impl TryFromBytes for Argon2Phc {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        if let Ok(bytesstr) = str::from_utf8(bytes) {
            Self::try_from(bytesstr)
        } else {
            Err(UnknownCryptoError)
        }
    }
}

impl AsRef<[u8]> for Argon2Phc {
    fn as_ref(&self) -> &[u8] {
        self.phc_string.as_bytes()
    }
}

impl AsMut<[u8]> for Argon2Phc {
    fn as_mut(&mut self) -> &mut [u8] {
        unimplemented!(
            "CORRECTNESS: Argon2Phc string should never be modified in the self.phc_string only."
        )
    }
}

impl Data for Argon2Phc {
    fn len(&self) -> usize {
        self.phc_string.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn new(_size: usize) -> Result<Self, UnknownCryptoError> {
        unimplemented!("CORRECTNESS: Not applicable for this type.")
    }

    #[cfg(feature = "zeroize")]
    fn memzero(&mut self) {
        use zeroize::Zeroize;
        self.hash.zeroize();
        self.phc_string.zeroize();
    }
}
